/*---------------------------------------------------------------------------------------------
 *  seclab-vscode: the agent-host protocol gate's filter (patch 0015).
 *  Pure and import-free on purpose: the same file runs under node's type stripping in the
 *  repo's unit tests. Everything the tab's agent host sends is data, filtered here before the
 *  workbench parses it; everything the workbench sends is filtered before it leaves.
 *--------------------------------------------------------------------------------------------*/

/** Verdict tables. Anything not listed is denied. Built from `seclabAhpPolicyData.ts`. */
export interface SeclabAhpTables {
	/** Client-to-agent-host requests. */
	readonly clientRequests: Readonly<Record<string, SeclabAhpVerdict>>;
	/** Client-to-agent-host notifications. */
	readonly clientNotifications: Readonly<Record<string, SeclabAhpVerdict>>;
	/** Agent-host-to-client notifications. Agent-host-to-client requests are always refused. */
	readonly serverNotifications: Readonly<Record<string, SeclabAhpVerdict>>;
	/** Action types the client may dispatch. */
	readonly clientActions: Readonly<Record<string, SeclabAhpVerdict>>;
	/** Action types the agent host may send. */
	readonly serverActions: Readonly<Record<string, SeclabAhpVerdict>>;
	/** `initialize` / `reconnect` `_meta` keys the client may send. */
	readonly clientMetaKeys: readonly string[];
	/** Root config keys the client may mirror into the agent host. */
	readonly rootConfigKeys: readonly string[];
}

export type SeclabAhpVerdict = 'allow' | 'deny';
export type SeclabAhpPriority = 'critical' | 'warning' | 'notice' | 'informational';

/** The shape `tab.events.report` accepts for source `ahp-gate` (tabd/src/obs/glue.ts). */
export interface SeclabAhpEvent {
	readonly source: 'ahp-gate';
	readonly class: 'ahp.decision';
	readonly priority: SeclabAhpPriority;
	readonly summary: string;
	readonly detail: Record<string, string | number | boolean>;
}

export interface SeclabAhpOutput {
	/** Frames to send on toward the agent host, in order. */
	readonly toUpstream: string[];
	/** Frames to deliver to the workbench's protocol client, in order. */
	readonly toClient: string[];
}

export const SECLAB_AHP_MAX_FRAME = 32 * 1024 * 1024;
const MAX_DEPTH = 64;
const MAX_TEXT = 80;
/** Keys removed from everything the agent host sends: the agent host chooses neither an
 *  authorization server for the user's credentials (A1) nor MCP App UI (A21). */
const STRIP_KEYS = new Set(['protectedResources', 'mcpApp']);
/** Error code for requests the gate refuses (JSON-RPC "method not found"). */
export const SECLAB_AHP_REFUSED = -32601;
const REFUSED_MESSAGE = 'Refused by the seclab agent-host gate';

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };
type Obj = { [k: string]: Json };

function isObj(v: unknown): v is Obj {
	return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function clip(s: unknown): string {
	const t = typeof s === 'string' ? s : typeof s;
	return t.length > MAX_TEXT ? t.slice(0, MAX_TEXT) : t;
}

function isUi(v: Json): boolean {
	return typeof v === 'string' && /^\s*ui:/i.test(v);
}

/** Removes STRIP_KEYS and any `ui:` string value, in place. Returns how many it removed.
 *  Throws past MAX_DEPTH. */
export function seclabAhpSanitize(value: Json, depth = 0): number {
	if (depth > MAX_DEPTH) {
		throw new Error('seclab AHP gate: message too deep');
	}
	let n = 0;
	if (Array.isArray(value)) {
		for (let i = value.length - 1; i >= 0; i--) {
			if (isUi(value[i])) {
				value.splice(i, 1);
				n++;
			} else {
				n += seclabAhpSanitize(value[i], depth + 1);
			}
		}
	} else if (isObj(value)) {
		for (const k of Object.keys(value)) {
			if (STRIP_KEYS.has(k) || isUi(value[k])) {
				delete value[k];
				n++;
			} else {
				n += seclabAhpSanitize(value[k], depth + 1);
			}
		}
	}
	return n;
}

interface Fragments { readonly originals: string[]; joined: string }
type Dir = 'in' | 'out';

/** One instance per transport (connection); never shared across connections. */
export class SeclabAhpFilter {
	private readonly tables: SeclabAhpTables;
	private readonly connection: number;
	private readonly emit: (e: SeclabAhpEvent) => void;
	/** Outbound request ids the gate let through, with their method. */
	private readonly pending = new Map<string, string>();
	private readonly fragments = { in: new Map<string, Fragments>(), out: new Map<string, Fragments>() };

	constructor(tables: SeclabAhpTables, connection: number, emit: (e: SeclabAhpEvent) => void) {
		this.tables = tables;
		this.connection = connection;
		this.emit = emit;
	}

	/** A frame the workbench sends toward the agent host. */
	fromClient(text: string): SeclabAhpOutput {
		return this.frame(text, 'out');
	}

	/** A frame the agent host sends toward the workbench. */
	fromUpstream(text: string): SeclabAhpOutput {
		return this.frame(text, 'in');
	}

	private frame(text: string, dir: Dir): SeclabAhpOutput {
		const out: SeclabAhpOutput = { toUpstream: [], toClient: [] };
		const msg = this.parse(text, dir);
		if (!msg) {
			return out;
		}
		const handle = (m: Obj, t: string, inner: boolean) => dir === 'in' ? this.upstream(m, t, out, inner) : this.client(m, t, out, inner);
		if (msg.method === 'channel/frame' && !('id' in msg)) {
			this.reassemble(text, msg, dir, out, handle);
		} else {
			const forward = handle(msg, text, false);
			if (forward !== undefined) {
				(dir === 'in' ? out.toClient : out.toUpstream).push(forward);
			}
		}
		return out;
	}

	/** Returns the text to forward (the original, or the rewritten message), or undefined to drop. */
	private client(msg: Obj, text: string, out: SeclabAhpOutput, inner: boolean): string | undefined {
		const method = msg.method;
		const hasId = 'id' in msg;
		if (typeof method !== 'string') {
			// The gate refuses every agent-host request, so the client has nothing to answer.
			this.deny('ahp-gate.client-response', 'out', '', { id: clip(String(msg.id)) });
			return undefined;
		}
		if (inner && (hasId || method === 'channel/frame')) {
			this.deny('ahp-gate.fragment-content', 'out', method);
			return undefined;
		}
		if (hasId) {
			if (this.tables.clientRequests[method] !== 'allow') {
				this.deny('ahp-gate.method', 'out', method);
				out.toClient.push(JSON.stringify({ jsonrpc: '2.0', id: msg.id, error: { code: SECLAB_AHP_REFUSED, message: REFUSED_MESSAGE } }));
				return undefined;
			}
			this.pending.set(String(msg.id), method);
			if ((method === 'initialize' || method === 'reconnect') && isObj(msg.params) && isObj(msg.params._meta)) {
				const meta = msg.params._meta;
				const removed = Object.keys(meta).filter(k => !this.tables.clientMetaKeys.includes(k));
				if (removed.length) {
					for (const k of removed) {
						delete meta[k];
					}
					this.strip('ahp-gate.client-meta', 'out', method, removed.length);
					return JSON.stringify(msg);
				}
			}
			return text;
		}
		if (this.tables.clientNotifications[method] !== 'allow') {
			this.deny('ahp-gate.method', 'out', method);
			return undefined;
		}
		if (method !== 'dispatchAction') {
			return text;
		}
		const action = isObj(msg.params) ? msg.params.action : undefined;
		const type = isObj(action) ? action.type : undefined;
		if (!isObj(action) || typeof type !== 'string' || this.tables.clientActions[type] !== 'allow') {
			this.deny('ahp-gate.action', 'out', method, { actionType: clip(type) });
			return undefined;
		}
		let removed = 0;
		if (type === 'root/configChanged') {
			// A19: host settings mirrored into the agent host. Only allowlisted keys leave.
			const config = isObj(action.config) ? action.config : {};
			for (const k of Object.keys(config)) {
				if (!this.tables.rootConfigKeys.includes(k)) {
					delete config[k];
					removed++;
				}
			}
			if (!Object.keys(config).length) {
				this.strip('ahp-gate.root-config', 'out', method, removed, type);
				return undefined;
			}
		} else if (type === 'session/activeClientSet' && isObj(action.activeClient)) {
			// No client tools (A18) and no host customizations (A19) are advertised to the tab.
			const client = action.activeClient;
			if (Array.isArray(client.tools) && client.tools.length) {
				removed += client.tools.length;
				client.tools = [];
			}
			if ('customizations' in client) {
				delete client.customizations;
				removed++;
			}
		}
		if (!removed) {
			return text;
		}
		this.strip(type === 'root/configChanged' ? 'ahp-gate.root-config' : 'ahp-gate.client-tools', 'out', method, removed, type);
		return JSON.stringify(msg);
	}

	private upstream(msg: Obj, text: string, out: SeclabAhpOutput, inner: boolean): string | undefined {
		const method = msg.method;
		const hasId = 'id' in msg;
		if (typeof method === 'string' && hasId) {
			// A16, A5, A26, A7: the agent host asks the trusted side to act (files, certificates,
			// proxies, credentials). The gate answers every such request itself.
			this.deny('ahp-gate.reverse-request', 'in', method);
			if (!inner) {
				out.toUpstream.push(JSON.stringify({ jsonrpc: '2.0', id: msg.id, error: { code: SECLAB_AHP_REFUSED, message: REFUSED_MESSAGE } }));
			}
			return undefined;
		}
		if (inner && (hasId || method === 'channel/frame')) {
			this.deny('ahp-gate.fragment-content', 'in', typeof method === 'string' ? method : '');
			return undefined;
		}
		let label: string;
		if (typeof method !== 'string') {
			const id = String(msg.id);
			const request = this.pending.get(id);
			if (request === undefined) {
				this.deny('ahp-gate.unsolicited-response', 'in', '', { id: clip(id) });
				return undefined;
			}
			this.pending.delete(id);
			label = request;
		} else {
			if (this.tables.serverNotifications[method] !== 'allow') {
				this.deny('ahp-gate.method', 'in', method);
				return undefined;
			}
			if (method === 'action') {
				const action = isObj(msg.params) ? msg.params.action : undefined;
				const type = isObj(action) ? action.type : undefined;
				if (typeof type !== 'string' || this.tables.serverActions[type] !== 'allow') {
					this.deny('ahp-gate.action', 'in', method, { actionType: clip(type) });
					return undefined;
				}
			}
			label = method;
		}
		let removed: number;
		try {
			removed = seclabAhpSanitize(msg);
		} catch {
			this.deny('ahp-gate.depth', 'in', label);
			return undefined;
		}
		if (label === 'initialize' && isObj(msg.result)) {
			// Positive control: the real agent host's root state passed the gate.
			this.event('informational', 'ahp-gate.initialize', 'allow', { dir: 'in', method: label, agents: rootAgents(msg.result) });
		}
		if (!removed) {
			return text;
		}
		this.strip('ahp-gate.strip', 'in', label, removed);
		return JSON.stringify(msg);
	}

	/** Holds fragments until the final one and filters the joined message. Releases the original
	 *  fragments if it passed unchanged, or the rewritten message as one final fragment. */
	private reassemble(text: string, msg: Obj, dir: Dir, out: SeclabAhpOutput, handle: (m: Obj, t: string, inner: boolean) => string | undefined): void {
		const p = msg.params;
		if (!isObj(p) || typeof p.channel !== 'string' || typeof p.data !== 'string') {
			this.deny('ahp-gate.fragment', dir, 'channel/frame');
			return;
		}
		const store = this.fragments[dir];
		const f = store.get(p.channel) ?? { originals: [], joined: '' };
		f.originals.push(text);
		f.joined += p.data;
		if (f.joined.length > SECLAB_AHP_MAX_FRAME) {
			store.delete(p.channel);
			this.deny('ahp-gate.size', dir, 'channel/frame');
			return;
		}
		if (p.final !== true) {
			store.set(p.channel, f);
			return;
		}
		store.delete(p.channel);
		const joined = this.parse(f.joined, dir);
		if (!joined) {
			return;
		}
		const result = handle(joined, f.joined, true);
		if (result === undefined) {
			return;
		}
		const target = dir === 'in' ? out.toClient : out.toUpstream;
		if (result === f.joined) {
			target.push(...f.originals);
		} else {
			target.push(JSON.stringify({ jsonrpc: '2.0', method: 'channel/frame', params: { channel: p.channel, data: result, final: true } }));
		}
	}

	private parse(text: string, dir: Dir): Obj | undefined {
		if (typeof text !== 'string' || text.length > SECLAB_AHP_MAX_FRAME) {
			this.deny('ahp-gate.size', dir, '');
			return undefined;
		}
		let v: unknown;
		try {
			v = JSON.parse(text);
		} catch {
			v = undefined;
		}
		if (!isObj(v) || v.jsonrpc !== '2.0') {
			this.deny('ahp-gate.malformed', dir, '');
			return undefined;
		}
		return v;
	}

	private deny(rule: string, dir: Dir, method: string, extra: Record<string, string | number> = {}): void {
		this.event('warning', rule, 'deny', { dir, method: clip(method), ...extra });
	}

	private strip(rule: string, dir: Dir, method: string, count: number, actionType?: string): void {
		this.event('notice', rule, 'strip', { dir, method: clip(method), count, ...(actionType ? { actionType: clip(actionType) } : {}) });
	}

	private event(priority: SeclabAhpPriority, rule: string, verdict: 'allow' | 'deny' | 'strip', extra: Record<string, string | number | boolean>): void {
		this.emit({
			source: 'ahp-gate', class: 'ahp.decision', priority,
			summary: `${rule} ${verdict}${extra.method ? ` ${extra.method}` : ''}`,
			detail: { gateRule: rule, connection: this.connection, verdict, ...extra },
		});
	}
}

function rootAgents(result: Obj): number {
	const snapshots = Array.isArray(result.snapshots) ? result.snapshots : [];
	for (const s of snapshots) {
		if (isObj(s) && isObj(s.state) && Array.isArray(s.state.agents)) {
			return s.state.agents.length;
		}
	}
	return 0;
}
