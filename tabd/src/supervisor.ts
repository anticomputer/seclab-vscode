// seclab-tabd core: protocol dispatch, tab lifecycle, REH channels, fence re-verify.
// Transport-agnostic: give it a writable for outgoing frames and feed it incoming bytes.

import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import { encodeData, encodeJson, FrameDecoder, FrameError } from './frames.ts';
import type { TabStore, TabRecord } from './state.ts';
import { fileIdentity } from './state.ts';
import { mintSentinel, rewriteSecret, type ScanResult, type VaultEntry } from './scan.ts';
import { DriverError, type BrokerHooks, type Driver, type DriverInfo, type FenceReport, type TabRuntimeSpec, type TabTemplate } from './drivers/types.ts';
import { BrokerControl, connectBroker } from './broker-control.ts';
import { BROKER_POLICY_SCHEMA } from './broker.ts';
import { defaultPolicy } from './broker-policy.ts';
import { Approvals, asJson, sanitizeApproval } from './approvals.ts';
import { CFS_CREDENTIAL_ID, CFS_RULE_IDS, cfsAllowRules, cfsImportParams, isCfsSentinel, newCfsSentinel, type AzToken } from './cfs.ts';
import { createHash, randomBytes } from 'node:crypto';
import { assertTabId, canonicalWorkspacePath, sandboxNameFor, TEMPLATE_NAME_RE, ValidationError, type PathPolicy } from './validate.ts';
import { ObsGlue, ObsParamError } from './obs/glue.ts';
import type { FalcoSensor } from './obs/falco.ts';
import type { ObsHub } from './obs/hub.ts';
import { WriteBackManager } from './writeback-manager.ts';
import { inspectWorkspace } from './inspect.ts';
import { checkRel } from './writeback.ts';

/** A workspace-relative path parameter for the write-back methods (validated, never a host path). */
function wbPath(v: unknown): string {
	try {
		return checkRel(v);
	} catch {
		throw new RpcError(-32602, 'path must be a workspace-relative path');
	}
}

export const PROTOCOL_VERSION = 'seclab-tabd/0.2';
export const SUPERVISOR_VERSION = '0.1.0';
const FENCE_REVERIFY_MS = 60_000;
const MAX_CHANNELS = 64;
/** Whole broker bring-up, connect to CA (review XX-2). */
const BROKER_SETUP_MS = 60_000;
/** A user-blocked destination as a broker deny rule (broker policy schema revision 5). */
interface BlockRule { id: string; host: string; ports?: number[] }
const MAX_BLOCKS = 256;
const BLOCK_HOST_RE = /^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*|\[?[0-9A-Fa-f:.]{2,45}\]?)$/;

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };
interface RpcRequest { jsonrpc: '2.0'; id?: number | string; method: string; params?: unknown }

export interface SupervisorOptions {
	readonly drivers: ReadonlyMap<string, Driver>;
	readonly templates: ReadonlyMap<string, TabTemplate>;
	readonly store: TabStore;
	readonly write: (chunk: Buffer) => void;
	readonly onFatal: (reason: string) => void;
	readonly audit?: (entry: Record<string, unknown>) => void;
	readonly fenceReverifyMs?: number;
	readonly pathPolicy?: PathPolicy;
	/** Pre-mount secret scanner; absent = scanning unavailable (fails closed). */
	readonly scan?: (hostPath: string) => Promise<ScanResult>;
	/** Remove stopped tabs unused for this many days at initialize; 0 or absent disables. */
	readonly gcDays?: number;
	/** Tab event logs (`<state>/events`); absent = in memory only. ADR tab-observability. */
	readonly eventsDir?: string;
	/** Bytes written to the client but not yet read; event notifications pause above a limit. */
	readonly outputBacklog?: () => number;
	/** OCI host sensor factory (Falco); see tabd/src/obs/falco.ts. */
	readonly hostSensor?: (hub: ObsHub) => FalcoSensor;
	/** Write-back gate state (`<state>/writeback`); absent = no write-back sync (tabs stay gated, nothing syncs). */
	readonly writebackDir?: string;
	/** Write-back sync interval (ms). */
	readonly writebackIntervalMs?: number;
	/**
	 * The policy a tab's broker loads (broker-policy.ts: the user's policy from the state
	 * directory, else deny-all). Throws on an invalid user policy, which fails the start.
	 */
	readonly brokerPolicy?: (tabId: string, opts: { prompts: boolean }) => Record<string, unknown>;
	/** CFS package feeds (B4): the host's az token source; absent = feeds unavailable. */
	readonly cfs?: { token(): Promise<AzToken> };
}

interface Channel { tabId: string; child: ChildProcessWithoutNullStreams }

class RpcError extends Error {
	readonly code: number;
	readonly data?: Json;
	constructor(code: number, message: string, data?: Json) {
		super(message);
		this.code = code;
		this.data = data;
	}
}

export class Supervisor {
	private readonly o: SupervisorOptions;
	private readonly decoder = new FrameDecoder();
	private initialized = false;
	private nextChannel = 1;
	private readonly channels = new Map<number, Channel>();
	private readonly fenceTimers = new Map<string, NodeJS.Timeout>();
	/** One long-lived control connection per running tab's broker (docs/broker-protocol.md §1). */
	private readonly brokers = new Map<string, BrokerControl>();
	private readonly approvals = new Approvals();
	private readonly cfsQueues = new Map<string, Promise<unknown>>();
	private clientShowsPrompts = false;
	private readonly phases = new Map<string, string>();
	private readonly owned = new Set<string>();
	private dead = false;
	private readonly obs: ObsGlue;
	private readonly wb?: WriteBackManager;

	constructor(o: SupervisorOptions) {
		this.o = o;
		this.obs = new ObsGlue({
			eventsDir: o.eventsDir,
			notify: (method, params) => this.notify(method, params),
			backlog: o.outputBacklog,
			hostSensor: o.hostSensor,
			assertTab: tabId => this.record(tabId).tabId,
			isRunning: async tabId => {
				const r = this.o.store.get(tabId);
				if (!r) {
					return false;
				}
				const spec = this.spec(r);
				return (await this.driverFor(spec.template).runningSandboxes()).has(spec.sandboxName);
			},
			// Persist a tab's log only where no other live supervisor holds its lease.
			owns: tabId => {
				const holder = this.o.store.leaseHolder(tabId);
				return this.owned.has(tabId) || holder === undefined || holder === process.pid || !pidAlive(holder);
			},
			listTabs: () => this.o.store.list().map(r => {
				const holder = this.o.store.leaseHolder(r.tabId);
				const phase = this.phases.get(r.tabId) ?? (holder !== undefined && holder !== process.pid && pidAlive(holder) ? 'Running' : 'Stopped');
				return { tabId: r.tabId, hostPath: r.hostPath, phase };
			}),
		});
		if (o.writebackDir) {
			this.wb = new WriteBackManager({
				dir: o.writebackDir,
				intervalMs: o.writebackIntervalMs,
				emit: (tabId, ev) => {
					this.obs.hub.trusted(tabId, { ...ev, source: 'gate' });
				},
				audit: (event, outcome, detail) => this.audit(event, outcome, detail as Record<string, Json>),
				onPending: (tabId, count) => this.notify('tab.writeback.pending', { tabId, count }),
			});
		}
	}

	/** Feed bytes from the client. Protocol violations are fatal. */
	receive(chunk: Buffer): void {
		if (this.dead) {
			return;
		}
		let frames;
		try {
			frames = this.decoder.push(chunk);
		} catch (e) {
			return this.fatal(e instanceof FrameError ? e.message : 'decode error');
		}
		for (const f of frames) {
			if (f.channel === 0) {
				let msg: unknown;
				try {
					msg = JSON.parse(f.payload.toString('utf8'));
				} catch {
					return this.fatal('invalid JSON on channel 0');
				}
				void this.dispatch(msg);
			} else {
				const ch = this.channels.get(f.channel);
				if (!ch) {
					// Data racing a close is dropped; data for a never-opened channel is fatal.
					if (f.channel >= this.nextChannel) {
						return this.fatal(`data for unopened channel ${f.channel}`);
					}
					continue;
				}
				ch.child.stdin.write(f.payload);
			}
		}
	}

	shutdown(): void {
		for (const id of [...this.channels.keys()]) {
			this.closeChannel(id, 'supervisor shutdown');
		}
		for (const t of this.fenceTimers.values()) {
			clearInterval(t);
		}
		this.fenceTimers.clear();
	}

	/**
	 * Client went away (stdin EOF). Without a supervisor nobody re-verifies the fence,
	 * so stop every tab this supervisor started, connected or adopted (fail closed).
	 */
	async clientGone(): Promise<void> {
		this.shutdown();
		for (const tabId of this.owned) {
			try {
				this.obs.stopping(tabId);
				const r = this.o.store.get(tabId);
				if (r) {
					const spec = this.spec(r);
					await this.driverFor(spec.template).stop(spec);
				}
				this.o.store.clearLease(tabId, process.pid);
			} catch { /* best effort */ }
		}
		await this.obs.shutdown();
	}

	private fatal(reason: string): void {
		this.dead = true;
		this.shutdown();
		this.o.onFatal(reason);
	}

	private send(msg: Record<string, Json | undefined>): void {
		if (!this.dead) {
			this.o.write(encodeJson({ jsonrpc: '2.0', ...msg }));
		}
	}

	private notify(method: string, params: Json): void {
		this.send({ method, params });
	}

	private audit(action: string, outcome: string, detail: Record<string, Json>): void {
		const entry = { ts: new Date().toISOString(), action, outcome, ...detail };
		this.o.audit?.(entry);
		this.notify('audit', entry as Json);
		this.obs.audit(entry);
	}

	private async dispatch(raw: unknown): Promise<void> {
		const req = raw as RpcRequest;
		if (!req || req.jsonrpc !== '2.0' || typeof req.method !== 'string') {
			return this.fatal('malformed JSON-RPC message');
		}
		const isRequest = req.id !== undefined;
		try {
			const result = await this.handle(req.method, req.params ?? {});
			if (isRequest) {
				this.send({ id: req.id as Json, result: (result ?? {}) as Json });
			}
		} catch (e) {
			const code = e instanceof RpcError || e instanceof DriverError ? e.code : e instanceof ValidationError ? -32002 : e instanceof ObsParamError ? -32602 : -32603;
			const message = (e as Error).message ?? 'internal error';
			if (isRequest) {
				const data = e instanceof RpcError ? e.data : undefined;
				this.send({ id: req.id as Json, error: data === undefined ? { code, message } : { code, message, data } });
			} else {
				this.notify('log', { level: 'error', message: `${req.method}: ${message}` });
			}
		}
	}

	private async handle(method: string, params: unknown): Promise<unknown> {
		const p = (params ?? {}) as Record<string, unknown>;
		if (method === 'initialize') {
			const v = p.protocolVersion;
			if (typeof v !== 'string' || v.split('.')[0] !== PROTOCOL_VERSION.split('.')[0]) {
				throw new RpcError(-32600, `unsupported protocol ${String(v)}; supervisor speaks ${PROTOCOL_VERSION}`);
			}
			this.initialized = true;
			// A client that shows broker prompts says so (the Tab Manager). Without one, nobody can
			// answer a prompt, so the default policy denies unmatched requests at once (B3).
			const client = (p.client ?? {}) as { capabilities?: { approvals?: unknown } };
			this.clientShowsPrompts = client.capabilities?.approvals === true;
			const drivers: DriverInfo[] = await Promise.all([...this.o.drivers.values()].map(d => d.probe()));
			await this.reconcile();
			await this.collectGarbage();
			return { protocolVersion: PROTOCOL_VERSION, supervisor: { version: SUPERVISOR_VERSION }, drivers, templates: [...this.o.templates.values()] };
		}
		if (!this.initialized) {
			throw new RpcError(-32001, 'not initialized');
		}
		switch (method) {
			case 'tab.claim': return this.claim(p);
			case 'tab.get': return { tab: this.view(this.record(p.tabId)) };
			case 'tab.list': return { tabs: this.o.store.list().map(r => this.view(r)) };
			case 'tab.ensureRunning': return this.ensureRunning(this.record(p.tabId), p.acceptFindings);
			case 'tab.scan': return this.scanTab(this.record(p.tabId));
			case 'tab.inspect': return inspectWorkspace(this.record(p.tabId).hostPath) as unknown as Json;
			case 'tab.moveSecrets': return this.moveSecrets(this.record(p.tabId), p.moves);
			case 'tab.restoreSecrets': return this.restoreSecrets(this.record(p.tabId));
			case 'tab.connect': return this.connect(this.record(p.tabId));
			case 'tab.stop': return this.stop(this.record(p.tabId));
			case 'tab.remove': return this.remove(this.record(p.tabId));
			case 'tab.reset': return this.reset(this.record(p.tabId));
			case 'tab.egress.block': return this.blockDestination(this.record(p.tabId), p.host, p.port);
			case 'tab.packages.get': return { cfs: this.cfsSentinel(this.record(p.tabId).tabId) !== undefined };
			case 'tab.packages.set': return this.setPackages(this.record(p.tabId), p.cfs);
			case 'tab.approval.list': return { approvals: this.approvals.list(this.record(p.tabId).tabId).map(asJson) };
			case 'tab.approval.decide': return this.decideApproval(this.record(p.tabId), p.approvalId, p.decision);
			case 'tab.userAction': return this.userAction(this.record(p.tabId));
			case 'tab.writeback.status': return this.writebackStatus(this.record(p.tabId));
			case 'tab.writeback.sync': return this.writebackSync(this.record(p.tabId));
			case 'tab.writeback.content': return this.writebackCall(this.record(p.tabId), wb => wb.content(String(p.tabId), wbPath(p.path)));
			case 'tab.writeback.decide': {
				const d = p.decision;
				if (d !== 'approve' && d !== 'reject' && d !== 'always') {
					throw new RpcError(-32602, 'decision must be approve, reject or always');
				}
				if (typeof p.sig !== 'string' || !/^[0-9a-f]{64}$/.test(p.sig)) {
					throw new RpcError(-32602, 'sig (the signature shown) is required');
				}
				return this.writebackCall(this.record(p.tabId), wb => wb.decide(String(p.tabId), wbPath(p.path), d, p.sig as string));
			}
			case 'tab.writeback.confirmDeletes': return this.writebackCall(this.record(p.tabId), async wb => {
				if (typeof p.digest !== 'string' || !/^[0-9a-f]{64}$/.test(p.digest)) {
					throw new RpcError(-32602, 'digest (of the held deletions shown) is required');
				}
				wb.confirmDeletes(String(p.tabId), p.digest);
				return {};
			});
			case 'stream.end': {
				const ch = this.channels.get(this.channelId(p.channel));
				ch?.child.stdin.end();
				return {};
			}
			case 'stream.close': this.closeChannel(this.channelId(p.channel), 'closed by client'); return {};
			case 'shutdown': {
				const stopTabs = p.stopTabs === true;
				const tabs = new Set([...this.channels.values()].map(c => c.tabId));
				this.shutdown();
				if (stopTabs) {
					for (const t of tabs) {
						await this.stop(this.record(t));
					}
				}
				return {};
			}
			default: {
				const r = this.obs.handle(method, p);
				if (r !== undefined) {
					return r;
				}
				throw new RpcError(-32601, `unknown method ${method}`);
			}
		}
	}

	private channelId(v: unknown): number {
		if (typeof v !== 'number' || !Number.isInteger(v) || v < 1) {
			throw new RpcError(-32602, 'invalid channel');
		}
		return v;
	}

	private record(tabId: unknown): TabRecord {
		const id = assertTabId(tabId);
		const r = this.o.store.get(id);
		if (!r) {
			throw new RpcError(-32004, `unknown tab ${id}`);
		}
		return r;
	}

	private template(name: string): TabTemplate {
		const t = this.o.templates.get(name);
		if (!t) {
			throw new RpcError(-32602, `unknown template ${name}`);
		}
		return t;
	}

	private driverFor(t: TabTemplate): Driver {
		const d = this.o.drivers.get(t.spec.driver);
		if (!d) {
			throw new RpcError(-32003, `driver ${t.spec.driver} unavailable`);
		}
		return d;
	}

	private spec(r: TabRecord): TabRuntimeSpec {
		return { tabId: r.tabId, sandboxName: sandboxNameFor(r.tabId), hostPath: r.hostPath, template: this.template(r.templateName) };
	}

	private view(r: TabRecord) {
		const t = this.o.templates.get(r.templateName);
		return {
			apiVersion: 'tabd.seclab.dev/v1alpha1', kind: 'Tab',
			metadata: { name: r.tabId, createdAt: r.createdAt },
			spec: { workspace: { hostPath: r.hostPath, mountPath: r.hostPath }, templateRef: { name: r.templateName }, driver: t?.spec.driver ?? null },
			status: { phase: this.phases.get(r.tabId) ?? 'Pending', ...(this.brokers.has(r.tabId) ? { brokerCapabilities: { ...this.brokers.get(r.tabId)!.capabilities } } : {}) },
		};
	}

	private setPhase(tabId: string, phase: string, conditions: Json[] = []): void {
		this.phases.set(tabId, phase);
		this.notify('tab.status', { tabId, phase, conditions });
	}

	private claim(p: Record<string, unknown>) {
		const ws = p.workspace as { hostPath?: unknown } | undefined;
		const hostPath = canonicalWorkspacePath(ws?.hostPath, this.o.pathPolicy);
		const tref = (p.templateRef as { name?: unknown } | undefined)?.name ?? 'default';
		if (typeof tref !== 'string' || !TEMPLATE_NAME_RE.test(tref)) {
			throw new RpcError(-32602, 'invalid templateRef');
		}
		const template = this.template(tref);
		const { record, created } = this.o.store.claim(hostPath, tref, template.spec.driver);
		this.audit('tab.claim', created ? 'created' : 'existing', { tabId: record.tabId, hostPath });
		return { tab: this.view(record) };
	}

	// ---- pre-mount secret scanning (ADR 20261104-pre-mount-secret-scan) ------------------

	private readonly scans = new Map<string, ScanResult>();

	private async scanTab(r: TabRecord) {
		if (!this.o.scan) {
			const res: ScanResult = { complete: false, error: 'secret scanner unavailable', findings: [], secrets: new Map() };
			this.scans.set(r.tabId, res);
			return { complete: false, error: res.error, overflow: false, findings: [] };
		}
		const res = await this.o.scan(r.hostPath);
		this.scans.set(r.tabId, res);
		this.audit('secret.scan', res.complete ? 'ok' : 'incomplete', { tabId: r.tabId, findings: res.findings.map(f => f.id), error: res.error ?? null, overflow: !!res.overflow });
		return { complete: res.complete, error: res.error, overflow: !!res.overflow, findings: res.findings };
	}

	/**
	 * Block unless every finding is moved or explicitly accepted (recorded exception), and
	 * an incomplete scan is explicitly accepted too. Findings are always reported first, even
	 * from an incomplete scan, so a failing pass can't hide what the other passes found.
	 */
	private async gateSecrets(r: TabRecord, accept: unknown): Promise<void> {
		const res = await this.scanTab(r);
		const accepted = new Set(Array.isArray(accept) ? accept.filter((x): x is string => typeof x === 'string') : []);
		const blocking = res.findings.filter(f => !accepted.has(f.id));
		const status = { incomplete: !res.complete, overflow: res.overflow ?? false, error: res.error ?? null };
		if (blocking.length) {
			throw new RpcError(-32020, `${blocking.length} secret(s) found in the workspace`, { findings: blocking as unknown as Json, ...status });
		}
		if (!res.complete && !accepted.has('scan-incomplete')) {
			throw new RpcError(-32021, res.error ?? 'secret scan incomplete', { findings: [], ...status });
		}
		const exceptions = [...res.findings.map(f => ({ id: f.id, file: f.file, line: f.line, rule: f.rule, source: f.source }))];
		if (!res.complete) {
			exceptions.push({ id: 'scan-incomplete', file: '', line: 0, rule: res.error ?? 'incomplete', source: 'worktree' as const });
		}
		if (exceptions.length) {
			const at = new Date().toISOString();
			const prior = this.o.store.readSide<Record<string, Json>>(r.tabId, 'exceptions');
			this.o.store.writeSide(r.tabId, 'exceptions', [...prior, ...exceptions.map(e => ({ ...e, at }))]);
			this.audit('secret.exception', 'opened-anyway', { tabId: r.tabId, at, files: exceptions.map(e => `${e.file}:${e.line} ${e.rule}`) });
		}
	}

	private async moveSecrets(r: TabRecord, moves: unknown) {
		const res = this.scans.get(r.tabId);
		if (!res) {
			throw new RpcError(-32602, 'scan the tab first');
		}
		const spec = this.spec(r);
		if ((await this.driverFor(spec.template).runningSandboxes()).has(spec.sandboxName)) {
			throw new RpcError(-32000, 'stop the tab before moving secrets (its workspace must not be in use)');
		}
		if (!Array.isArray(moves)) {
			throw new RpcError(-32602, 'moves must be an array');
		}
		const vault = this.o.store.readSide<VaultEntry>(r.tabId, 'vault');
		const moved: Array<{ id: string; sentinel: string }> = [];
		for (const m of moves as Array<{ id?: unknown; bind?: { host?: unknown; path?: unknown } }>) {
			const f = res.findings.find(x => x.id === m.id);
			const secret = f ? res.secrets.get(f.id) : undefined;
			const host = m.bind?.host;
			const bindPath = m.bind?.path ?? '/**';
			if (!f || !f.movable || !secret) {
				throw new RpcError(-32602, `finding ${String(m.id)} is not movable`);
			}
			if (typeof host !== 'string' || !/^(?:\*\.)?[a-z0-9.-]{1,253}$/i.test(host) || typeof bindPath !== 'string' || !/^\/[\x21-\x7e]{0,512}$/.test(bindPath)) {
				throw new RpcError(-32602, 'invalid credential binding');
			}
			const sentinel = mintSentinel(f.rule);
			// Vault first: a crash after the rewrite must never lose the only copy.
			const entry: VaultEntry = { id: f.id, file: f.file, line: f.line, rule: f.rule, sentinel, secret, bind: { host, path: bindPath }, movedAt: new Date().toISOString() };
			this.o.store.writeSide(r.tabId, 'vault', [...vault, entry]);
			try {
				rewriteSecret(r.hostPath, f.file, f.line, secret, sentinel);
			} catch (e) {
				this.o.store.writeSide(r.tabId, 'vault', vault);
				throw new RpcError(-32000, `could not move ${f.file}:${f.line}: ${(e as Error).message}`);
			}
			vault.push(entry);
			moved.push({ id: f.id, sentinel });
			this.audit('secret.move', 'ok', { tabId: r.tabId, file: `${f.file}:${f.line}`, rule: f.rule, bindHost: host });
		}
		this.scans.delete(r.tabId);
		return { moved };
	}

	private async restoreSecrets(r: TabRecord) {
		const spec = this.spec(r);
		if ((await this.driverFor(spec.template).runningSandboxes()).has(spec.sandboxName)) {
			throw new RpcError(-32000, 'stop the tab before restoring secrets');
		}
		const vault = this.o.store.readSide<VaultEntry>(r.tabId, 'vault');
		const kept: VaultEntry[] = [];
		const restored: string[] = [];
		for (const v of vault) {
			try {
				rewriteSecret(r.hostPath, v.file, v.line, v.sentinel, v.secret);
				restored.push(`${v.file}:${v.line}`);
			} catch {
				kept.push(v);
			}
		}
		this.o.store.writeSide(r.tabId, 'vault', kept);
		this.audit('secret.restore', 'ok', { tabId: r.tabId, restored });
		return { restored, notRestored: kept.map(v => `${v.file}:${v.line}`) };
	}

	private async ensureRunning(r: TabRecord, acceptFindings?: unknown) {
		const spec = this.spec(r);
		this.setPhase(r.tabId, 'Starting');
		try {
			// Re-validate right before mounting: the path may have been swapped (e.g. for a
			// symlink) since it was claimed.
			const now = canonicalWorkspacePath(r.hostPath, this.o.pathPolicy);
			const id = fileIdentity(now);
			if (now !== r.hostPath || id.dev !== r.dev || id.ino !== r.ino) {
				throw new ValidationError(`workspace ${r.hostPath} changed identity since it was claimed`);
			}
			// No real secret enters a tab: scan before every (re)mount.
			await this.gateSecrets(r, acceptFindings);
			const broker = spec.template.spec.broker === 'required' ? this.brokerHooks(r) : undefined;
			await this.driverFor(spec.template).ensureRunning(spec, r.connectionToken, this.obs.sensorHooks(r.tabId, r.hostPath), broker);
		} catch (e) {
			this.setPhase(r.tabId, 'Failed', [{ type: 'Ready', status: 'False', reason: 'StartFailed', message: (e as Error).message }]);
			this.audit('tab.ensureRunning', 'fail', { tabId: r.tabId, error: (e as Error).message });
			throw e;
		}
		this.setPhase(r.tabId, 'Running', [{ type: 'Ready', status: 'True' }, { type: 'FenceVerified', status: 'True' }, { type: 'RehReady', status: 'True' }]);
		this.own(r.tabId);
		const drv = this.driverFor(spec.template);
		this.obs.started(r.tabId, r.hostPath, drv.policyLog ? () => drv.policyLog!(spec) : undefined);
		this.audit('tab.ensureRunning', 'ok', { tabId: r.tabId });
		return { tab: this.view(r), connectionToken: r.connectionToken };
	}

	/**
	 * Broker bring-up (plan tabd-broker-wiring B1, docs/broker-protocol.md §2): hello (checked),
	 * health, a fresh proxy password, the tab's policy, the CA. The real proxy password goes only
	 * to the broker and to the driver, which writes it into the workspace; it is never audited.
	 */
	private brokerHooks(r: TabRecord): BrokerHooks {
		return {
			configure: async (openControl, image) => {
				this.closeBroker(r.tabId).catch(() => undefined);
				// One deadline for the whole bring-up (review XX-2): connect, health and every request.
				const deadline = Date.now() + BROKER_SETUP_MS;
				const left = () => {
					const ms = deadline - Date.now();
					if (ms <= 0) {
						throw new Error(`broker setup exceeded ${BROKER_SETUP_MS / 1000} s`);
					}
					return Math.min(ms, 15_000);
				};
				const c = await connectBroker(openControl, r.tabId, { deadline, version: image?.version });
				try {
					for (;;) {
						const h = await c.request('health', undefined, left()) as { status?: unknown } | undefined;
						if (h?.status === 'ok') {
							break;
						}
						left();
						await new Promise(res => setTimeout(res, 500));
					}
					const proxyPassword = randomBytes(24).toString('base64url');
					await c.request('proxy.auth.set', { username: 'seclab', password: proxyPassword }, left());
					const policy = this.o.brokerPolicy ? this.o.brokerPolicy(r.tabId, { prompts: this.clientShowsPrompts }) : defaultPolicy(r.tabId, this.clientShowsPrompts);
					// The user's blocked destinations (tab.egress.block) ride on every start, once the
					// broker can enforce them; deny precedes every allow, baseline and prompt.
					const blocks = this.o.store.readSide<BlockRule>(r.tabId, 'blocks');
					if (blocks.length && c.capabilities.denyRules) {
						policy.deny = [...(Array.isArray(policy.deny) ? policy.deny : []), ...blocks];
					}
					const loaded = await c.request('policy.load', { policy }, left()) as { revision?: unknown } | undefined;
					const ca = await c.request('ca.get', undefined, left()) as { certPem?: unknown; pemSha256?: unknown } | undefined;
					const certPem = ca?.certPem;
					const pemSha256 = ca?.pemSha256;
					// Format, not integrity: the broker supplies both values (review XX note). The
					// driver also requires exactly one PEM certificate before writing it to the tab.
					if (typeof certPem !== 'string' || typeof pemSha256 !== 'string' || createHash('sha256').update(certPem).digest('hex') !== pemSha256) {
						throw new Error('ca.get: certificate does not match its sha256');
					}
					const feedSentinel = this.attachBroker(r.tabId, c);
					this.audit('broker.configure', 'ok', { tabId: r.tabId, policyRevision: typeof loaded?.revision === 'number' ? loaded.revision : null, caSha256: pemSha256 });
					return { caPem: certPem, proxyUser: 'seclab', proxyPassword, ...(feedSentinel ? { feedSentinel } : {}) };
				} catch (e) {
					c.close();
					this.audit('broker.configure', 'fail', { tabId: r.tabId, error: (e as Error).message });
					throw e;
				}
			},
		};
	}

	/**
	 * Make `c` this tab's broker control connection: drop it on close, stream the broker's audit
	 * into the tab's events, surface its prompts and, when the user enabled package feeds, import
	 * the CFS credential (in the background: az may take a while, or fail; the tab still runs).
	 * Used at bring-up and when adopting a running tab (B3c). Returns the tab's CFS sentinel.
	 */
	private attachBroker(tabId: string, c: BrokerControl, surfacePrompts = true): string | undefined {
		c.onClose(e => {
			this.obs.brokerDetached(tabId, c);
			if (this.brokers.get(tabId) === c) {
				this.brokers.delete(tabId);
				this.audit('broker.control', 'closed', { tabId, reason: e.message });
			}
		});
		this.brokers.set(tabId, c);
		void this.obs.brokerAttached(tabId, c);
		if (surfacePrompts) {
			this.attachApprovals(tabId, c);
		}
		const feedSentinel = this.cfsSentinel(tabId);
		if (feedSentinel) {
			this.attachCfs(tabId, c, feedSentinel);
		}
		return feedSentinel;
	}

	/**
	 * B3c: a running tab adopted from a dead supervisor gets its broker's control connection
	 * back, without touching the broker's state (policy, grants, proxy credential, CA): its
	 * prompts, audit stream and package-feed refresh work again. The fence check before adoption
	 * already verified the running broker is the pinned image. Failure leaves the tab adopted
	 * without broker control (prompts time out to deny), and is audited.
	 */
	private async reattachBroker(r: TabRecord): Promise<void> {
		const spec = this.spec(r);
		const driver = this.driverFor(spec.template);
		if (spec.template.spec.broker !== 'required' || !driver.openBrokerControl || this.brokers.has(r.tabId)) {
			return;
		}
		try {
			const c = await connectBroker(() => driver.openBrokerControl!(spec), r.tabId, { deadline: Date.now() + 20_000 });
			// Prompts only to a client that can answer them (review HHH-1); otherwise the broker's
			// held requests time out to deny, as with no controller.
			this.attachBroker(r.tabId, c, this.clientShowsPrompts);
			// Feeds turned off while nothing controlled this broker: apply it now (review HHH-2).
			if (!this.cfsSentinel(r.tabId)) {
				await this.removeCfs(c).catch(() => undefined);
				await driver.installFeed?.(spec, undefined).catch((e: Error) => this.audit('tab.packages', 'cleanup-failed', { tabId: r.tabId, error: e.message.slice(0, 200) }));
			}
			this.audit('broker.control', 'reattached', { tabId: r.tabId, prompts: this.clientShowsPrompts });
		} catch (e) {
			this.audit('broker.control', 'reattach-fail', { tabId: r.tabId, error: (e as Error).message.slice(0, 200) });
		}
	}

	/**
	 * Prompts (plan tabd-broker-wiring B3): the broker's held requests reach the Tab Manager as
	 * `tab.approval` (sanitised, with the request's process lineage as quoted data, never a
	 * decision input), and their resolution as `tab.approval.resolved`. On every (re)connect
	 * the broker learns the tab was just opened, and still-pending approvals are re-surfaced.
	 */
	private attachApprovals(tabId: string, c: BrokerControl): void {
		const surface = (raw: unknown) => {
			const a = sanitizeApproval(raw);
			if (!a || !this.approvals.add(tabId, a)) {
				this.audit('broker.approval', 'dropped', { tabId });
				return;
			}
			const lineage = this.obs.promptLineage(tabId, a.approvalId);
			this.audit('broker.approval', 'requested', { tabId, approvalId: a.approvalId, kind: a.kind, host: a.request.host, port: a.request.port });
			this.notify('tab.approval', { tabId, approval: asJson(a), lineage: lineage as unknown as Json });
		};
		c.onNotification(n => {
			if (n.method === 'approval.requested') {
				surface(n.params);
			} else if (n.method === 'approval.resolved') {
				const p = n.params as { approvalId?: unknown; decision?: unknown; by?: unknown } | null;
				if (p && typeof p.approvalId === 'string' && this.approvals.resolve(tabId, p.approvalId)) {
					this.notify('tab.approval.resolved', { tabId, approvalId: p.approvalId, decision: String(p.decision).slice(0, 32), by: String(p.by).slice(0, 32) });
				}
			}
		});
		c.onClose(() => {
			if (!this.brokers.has(tabId) || this.brokers.get(tabId) === c) {
				this.approvals.forget(tabId);
			}
		});
		void c.request('tab.event', { kind: 'opened' }).catch(() => undefined);
		void c.request('approval.list').then(res => {
			for (const a of ((res as { approvals?: unknown[] } | undefined)?.approvals ?? [])) {
				surface(a);
			}
		}).catch(() => undefined);
	}

	/** The user's answer to one of this tab's approvals; only a decision the approval offered. */
	private async decideApproval(r: TabRecord, approvalId: unknown, decision: unknown) {
		const ok = this.approvals.check(r.tabId, approvalId, decision);
		if (typeof ok === 'string') {
			throw new RpcError(-32602, ok);
		}
		const c = this.brokers.get(r.tabId);
		if (!c) {
			throw new RpcError(-32013, 'this tab has no broker connection');
		}
		await c.request('approval.decide', { approvalId: ok.approval.approvalId, decision: ok.decision });
		this.approvals.resolve(r.tabId, ok.approval.approvalId);
		this.audit('broker.approval', 'decided', { tabId: r.tabId, approvalId: ok.approval.approvalId, decision: ok.decision, host: ok.approval.request.host });
		return {};
	}

	/**
	 * The user did ordinary work in this tab (from the Tab Manager: editor input, never a consent
	 * dialog). Opens the broker's user-action gate; at most once a second.
	 */
	private async userAction(r: TabRecord) {
		const c = this.brokers.get(r.tabId);
		if (c && this.approvals.userActionDue(r.tabId)) {
			await c.request('tab.event', { kind: 'userAction' });
		}
		return {};
	}

	/**
	 * The user blocked a destination for this tab (Block Destination on a notification). Exact
	 * host, optional port. Persisted with the tab and applied now and on every later start, as a
	 * broker deny rule, which precedes every allow, baseline rule and prompt. Refused, and never
	 * recorded as applied, unless the tab's broker can enforce it (`capabilities.denyRules`).
	 */
	/** The tab's CFS sentinel when the user enabled package feeds for it (`tab.packages.set`). */
	private cfsSentinel(tabId: string): string | undefined {
		const s = this.o.store.readSide<{ feed?: unknown; sentinel?: unknown }>(tabId, 'packages').find(e => e.feed === CFS_CREDENTIAL_ID)?.sentinel;
		return isCfsSentinel(s) ? s : undefined;
	}

	/** Import budgets on `credential.import` arrived in broker policy schema revision 7 (review EEE-1). */
	private cfsSupported(): string | undefined {
		if (!this.o.cfs) {
			return 'package feeds are unavailable (no az token source)';
		}
		return (BROKER_POLICY_SCHEMA.revision as number) >= 7 ? undefined : 'package feeds need broker policy schema revision 7 (budgets on imported credentials)';
	}

	/** CFS work for one tab runs one step at a time (review EEE-2): enable, disable and start imports never interleave. */
	private cfsSerial<T>(tabId: string, fn: () => Promise<T>): Promise<T> {
		const prev = this.cfsQueues.get(tabId) ?? Promise.resolve();
		const next = prev.catch(() => undefined).then(fn);
		const tail = next.catch(() => undefined);
		this.cfsQueues.set(tabId, tail);
		void tail.then(() => {
			if (this.cfsQueues.get(tabId) === tail) {
				this.cfsQueues.delete(tabId);
			}
		});
		return next;
	}

	/** Still wanted: feeds on with this sentinel, and this broker connection still the tab's. */
	private cfsCurrent(tabId: string, c: BrokerControl, sentinel: string): boolean {
		return this.cfsSentinel(tabId) === sentinel && this.brokers.get(tabId) === c;
	}

	/**
	 * Put the CFS credential into a connected broker: mint the host's token (az, never written
	 * anywhere), import it under the tab's sentinel with GET-only bindings and the budget, allow
	 * the two feed paths. Re-checked after each slow step: if feeds were turned off or the broker
	 * changed meanwhile, the import is undone rather than left behind (review EEE-2).
	 */
	private async importCfs(tabId: string, c: BrokerControl, sentinel: string): Promise<void> {
		const unsupported = this.cfsSupported();
		if (unsupported) {
			throw new RpcError(-32013, unsupported);
		}
		const token = await this.o.cfs!.token();
		if (!this.cfsCurrent(tabId, c, sentinel)) {
			return;
		}
		await c.request('credential.import', cfsImportParams(sentinel, token), 30_000);
		await c.request('policy.update', { removeAllow: CFS_RULE_IDS }).catch(() => undefined);
		await c.request('policy.update', { addAllow: cfsAllowRules() });
		if (!this.cfsCurrent(tabId, c, sentinel)) {
			await this.removeCfs(c);
			return;
		}
		this.audit('tab.packages', 'imported', { tabId, feed: CFS_CREDENTIAL_ID, expiresAt: token.expiresAt });
	}

	/** Remove the feed rules and revoke the credential (sentinel rotated); throws if the broker didn't confirm. */
	private async removeCfs(c: BrokerControl): Promise<void> {
		await c.request('policy.update', { removeAllow: CFS_RULE_IDS });
		await c.request('credential.revoke', { id: CFS_CREDENTIAL_ID, rotateSentinel: true });
	}

	/** Answer the broker's `credential.needed` for cfs with a fresh host token, while feeds stay on with this sentinel. */
	private attachCfsRefresh(tabId: string, c: BrokerControl, sentinel: string): void {
		c.onNotification(n => {
			const p = n.params as { id?: unknown } | null;
			if (n.method !== 'credential.needed' || p?.id !== CFS_CREDENTIAL_ID || !this.o.cfs || !this.cfsCurrent(tabId, c, sentinel)) {
				return;
			}
			void this.o.cfs.token()
				.then(t => c.request('credential.provide', { id: CFS_CREDENTIAL_ID, value: t.value, expiresAt: t.expiresAt }))
				.then(() => this.audit('tab.packages', 'refreshed', { tabId, feed: CFS_CREDENTIAL_ID }))
				.catch((e: Error) => this.cfsProblem(tabId, e));
		});
	}

	/** At broker bring-up: refresh on demand, and import in the background (az may be slow or fail; the tab still starts). */
	private attachCfs(tabId: string, c: BrokerControl, sentinel: string): void {
		this.attachCfsRefresh(tabId, c, sentinel);
		void this.cfsSerial(tabId, () => this.importCfs(tabId, c, sentinel)).catch((e: Error) => this.cfsProblem(tabId, e));
	}

	private cfsProblem(tabId: string, e: Error): void {
		// az's message names the fix (az login); it never contains the token.
		const message = e.message.slice(0, 300);
		this.audit('tab.packages', 'fail', { tabId, feed: CFS_CREDENTIAL_ID, error: message });
		this.notify('tab.packages.problem', { tabId, feed: CFS_CREDENTIAL_ID, message });
	}

	/**
	 * The user turned CFS package feeds on or off for this tab (ADR cfs-package-feeds-in-tabs:
	 * off by default, per tab). Persisted with the tab; applied at once to a running tab (import
	 * and allow, or revoke and remove, and the tab's npm/pip config), and on every start.
	 */
	private async setPackages(r: TabRecord, cfsIn: unknown) {
		if (typeof cfsIn !== 'boolean') {
			throw new RpcError(-32602, 'cfs must be true or false');
		}
		if (cfsIn) {
			const unsupported = this.cfsSupported();
			if (unsupported) {
				throw new RpcError(-32013, unsupported);
			}
		}
		return this.cfsSerial(r.tabId, async () => {
			const spec = this.spec(r);
			const driver = this.driverFor(spec.template);
			// Only a running sandbox is touched (review EEE-4: sbx exec would start a stopped one
			// without ensureRunning's checks); otherwise the setting applies at the next start.
			const running = (await driver.runningSandboxes()).has(spec.sandboxName);
			const c = running ? this.brokers.get(r.tabId) : undefined;
			const before = this.cfsSentinel(r.tabId);
			if (cfsIn) {
				const sentinel = before ?? newCfsSentinel(randomBytes);
				this.o.store.writeSide(r.tabId, 'packages', [{ feed: CFS_CREDENTIAL_ID, sentinel }]);
				if (c) {
					if (!before) {
						this.attachCfsRefresh(r.tabId, c, sentinel);
					}
					await this.importCfs(r.tabId, c, sentinel);
					await driver.installFeed?.(spec, sentinel);
				}
			} else {
				this.o.store.writeSide(r.tabId, 'packages', []);
				if (c) {
					try {
						await this.removeCfs(c);
					} catch (e) {
						// Fail closed (review EEE-2): the broker didn't confirm the removal, so the tab stops.
						this.audit('tab.packages', 'disable-failed', { tabId: r.tabId, error: (e as Error).message.slice(0, 200) });
						await this.stop(r).catch(() => undefined);
						throw new RpcError(-32013, 'could not turn package feeds off in the running tab, so the tab was stopped');
					}
					await driver.installFeed?.(spec, undefined);
				}
			}
			this.audit('tab.packages', cfsIn ? 'enabled' : 'disabled', { tabId: r.tabId, feed: CFS_CREDENTIAL_ID, running: !!c });
			return { cfs: cfsIn, applied: !!c };
		});
	}

	private async blockDestination(r: TabRecord, hostIn: unknown, portIn: unknown) {
		if (typeof hostIn !== 'string' || hostIn.length > 253 || !BLOCK_HOST_RE.test(hostIn)) {
			throw new RpcError(-32602, 'host must be an exact host name or IP address');
		}
		const host = hostIn.replace(/^\[|\]$/g, '').toLowerCase();
		if (portIn !== undefined && (typeof portIn !== 'number' || !Number.isInteger(portIn) || portIn < 1 || portIn > 65535)) {
			throw new RpcError(-32602, 'port must be 1..65535');
		}
		const c = this.brokers.get(r.tabId);
		if (!c || !c.capabilities.denyRules) {
			throw new RpcError(-32013, 'this tab\'s broker cannot block destinations (needs broker deny rules)');
		}
		const id = `user-block-${createHash('sha256').update(`${host}:${portIn ?? '*'}`).digest('hex').slice(0, 16)}`;
		const rule: BlockRule = { id, host, ...(portIn !== undefined ? { ports: [portIn as number] } : {}) };
		const blocks = this.o.store.readSide<BlockRule>(r.tabId, 'blocks');
		if (!blocks.some(b => b.id === id)) {
			if (blocks.length >= MAX_BLOCKS) {
				throw new RpcError(-32602, `at most ${MAX_BLOCKS} blocked destinations per tab`);
			}
			await c.request('policy.update', { addDeny: [rule] });
			this.o.store.writeSide(r.tabId, 'blocks', [...blocks, rule]);
		}
		this.audit('tab.egress.block', 'ok', { tabId: r.tabId, host, port: (portIn as number | undefined) ?? null, rule: id });
		return { rule: id };
	}

	/** Drop the tab's broker connection; with `shutdown`, first tell the broker to drop every credential and exit. */
	private async closeBroker(tabId: string, shutdown?: string): Promise<void> {
		const c = this.brokers.get(tabId);
		if (!c) {
			return;
		}
		this.brokers.delete(tabId);
		if (shutdown) {
			await c.request('broker.shutdown', { reason: shutdown.slice(0, 64) }, 5_000).catch(() => undefined);
		}
		c.close();
	}

	private async verify(r: TabRecord): Promise<FenceReport> {
		const spec = this.spec(r);
		const report = await this.driverFor(spec.template).verifyFence(spec);
		this.audit('fence.verify', report.ok ? 'ok' : 'fail', { tabId: r.tabId, problems: [...report.problems] });
		return report;
	}

	private async connect(r: TabRecord) {
		if (this.channels.size >= MAX_CHANNELS) {
			throw new RpcError(-32000, 'too many open channels');
		}
		const report = await this.verify(r);
		if (!report.ok) {
			this.setPhase(r.tabId, 'Failed', [{ type: 'FenceVerified', status: 'False', reason: 'Mismatch', message: report.problems.join('; ') }]);
			await this.quarantine(r);
			throw new RpcError(-32010, `fence verification failed: ${report.problems.join('; ')}`);
		}
		const spec = this.spec(r);
		// `exec` would silently start a stopped (e.g. quarantined) sandbox, bypassing the
		// identity re-check in ensureRunning; only connect to a running one.
		if (!(await this.driverFor(spec.template).runningSandboxes()).has(spec.sandboxName)) {
			throw new RpcError(-32012, 'tab is not running; call tab.ensureRunning first');
		}
		const child = this.driverFor(spec.template).connectReh(spec);
		const id = this.nextChannel++;
		this.channels.set(id, { tabId: r.tabId, child });
		this.own(r.tabId);
		child.stdout.on('data', (d: Buffer) => {
			if (this.channels.has(id)) {
				for (const f of encodeData(id, d)) {
					this.o.write(f);
				}
			}
		});
		child.stdout.on('end', () => this.channels.has(id) && this.notify('stream.end', { channel: id }));
		let stderrTail = '';
		child.stderr.on('data', (d: Buffer) => { stderrTail = (stderrTail + d.toString('utf8')).slice(-400); });
		child.on('error', err => this.closeChannel(id, `exec error: ${err.message}`));
		child.on('close', code => this.closeChannel(id, code === 0 ? undefined : `exec exited ${code}: ${stderrTail.trim()}`));
		this.audit('tab.connect', 'ok', { tabId: r.tabId, channel: id });
		return { channel: id, connectionToken: r.connectionToken };
	}

	private ensureReverify(tabId: string): void {
		if (this.fenceTimers.has(tabId)) {
			return;
		}
		const stopMonitoring = () => {
			clearInterval(timer);
			this.fenceTimers.delete(tabId);
		};
		const tick = async () => {
			const r = this.o.store.get(tabId);
			if (!r) {
				return stopMonitoring(); // removed (possibly by another supervisor)
			}
			const spec = this.spec(r);
			// Keep verifying for as long as the sandbox runs, connected or not: workspace
			// code can keep running in the sandbox after the UI disconnects.
			if (!(await this.driverFor(spec.template).runningSandboxes()).has(spec.sandboxName)) {
				return stopMonitoring();
			}
			const report = await this.verify(r);
			if (!report.ok) {
				this.setPhase(tabId, 'Failed', [{ type: 'FenceVerified', status: 'False', reason: 'Drift', message: report.problems.join('; ') }]);
				await this.quarantine(r);
			}
		};
		const timer = setInterval(() => {
			tick().catch(async e => {
				// Fail closed: an error while verifying quarantines the tab.
				this.audit('fence.monitor', 'error', { tabId, error: (e as Error).message });
				const r = this.o.store.get(tabId);
				if (r) {
					await this.quarantine(r).catch(() => { /* audited inside */ });
				}
			});
		}, this.o.fenceReverifyMs ?? FENCE_REVERIFY_MS);
		timer.unref?.();
		this.fenceTimers.set(tabId, timer);
	}

	/** Take responsibility for a running tab: monitor its fence and stop it when we exit. */
	private own(tabId: string): void {
		this.owned.add(tabId);
		this.o.store.writeLease(tabId, process.pid);
		this.o.store.touch(tabId);
		this.obs.own(tabId);
		this.ensureReverify(tabId);
		this.startWriteBack(tabId);
	}

	/** Write-back gate 2b: sync a gated tab's upper layer while we own it. */
	private startWriteBack(tabId: string): void {
		const r = this.o.store.get(tabId);
		if (!this.wb || !r) {
			return;
		}
		const spec = this.spec(r);
		const driver = this.driverFor(spec.template);
		if (driver.upperReader) {
			this.wb.start(tabId, r.hostPath, { dev: r.dev, ino: r.ino }, driver.upperReader(spec));
		}
	}

	/**
	 * Startup reconciliation. A running tab whose lease holder is gone (supervisor crash,
	 * editor killed) has had no fence monitoring: verify it now and either adopt it or
	 * quarantine it. Tabs leased by another live supervisor are left to that supervisor.
	 */
	private async reconcile(): Promise<void> {
		for (const [name, driver] of this.o.drivers) {
			let running: Set<string>;
			try {
				running = await driver.runningSandboxes();
			} catch {
				continue;
			}
			for (const r of this.o.store.list()) {
				const spec = this.spec(r);
				if (spec.template.spec.driver !== name || !running.has(spec.sandboxName)) {
					continue;
				}
				const holder = this.o.store.leaseHolder(r.tabId);
				if (holder !== undefined && holder !== process.pid && pidAlive(holder)) {
					continue;
				}
				const report = await this.verify(r).catch(() => ({ ok: false, problems: ['verify failed'], checkedAt: '' }));
				if (report.ok) {
					this.own(r.tabId);
					this.audit('tab.reconcile', 'adopted', { tabId: r.tabId });
					this.obs.adopted(r.tabId);
					await this.reattachBroker(r);
				} else {
					await this.quarantine(r);
					this.audit('tab.reconcile', 'quarantined', { tabId: r.tabId });
				}
			}
		}
	}

	/** Fence failed: drop every channel of the tab, re-apply missing rules and stop the sandbox. */
	private async quarantine(r: TabRecord): Promise<void> {
		for (const [id, c] of [...this.channels.entries()]) {
			if (c.tabId === r.tabId) {
				this.closeChannel(id, 'tab quarantined');
			}
		}
		try {
			const spec = this.spec(r);
			this.obs.stopping(r.tabId);
			this.wb?.stop(r.tabId);
			await this.closeBroker(r.tabId, 'tab quarantined');
			await this.driverFor(spec.template).quarantine(spec);
			this.audit('tab.quarantine', 'ok', { tabId: r.tabId });
		} catch (e) {
			this.audit('tab.quarantine', 'fail', { tabId: r.tabId, error: (e as Error).message });
		}
	}

	private closeChannel(id: number, error?: string): void {
		const ch = this.channels.get(id);
		if (!ch) {
			return;
		}
		this.channels.delete(id);
		try {
			ch.child.kill('SIGKILL');
		} catch { /* already gone */ }
		this.notify('stream.close', error ? { channel: id, error } : { channel: id });
	}

	/** Write-back gate: is the tab gated, is sync active, and what is held for review. */
	private writebackStatus(r: TabRecord) {
		const spec = this.spec(r);
		const gated = !!this.driverFor(spec.template).upperReader;
		const s = this.wb?.status(r.tabId) ?? { active: false, pending: [] };
		return { gated, ...s } as unknown as Json;
	}

	/** Write-back gate: sync now (the loop also runs on its own). */
	private async writebackCall(r: TabRecord, f: (wb: WriteBackManager) => Promise<unknown>) {
		if (!this.wb || !this.driverFor(this.spec(r).template).upperReader) {
			throw new RpcError(-32013, 'write-back is not gated for this tab');
		}
		try {
			return await f(this.wb) as Json;
		} catch (e) {
			throw new RpcError(-32013, (e as Error).message.slice(0, 300));
		}
	}

	/** Write-back gate: sync now (the loop also runs on its own). */
	private async writebackSync(r: TabRecord) {
		if (!this.wb || !this.driverFor(this.spec(r).template).upperReader) {
			throw new RpcError(-32013, 'write-back is not gated for this tab');
		}
		const res = await this.wb.sync(r.tabId).catch(e => {
			throw new RpcError(-32013, `write-back sync failed: ${(e as Error).message}`);
		});
		return { applied: res.applied, held: res.held.map(h => ({ path: h.path, kind: h.kind, reasons: h.reasons })), refused: res.refused, mirrored: res.mirrored } as unknown as Json;
	}

	private async stop(r: TabRecord) {
		for (const [id, c] of [...this.channels.entries()]) {
			if (c.tabId === r.tabId) {
				this.closeChannel(id, 'tab stopped');
			}
		}
		const spec = this.spec(r);
		// Last write-back sync while the VM is up: best effort, bounded (review MM-4). The upper
		// layer survives stop, so anything missed syncs on the next start.
		if (this.wb) {
			let timer: NodeJS.Timeout | undefined;
			await Promise.race([
				this.wb.sync(r.tabId).catch(() => { /* recorded */ }),
				new Promise<void>(res => {
					timer = setTimeout(res, 15_000);
				}),
			]);
			clearTimeout(timer);
		}
		this.wb?.stop(r.tabId);
		this.obs.stopping(r.tabId);
		await this.closeBroker(r.tabId, 'tab stopped');
		await this.driverFor(spec.template).stop(spec);
		this.setPhase(r.tabId, 'Stopped');
		this.audit('tab.stop', 'ok', { tabId: r.tabId });
		return { tab: this.view(r) };
	}

	private async remove(r: TabRecord) {
		// The vault is the only copy of secrets moved out of the workspace: removing the tab
		// would orphan it. Restore first (tab.restoreSecrets).
		if (this.o.store.readSide(r.tabId, 'vault').length) {
			throw new RpcError(-32022, 'tab holds moved secrets; restore them (tab.restoreSecrets) before removing the tab');
		}
		await this.stop(r);
		const spec = this.spec(r);
		await this.driverFor(spec.template).remove(spec);
		this.wb?.discard(r.tabId);
		this.obs.brokerForget(r.tabId);
		this.o.store.forget(r.tabId);
		this.audit('tab.remove', 'ok', { tabId: r.tabId });
		return {};
	}

	/**
	 * Rebuild the tab from its template: the sandbox and its home (installed extensions,
	 * anything a payload dropped there) are discarded; the tab id, workspace mapping,
	 * vault and exceptions are kept, so the next ensureRunning starts it fresh.
	 */
	private async reset(r: TabRecord) {
		await this.stop(r);
		const spec = this.spec(r);
		await this.driverFor(spec.template).remove(spec);
		// The VM, and with it the upper layer, is gone: anything still held there is discarded.
		this.wb?.discard(r.tabId);
		this.owned.delete(r.tabId);
		this.o.store.clearLease(r.tabId);
		this.setPhase(r.tabId, 'Stopped');
		this.audit('tab.reset', 'ok', { tabId: r.tabId });
		return { tab: this.view(r) };
	}

	/**
	 * Garbage collection: stopped tabs unused for gcDays are removed. Never a tab that is
	 * running (any driver), leased by a live supervisor, or holding vaulted secrets (its
	 * vault is the only copy of values moved out of the workspace).
	 */
	private async collectGarbage(): Promise<void> {
		const days = this.o.gcDays ?? 0;
		if (!(days > 0)) {
			return;
		}
		const cutoff = Date.now() - days * 86_400_000;
		const running = new Set<string>();
		for (const d of this.o.drivers.values()) {
			try {
				for (const n of await d.runningSandboxes()) {
					running.add(n);
				}
			} catch {
				return; // can't tell what is running: collect nothing
			}
		}
		for (const r of this.o.store.list()) {
			const spec = this.spec(r);
			// Only tabs created under the driver this supervisor runs: removing through another
			// driver would forget the tab and orphan its real sandbox (R-5). Older records
			// without a driver are never collected.
			if (r.driver !== spec.template.spec.driver) {
				continue;
			}
			const holder = this.o.store.leaseHolder(r.tabId);
			if (this.o.store.lastUsed(r) > cutoff || running.has(spec.sandboxName) || this.owned.has(r.tabId)
				|| (holder !== undefined && pidAlive(holder))) {
				continue;
			}
			if (this.o.store.readSide(r.tabId, 'vault').length) {
				this.audit('tab.gc', 'skipped', { tabId: r.tabId, reason: 'vault holds moved secrets' });
				continue;
			}
			try {
				await this.driverFor(spec.template).remove(spec);
				this.o.store.forget(r.tabId);
				this.audit('tab.gc', 'removed', { tabId: r.tabId, unusedDays: days });
			} catch (e) {
				this.audit('tab.gc', 'fail', { tabId: r.tabId, error: (e as Error).message });
			}
		}
	}
}

function pidAlive(pid: number): boolean {
	try {
		process.kill(pid, 0);
		return true;
	} catch (e) {
		return (e as NodeJS.ErrnoException).code === 'EPERM';
	}
}
