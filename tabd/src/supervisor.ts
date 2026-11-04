// seclab-tabd core: protocol dispatch, tab lifecycle, REH channels, fence re-verify.
// Transport-agnostic: give it a writable for outgoing frames and feed it incoming bytes.

import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import { encodeData, encodeJson, FrameDecoder, FrameError } from './frames.ts';
import type { TabStore, TabRecord } from './state.ts';
import { fileIdentity } from './state.ts';
import { mintSentinel, rewriteSecret, type ScanResult, type VaultEntry } from './scan.ts';
import { DriverError, type Driver, type DriverInfo, type FenceReport, type TabRuntimeSpec, type TabTemplate } from './drivers/types.ts';
import { assertTabId, canonicalWorkspacePath, sandboxNameFor, TEMPLATE_NAME_RE, ValidationError, type PathPolicy } from './validate.ts';
import { ObsGlue, ObsParamError } from './obs/glue.ts';
import type { FalcoSensor } from './obs/falco.ts';
import type { ObsHub } from './obs/hub.ts';

export const PROTOCOL_VERSION = 'seclab-tabd/0.2';
export const SUPERVISOR_VERSION = '0.1.0';
const FENCE_REVERIFY_MS = 60_000;
const MAX_CHANNELS = 64;

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
	private readonly phases = new Map<string, string>();
	private readonly owned = new Set<string>();
	private dead = false;
	private readonly obs: ObsGlue;

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
		});
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
			case 'tab.moveSecrets': return this.moveSecrets(this.record(p.tabId), p.moves);
			case 'tab.restoreSecrets': return this.restoreSecrets(this.record(p.tabId));
			case 'tab.connect': return this.connect(this.record(p.tabId));
			case 'tab.stop': return this.stop(this.record(p.tabId));
			case 'tab.remove': return this.remove(this.record(p.tabId));
			case 'tab.reset': return this.reset(this.record(p.tabId));
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
			status: { phase: this.phases.get(r.tabId) ?? 'Pending' },
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
			await this.driverFor(spec.template).ensureRunning(spec, r.connectionToken, this.obs.sensorHooks(r.tabId, r.hostPath));
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

	private async stop(r: TabRecord) {
		for (const [id, c] of [...this.channels.entries()]) {
			if (c.tabId === r.tabId) {
				this.closeChannel(id, 'tab stopped');
			}
		}
		const spec = this.spec(r);
		this.obs.stopping(r.tabId);
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
