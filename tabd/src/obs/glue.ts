// Supervisor glue for tab observability: protocol methods, sensor hooks for drivers, and the
// mapping from supervisor audit entries to trusted events. Kept out of supervisor.ts so the
// core stays small. Spec: docs/tabd/PROTOCOL.md §3-4, docs/tabd/EVENTS.md.

import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { PolicyLogEntry, SensorHooks } from '../drivers/types.ts';
import { BrokerAuditFeed, type AuditControl } from './broker-audit.ts';
import type { FalcoSensor } from './falco.ts';
import { LineageCorrelator, type Attribution } from './lineage.ts';
import { listSegments, ObsHub, segName, type Observation } from './hub.ts';
import { CollectorSession } from './sbx-collector.ts';
import { CLASSES, isTabId, PRIORITIES, priorityRank, SOURCES, weakestIntegrity, type EventClass, type Integrity, type ObsEvent, type Priority } from './schema.ts';
import { WorkspaceWatcher } from './workspace-watch.ts';

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

export const POLICY_POLL_MS = 10_000;

export const MAX_SUBSCRIPTIONS = 16;
export const MAX_REPORT_EVENTS = 64;
export const MAX_TAIL = 1000;
/** Cross-tab detection query: at most this many events, reading at most this much log per tab. */
export const MAX_QUERY = 500;
const QUERY_BYTES_PER_TAB = 16 << 20;

/** Events for the cross-tab summary: detections, and trusted failures worth a user's attention. */
function isNotable(e: ObsEvent, minRank: number): boolean {
	if (!(PRIORITIES as readonly string[]).includes(e.priority) || priorityRank(e.priority) > minRank) {
		return false;
	}
	return e.class === 'detection' || (e.integrity === 'trusted' && (e.class === 'fence.verify' || e.class === 'tab.lifecycle' || (e.class === 'sensor.status' && e.detail?.status === 'unobserved')));
}
/** Broker events that get a lineage attribution (requests with a destination). */
const ATTRIBUTED = /^(?:request\.allowed|request\.denied|request\.denied_unprompted|approval\.requested|upstream\.blocked|credential\.injected|sentinel\.misplaced|model\.call|model\.denied)$/;
const ATTRIBUTION_DELAY_MS = 600;
/** A broker event is live (attributable) when its own timestamp is this close to now. */
const LIVE_SKEW_MS = 5_000;
const MAX_PENDING_ATTRIBUTIONS = 256;
/** How long an opened agent-host connection may go without `ahp-gate.verified`. */
export const AHP_VERIFY_MS = 2_000;
const MAX_AHP_OPEN = 1024;
const MAX_AHP_OPEN_PER_TAB = 64;
/** Stop pushing event notifications while this many bytes wait for the client to read. */
export const NOTIFY_BACKLOG_LIMIT = 4 << 20;
/**
 * What each trusted client component may report. The write-back gate's classes are reserved.
 * Integrity comes from the source table (schema SOURCES), never from the report: the AHP
 * sources are `trusted`, `agent-host` (the agent host's self-description, relayed) is
 * `tab-reported`.
 */
const CLIENT_SOURCES: ReadonlyMap<string, ReadonlySet<string>> = new Map([
	['rpc-filter', new Set(['rpc.decision'])], ['gate', new Set<string>()],
	['ahp-gate', new Set(['ahp.decision'])], ['ahp-reverse', new Set(['ahp.decision'])], ['ahp-credential', new Set(['ahp.decision'])],
	['agent-host', new Set(['agent.session', 'agent.turn', 'agent.tool'])],
	['config-filter', new Set(['config.withheld'])],
]);

export class ObsParamError extends Error { }

interface Subscription { tabId?: string; minRank: number; classes?: ReadonlySet<string>; lagged: number }

export interface ObsGlueOptions {
	readonly eventsDir?: string;
	readonly notify: (method: string, params: Json) => void;
	/** Bytes written to the client but not yet consumed (stdout backlog). */
	readonly backlog?: () => number;
	/** Does this tab exist? (throws the supervisor's unknown-tab error otherwise) */
	readonly assertTab: (tabId: unknown) => string;
	readonly isRunning: (tabId: string) => Promise<boolean>;
	/** Persist this tab's log (this supervisor holds the lease). */
	readonly owns: (tabId: string) => boolean;
	/** Every tab in the state directory (running or stopped), for the cross-tab detection query. */
	readonly listTabs?: () => Array<{ tabId: string; hostPath: string; phase: string }>;
	/** OCI host sensor (Falco), when the OCI driver is in use. */
	readonly hostSensor?: (hub: ObsHub) => FalcoSensor;
}

export class ObsGlue {
	readonly hub: ObsHub;
	private readonly o: ObsGlueOptions;
	private readonly subs = new Map<number, Subscription>();
	private nextSub = 1;
	private readonly sessions = new Map<string, CollectorSession>();
	private readonly modes = new Map<string, 'default' | 'deep'>();
	private readonly falco?: FalcoSensor;
	private readonly watchers = new Map<string, WorkspaceWatcher>();
	private readonly pollers = new Map<string, NodeJS.Timeout>();
	private readonly brokerFeeds = new Map<string, { feed: BrokerAuditFeed; control?: AuditControl }>();
	private readonly lineage = new LineageCorrelator();
	private readonly pendingAttributions = new Map<string, number>();
	private readonly promptLineages = new Map<string, Map<string, Attribution>>();
	private readonly ahpOpen = new Map<string, NodeJS.Timeout>();
	private readonly recentExact = new Map<string, number>();

	constructor(o: ObsGlueOptions) {
		this.o = o;
		this.hub = new ObsHub({
			dir: o.eventsDir,
			persist: tabId => o.owns(tabId),
			onEvent: e => {
				this.lineage.observe(e, this.hub.contextOf(e.tabId));
				this.fanout(e);
			},
			// `reason` can carry sensor-derived text: tagged like event fields.
			onObservation: (tabId, ob) => o.notify('tab.observation', { tabId, ...ob, untrusted: ['reason'] } as unknown as Json),
		});
		this.falco = o.hostSensor?.(this.hub);
	}

	private fanout(e: ObsEvent): void {
		const busy = (this.o.backlog?.() ?? 0) > NOTIFY_BACKLOG_LIMIT;
		for (const [id, s] of this.subs) {
			if ((s.tabId && s.tabId !== e.tabId) || priorityRank(e.priority) > s.minRank || (s.classes && !s.classes.has(e.class))) {
				continue;
			}
			if (busy) {
				s.lagged++;
				continue;
			}
			const params: Record<string, Json> = { subscription: id, event: e as unknown as Json };
			if (s.lagged) {
				params.lagged = s.lagged;
				s.lagged = 0;
			}
			this.o.notify('tab.event', params);
		}
	}

	/** Protocol methods; returns undefined for methods that aren't ours. */
	handle(method: string, p: Record<string, unknown>): unknown {
		switch (method) {
			case 'tab.events.subscribe': return this.subscribe(p);
			case 'tab.events.unsubscribe': {
				const id = p.subscription;
				if (typeof id !== 'number' || !this.subs.delete(id)) {
					throw new ObsParamError('unknown subscription');
				}
				return {};
			}
			case 'tab.events.tail': {
				const tabId = this.o.assertTab(p.tabId);
				const limit = p.limit === undefined ? 200 : p.limit;
				if (typeof limit !== 'number' || !Number.isInteger(limit) || limit < 1 || limit > MAX_TAIL) {
					throw new ObsParamError(`limit must be 1..${MAX_TAIL}`);
				}
				const before = p.beforeSeq;
				if (before !== undefined && (typeof before !== 'number' || !Number.isSafeInteger(before) || before < 1)) {
					throw new ObsParamError('invalid beforeSeq');
				}
				return { events: this.hub.tail(tabId, limit, before as number | undefined), observation: this.hub.observation(tabId) };
			}
			case 'tab.events.report': return this.report(p);
			case 'tab.detections.query': return this.queryDetections(p);
			case 'tab.observe': {
				const tabId = this.o.assertTab(p.tabId);
				if (p.mode !== 'default' && p.mode !== 'deep') {
					throw new ObsParamError('mode must be default or deep');
				}
				this.modes.set(tabId, p.mode);
				this.hub.trusted(tabId, { class: 'sensor.status', priority: 'notice', summary: `observation mode set to ${p.mode} (applies when the collector next starts)`, detail: { status: 'mode', mode: p.mode } });
				return { mode: p.mode, appliesOnRestart: this.sessions.get(tabId)?.alive ?? false, observation: this.hub.observation(tabId) };
			}
			default: return undefined;
		}
	}

	/**
	 * Detections and other notable events across every tab this state directory knows, running
	 * or stopped, read from the persisted per-tab logs (whichever supervisor wrote them). For the
	 * Tab Manager's cross-tab summary. Read-only; bounded per tab and in total.
	 */
	private queryDetections(p: Record<string, unknown>) {
		const min = p.minPriority === undefined ? 'warning' : p.minPriority;
		if (typeof min !== 'string' || !(PRIORITIES as readonly string[]).includes(min)) {
			throw new ObsParamError('invalid minPriority');
		}
		const limit = p.limit === undefined ? 200 : p.limit;
		if (typeof limit !== 'number' || !Number.isInteger(limit) || limit < 1 || limit > MAX_QUERY) {
			throw new ObsParamError(`limit must be 1..${MAX_QUERY}`);
		}
		let only: Set<string> | undefined;
		if (p.tabIds !== undefined) {
			if (!Array.isArray(p.tabIds) || p.tabIds.length > 64 || !p.tabIds.every(isTabId)) {
				throw new ObsParamError('tabIds must be up to 64 tab ids');
			}
			only = new Set(p.tabIds as string[]);
		}
		const minRank = priorityRank(min as Priority);
		const tabs = (this.o.listTabs?.() ?? []).filter(t => !only || only.has(t.tabId)).slice(0, 64);
		const out: ObsEvent[] = [];
		for (const t of tabs) {
			out.push(...this.readNotable(t.tabId, minRank));
		}
		out.sort((a, b) => b.time.localeCompare(a.time) || b.seq - a.seq);
		return { events: out.slice(0, limit), tabs };
	}

	/** A tab's notable events from its log (newest segments first, at most QUERY_BYTES_PER_TAB), plus this supervisor's unflushed ring. */
	private readNotable(tabId: string, minRank: number): ObsEvent[] {
		const live = this.hub.tail(tabId, MAX_TAIL).filter(e => isNotable(e, minRank));
		const dir = this.o.eventsDir ? path.join(this.o.eventsDir, tabId) : undefined;
		if (!dir) {
			return live;
		}
		const found: ObsEvent[] = [];
		const seen = new Set(live.map(e => e.seq));
		let budget = QUERY_BYTES_PER_TAB;
		for (const n of listSegments(dir).reverse()) {
			if (budget <= 0 || found.length >= MAX_QUERY) {
				break;
			}
			let text: string;
			try {
				const fd = fs.openSync(path.join(dir, segName(n)), fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
				try {
					const size = fs.fstatSync(fd).size;
					const len = Math.min(size, budget);
					const buf = Buffer.alloc(len);
					fs.readSync(fd, buf, 0, len, size - len);
					budget -= len;
					text = buf.toString('utf8');
				} finally {
					fs.closeSync(fd);
				}
			} catch {
				continue;
			}
			// A partial first line (budget cut, or a writer mid-append) fails to parse and is skipped.
			for (const line of text.split('\n')) {
				if (!line.includes('"priority"')) {
					continue;
				}
				let e: ObsEvent;
				try {
					e = JSON.parse(line) as ObsEvent;
				} catch {
					continue;
				}
				if (e && typeof e === 'object' && e.tabId === tabId && typeof e.seq === 'number' && typeof e.time === 'string' && !seen.has(e.seq) && isNotable(e, minRank)) {
					seen.add(e.seq);
					found.push(e);
				}
			}
		}
		return [...live, ...found];
	}

	private subscribe(p: Record<string, unknown>) {
		if (this.subs.size >= MAX_SUBSCRIPTIONS) {
			throw new ObsParamError('too many subscriptions');
		}
		const tabId = p.tabId === undefined ? undefined : this.o.assertTab(p.tabId);
		const min = p.minPriority === undefined ? 'debug' : p.minPriority;
		if (typeof min !== 'string' || !(PRIORITIES as readonly string[]).includes(min)) {
			throw new ObsParamError('invalid minPriority');
		}
		let classes: Set<string> | undefined;
		if (p.classes !== undefined) {
			if (!Array.isArray(p.classes) || p.classes.length > 32 || !p.classes.every(c => typeof c === 'string' && Object.hasOwn(CLASSES, c))) {
				throw new ObsParamError('invalid classes');
			}
			classes = new Set(p.classes as EventClass[]);
		}
		const since = p.sinceSeq;
		if (since !== undefined && (tabId === undefined || typeof since !== 'number' || !Number.isSafeInteger(since) || since < 0)) {
			throw new ObsParamError('sinceSeq needs a tabId and a non-negative integer');
		}
		const id = this.nextSub++;
		const sub: Subscription = { tabId, minRank: priorityRank(min as Priority), classes, lagged: 0 };
		this.subs.set(id, sub);
		const replay = tabId !== undefined && since !== undefined ? this.hub.tail(tabId, MAX_TAIL).filter(e => e.seq > (since as number)) : [];
		// Replay after the response is written.
		queueMicrotask(() => {
			for (const e of replay) {
				if (this.subs.get(id) === sub && priorityRank(e.priority) <= sub.minRank && (!sub.classes || sub.classes.has(e.class))) {
					this.o.notify('tab.event', { subscription: id, event: e as unknown as Json, replay: true });
				}
			}
		});
		return { subscription: id, lastSeq: tabId ? this.hub.lastSeq(tabId) : null, observation: tabId ? this.hub.observation(tabId) as unknown as Json : null };
	}

	/** Trusted client components (RPC filter, write-back gate) report decisions. */
	private report(p: Record<string, unknown>) {
		const tabId = this.o.assertTab(p.tabId);
		if (!Array.isArray(p.events) || p.events.length > MAX_REPORT_EVENTS) {
			throw new ObsParamError(`events must be an array of at most ${MAX_REPORT_EVENTS}`);
		}
		let accepted = 0, rejected = 0;
		for (const ev of p.events) {
			const e = (typeof ev === 'object' && ev !== null ? ev : {}) as Record<string, unknown>;
			const allowed = typeof e.source === 'string' ? CLIENT_SOURCES.get(e.source) : undefined;
			if (!allowed || typeof e.class !== 'string' || !allowed.has(e.class)) {
				rejected++;
				continue;
			}
			// Only these fields; integrity is fixed by the source, never taken from the report.
			const integrity = SOURCES[e.source as string].integrity;
			// The connection watch runs on the validated report before any rate limit, so a tab
			// that floods the gate with denials can't drop an opened/verified signal (review AE-1).
			const watch = e.source === 'ahp-gate' ? this.ahpSignal(e.detail) : undefined;
			const ev2 = this.hub.emit(tabId, { source: e.source, class: e.class, priority: e.priority, summary: e.summary, detail: e.detail, integrity });
			if (watch) {
				this.watchAhp(tabId, watch, ev2);
			}
			if (ev2) {
				accepted++;
			} else {
				rejected++;
			}
		}
		return { accepted, rejected };
	}

	private ahpSignal(detail: unknown): { rule: 'opened' | 'verified'; conn: number } | undefined {
		const d = (typeof detail === 'object' && detail !== null ? detail : {}) as Record<string, unknown>;
		const conn = d.connection;
		if (typeof conn !== 'number' || !Number.isInteger(conn) || conn < 0) {
			return undefined;
		}
		return d.gateRule === 'ahp-gate.opened' ? { rule: 'opened', conn } : d.gateRule === 'ahp-gate.verified' ? { rule: 'verified', conn } : undefined;
	}

	/**
	 * AHP connections must be gated (secure-agentic §3): the trusted renderer reports
	 * `ahp-gate.opened` for every agent-host connection and `ahp-gate.verified` once its gate is
	 * in place. Opened and not verified within AHP_VERIFY_MS is an ungated transport. The
	 * detection is stamped directly (no rate bucket a tab could drain).
	 */
	private watchAhp(tabId: string, s: { rule: 'opened' | 'verified'; conn: number }, e: ObsEvent | undefined): void {
		const key = `${tabId}\u0000${s.conn}`;
		if (s.rule === 'verified') {
			clearTimeout(this.ahpOpen.get(key));
			this.ahpOpen.delete(key);
			return;
		}
		if (this.ahpOpen.has(key)) {
			return;
		}
		if (this.ahpOpen.size >= MAX_AHP_OPEN || [...this.ahpOpen.keys()].filter(k => k.startsWith(`${tabId}\u0000`)).length >= MAX_AHP_OPEN_PER_TAB) {
			// Fail closed: a connection we can't watch is reported, not ignored. Per tab, so one
			// tab's connection churn can't raise alarms for another's (review 9b note).
			this.hub.detection(tabId, { rule: 'ahp.ungated', summary: `agent-host connection ${s.conn} opened while too many others await verification`, detail: { connection: s.conn }, cause: e ? [e.seq] : [] });
			return;
		}
		const timer = setTimeout(() => {
			this.ahpOpen.delete(key);
			this.hub.detection(tabId, {
				rule: 'ahp.ungated', summary: `agent-host connection ${s.conn} opened without a verified gate within ${AHP_VERIFY_MS / 1000} s`,
				detail: { connection: s.conn }, cause: e ? [e.seq] : [],
			});
		}, AHP_VERIFY_MS);
		timer.unref();
		this.ahpOpen.set(key, timer);
	}

	/** Hooks handed to driver.ensureRunning for this tab. */
	sensorHooks(tabId: string, workspace: string): SensorHooks {
		const falco = this.falco;
		return {
			brokerEndpoint: ep => {
				this.hub.context(tabId, { brokerPort: ep.port, ...(ep.addrs?.length ? { brokerAddrs: new Set(ep.addrs) } : {}) });
			},
			...(falco ? {
				beforeReh: async ({ containerId }: { containerId: string }) => {
					this.hub.context(tabId, { openedAt: Date.now(), workspace });
					await falco.add(tabId, containerId, this.modes.get(tabId) === 'deep');
				},
			} : {}),
			startCollector: async (spawnCollector: () => ChildProcessWithoutNullStreams, token: string) => {
				this.hub.context(tabId, { openedAt: Date.now(), workspace });
				const existing = this.sessions.get(tabId);
				if (existing?.alive) {
					await existing.ensureReh(token);
					return;
				}
				const mode = this.modes.get(tabId) ?? 'default';
				const s = new CollectorSession(tabId, spawnCollector(), this.hub, { mode, isRunning: () => this.o.isRunning(tabId) });
				this.sessions.set(tabId, s);
				s.configure(token, workspace);
				try {
					await s.rehReady;
				} catch (e) {
					s.close();
					this.sessions.delete(tabId);
					throw e;
				}
			},
		};
	}

	/** The tab is running: start the trusted host-side sources (workspace watcher, runtime policy log). */
	started(tabId: string, workspace: string, policyLog?: () => Promise<PolicyLogEntry[]>): void {
		if (!this.watchers.has(tabId)) {
			try {
				const w = new WorkspaceWatcher(tabId, workspace, this.hub);
				w.start();
				this.watchers.set(tabId, w);
			} catch (e) {
				this.hub.trusted(tabId, { class: 'sensor.status', priority: 'warning', summary: `workspace watcher failed: ${(e as Error).message}`, detail: { status: 'workspace-watch' } });
			}
		}
		if (policyLog && !this.pollers.has(tabId)) {
			const seen = new Map<string, number>();
			let first = true;
			const tick = async () => {
				let entries: PolicyLogEntry[];
				try {
					entries = await policyLog();
				} catch {
					return;
				}
				for (const e of entries) {
					const key = `${e.decision}|${e.host}|${e.proxyType}`;
					const delta = e.count - (seen.get(key) ?? 0);
					seen.set(key, e.count);
					if (first || delta <= 0) {
						continue; // the first read is the baseline (the log outlives restarts)
					}
					const m = /^(.*):(\d{1,5})$/.exec(e.host);
					this.hub.emit(tabId, {
						source: 'sbx-policy', integrity: 'trusted', class: 'policy.log', priority: e.decision === 'blocked' ? 'notice' : 'debug',
						summary: `sbx ${e.decision} ${e.host} ×${delta}${e.reason ? ` (${e.reason})` : ''}`,
						net: { addr: m ? m[1] : e.host, port: m ? Number(m[2]) : undefined, result: e.decision },
						detail: { decision: e.decision, host: e.host, count: delta, proxyType: e.proxyType, ...(e.reason ? { reason: e.reason } : {}) },
					});
				}
				first = false;
			};
			void tick();
			const t = setInterval(() => void tick(), POLICY_POLL_MS);
			t.unref?.();
			this.pollers.set(tabId, t);
		}
	}

	/** The supervisor is stopping, removing or quarantining the tab. */
	stopping(tabId: string): void {
		this.hub.expectEnd(tabId);
		this.sessions.get(tabId)?.close();
		this.sessions.delete(tabId);
		this.watchers.get(tabId)?.stop();
		this.watchers.delete(tabId);
		clearInterval(this.pollers.get(tabId));
		this.pollers.delete(tabId);
		void this.falco?.remove(tabId).catch(() => undefined);
	}

	/** Adopted at startup without a collector: unobserved until the next ensureRunning. */
	adopted(tabId: string): void {
		if (!this.sessions.get(tabId)?.alive) {
			this.hub.setObservation(tabId, 'unobserved', 'adopted after a supervisor restart; observation resumes when the window reconnects');
		}
	}

	/** The tab's in-VM collector session (sbx) is up. */
	collectorAlive(tabId: string): boolean {
		return this.sessions.get(tabId)?.alive ?? false;
	}

	own(tabId: string): void {
		this.hub.own(tabId);
	}

	/** Mirror supervisor audit entries as trusted events. */
	audit(entry: Record<string, unknown>): void {
		const tabId = entry.tabId;
		if (!isTabId(tabId)) {
			return;
		}
		const action = String(entry.action ?? '');
		const outcome = String(entry.outcome ?? '');
		const cls: EventClass = action.startsWith('fence.') ? 'fence.verify' : action.startsWith('secret.') ? 'scan.result' : 'tab.lifecycle';
		const bad = /fail|error|quarantined/.test(outcome) || action === 'tab.quarantine';
		const priority: Priority = action === 'tab.quarantine' || (cls === 'fence.verify' && bad) ? 'critical' : bad ? 'warning' : action === 'fence.verify' ? 'debug' : 'notice';
		const detail: Record<string, string | number | boolean> = { action, outcome };
		for (const k of ['error', 'channel', 'restored'] as const) {
			const v = entry[k];
			if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') {
				detail[k] = v;
			}
		}
		if (Array.isArray(entry.problems) && entry.problems.length) {
			detail.problems = entry.problems.map(String).join('; ');
		}
		if (Array.isArray(entry.findings)) {
			detail.findings = entry.findings.length;
		}
		this.hub.trusted(tabId, { class: cls, priority, summary: `${action} ${outcome}${detail.error ? `: ${String(detail.error)}` : detail.problems ? `: ${String(detail.problems)}` : ''}`, detail });
	}

	observation(tabId: string): Observation {
		return this.hub.observation(tabId);
	}

	/**
	 * The tab's broker control channel is up (tabd owns it): stream its audit events as trusted
	 * events, replaying what the broker still holds. Never throws; failures are status events.
	 */
	brokerAttached(tabId: string, control: AuditControl): Promise<void> {
		let entry = this.brokerFeeds.get(tabId);
		if (!entry) {
			const lastByDest = new Map<string, ObsEvent>();
			const dest = (m: { net?: { addr: string; port?: number } }) => `${m.net?.addr ?? ''}:${m.net?.port ?? ''}`;
			const feed = new BrokerAuditFeed(tabId, {
				emit: (m, count) => {
					const e = this.hub.emit(tabId, {
						source: 'broker', integrity: 'trusted', class: m.class, priority: m.priority, summary: m.summary,
						...(m.net ? { net: m.net } : {}), detail: count ? { ...m.detail, count } : m.detail,
					});
					if (e && m.net) {
						if (!lastByDest.has(dest(m)) && lastByDest.size >= 512) {
							lastByDest.delete(lastByDest.keys().next().value!);
						}
						lastByDest.set(dest(m), e);
						// Only live events: a replayed one is stamped now, not when it happened.
						if (!count && ATTRIBUTED.test(String(m.detail.auditType)) && m.ts !== undefined && Math.abs(Date.now() - m.ts * 1000) < LIVE_SKEW_MS) {
							this.scheduleAttribution(e);
						}
					}
				},
				status: (priority, summary, detail) => {
					this.hub.trusted(tabId, { class: 'broker.status', priority, summary, detail });
				},
				timing: (m, tMs) => {
					this.hub.brokerTiming(tabId, dest(m), tMs, lastByDest.get(dest(m)));
				},
			});
			entry = { feed };
			this.brokerFeeds.set(tabId, entry);
		}
		entry.control = control;
		return entry.feed.attach(control).catch(() => undefined);
	}

	/** That control channel closed (only acts if it is still the current one). */
	brokerDetached(tabId: string, control: AuditControl): void {
		const entry = this.brokerFeeds.get(tabId);
		if (entry?.control === control) {
			entry.feed.detach();
			entry.control = undefined;
		}
	}

	/** The tab is gone: drop its feed (pending aggregates are flushed). */
	brokerForget(tabId: string): void {
		this.brokerFeeds.get(tabId)?.feed.detach();
		this.brokerFeeds.delete(tabId);
		this.lineage.forget(tabId);
		this.promptLineages.delete(tabId);
		for (const [k, t] of this.ahpOpen) {
			if (k.startsWith(`${tabId}\u0000`)) {
				clearTimeout(t);
				this.ahpOpen.delete(k);
			}
		}
	}

	/**
	 * Which process probably made the broker request tabd saw at `atMs` (default now): for the
	 * prompt (plan B3) to show "bash → node → curl" with its integrity and confidence. Display
	 * data only: the chain is tab-chosen text and must never drive a decision.
	 */
	lineageFor(tabId: string, atMs = Date.now()): Attribution {
		return { ...this.lineage.attribute(tabId, atMs, false, this.sensorIntegrity(tabId)), computed: true };
	}

	/**
	 * The attribution for a broker prompt (plan B3): the one recorded when the broker event
	 * arrived, or one computed now, marked `computed` (review LN-3), if none was recorded yet.
	 */
	promptLineage(tabId: string, approvalId: string): Attribution {
		return this.promptLineages.get(tabId)?.get(approvalId) ?? this.lineageFor(tabId);
	}

	/** The integrity a "nobody observed" claim can have: the level of the tab's sensor. */
	private sensorIntegrity(tabId: string): Integrity {
		return this.hub.observation(tabId).sensor === 'falco' ? 'host-observed' : 'tab-vm-root';
	}

	/** Emit an egress.attribution for a broker event once late connects have had time to arrive. */
	private scheduleAttribution(e: ObsEvent): void {
		const n = this.pendingAttributions.get(e.tabId) ?? 0;
		if (n >= MAX_PENDING_ATTRIBUTIONS) {
			return;
		}
		this.pendingAttributions.set(e.tabId, n + 1);
		const timer = setTimeout(() => {
			this.pendingAttributions.set(e.tabId, (this.pendingAttributions.get(e.tabId) ?? 1) - 1);
			const clientPort = typeof e.detail?.clientPort === 'number' ? e.detail.clientPort : undefined;
			const a = this.lineage.attribute(e.tabId, Date.parse(e.time), true, this.sensorIntegrity(e.tabId), clientPort);
			if (a.confidence === 'exact') {
				// One request can produce two audit events (e.g. denied_unprompted, then denied).
				const k = `${e.tabId}\u0000${clientPort}\u0000${e.net?.addr}:${e.net?.port}`;
				const last = this.recentExact.get(k);
				this.recentExact.set(k, Date.parse(e.time));
				if (this.recentExact.size > 512) {
					this.recentExact.delete(this.recentExact.keys().next().value!);
				}
				if (last !== undefined && Math.abs(Date.parse(e.time) - last) < 1000 && e.detail?.auditType !== 'approval.requested') {
					return;
				}
			}
			const approvalId = e.detail?.auditType === 'approval.requested' && typeof e.detail.approvalId === 'string' ? e.detail.approvalId : undefined;
			if (approvalId) {
				// Per tab, so one tab's prompt flood can't evict another's (review LN-3).
				let m = this.promptLineages.get(e.tabId);
				if (!m) {
					m = new Map();
					this.promptLineages.set(e.tabId, m);
				}
				if (m.size >= 64) {
					m.delete(m.keys().next().value!);
				}
				m.set(approvalId, a);
			}
			if (a.confidence === 'none' && e.detail?.auditType !== 'approval.requested') {
				return;
			}
			const target = `${e.net?.addr ?? '?'}:${e.net?.port ?? '?'}`;
			this.hub.emit(e.tabId, {
				source: 'detector', integrity: weakestIntegrity([e.integrity, a.integrity]), class: 'egress.attribution', priority: 'informational',
				summary: a.chain ? `${a.chain} → ${target}${a.confidence === 'exact' ? ' (matched by connection)' : a.confidence === 'ambiguous' ? ` (probable; ${a.candidates} candidates)` : ' (probable)'}` : `${target}: no process observed connecting to the broker`,
				...(a.proc ? { proc: a.proc } : {}), ...(e.net ? { net: e.net } : {}),
				detail: { confidence: a.confidence, candidates: a.candidates, auditType: String(e.detail?.auditType ?? ''), ...(a.confidence === 'exact' ? { joinedBy: 'client-port' } : {}) },
				cause: [e.seq, ...a.cause],
			});
		}, ATTRIBUTION_DELAY_MS);
		timer.unref();
	}

	shutdown(): Promise<void> {
		for (const tabId of [...this.watchers.keys(), ...this.pollers.keys()]) {
			this.watchers.get(tabId)?.stop();
			clearInterval(this.pollers.get(tabId));
		}
		this.watchers.clear();
		this.pollers.clear();
		for (const [tabId, s] of this.sessions) {
			this.hub.expectEnd(tabId);
			s.close();
		}
		this.sessions.clear();
		this.hub.close();
		return this.falco?.stop().catch(() => undefined) ?? Promise.resolve();
	}
}
