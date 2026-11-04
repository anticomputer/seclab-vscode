// Supervisor glue for tab observability: protocol methods, sensor hooks for drivers, and the
// mapping from supervisor audit entries to trusted events. Kept out of supervisor.ts so the
// core stays small. Spec: docs/tabd/PROTOCOL.md §3-4, docs/tabd/EVENTS.md.

import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import type { SensorHooks } from '../drivers/types.ts';
import { ObsHub, type Observation } from './hub.ts';
import { CollectorSession } from './sbx-collector.ts';
import { CLASSES, isTabId, PRIORITIES, priorityRank, type EventClass, type ObsEvent, type Priority } from './schema.ts';

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

export const MAX_SUBSCRIPTIONS = 16;
export const MAX_REPORT_EVENTS = 64;
export const MAX_TAIL = 1000;
/** Stop pushing event notifications while this many bytes wait for the client to read. */
export const NOTIFY_BACKLOG_LIMIT = 4 << 20;
/** What each trusted client component may report. The write-back gate's classes are reserved. */
const CLIENT_SOURCES: ReadonlyMap<string, ReadonlySet<string>> = new Map([['rpc-filter', new Set(['rpc.decision'])], ['gate', new Set<string>()]]);

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
}

export class ObsGlue {
	readonly hub: ObsHub;
	private readonly o: ObsGlueOptions;
	private readonly subs = new Map<number, Subscription>();
	private nextSub = 1;
	private readonly sessions = new Map<string, CollectorSession>();
	private readonly modes = new Map<string, 'default' | 'deep'>();

	constructor(o: ObsGlueOptions) {
		this.o = o;
		this.hub = new ObsHub({
			dir: o.eventsDir,
			persist: tabId => o.owns(tabId),
			onEvent: e => this.fanout(e),
			onObservation: (tabId, ob) => o.notify('tab.observation', { tabId, ...ob } as unknown as Json),
		});
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
			if (this.hub.emit(tabId, { source: e.source, class: e.class, priority: e.priority, summary: e.summary, detail: e.detail, integrity: 'trusted' })) {
				accepted++;
			} else {
				rejected++;
			}
		}
		return { accepted, rejected };
	}

	/** Hooks handed to driver.ensureRunning for this tab. */
	sensorHooks(tabId: string, workspace: string): SensorHooks {
		return {
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
				s.configure(token);
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

	/** The supervisor is stopping, removing or quarantining the tab. */
	stopping(tabId: string): void {
		this.hub.expectEnd(tabId);
		this.sessions.get(tabId)?.close();
		this.sessions.delete(tabId);
	}

	/** Adopted at startup without a collector: unobserved until the next ensureRunning. */
	adopted(tabId: string): void {
		if (!this.sessions.get(tabId)?.alive) {
			this.hub.setObservation(tabId, 'unobserved', 'adopted after a supervisor restart; observation resumes when the window reconnects');
		}
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

	shutdown(): void {
		for (const [tabId, s] of this.sessions) {
			this.hub.expectEnd(tabId);
			s.close();
		}
		this.sessions.clear();
		this.hub.close();
	}
}
