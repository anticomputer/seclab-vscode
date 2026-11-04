// The per-tab observability hub (ADR tab-observability §3, §4): one ordered stream per tab,
// stamped with a supervisor sequence number and time, rate-limited, persisted as rotated JSONL,
// fanned out to subscribers, and watched for sensor gaps. Every input goes through
// normalizeDraft; nothing here interprets event content beyond detection rules.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { Detector, type TabContext } from './detect.ts';
import { EventError, isTabId, normalizeDraft, type EventDraft, type ObsEvent, type ObservationState } from './schema.ts';
import { safeText } from './text.ts';

export const RING_SIZE = 2000;
export const SEGMENT_BYTES = 8 << 20;
export const SEGMENTS_KEPT = 4;
export const MAX_TAB_LOG_DIRS = 64;
export const HEARTBEAT_TIMEOUT_MS = 6000;

interface Bucket { tokens: number; last: number; readonly rate: number; readonly burst: number; dropped: number }

export interface Observation { state: ObservationState; since: string; reason: string; sensor?: string; mode?: string }

interface TabState {
	seq: number;
	ring: ObsEvent[];
	buckets: Record<BucketName, Bucket>;
	observation: Observation;
	lastHeartbeat?: number;
	expectEnd: boolean;
	ctx: TabContext;
	detector: Detector;
	writer?: SegmentWriter;
	invalid: number;
}

export interface HubOptions {
	/** `<state>/events`; absent = memory only (tests). */
	readonly dir?: string;
	/** Persist only tabs this process owns (lease holder). */
	readonly persist?: (tabId: string) => boolean;
	readonly onEvent?: (e: ObsEvent) => void;
	readonly onObservation?: (tabId: string, o: Observation) => void;
	readonly now?: () => number;
	readonly sensorRate?: { rate: number; burst: number };
	readonly trustedRate?: { rate: number; burst: number };
}

/**
 * Rate-limit groups (security review OR-3): volume a tab can drive never shares a bucket with
 * events it must not be able to push out. Supervisor events (`tabd`) are never limited.
 */
type BucketName = 'sensor' | 'tabDriven' | 'client';
const BUCKET_OF: Readonly<Record<string, BucketName | undefined>> = {
	'sbx-collector': 'sensor', 'falco': 'sensor', 'detector': 'sensor',
	'workspace-watch': 'tabDriven', 'sbx-policy': 'tabDriven', 'broker': 'tabDriven', 'scan': 'tabDriven',
	'rpc-filter': 'client', 'gate': 'client',
};

export class ObsHub {
	private readonly tabs = new Map<string, TabState>();
	private readonly o: HubOptions;
	private readonly timer: NodeJS.Timeout;

	constructor(o: HubOptions = {}) {
		this.o = o;
		if (o.dir) {
			fs.mkdirSync(o.dir, { recursive: true, mode: 0o700 });
		}
		this.timer = setInterval(() => this.tick(), 1000);
		this.timer.unref?.();
	}

	private now(): number {
		return this.o.now?.() ?? Date.now();
	}

	private state(tabId: string): TabState {
		if (!isTabId(tabId)) {
			throw new EventError('invalid tab id');
		}
		let s = this.tabs.get(tabId);
		if (!s) {
			const t = this.now();
			const sr = this.o.sensorRate ?? { rate: 500, burst: 5000 };
			const tr = this.o.trustedRate ?? { rate: 200, burst: 2000 };
			s = {
				seq: 0, ring: [], invalid: 0, expectEnd: false, ctx: {}, detector: new Detector(),
				buckets: {
					sensor: { tokens: sr.burst, last: t, rate: sr.rate, burst: sr.burst, dropped: 0 },
					tabDriven: { tokens: tr.burst, last: t, rate: tr.rate, burst: tr.burst, dropped: 0 },
					client: { tokens: tr.burst, last: t, rate: tr.rate, burst: tr.burst, dropped: 0 },
				},
				observation: { state: 'unavailable', since: new Date(t).toISOString(), reason: 'no sensor attached' },
			};
			if (this.o.dir && (this.o.persist?.(tabId) ?? true)) {
				s.writer = new SegmentWriter(this.o.dir, tabId);
				s.seq = s.writer.lastSeq;
			}
			this.tabs.set(tabId, s);
		}
		return s;
	}

	context(tabId: string, ctx: Partial<TabContext>): void {
		Object.assign(this.state(tabId).ctx, ctx);
	}

	/** Start persisting a tab this supervisor now owns (continuing its log's sequence). */
	own(tabId: string): void {
		const s = this.state(tabId);
		if (!s.writer && this.o.dir) {
			s.writer = new SegmentWriter(this.o.dir, tabId);
			s.seq = Math.max(s.seq, s.writer.lastSeq);
		}
	}

	/**
	 * Accept an event draft from any source. Returns the stamped event, or undefined when it
	 * was invalid or rate-limited (both counted and summarised, never silently lost).
	 */
	emit(tabId: string, input: unknown): ObsEvent | undefined {
		const s = this.state(tabId);
		let draft: EventDraft;
		try {
			draft = normalizeDraft(input);
		} catch {
			s.invalid++;
			return undefined;
		}
		const group = BUCKET_OF[draft.source];
		const bucket = group ? s.buckets[group] : undefined;
		if (bucket && !take(bucket, this.now())) {
			bucket.dropped++;
			return undefined;
		}
		const e = this.stamp(tabId, s, draft);
		for (const d of s.detector.check(e, s.ctx)) {
			this.stamp(tabId, s, normalizeDraft(d));
		}
		return e;
	}

	private stamp(tabId: string, s: TabState, d: EventDraft): ObsEvent {
		const e: ObsEvent = { v: 1, seq: ++s.seq, time: new Date(this.now()).toISOString(), tabId, ...d };
		s.ring.push(e);
		if (s.ring.length > RING_SIZE) {
			s.ring.shift();
		}
		s.writer?.append(e);
		this.o.onEvent?.(e);
		return e;
	}

	/** Trusted supervisor event (lifecycle, fence, scan, observation). */
	trusted(tabId: string, draft: Omit<EventDraft, 'source' | 'integrity'> & { source?: EventDraft['source'] }): ObsEvent | undefined {
		return this.emit(tabId, { source: 'tabd', ...draft, integrity: 'trusted' });
	}

	tail(tabId: string, limit: number, beforeSeq?: number): ObsEvent[] {
		const s = this.tabs.get(tabId);
		if (!s) {
			return [];
		}
		const pick = beforeSeq === undefined ? s.ring : s.ring.filter(e => e.seq < beforeSeq);
		return pick.slice(-Math.max(1, Math.min(limit, RING_SIZE)));
	}

	lastSeq(tabId: string): number {
		return this.tabs.get(tabId)?.seq ?? 0;
	}

	observation(tabId: string): Observation {
		return { ...this.state(tabId).observation };
	}

	/** A sensor attached or reported state. */
	setObservation(tabId: string, state: ObservationState, rawReason: string, extra: { sensor?: string; mode?: string } = {}): void {
		const s = this.state(tabId);
		// Reasons can carry sensor-derived text (exit codes, stderr tails): escape and cap.
		const reason = safeText(rawReason, 300);
		const prev = s.observation;
		if (prev.state === state && prev.reason === reason) {
			return;
		}
		s.observation = { state, since: new Date(this.now()).toISOString(), reason, ...extra };
		if (state === 'observed') {
			// Only heartbeats prove liveness; a state change (e.g. rate recovery) must not.
			s.lastHeartbeat ??= this.now();
			s.expectEnd = false;
		}
		const priority = state === 'unobserved' ? 'critical' : state === 'degraded' ? 'warning' : 'notice';
		this.trusted(tabId, { class: 'sensor.status', priority, summary: `observation ${state}: ${reason}`, detail: { status: state, reason, ...(extra.sensor ? { sensor: extra.sensor } : {}), ...(extra.mode ? { mode: extra.mode } : {}) } });
		this.o.onObservation?.(tabId, this.observation(tabId));
	}

	heartbeat(tabId: string): void {
		const s = this.state(tabId);
		s.lastHeartbeat = this.now();
		if (s.observation.state === 'unobserved' && s.observation.reason.startsWith('no heartbeat')) {
			this.setObservation(tabId, 'observed', 'heartbeat resumed', { sensor: s.observation.sensor, mode: s.observation.mode });
		}
	}

	/** The supervisor is about to stop the tab: a sensor EOF is expected, not a gap. */
	expectEnd(tabId: string): void {
		this.state(tabId).expectEnd = true;
	}

	/** The sensor stream ended. Only a stop the supervisor asked for is "unavailable". */
	sensorEnded(tabId: string, reason: string, sandboxRunning: boolean): void {
		const s = this.state(tabId);
		if (s.expectEnd) {
			this.setObservation(tabId, 'unavailable', 'tab stopped');
			return;
		}
		// A tab can stop its own sandbox (e.g. SIGTERM to PID 1 under sbx): that blinds the sensor too.
		this.setObservation(tabId, 'unobserved', sandboxRunning ? `sensor ended: ${reason}` : `sandbox stopped unexpectedly (${reason})`, { sensor: s.observation.sensor });
	}

	private tick(): void {
		const t = this.now();
		for (const [tabId, s] of this.tabs) {
			for (const what of ['sensor', 'tabDriven', 'client'] as const) {
				const b = s.buckets[what];
				if (b.dropped > 0) {
					const n = b.dropped;
					b.dropped = 0;
					this.stamp(tabId, s, normalizeDraft({ source: 'tabd', integrity: 'trusted', class: 'sensor.status', priority: 'warning', summary: `${n} ${what} events dropped (rate limit)`, detail: { status: 'dropped', count: n, stream: what } }));
					if (what === 'sensor' && s.observation.state === 'observed') {
						this.setObservation(tabId, 'degraded', 'events dropped by rate limit', { sensor: s.observation.sensor, mode: s.observation.mode });
					}
				} else if (what === 'sensor' && s.observation.state === 'degraded' && s.observation.reason === 'events dropped by rate limit') {
					this.setObservation(tabId, 'observed', 'rate back to normal', { sensor: s.observation.sensor, mode: s.observation.mode });
				}
			}
			if (s.invalid > 0) {
				const n = s.invalid;
				s.invalid = 0;
				this.stamp(tabId, s, normalizeDraft({ source: 'tabd', integrity: 'trusted', class: 'sensor.status', priority: 'warning', summary: `${n} malformed events rejected`, detail: { status: 'invalid', count: n } }));
			}
			if ((s.observation.state === 'observed' || s.observation.state === 'degraded') && s.lastHeartbeat !== undefined && t - s.lastHeartbeat > HEARTBEAT_TIMEOUT_MS) {
				this.setObservation(tabId, 'unobserved', `no heartbeat for ${Math.round((t - s.lastHeartbeat) / 1000)} s`, { sensor: s.observation.sensor });
			}
			s.writer?.flush();
		}
	}

	forget(tabId: string): void {
		const s = this.tabs.get(tabId);
		s?.writer?.close();
		this.tabs.delete(tabId);
	}

	close(): void {
		clearInterval(this.timer);
		for (const s of this.tabs.values()) {
			s.writer?.close();
		}
	}

	/** For tests: run the periodic work now. */
	tickNow(): void {
		this.tick();
	}

	/** A sensor sent something unparseable (counted and summarised once a second). */
	countInvalid(tabId: string): void {
		this.state(tabId).invalid++;
	}
}

function take(b: Bucket, now: number): boolean {
	b.tokens = Math.min(b.burst, b.tokens + ((now - b.last) / 1000) * b.rate);
	b.last = now;
	if (b.tokens < 1) {
		return false;
	}
	b.tokens -= 1;
	return true;
}

/** Append-only JSONL segments: events-<n>.jsonl, rotated at SEGMENT_BYTES, SEGMENTS_KEPT kept. */
export class SegmentWriter {
	readonly lastSeq: number;
	private readonly dir: string;
	private index: number;
	private size: number;
	private fd: number;
	private buf: string[] = [];

	constructor(root: string, tabId: string) {
		if (!isTabId(tabId)) {
			throw new EventError('invalid tab id');
		}
		this.dir = path.join(root, tabId);
		if (!fs.existsSync(this.dir)) {
			pruneTabDirs(root);
		}
		fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
		const segs = listSegments(this.dir);
		this.index = segs.length ? segs[segs.length - 1] : 1;
		this.lastSeq = segs.length ? lastSeqIn(path.join(this.dir, segName(this.index))) : 0;
		this.fd = this.open();
		this.size = fs.fstatSync(this.fd).size;
	}

	private open(): number {
		return fs.openSync(path.join(this.dir, segName(this.index)), fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_CREAT | fs.constants.O_NOFOLLOW, 0o600);
	}

	append(e: ObsEvent): void {
		this.buf.push(JSON.stringify(e));
		if (this.buf.length >= 256) {
			this.flush();
		}
	}

	flush(): void {
		if (!this.buf.length) {
			return;
		}
		const data = this.buf.join('\n') + '\n';
		this.buf = [];
		fs.writeSync(this.fd, data);
		this.size += Buffer.byteLength(data);
		if (this.size >= SEGMENT_BYTES) {
			fs.closeSync(this.fd);
			this.index++;
			this.fd = this.open();
			this.size = 0;
			for (const old of listSegments(this.dir).slice(0, -SEGMENTS_KEPT)) {
				fs.rmSync(path.join(this.dir, segName(old)), { force: true });
			}
		}
	}

	close(): void {
		try {
			this.flush();
			fs.closeSync(this.fd);
		} catch { /* already closed */ }
	}
}

export function segName(n: number): string {
	return `events-${String(n).padStart(6, '0')}.jsonl`;
}

export function listSegments(dir: string): number[] {
	let names: string[];
	try {
		names = fs.readdirSync(dir);
	} catch {
		return [];
	}
	return names.map(n => /^events-(\d{6})\.jsonl$/.exec(n)).filter((m): m is RegExpExecArray => !!m).map(m => Number(m[1])).sort((a, b) => a - b);
}

function lastSeqIn(file: string): number {
	try {
		const fd = fs.openSync(file, 'r');
		try {
			const size = fs.fstatSync(fd).size;
			const len = Math.min(size, 256 * 1024);
			const b = Buffer.alloc(len);
			fs.readSync(fd, b, 0, len, size - len);
			const lines = b.toString('utf8').split('\n').filter(Boolean);
			for (let i = lines.length - 1; i >= 0; i--) {
				try {
					const seq = (JSON.parse(lines[i]) as { seq?: unknown }).seq;
					if (typeof seq === 'number' && Number.isSafeInteger(seq)) {
						return seq;
					}
				} catch { /* torn line */ }
			}
		} finally {
			fs.closeSync(fd);
		}
	} catch { /* empty */ }
	return 0;
}

/** Keep at most MAX_TAB_LOG_DIRS tab log directories: drop the least recently written. */
function pruneTabDirs(root: string): void {
	const dirs = fs.readdirSync(root).filter(isTabId).map(n => ({ n, m: fs.statSync(path.join(root, n)).mtimeMs })).sort((a, b) => a.m - b.m);
	for (const d of dirs.slice(0, Math.max(0, dirs.length - MAX_TAB_LOG_DIRS + 1))) {
		fs.rmSync(path.join(root, d.n), { recursive: true, force: true });
	}
}
