// tabd side of the sbx in-VM collector (sandbox/rootfs/opt/seclab/bin/seclab-obs-collect).
// The collector's stdout is tab-derived data: bounded line splitting, strict JSON kinds, strict
// strace parsing, and everything becomes an event draft that the hub normalises again.

import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import { isCredentialPath } from './detect.ts';
import type { ObsHub } from './hub.ts';
import { StraceParser, StraceTracker } from './strace.ts';

export const MAX_RECORD = 160 * 1024; // a 64 KiB strace line, JSON-escaped
const SOURCE = { source: 'sbx-collector', integrity: 'tab-vm-root' } as const;

export interface CollectorOptions {
	readonly mode: 'default' | 'deep';
	/** Is the sandbox still running? Decides between "unobserved" and "stopped" on EOF. */
	readonly isRunning: () => Promise<boolean>;
	readonly rehTimeoutMs?: number;
}

/** Splits a byte stream into lines of at most `max` bytes; longer lines are dropped whole. */
export class LineSplitter {
	private buf: Buffer[] = [];
	private size = 0;
	private skipping = false;
	private readonly max: number;
	constructor(max: number) {
		this.max = max;
	}

	push(chunk: Buffer, onLine: (l: Buffer) => void, onOversize: () => void): void {
		let start = 0;
		for (;;) {
			const nl = chunk.indexOf(10, start);
			const part = chunk.subarray(start, nl < 0 ? chunk.length : nl);
			if (!this.skipping) {
				if (this.size + part.length > this.max) {
					this.skipping = true;
					this.buf = [];
					this.size = 0;
					onOversize();
				} else {
					this.buf.push(part);
					this.size += part.length;
				}
			}
			if (nl < 0) {
				return;
			}
			if (!this.skipping) {
				onLine(Buffer.concat(this.buf));
			}
			this.buf = [];
			this.size = 0;
			this.skipping = false;
			start = nl + 1;
		}
	}
}

export class CollectorSession {
	readonly rehReady: Promise<void>;
	private readonly tabId: string;
	private readonly hub: ObsHub;
	private readonly o: CollectorOptions;
	private readonly child: ChildProcessWithoutNullStreams;
	private readonly parser = new StraceParser();
	private readonly tracker: StraceTracker;
	private readonly sensorPids = new Set<number>();
	private lastN = 0;
	private rehSettled = false;
	private resolveReh!: () => void;
	private rejectReh!: (e: Error) => void;
	private readonly flushTimer: NodeJS.Timeout;
	private stderrTail = '';
	private closed = false;
	private nextRehId = 0;
	private readonly rehWaiters = new Map<number, (err?: Error) => void>();
	private corruptTimes: number[] = [];

	constructor(tabId: string, child: ChildProcessWithoutNullStreams, hub: ObsHub, o: CollectorOptions) {
		this.tabId = tabId;
		this.child = child;
		this.hub = hub;
		this.o = o;
		this.tracker = new StraceTracker({ collectorPids: () => this.sensorPids, sensitivePath: isCredentialPath });
		this.rehReady = new Promise((res, rej) => {
			this.resolveReh = res;
			this.rejectReh = rej;
		});
		const timeout = setTimeout(() => this.settleReh(new Error('collector did not report the REH within the timeout')), o.rehTimeoutMs ?? 120_000);
		timeout.unref?.();
		void this.rehReady.catch(() => undefined).finally(() => clearTimeout(timeout));
		const split = new LineSplitter(MAX_RECORD);
		child.stdout.on('data', (d: Buffer) => split.push(d, l => this.record(l), () => this.corrupt()));
		child.stderr.on('data', (d: Buffer) => { this.stderrTail = (this.stderrTail + d.toString('utf8')).slice(-400); });
		child.on('error', e => this.ended(`exec error: ${e.message}`));
		child.on('close', code => this.ended(`collector exited (${code})${this.stderrTail ? `: ${this.stderrTail.trim()}` : ''}`));
		this.flushTimer = setInterval(() => this.emitAll(this.tracker.flush(Number.POSITIVE_INFINITY)), 150);
		this.flushTimer.unref?.();
	}

	/** Send the one config line. The token goes over stdin, never argv. */
	configure(token: string, workspace: string): void {
		this.child.stdin.write(`${JSON.stringify({ v: 1, mode: this.o.mode, token, user: 'agent', relayUser: 'seclab-relay', workspace })}\n`);
	}

	/** Ask the running collector to make sure the REH runs, under a fresh tracer and guard. */
	ensureReh(token: string, timeoutMs = 90_000): Promise<void> {
		const id = ++this.nextRehId;
		return new Promise<void>((resolve, reject) => {
			const timer = setTimeout(() => {
				this.rehWaiters.delete(id);
				reject(new Error('collector did not confirm the REH in time'));
			}, timeoutMs);
			timer.unref?.();
			this.rehWaiters.set(id, err => {
				clearTimeout(timer);
				this.rehWaiters.delete(id);
				if (err) {
					reject(err);
				} else {
					resolve();
				}
			});
			this.child.stdin.write(`${JSON.stringify({ cmd: 'ensure-reh', id, token })}\n`);
		});
	}

	get alive(): boolean {
		return !this.closed;
	}

	/** Stop observing: closing stdin makes the collector detach strace and exit. */
	close(): void {
		this.hub.expectEnd(this.tabId);
		this.child.stdin.end();
		setTimeout(() => this.child.kill('SIGKILL'), 5000).unref?.();
	}

	private settleReh(err?: Error): void {
		if (this.rehSettled) {
			return;
		}
		this.rehSettled = true;
		if (err) {
			this.rejectReh(err);
		} else {
			this.resolveReh();
		}
	}

	private ended(reason: string): void {
		this.closed = true;
		clearInterval(this.flushTimer);
		this.settleReh(new Error(reason));
		for (const w of [...this.rehWaiters.values()]) {
			w(new Error(reason));
		}
		void this.o.isRunning().catch(() => false).then(running => this.hub.sensorEnded(this.tabId, reason, running));
	}

	private emitAll(drafts: ReadonlyArray<Record<string, unknown>>): void {
		for (const d of drafts) {
			this.hub.emit(this.tabId, { ...d, ...SOURCE });
		}
	}

	private status(priority: string, summary: string, detail: Record<string, unknown> = {}): void {
		this.hub.emit(this.tabId, { ...SOURCE, class: 'sensor.status', priority, summary, detail });
	}

	/** Unparseable or oversized sensor output: counted; repeated, it marks the tab degraded (review OR-2). */
	private corrupt(): void {
		this.hub.countInvalid(this.tabId);
		const now = Date.now();
		this.corruptTimes = this.corruptTimes.filter(t => now - t < 10_000);
		this.corruptTimes.push(now);
		if (this.corruptTimes.length === 3) {
			this.hub.setObservation(this.tabId, 'degraded', 'sensor output is being corrupted or forged', { sensor: 'sbx-collector', mode: this.o.mode });
		}
	}

	private record(line: Buffer): void {
		let r: Record<string, unknown>;
		try {
			r = JSON.parse(line.toString('utf8'));
		} catch {
			return this.corrupt();
		}
		if (typeof r !== 'object' || r === null || Array.isArray(r) || typeof r.k !== 'string') {
			return this.hub.countInvalid(this.tabId);
		}
		// Contiguous sequence: a gap means records were lost or injected.
		if (typeof r.n === 'number' && Number.isSafeInteger(r.n)) {
			if (this.lastN && r.n !== this.lastN + 1) {
				this.status('warning', `collector sequence gap: expected ${this.lastN + 1}, got ${r.n}`, { status: 'seq-gap' });
				this.hub.setObservation(this.tabId, 'degraded', 'collector sequence gap', { sensor: 'sbx-collector', mode: this.o.mode });
			}
			this.lastN = r.n;
		}
		const int = (v: unknown) => (typeof v === 'number' && Number.isInteger(v) && v >= 0 && v < 0x40000000 ? v : undefined);
		const s = (v: unknown, max = 512) => (typeof v === 'string' ? v.slice(0, max) : undefined);
		switch (r.k) {
			case 's': {
				const l = s(r.l, 64 * 1024);
				if (l === undefined) {
					return this.hub.countInvalid(this.tabId);
				}
				let rec;
				try {
					rec = this.parser.parse(l);
				} catch {
					return this.corrupt();
				}
				if (rec) {
					this.emitAll(this.tracker.handle(rec));
				}
				return;
			}
			case 'hb':
				this.hub.heartbeat(this.tabId);
				if (Array.isArray(r.pids)) {
					this.sensorPids.clear();
					for (const p of r.pids.slice(0, 64)) {
						const v = int(p);
						if (v) {
							this.sensorPids.add(v);
						}
					}
				}
				return;
			case 'hello': {
				const pid = int(r.pid);
				if (pid) {
					this.sensorPids.add(pid);
				}
				const addrs = Array.isArray(r.brokerAddrs) ? r.brokerAddrs.map(a => s(a, 64)).filter((a): a is string => !!a && /^[0-9a-fA-F.:]+$/.test(a)).slice(0, 8) : [];
				this.hub.context(this.tabId, { brokerAddrs: new Set(addrs) });
				this.hub.heartbeat(this.tabId);
				this.hub.setObservation(this.tabId, 'observed', 'collector started', { sensor: 'sbx-collector', mode: this.o.mode });
				this.status('informational', `collector up: kernel ${s(r.kernel, 64) ?? '?'}, ${s(r.strace, 64) ?? '?'}, mode ${this.o.mode}`, { status: 'started', mode: this.o.mode });
				return;
			}
			case 'sysctl':
				if (r.ok !== true) {
					this.status('warning', `hardening sysctl ${s(r.name, 64) ?? '?'} failed: ${s(r.err, 120) ?? '?'}`, { status: 'sysctl-failed' });
				}
				return;
			case 'hp-ready':
				this.status('informational', `${int(r.count) ?? 0} honeypots armed`, { status: 'honeypots', count: int(r.count) ?? 0 });
				return;
			case 'hp-skip':
				this.status('notice', `honeypot not armed: ${s(r.path) ?? '?'} (${s(r.err, 120) ?? '?'})`, { status: 'honeypot-skipped' });
				return;
			case 'hp': {
				const kind = r.kind === 'read' || r.kind === 'write' || r.kind === 'tamper' ? r.kind : 'unknown';
				const path = s(r.path) ?? '?';
				this.hub.emit(this.tabId, {
					...SOURCE, class: 'honeypot.access', priority: kind === 'read' ? 'warning' : 'notice',
					summary: `honeypot ${kind}: ${path}`, file: { path, op: kind }, detail: { kind },
				});
				return;
			}
			case 'proc':
			case 'untraced': {
				const pid = int(r.pid);
				if (!pid) {
					return this.hub.countInvalid(this.tabId);
				}
				const argv = Array.isArray(r.argv) ? r.argv.map(a => s(a, 256)).filter((a): a is string => a !== undefined).slice(0, 32) : undefined;
				this.tracker.seed(pid, { ppid: int(r.ppid), uid: int(r.uid), exe: s(r.exe), argv, cwd: s(r.cwd) });
				if (r.k === 'untraced') {
					const tracer = int(r.tracer) ?? 0;
					const foreign = tracer !== 0;
					this.hub.emit(this.tabId, {
						...SOURCE, class: 'sensor.status', priority: foreign ? 'critical' : 'warning', proc: this.tracker.proc(pid),
						summary: foreign ? `process ${pid} is traced by another process (${tracer}): unobserved` : `process ${pid} was untraced${r.attached === true ? '; now attached' : ' and could not be attached'}`,
						detail: { status: 'untraced', tracer, attached: r.attached === true },
					});
					if (foreign || r.attached !== true) {
						this.hub.setObservation(this.tabId, 'degraded', `process ${pid} escaped tracing`, { sensor: 'sbx-collector', mode: this.o.mode });
					}
				}
				return;
			}
			case 'reh': {
				const id = int(r.id) ?? 0;
				const err = r.code === 0 ? undefined : new Error(`REH failed to start under the collector (code ${String(r.code)})`);
				if (id === 0) {
					this.settleReh(err);
				} else {
					this.rehWaiters.get(id)?.(err);
				}
				return;
			}
			case 'strace-exit':
				if (r.i === 0) {
					this.hub.setObservation(this.tabId, 'unobserved', `strace exited (${String(r.code)})`, { sensor: 'sbx-collector' });
				}
				return;
			case 'strace-err':
				this.status('debug', `strace: ${s(r.msg, 200) ?? ''}`, { status: 'strace-stderr' });
				return;
			case 'oversize':
				return this.corrupt();
			case 'err':
				this.status('error', `collector error: ${s(r.msg, 300) ?? '?'}`, { status: 'error' });
				if (r.fatal === true) {
					this.settleReh(new Error(`collector: ${s(r.msg, 300) ?? 'fatal error'}`));
				}
				return;
			case 'bye':
				return;
			default:
				return this.hub.countInvalid(this.tabId);
		}
	}
}
