/*---------------------------------------------------------------------------------------------
 *  Window decision logs -> `tab.events.report` (EDR window-decision-logs). The trusted renderer
 *  writes the AHP gate's (patch 0015) and the RPC filter's decisions to per-window logs through
 *  `ILoggerService`, one JSON object per line behind the logger's prefix. The Tab Manager, in the
 *  same window's local extension host, tails them and reports each line for its own window's tab.
 *
 *  The files are written by the main process on the host; a tab reaches them only through
 *  `MainThreadLogger.*` (denied by the RPC filter) or a local file write (no such channel), so
 *  nothing is forwarded unless the build says the filter ships (`rpcFilterShipped`). The content
 *  is still treated as hostile: bounded lines, a fixed field set, and per-file source allowlists;
 *  tabd validates again and sets integrity from the source.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'node:fs';
import * as path from 'node:path';

export interface ReportEvent { source: string; class: string; priority: string; summary: string; detail?: Record<string, unknown> }

export interface WindowLog {
	/** Sources this file may carry (tabd then fixes each source's classes). */
	readonly sources: ReadonlySet<string>;
	/** Reported when lines may have been lost (a rotation the tailer couldn't follow). */
	readonly skipped: ReportEvent;
}

/** The gate first: its opened/verified pair is timed by arrival (tabd `ahp.ungated`). */
export const WINDOW_LOGS: ReadonlyMap<string, WindowLog> = new Map([
	['seclabAhpGate.log', {
		sources: new Set(['ahp-gate', 'ahp-reverse', 'ahp-credential']),
		skipped: { source: 'ahp-gate', class: 'ahp.decision', priority: 'warning', summary: 'ahp-gate.log-skipped', detail: { gateRule: 'ahp-gate.log-skipped', connection: 0, verdict: 'deny' } },
	}],
	['seclabRpcFilter.log', {
		sources: new Set(['rpc-filter']),
		skipped: { source: 'rpc-filter', class: 'rpc.decision', priority: 'warning', summary: 'log lines skipped', detail: { surface: 'rpc', ref: 'rpc:seclab.log-skipped', verdict: 'deny', reason: 'log-skipped' } },
	}],
]);

export const MAX_LINE_BYTES = 8192;
const READ_CHUNK = 64 * 1024;
const MAX_READ_PER_POLL = 256 * 1024;
const MAX_DETAIL_KEYS = 32;
/** spdlog keeps `<name>.<k>.log` for k = 1..filecount (6 in 1.145); look a little further. */
const MAX_ROTATED = 10;

/**
 * The RPC policy table this build applied (`product.json` `seclabRpcPolicy.sha256`, stamped
 * by prepare.sh iff the filter's 0005 is in the series; EDR rpc-policy-stamp). This proves the
 * table was applied, not that the filter enforces: see `ENFORCEMENT_MARKER`.
 */
export function rpcPolicyApplied(product: unknown): string | undefined {
	const s = typeof product === 'object' && product !== null ? (product as Record<string, unknown>).seclabRpcPolicy : undefined;
	const sha = typeof s === 'object' && s !== null ? (s as Record<string, unknown>).sha256 : undefined;
	return typeof sha === 'string' && /^[0-9a-f]{64}$/.test(sha) ? sha : undefined;
}

/**
 * The literal the filter's enforcing code carries in the built workbench bundle, for that table.
 * Assembled at run time so this bundle never contains the prefix itself: check-release treats
 * any occurrence of that prefix in a release artefact as the filter's own marker.
 */
export const ENFORCEMENT_MARKER = (sha256: string) => `${['seclabRpcFilter', 'Enforcing'].join('')}:${sha256}`;

/**
 * Whether this build ships the RPC filter, which is what makes the window logs tab-proof: the
 * policy stamp, and the enforcing code's marker for that same table in the workbench bundle.
 */
export async function rpcFilterShipped(product: unknown, bundle: string): Promise<boolean> {
	const sha = rpcPolicyApplied(product);
	return sha !== undefined && fileContains(bundle, ENFORCEMENT_MARKER(sha));
}

/** Streams a (large) file looking for an ASCII literal. */
export async function fileContains(file: string, needle: string): Promise<boolean> {
	let tail = '';
	try {
		for await (const chunk of fs.createReadStream(file, { encoding: 'latin1', highWaterMark: 1 << 20 })) {
			const s = tail + (chunk as string);
			if (s.includes(needle)) {
				return true;
			}
			tail = s.slice(-needle.length);
		}
	} catch {
		return false;
	}
	return false;
}

/** One log line (logger prefix, then a JSON object) to a report event, or undefined. */
export function parseWindowLogLine(line: string, sources: ReadonlySet<string>): ReportEvent | undefined {
	if (line.length > MAX_LINE_BYTES) {
		return undefined;
	}
	const at = line.indexOf('{');
	if (at < 0) {
		return undefined;
	}
	let o: unknown;
	try {
		o = JSON.parse(line.slice(at));
	} catch {
		return undefined;
	}
	if (typeof o !== 'object' || o === null || Array.isArray(o)) {
		return undefined;
	}
	const r = o as Record<string, unknown>;
	if (typeof r.source !== 'string' || !sources.has(r.source) || typeof r.class !== 'string' || typeof r.priority !== 'string' || typeof r.summary !== 'string') {
		return undefined;
	}
	const ev: ReportEvent = { source: r.source, class: r.class, priority: r.priority, summary: r.summary };
	if (r.detail !== undefined) {
		if (typeof r.detail !== 'object' || r.detail === null || Array.isArray(r.detail) || Object.keys(r.detail).length > MAX_DETAIL_KEYS) {
			return undefined;
		}
		// Flat scalars only (tabd's detail schema); anything nested is dropped here.
		const d: Record<string, unknown> = {};
		for (const [k, v] of Object.entries(r.detail)) {
			if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') {
				d[k] = v;
			}
		}
		ev.detail = d;
	}
	return ev;
}

/** spdlog's name for the k-th rotated file: `a.log` -> `a.1.log`. */
export function rotatedName(file: string, k: number): string {
	if (k === 0) {
		return file;
	}
	const ext = path.extname(file);
	return `${file.slice(0, file.length - ext.length)}.${k}${ext}`;
}

/**
 * Follows one log file across spdlog's rename rotation (`a.log` -> `a.1.log` -> ...). The
 * descriptor stays open, so the current file is read to its end; the next one is the file
 * that now sits one index below ours, found by inode, so no rotated file is skipped. If ours
 * can't be found (rotated off the end), lines may be lost and the file's `skipped` marker is
 * reported. A file truncated in place is read again from the start. At most
 * MAX_READ_PER_POLL per call; the caller stops polling while it is behind, so the files on
 * disk (bounded by the logger's rotation) are the only buffer.
 */
export class WindowLogTail {
	readonly file: string;
	private readonly log: WindowLog;
	private fd: number | undefined;
	private ino = 0;
	private pos = 0;
	private partial = '';
	private skipping = false;
	/** Lines dropped as oversized or invalid (counted, never forwarded). */
	invalid = 0;

	constructor(file: string, log: WindowLog) {
		this.file = file;
		this.log = log;
	}

	/** Where reading has got to (a line start), so a reloaded window doesn't report lines twice. */
	position(): { ino: number; pos: number } | undefined {
		return this.fd === undefined || this.skipping ? undefined : { ino: this.ino, pos: this.pos - Buffer.byteLength(this.partial) };
	}

	/** Start from a saved position: the file with that inode, current or rotated. */
	resume(p: { ino: number; pos: number } | undefined): void {
		if (!p || !Number.isInteger(p.pos) || p.pos < 0) {
			return;
		}
		for (let k = 0; k <= MAX_ROTATED; k++) {
			if (statOrUndefined(rotatedName(this.file, k))?.ino === p.ino) {
				if (this.open(rotatedName(this.file, k)) && this.ino === p.ino && p.pos <= fs.fstatSync(this.fd!).size) {
					this.pos = p.pos;
				} else {
					this.close();
				}
				return;
			}
		}
	}

	poll(): ReportEvent[] {
		const out: ReportEvent[] = [];
		if (this.fd === undefined && !this.open(this.file)) {
			return out;
		}
		let read = 0;
		const buf = Buffer.allocUnsafe(READ_CHUNK);
		for (;;) {
			if (fs.fstatSync(this.fd!).size < this.pos) {
				// Truncated in place.
				this.pos = 0;
				this.partial = '';
				this.skipping = false;
			}
			while (read < MAX_READ_PER_POLL) {
				const n = fs.readSync(this.fd!, buf, 0, READ_CHUNK, this.pos);
				if (n <= 0) {
					break;
				}
				this.pos += n;
				read += n;
				this.lines(buf.toString('utf8', 0, n), out);
			}
			if (read >= MAX_READ_PER_POLL || statOrUndefined(this.file)?.ino === this.ino) {
				return out;
			}
			// Rotated: ours is now `.k`; the next is `.k-1` (or the current name).
			let k = 1;
			while (k <= MAX_ROTATED && statOrUndefined(rotatedName(this.file, k))?.ino !== this.ino) {
				k++;
			}
			this.close();
			this.partial = '';
			this.skipping = false;
			let next = k - 1;
			if (k > MAX_ROTATED) {
				// Ours is gone, and maybe others with it: resume at the oldest rotated file left.
				out.push(this.log.skipped);
				next = MAX_ROTATED;
				while (next > 0 && !statOrUndefined(rotatedName(this.file, next))) {
					next--;
				}
			}
			if (!this.open(rotatedName(this.file, next))) {
				return out;
			}
		}
	}

	private lines(text: string, out: ReportEvent[]): void {
		let s = this.partial + text;
		this.partial = '';
		for (let nl = s.indexOf('\n'); nl >= 0; nl = s.indexOf('\n')) {
			const line = s.slice(0, nl);
			s = s.slice(nl + 1);
			if (this.skipping) {
				this.skipping = false;
				continue;
			}
			const ev = parseWindowLogLine(line, this.log.sources);
			if (ev) {
				out.push(ev);
			} else if (line.trim()) {
				this.invalid++;
			}
		}
		if (s.length > MAX_LINE_BYTES) {
			// An oversized line: drop it through its newline.
			this.skipping = true;
			this.invalid++;
			s = '';
		}
		this.partial = this.skipping ? '' : s;
	}

	private open(file: string): boolean {
		let fd: number;
		try {
			fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
		} catch {
			return false;
		}
		const st = fs.fstatSync(fd);
		if (!st.isFile()) {
			fs.closeSync(fd);
			return false;
		}
		this.fd = fd;
		this.ino = st.ino;
		this.pos = 0;
		return true;
	}

	close(): void {
		if (this.fd !== undefined) {
			fs.closeSync(this.fd);
			this.fd = undefined;
		}
	}
}

function statOrUndefined(p: string): fs.Stats | undefined {
	try {
		return fs.lstatSync(p);
	} catch {
		return undefined;
	}
}

export interface WindowLogForwarderOptions {
	/** The window's log directory (`windowLogsPath`). */
	readonly dir: string;
	/** Reports up to 64 events for this window's tab; rejects if tabd is unavailable. */
	readonly report: (events: ReportEvent[]) => Promise<unknown>;
	readonly intervalMs?: number;
	readonly state?: { get(file: string): { ino: number; pos: number } | undefined; set(file: string, p: { ino: number; pos: number }): void };
	readonly onInvalid?: (file: string, count: number) => void;
}

/** Batches per file per round, so one file's backlog can't hold back the other (review round 12). */
const BATCHES_PER_TICK = 4;

/** Tails every window decision log and reports its lines in order, a bounded amount per round. */
export class WindowLogForwarder {
	private readonly tails: WindowLogTail[] = [];
	private timer: NodeJS.Timeout | undefined;
	private busy = false;
	private readonly backlog = new Map<WindowLogTail, ReportEvent[]>();
	private readonly invalidSeen = new Map<WindowLogTail, number>();
	private readonly o: WindowLogForwarderOptions;

	constructor(o: WindowLogForwarderOptions) {
		this.o = o;
		for (const [name, log] of WINDOW_LOGS) {
			const t = new WindowLogTail(path.join(o.dir, name), log);
			t.resume(o.state?.get(name));
			this.tails.push(t);
		}
	}

	start(): void {
		if (!this.timer) {
			this.timer = setInterval(() => void this.tick(), this.o.intervalMs ?? 500);
			this.timer.unref?.();
			void this.tick();
		}
	}

	/** One round: per file, report what's pending (bounded), reading more once caught up. */
	async tick(): Promise<void> {
		if (this.busy) {
			return;
		}
		this.busy = true;
		try {
			for (const t of this.tails) {
				await this.drain(t);
			}
		} catch {
			// tabd unavailable: the backlog is kept and retried on the next round.
		} finally {
			this.busy = false;
		}
	}

	private async drain(t: WindowLogTail): Promise<void> {
		let pending = this.backlog.get(t) ?? [];
		if (!pending.length) {
			pending = t.poll();
			this.backlog.set(t, pending);
		}
		for (let n = 0; pending.length && n < BATCHES_PER_TICK; n++) {
			await this.o.report(pending.slice(0, 64));
			pending = pending.slice(64);
			this.backlog.set(t, pending);
		}
		if (!pending.length) {
			const p = t.position();
			if (p) {
				this.o.state?.set(path.basename(t.file), p);
			}
		}
		if (t.invalid !== (this.invalidSeen.get(t) ?? 0)) {
			this.invalidSeen.set(t, t.invalid);
			this.o.onInvalid?.(t.file, t.invalid);
		}
	}

	dispose(): void {
		clearInterval(this.timer);
		this.timer = undefined;
		for (const t of this.tails) {
			t.close();
		}
	}
}
