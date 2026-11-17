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
const EMPTY = Buffer.alloc(0);

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
	/** An incomplete last line, as bytes: a UTF-8 character can straddle two reads (CR10-2). */
	private partial: Buffer = EMPTY;
	private skipping = false;
	/** A saved position's file had rotated away: report `skipped` first (CR10-13). */
	private lostOnResume = false;
	/** Lines dropped as oversized or invalid (counted, never forwarded). */
	invalid = 0;
	/** Lines stamped before this window session began (an earlier tab in the same window). */
	earlier = 0;
	/** Session start (logger time, ms): earlier lines are another session's and never forwarded. */
	notBefore: number | undefined;

	/** Where this tail's checkpoint is kept: the file name, plus `#lane` for a second lane. */
	readonly key: string;
	/** Only the lines of this lane (CR10-10); others are skipped silently. */
	private readonly lane: ((e: ReportEvent) => boolean) | undefined;

	/** Whether this tail counts the file's invalid lines (one tail per file does). */
	private readonly countInvalid: boolean;

	/**
	 * Whether what tabd defers is sent again. Not for AHP connection lifecycle: tabd watches it on
	 * first sight and never defers it (dropped and summarised past its bucket; CR10-12).
	 */
	readonly retry: boolean;

	constructor(file: string, log: WindowLog, lane?: { key?: string; accept: (e: ReportEvent) => boolean; countInvalid?: boolean; retry?: boolean }) {
		this.file = file;
		this.log = log;
		this.key = lane?.key ? `${path.basename(file)}#${lane.key}` : path.basename(file);
		this.lane = lane?.accept;
		this.countInvalid = !lane || !!lane.countInvalid;
		this.retry = lane?.retry ?? true;
	}

	/** Where reading has got to (a line start), so a reloaded window doesn't report lines twice. */
	position(): { ino: number; pos: number } | undefined {
		return this.fd === undefined || this.skipping ? undefined : { ino: this.ino, pos: this.pos - this.partial.length };
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
		// The saved file has rotated away: whatever it held after the checkpoint, and maybe more,
		// is gone. Start at the oldest file left and report the loss, rather than skip every
		// rotated file by starting at the current one (CR10-13).
		// Set first: if nothing can be opened yet, the first poll that opens a file reports it (CR10-28).
		this.lostOnResume = true;
		this.open(rotatedName(this.file, this.oldestSlot()));
	}

	/** Start reading at the oldest rotated file left (or the current one). */
	startAtOldest(): void {
		this.close();
		this.open(rotatedName(this.file, this.oldestSlot()));
	}

	/** The highest rotation slot on disk (0 if there is no rotated file). */
	private oldestSlot(): number {
		let k = MAX_ROTATED;
		while (k > 0 && !statOrUndefined(rotatedName(this.file, k))) {
			k--;
		}
		return k;
	}

	poll(): ReportEvent[] {
		return this.pollAt().map(x => x.ev);
	}

	/**
	 * Open the file if it isn't, and say where reading starts (a checkpoint for a tail that has
	 * none yet). Undefined while a loss found on resume is still to be reported (CR10-13).
	 */
	anchor(): { ino: number; pos: number } | undefined {
		if (this.lostOnResume || (this.fd === undefined && !this.open(this.file))) {
			return undefined;
		}
		return this.position();
	}

	/**
	 * New events, each with where its line ends: a checkpoint there means every line up to and
	 * including it was delivered (CR10-11). The `skipped` marker has no line of its own.
	 */
	pollAt(): Array<{ ev: ReportEvent; end?: { ino: number; pos: number } }> {
		const out: Array<{ ev: ReportEvent; end?: { ino: number; pos: number } }> = [];
		if (this.fd === undefined && !this.open(this.file)) {
			return out;
		}
		if (this.lostOnResume) {
			this.lostOnResume = false;
			out.push({ ev: this.log.skipped, end: { ino: this.ino, pos: this.pos } });
		}
		let read = 0;
		const buf = Buffer.allocUnsafe(READ_CHUNK);
		for (;;) {
			if (fs.fstatSync(this.fd!).size < this.pos) {
				// Truncated in place.
				this.pos = 0;
				this.partial = EMPTY;
				this.skipping = false;
			}
			while (read < MAX_READ_PER_POLL) {
				const n = fs.readSync(this.fd!, buf, 0, READ_CHUNK, this.pos);
				if (n <= 0) {
					break;
				}
				this.pos += n;
				read += n;
				this.lines(buf.subarray(0, n), out);
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
			this.partial = EMPTY;
			this.skipping = false;
			let next = k - 1;
			let marker: { ev: ReportEvent; end?: { ino: number; pos: number } } | undefined;
			if (k > MAX_ROTATED) {
				// Ours is gone, and maybe others with it: resume at the oldest rotated file left.
				marker = { ev: this.log.skipped };
				out.push(marker);
				next = this.oldestSlot();
			}
			if (!this.open(rotatedName(this.file, next))) {
				return out;
			}
			if (marker) {
				// Delivering the marker moves the checkpoint into the file read next (CR10-13).
				marker.end = { ino: this.ino, pos: 0 };
			}
		}
	}

	private lines(chunk: Buffer, out: Array<{ ev: ReportEvent; end?: { ino: number; pos: number } }>): void {
		const s = this.partial.length ? Buffer.concat([this.partial, chunk]) : chunk;
		this.partial = EMPTY;
		// `this.pos` is already past `chunk`: `s` starts this many bytes into the file.
		const base = this.pos - s.length;
		let start = 0;
		for (let nl = s.indexOf(0x0a, start); nl >= 0; nl = s.indexOf(0x0a, start)) {
			// Only whole lines are decoded, so a multi-byte character is never split.
			const line = s.toString('utf8', start, nl);
			start = nl + 1;
			if (this.skipping) {
				this.skipping = false;
				continue;
			}
			const ev = parseWindowLogLine(line, this.log.sources);
			if (ev && this.lane && !this.lane(ev)) {
				continue;
			}
			if (ev && this.notBefore !== undefined) {
				const t = loggerTime(line);
				if (t === undefined) {
					// Only one tail accepts a parsed line, so it counts it (CR10-14).
					this.invalid++;
					continue;
				}
				if (t < this.notBefore) {
					this.earlier++;
					continue;
				}
			}
			if (ev) {
				out.push({ ev, end: { ino: this.ino, pos: base + start } });
			} else if (line.trim() && this.countInvalid) {
				this.invalid++;
			}
		}
		const rest = s.length - start;
		if (rest > MAX_LINE_BYTES) {
			// An oversized line: drop it through its newline.
			this.skipping = true;
			this.invalid += this.countInvalid ? 1 : 0;
		}
		// A copy: `chunk` is the caller's reused read buffer.
		this.partial = this.skipping || rest === 0 ? EMPTY : Buffer.from(s.subarray(start));
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

/** The logger's own timestamp (`2026-11-16 14:28:02.366 [info] …`, host local time), in ms. */
export function loggerTime(line: string): number | undefined {
	const m = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})\.(\d{3}) /.exec(line);
	if (!m) {
		return undefined;
	}
	const t = new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6], +m[7]).getTime();
	return Number.isFinite(t) ? t : undefined;
}

/** Where this window session's RPC-filter log begins. */
export interface WindowSession {
	time: number; ino: number; pos: number;
	/** The logger time of the last RPC-filter line before the install line (the previous session's), if any. */
	prevLast?: number;
}

/**
 * The gate logs from the same renderer before the RPC filter installs (it is asked first, at
 * startup: measured 0.2 s earlier). Its lines get this much grace before the install line, but
 * never reach back to the previous session's last RPC-filter line.
 */
export const GATE_GRACE_MS = 3000;

/**
 * The start of the current window session (review round 14): the last `rpc:seclab.installed`
 * line the RPC filter wrote. A window keeps its log folder when it is reused for another
 * workspace, and its renderer reloads and installs the filter again, so everything before the
 * latest install line belongs to an earlier tab. Searched newest file first. Undefined until the
 * filter has written one (then nothing is forwarded yet).
 */
export function findWindowSession(rpcLog: string): WindowSession | undefined {
	for (let k = 0; k <= MAX_ROTATED; k++) {
		const file = rotatedName(rpcLog, k);
		let fd: number;
		try {
			fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
		} catch {
			if (k === 0) {
				continue;
			}
			return undefined;
		}
		try {
			const st = fs.fstatSync(fd);
			if (!st.isFile() || st.size > 64 << 20) {
				continue;
			}
			const buf = Buffer.alloc(st.size);
			const n = fs.readSync(fd, buf, 0, st.size, 0);
			let found: WindowSession | undefined;
			let lastTime: number | undefined;
			// Offsets are counted in bytes, never re-encoded from decoded text (CR10-2).
			for (let start = 0, nl = 0; start < n; start = nl + 1) {
				nl = buf.indexOf(0x0a, start);
				if (nl < 0 || nl >= n) {
					nl = n;
				}
				const line = buf.toString('utf8', start, nl);
				const lt = loggerTime(line);
				if (line.includes('rpc:seclab.installed')) {
					const ev = parseWindowLogLine(line, WINDOW_LOGS.get('seclabRpcFilter.log')!.sources);
					if (ev?.detail?.ref === 'rpc:seclab.installed' && lt !== undefined) {
						found = { time: lt, ino: st.ino, pos: start, ...(lastTime !== undefined ? { prevLast: lastTime } : {}) };
					}
				}
				if (lt !== undefined) {
					lastTime = lt;
				}
			}
			if (found) {
				// The install line opens this file: the previous session's last line is the last
				// timed line of the next older file (CR10-27).
				if (found.prevLast === undefined && k < MAX_ROTATED) {
					const before = lastLoggerTime(rotatedName(rpcLog, k + 1));
					if (before !== undefined) {
						found.prevLast = before;
					}
				}
				return found;
			}
		} finally {
			fs.closeSync(fd);
		}
	}
	return undefined;
}

/** The logger time of the last timed line in a log file, if any (bounded like findWindowSession). */
function lastLoggerTime(file: string): number | undefined {
	let fd: number;
	try {
		fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
	} catch {
		return undefined;
	}
	try {
		const st = fs.fstatSync(fd);
		if (!st.isFile() || st.size > 64 << 20) {
			return undefined;
		}
		const buf = Buffer.alloc(st.size);
		const n = fs.readSync(fd, buf, 0, st.size, 0);
		let last: number | undefined;
		for (let start = 0, nl = 0; start < n; start = nl + 1) {
			nl = buf.indexOf(0x0a, start);
			if (nl < 0 || nl >= n) {
				nl = n;
			}
			last = loggerTime(buf.toString('utf8', start, Math.min(nl, start + 64))) ?? last;
		}
		return last;
	} finally {
		fs.closeSync(fd);
	}
}

/** The tabd rate bucket an event lands in, as far as ordering matters: AHP connection lifecycle or the rest. */
function laneOf(e: ReportEvent): string {
	const g = e.detail?.gateRule;
	return e.source === 'ahp-gate' && (g === 'ahp-gate.opened' || g === 'ahp-gate.verified') ? 'ahp-life' : 'other';
}

/** `tab.events.report`'s `limited`: valid indices of the batch, ascending and unique, else none. */
function limitedIndices(r: unknown, n: number): number[] {
	const l = (r as { limited?: unknown } | undefined)?.limited;
	if (!Array.isArray(l) || l.length > n || !l.every((i, k) => Number.isInteger(i) && i >= 0 && i < n && (k === 0 || i > l[k - 1]))) {
		return [];
	}
	return l as number[];
}

/** The rotation slot holding inode `ino` (0 is the current file), if it is still on disk. */
function rotationSlot(file: string, ino: number): number | undefined {
	for (let k = 0; k <= MAX_ROTATED; k++) {
		if (statOrUndefined(rotatedName(file, k))?.ino === ino) {
			return k;
		}
	}
	return undefined;
}

const isCount = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;

function validPosition(v: unknown): { ino: number; pos: number; dir?: string } | undefined {
	const p = v as { ino?: unknown; pos?: unknown; dir?: unknown } | undefined;
	if (!p || !isCount(p.ino) || !isCount(p.pos) || (p.dir !== undefined && typeof p.dir !== 'string')) {
		return undefined;
	}
	return { ino: p.ino, pos: p.pos, ...(typeof p.dir === 'string' ? { dir: p.dir } : {}) };
}

function validSession(v: unknown): WindowSession | undefined {
	const p = v as { time?: unknown; ino?: unknown; pos?: unknown; prevLast?: unknown } | undefined;
	if (!p || !isCount(p.time) || !isCount(p.ino) || !isCount(p.pos) || (p.prevLast !== undefined && !isCount(p.prevLast))) {
		return undefined;
	}
	return { time: p.time, ino: p.ino, pos: p.pos, ...(p.prevLast !== undefined ? { prevLast: p.prevLast } : {}) };
}

export interface WindowLogForwarderOptions {
	/** The window's log directory (`windowLogsPath`). */
	readonly dir: string;
	/**
	 * Reports up to 64 events for this window's tab; rejects if tabd is unavailable. `retry`:
	 * the forwarder sends again what tabd defers (`retryLimited`).
	 */
	readonly report: (events: ReportEvent[], o: { retry: boolean }) => Promise<unknown>;
	readonly intervalMs?: number;
	/** Checkpoints per tail key. Saved with the log folder they belong to (CR10-15); read back as untrusted. */
	readonly state?: { get(key: string): unknown; set(key: string, p: { ino: number; pos: number; dir: string }): void };
	/** The bound window session, kept outside the rotating log (CR10-3). Read back as untrusted. */
	readonly session?: { get(): unknown; set(s: WindowSession): void };
	readonly onInvalid?: (file: string, count: number) => void;
}

/** Batches per file per round, so one file's backlog can't hold back the other (review round 12). */
const BATCHES_PER_TICK = 4;

/** Tails every window decision log and reports its lines in order, a bounded amount per round. */
export class WindowLogForwarder {
	private readonly tails: WindowLogTail[] = [];
	private timer: NodeJS.Timeout | undefined;
	private readonly inflight = new Set<WindowLogTail>();
	private readonly backlog = new Map<WindowLogTail, Array<{ ev: ReportEvent; end?: { ino: number; pos: number } }>>();
	private readonly invalidSeen = new Map<WindowLogTail, number>();
	private readonly o: WindowLogForwarderOptions;
	private session: WindowSession | undefined;
	private lostReported = false;

	constructor(o: WindowLogForwarderOptions) {
		this.o = o;
		for (const [name, log] of WINDOW_LOGS) {
			const file = path.join(o.dir, name);
			if (name === 'seclabAhpGate.log') {
				// Two tails, each in order with its own checkpoint (CR10-10): AHP connection
				// lifecycle lines (their own tabd bucket; `ahp.ungated` watches them on first sight)
				// are never held back by gate denials waiting for the rate limit.
				this.tails.push(new WindowLogTail(file, log, { accept: e => laneOf(e) === 'other', countInvalid: true }));
				this.tails.push(new WindowLogTail(file, log, { key: 'lifecycle', accept: e => laneOf(e) === 'ahp-life', retry: false }));
			} else {
				this.tails.push(new WindowLogTail(file, log));
			}
		}
	}

	/**
	 * Bind the tails to this window session (review round 14): the RPC log starts at the
	 * session's install line, or at the saved position when that is later in the same file (a
	 * restarted extension host); every line stamped before the session is dropped. Until the
	 * filter has written its install line there is no session, and nothing is forwarded.
	 */
	private bindSession(): boolean {
		if (this.session) {
			return true;
		}
		const rpcLog = path.join(this.o.dir, 'seclabRpcFilter.log');
		const savedRpc = this.checkpoint(rpcLog, 'seclabRpcFilter.log');
		let s = findWindowSession(rpcLog);
		if (s) {
			this.o.session?.set(s);
		} else {
			// CR10-3: the install line can rotate away while this renderer lives on (an extension
			// host restart keeps it, and it installs once). While the saved checkpoint's file is
			// still on disk no newer session can have started: its install line would be in that
			// file or a newer one, and findWindowSession reads them all. So the saved session holds
			// from that checkpoint. Otherwise nothing can be attributed: report the loss once.
			const saved = validSession(this.o.session?.get());
			if (!saved || !savedRpc || rotationSlot(rpcLog, savedRpc.ino) === undefined) {
				this.reportLost(rpcLog);
				return false;
			}
			s = { ...saved, ino: savedRpc.ino, pos: savedRpc.pos };
		}
		this.session = s;
		for (const t of this.tails) {
			let saved = this.checkpoint(t.file, t.key);
			if (!saved && t.key.endsWith('#lifecycle')) {
				// Upgrade: the single gate tail delivered both lanes up to its checkpoint, so the
				// lifecycle lane starts there (persisted below, once; CR10-18).
				saved = this.checkpoint(t.file, path.basename(t.file));
			}
			if (t.key === 'seclabRpcFilter.log') {
				t.notBefore = s.time;
				// CR10-4: the checkpoint may be in a newer rotated file than the install line; it
				// is resumed whenever it is at or after the session start in the rotation chain.
				const at = savedRpc ? rotationSlot(rpcLog, savedRpc.ino) : undefined, start = rotationSlot(rpcLog, s.ino);
				const later = savedRpc && at !== undefined && (start === undefined || at < start || (at === start && savedRpc.pos >= s.pos));
				t.resume(later ? savedRpc : { ino: s.ino, pos: s.pos });
			} else {
				t.notBefore = Math.max(s.time - GATE_GRACE_MS, s.prevLast !== undefined ? s.prevLast + 1 : -Infinity);
				if (saved) {
					t.resume(saved);
				} else {
					// No usable checkpoint (a new window, an upgrade whose file rotated away): read
					// every file still on disk, oldest first; `notBefore` keeps other sessions' lines
					// out, so none of this session's is skipped (CR10-22).
					t.startAtOldest();
				}
			}
			// Every tail starts from a saved point (CR10-19): one that has none yet, whose first
			// events are then deferred, would otherwise start at the current file after a rotation
			// and a restart. Not while a loss is still to be reported, so a restart reports it again.
			const at = t.anchor();
			if (at) {
				this.o.state?.set(t.key, { ...at, dir: this.o.dir });
			}
		}
		return true;
	}

	/**
	 * A saved checkpoint, only if it belongs to this window's log folder (CR10-15): a new
	 * window logs to a new folder, so another folder's checkpoint is no one's loss. One saved
	 * before checkpoints carried their folder counts if its file is in this rotation chain.
	 */
	private checkpoint(file: string, key: string): { ino: number; pos: number } | undefined {
		const p = validPosition(this.o.state?.get(key));
		if (!p) {
			return undefined;
		}
		const ours = p.dir !== undefined ? p.dir === this.o.dir : rotationSlot(file, p.ino) !== undefined;
		return ours ? { ino: p.ino, pos: p.pos } : undefined;
	}

	/** The RPC log has lines but no session can be bound: its `skipped` marker, once (CR10-3). */
	private reportLost(rpcLog: string): void {
		if (this.lostReported || !(statOrUndefined(rpcLog)?.size)) {
			return;
		}
		this.lostReported = true;
		// Sent again later if tabd is away or defers it (CR10-7).
		void this.o.report([WINDOW_LOGS.get('seclabRpcFilter.log')!.skipped], { retry: true }).then(r => {
			if (limitedIndices(r, 1).length) {
				this.lostReported = false;
			}
		}, () => {
			this.lostReported = false;
		});
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
		if (!this.bindSession()) {
			return;
		}
		// Each tail on its own: a report outstanding for one (a deferred denial batch) never holds
		// up another's reads or reports, so a `verified` is never stuck behind it (CR10-26).
		await Promise.all(this.tails.map(async t => {
			if (this.inflight.has(t)) {
				return;
			}
			this.inflight.add(t);
			try {
				await this.drain(t);
			} catch {
				// tabd unavailable: the backlog is kept and retried on the next round.
			} finally {
				this.inflight.delete(t);
			}
		}));
	}

	private async drain(t: WindowLogTail): Promise<void> {
		let pending = this.backlog.get(t) ?? [];
		if (!pending.length) {
			pending = t.pollAt();
			this.backlog.set(t, pending);
		}
		// In order, a bounded number of batches per round. With `retry`, tabd accepts an exact
		// prefix and defers the rest (CR10-9): the deferred events stay at the head and the round
		// ends (CR10-5). The checkpoint moves to the end of the last delivered line, so a restart
		// never replays what tabd acknowledged (CR10-11). Without `retry` (AHP lifecycle) nothing
		// is deferred: what tabd's bucket can't take it drops and summarises.
		let delivered: { ino: number; pos: number } | undefined;
		try {
			for (let n = 0; pending.length && n < BATCHES_PER_TICK; n++) {
				const batch = pending.slice(0, 64);
				const r = await this.o.report(batch.map(x => x.ev), { retry: t.retry });
				const limited = t.retry ? limitedIndices(r, batch.length) : [];
				const k = limited.length ? limited[0] : batch.length;
				for (let j = 0; j < k; j++) {
					delivered = batch[j].end ?? delivered;
				}
				pending = pending.slice(k);
				// Saved as soon as tabd has acknowledged it, before the next report (CR10-24).
				if (k > 0 && delivered) {
					this.o.state?.set(t.key, { ...delivered, dir: this.o.dir });
				}
				if (limited.length) {
					break;
				}
			}
		} finally {
			this.backlog.set(t, pending);
			// The read position is undefined while an oversized line is being skipped: then the
			// end of the last delivered line still stands (CR10-23).
			const p = pending.length ? delivered : t.position() ?? delivered;
			if (p) {
				this.o.state?.set(t.key, { ...p, dir: this.o.dir });
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
