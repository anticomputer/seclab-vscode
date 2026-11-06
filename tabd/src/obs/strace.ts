// Strict, bounded parser for strace 6.x output (`-f -ttt -q -s 256 -e signal=none`), and a
// process tracker that turns syscall records into observability event drafts.
// Input is tab-derived (the collector is root in the tab's VM, but the VM is the tab):
// every limit here is a security property. Nothing parsed here drives a host action.

import type { EventDraft, Priority, ProcInfo } from './schema.ts';

export const MAX_LINE = 64 * 1024;
const MAX_DEPTH = 8;
const MAX_TOKENS = 4096;
const MAX_PIDS = 4096;
const MAX_PENDING = 1024;
const MAX_DEFERRED = 256;

export type Arg =
	| { t: 'str'; v: string; trunc: boolean }
	| { t: 'arr'; v: Arg[] }
	| { t: 'obj'; v: Array<[string | null, Arg]> }
	| { t: 'call'; name: string; v: Arg[] }
	| { t: 'raw'; v: string };

export type StraceRecord =
	| { kind: 'syscall'; pid: number; ts: number; name: string; args: Arg[]; ret: string; errno?: string }
	| { kind: 'exit'; pid: number; ts: number; code?: number; signal?: string };

class ParseError extends Error { }

/** Decode a strace-escaped string body (between the quotes) to text. */
export function unescapeStrace(body: string): string {
	const bytes: number[] = [];
	for (let i = 0; i < body.length; i++) {
		const c = body.charCodeAt(i);
		if (c !== 0x5c) {
			// strace prints printable ASCII literally; anything else is escaped.
			if (c > 0x7e || c < 0x20) {
				throw new ParseError('unescaped non-printable');
			}
			bytes.push(c);
			continue;
		}
		const n = body[++i];
		switch (n) {
			case 'n': bytes.push(10); break;
			case 't': bytes.push(9); break;
			case 'r': bytes.push(13); break;
			case 'v': bytes.push(11); break;
			case 'f': bytes.push(12); break;
			case '\\': bytes.push(0x5c); break;
			case '"': bytes.push(0x22); break;
			case 'x': {
				const h = body.slice(i + 1, i + 3);
				if (!/^[0-9a-fA-F]{2}$/.test(h)) {
					throw new ParseError('bad \\x escape');
				}
				bytes.push(parseInt(h, 16));
				i += 2;
				break;
			}
			default: {
				const m = /^[0-7]{1,3}/.exec(body.slice(i, i + 3));
				if (!m) {
					throw new ParseError('bad escape');
				}
				bytes.push(parseInt(m[0], 8) & 0xff);
				i += m[0].length - 1;
			}
		}
	}
	return Buffer.from(bytes).toString('utf8');
}

class ArgParser {
	private i = 0;
	private tokens = 0;
	private readonly s: string;
	constructor(s: string) {
		this.s = s;
	}

	get pos() { return this.i; }

	private ws() {
		for (;;) {
			while (this.s[this.i] === ' ') {
				this.i++;
			}
			if (this.s.startsWith('/*', this.i)) {
				const end = this.s.indexOf('*/', this.i + 2);
				if (end < 0) {
					throw new ParseError('unterminated comment');
				}
				this.i = end + 2;
				continue;
			}
			return;
		}
	}

	/** Parse a comma-separated list until `close`; consumes `close`. */
	list(close: string, depth: number, keyed: boolean): Array<[string | null, Arg]> {
		if (depth > MAX_DEPTH) {
			throw new ParseError('too deep');
		}
		const out: Array<[string | null, Arg]> = [];
		this.ws();
		if (this.s[this.i] === close) {
			this.i++;
			return out;
		}
		for (;;) {
			if (++this.tokens > MAX_TOKENS) {
				throw new ParseError('too many tokens');
			}
			this.ws();
			let key: string | null = null;
			if (keyed) {
				const m = /^([a-zA-Z_][a-zA-Z0-9_.]*)=/.exec(this.s.slice(this.i, this.i + 64));
				if (m) {
					key = m[1];
					this.i += m[0].length;
				}
			}
			out.push([key, this.value(depth)]);
			this.ws();
			const c = this.s[this.i];
			if (c === ',') {
				this.i++;
				continue;
			}
			if (c === close) {
				this.i++;
				return out;
			}
			throw new ParseError(`unexpected ${JSON.stringify(c ?? 'EOL')}`);
		}
	}

	value(depth: number): Arg {
		this.ws();
		const c = this.s[this.i];
		if (c === '"') {
			let j = this.i + 1;
			while (j < this.s.length && this.s[j] !== '"') {
				j += this.s[j] === '\\' ? 2 : 1;
			}
			if (j >= this.s.length) {
				throw new ParseError('unterminated string');
			}
			const v = unescapeStrace(this.s.slice(this.i + 1, j));
			this.i = j + 1;
			const trunc = this.s.startsWith('...', this.i);
			if (trunc) {
				this.i += 3;
			}
			return { t: 'str', v, trunc };
		}
		if (c === '[') {
			this.i++;
			return { t: 'arr', v: this.list(']', depth + 1, false).map(([, a]) => a) };
		}
		if (c === '{') {
			this.i++;
			return { t: 'obj', v: this.list('}', depth + 1, true) };
		}
		// Bare word, number, flags (A|B), pointer, `...`, or a call like htons(80).
		const m = /^[^,()[\]{}"]+/.exec(this.s.slice(this.i, this.i + 4096));
		if (!m) {
			throw new ParseError(`unexpected ${JSON.stringify(c ?? 'EOL')}`);
		}
		this.i += m[0].length;
		const word = m[0].trim();
		if (this.s[this.i] === '(' && /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(word)) {
			this.i++;
			return { t: 'call', name: word, v: this.list(')', depth + 1, false).map(([, a]) => a) };
		}
		return { t: 'raw', v: word };
	}

	rest(): string {
		return this.s.slice(this.i);
	}
}

const HEAD = /^(\d{1,10}) +(\d{1,12}\.\d{1,9}) +/;

/**
 * Parses one strace line. Lines split by `<unfinished ...>` are stitched per pid. Returns
 * undefined for lines that carry nothing we use; throws on malformed input.
 */
export class StraceParser {
	private readonly pending = new Map<number, string>();

	parse(line: string): StraceRecord | undefined {
		if (line.length > MAX_LINE) {
			throw new ParseError('line too long');
		}
		const h = HEAD.exec(line);
		if (!h) {
			throw new ParseError('no pid/timestamp');
		}
		const pid = Number(h[1]);
		const ts = Number(h[2]);
		let body = line.slice(h[0].length);
		const ex = /^\+\+\+ (?:exited with (\d{1,3})|killed by (SIG[A-Z0-9]{1,12})(?: \(core dumped\))?) \+\+\+$/.exec(body);
		if (ex) {
			this.pending.delete(pid);
			return ex[1] !== undefined ? { kind: 'exit', pid, ts, code: Number(ex[1]) } : { kind: 'exit', pid, ts, signal: ex[2] };
		}
		if (body.startsWith('---')) {
			return undefined; // signal delivery (normally suppressed)
		}
		if (body.endsWith(' <unfinished ...>')) {
			if (this.pending.size >= MAX_PENDING && !this.pending.has(pid)) {
				throw new ParseError('too many unfinished syscalls');
			}
			this.pending.set(pid, body.slice(0, -' <unfinished ...>'.length));
			return undefined;
		}
		const res = /^<\.\.\. ([a-z0-9_]{1,32}) resumed>/.exec(body);
		if (res) {
			const head = this.pending.get(pid);
			this.pending.delete(pid);
			if (head === undefined || !head.startsWith(`${res[1]}(`)) {
				return undefined; // resumed without (or with another) head: attach race; skip
			}
			body = head + body.slice(res[0].length);
		}
		const nm = /^([a-z0-9_]{1,32})\(/.exec(body);
		if (!nm) {
			throw new ParseError('no syscall');
		}
		const p = new ArgParser(body.slice(nm[0].length));
		const args = p.list(')', 0, true).map(([k, a]) => (k ? { t: 'obj', v: [[k, a]] } as Arg : a));
		const r = / += +(-?\d+|\?|0x[0-9a-f]+)(?: ([A-Z][A-Z0-9_]{1,31}))?(?: \(.*\))?(?: <[a-z ]+>)?$/.exec(p.rest());
		if (!r) {
			throw new ParseError('no return value');
		}
		return { kind: 'syscall', pid, ts, name: nm[1], args, ret: r[1], errno: r[2] };
	}
}

// ---- process tracking and event drafts ------------------------------------------------

interface Proc { ppid?: number; uid?: number; exe?: string; argv?: string[]; cwd?: string; exited?: boolean; seen: number }

const str = (a: Arg | undefined): string | undefined => (a?.t === 'str' ? a.v : undefined);
const raw = (a: Arg | undefined): string | undefined => (a?.t === 'raw' ? a.v : undefined);
function field(a: Arg | undefined, key: string): Arg | undefined {
	return a?.t === 'obj' ? a.v.find(([k]) => k === key)?.[1] : undefined;
}

const NETWORK_TOOLS = /^(?:curl|wget|nc|ncat|netcat|socat|telnet|ssh|scp|sftp|ftp|tftp|openssl|dig|nslookup|host)$/;
const SENSITIVE_CALLS = new Set(['mount', 'umount2', 'unshare', 'setns', 'bpf', 'memfd_create', 'init_module', 'finit_module', 'pivot_root', 'chroot', 'perf_event_open', 'keyctl', 'add_key']);
const PRIV_CALLS = new Set(['setuid', 'setgid', 'setreuid', 'setregid', 'setresuid', 'setresgid', 'setfsuid', 'setfsgid', 'capset']);

export interface TrackerOptions {
	/** The collector's own pids: signals and ptrace aimed at them are tampering. */
	readonly collectorPids?: () => ReadonlySet<number>;
	/** Paths whose opens are always reported (credential-like), even outside deep mode. */
	readonly sensitivePath?: (p: string) => boolean;
}

export class StraceTracker {
	private readonly procs = new Map<number, Proc>();
	private readonly o: TrackerOptions;
	private tick = 0;
	private deferred: Array<{ pid: number; ts: number; draft: Omit<EventDraft, 'source' | 'integrity' | 'proc'>; snapshot: { exe?: string; argv?: string[] } }> = [];
	/** Socket type per (pid, fd) from socket(): tells a TCP connect from a UDP routability probe. */
	private readonly sockets = new Map<string, 'tcp' | 'udp'>();

	constructor(o: TrackerOptions = {}) {
		this.o = o;
	}

	/** Release exec events still waiting for their parent, if older than `maxAgeS` (strace clock). */
	flush(nowTs: number, maxAgeS = 0.1): Array<Omit<EventDraft, 'source' | 'integrity'>> {
		return this.release(d => nowTs - d.ts >= maxAgeS);
	}

	private release(pick: (d: { pid: number; ts: number }) => boolean): Array<Omit<EventDraft, 'source' | 'integrity'>> {
		const out: Array<Omit<EventDraft, 'source' | 'integrity'>> = [];
		this.deferred = this.deferred.filter(d => {
			if (!pick(d)) {
				return true;
			}
			// The process may have exec'd again since; report what it ran at the time.
			const proc = { ...this.proc(d.pid), ...d.snapshot };
			const summary = d.draft.class === 'net.connect' ? `${d.draft.summary} by ${base(proc.exe ?? String(d.pid))}` : d.draft.summary;
			out.push({ ...d.draft, summary, proc });
			return false;
		});
		return out;
	}

	/** Seed what the collector read from /proc for processes it attached to. */
	seed(pid: number, info: { ppid?: number; uid?: number; exe?: string; argv?: string[]; cwd?: string }): void {
		this.put(pid, { ...info, seen: ++this.tick });
	}

	proc(pid: number): ProcInfo {
		const p = this.procs.get(pid);
		const out: ProcInfo = { pid };
		if (p?.ppid !== undefined) {
			out.ppid = p.ppid;
		}
		if (p?.uid !== undefined) {
			out.uid = p.uid;
		}
		if (p?.exe) {
			out.exe = p.exe;
		}
		if (p?.argv) {
			out.argv = p.argv;
		}
		const lineage: Array<{ pid: number; exe: string }> = [];
		let cur = p?.ppid;
		const seen = new Set<number>([pid]);
		while (cur !== undefined && cur > 0 && lineage.length < 8 && !seen.has(cur)) {
			seen.add(cur);
			const pp = this.procs.get(cur);
			lineage.push({ pid: cur, exe: pp?.argv ? summarizeArgv(pp.argv, 96) : pp?.exe ?? '?' });
			cur = pp?.ppid;
		}
		if (lineage.length) {
			out.lineage = lineage;
		}
		return out;
	}

	/** Ancestor argv lists, nearest first (for detection rules). */
	ancestors(pid: number, max = 8): Array<{ pid: number; exe?: string; argv?: string[] }> {
		const out: Array<{ pid: number; exe?: string; argv?: string[] }> = [];
		let cur = this.procs.get(pid)?.ppid;
		const seen = new Set<number>([pid]);
		while (cur !== undefined && cur > 0 && out.length < max && !seen.has(cur)) {
			seen.add(cur);
			const p = this.procs.get(cur);
			out.push({ pid: cur, exe: p?.exe, argv: p?.argv });
			cur = p?.ppid;
		}
		return out;
	}

	private put(pid: number, p: Proc): void {
		if (!this.procs.has(pid) && this.procs.size >= MAX_PIDS) {
			// Evict the oldest exited process, else the oldest overall.
			let victim: number | undefined, oldest = Infinity;
			for (const [k, v] of this.procs) {
				const score = v.seen - (v.exited ? 1e12 : 0);
				if (score < oldest) {
					oldest = score;
					victim = k;
				}
			}
			if (victim !== undefined) {
				this.procs.delete(victim);
			}
		}
		this.procs.set(pid, { ...this.procs.get(pid), ...p });
	}

	private get(pid: number): Proc {
		let p = this.procs.get(pid);
		if (!p) {
			this.put(pid, { seen: ++this.tick });
			p = this.procs.get(pid)!;
		}
		return p;
	}

	/** An exec whose strace record exceeded the line cap: report the program, flag the argv. */
	truncatedExec(pid: number, path: string): Array<Omit<EventDraft, 'source' | 'integrity'>> {
		const p = this.get(pid);
		p.exe = path;
		p.argv = [path, '[argv not recorded: oversized]'];
		return [{
			class: 'process.exec', priority: 'warning', proc: this.proc(pid),
			summary: `exec ${path} with an oversized argument list (not recorded)`, detail: { truncated: true },
		}];
	}

	/** Turn one record into zero or more drafts (integrity/source filled by the caller). */
	handle(r: StraceRecord): Array<Omit<EventDraft, 'source' | 'integrity'>> {
		if (r.kind === 'exit') {
			const p = this.get(r.pid);
			p.exited = true;
			return [{
				class: 'process.exit', priority: 'debug', proc: this.proc(r.pid),
				summary: `exit ${p.exe ? base(p.exe) : r.pid} ${r.signal ? `killed by ${r.signal}` : `code ${r.code}`}`,
				detail: r.signal ? { signal: r.signal } : { code: r.code ?? 0 },
				sensorTime: isoFromEpoch(r.ts),
			}];
		}
		const ok = r.ret !== '?' && !r.ret.startsWith('-');
		const sensorTime = isoFromEpoch(r.ts);
		const a = r.args;
		const proc = () => this.proc(r.pid);
		const result = ok ? 'ok' : (r.errno ?? r.ret);
		switch (r.name) {
			case 'clone': case 'clone3': case 'fork': case 'vfork': {
				const child = Number(r.ret);
				if (ok && Number.isInteger(child) && child > 0) {
					const parent = this.get(r.pid);
					const known = this.procs.get(child);
					// The child's own lines can precede this one: never overwrite what it did itself.
					this.put(child, known && !known.exited
						? { ppid: r.pid, uid: known.uid ?? parent.uid, cwd: known.cwd ?? parent.cwd, seen: known.seen }
						: { ppid: r.pid, uid: parent.uid, exe: parent.exe, argv: parent.argv, cwd: parent.cwd, exited: false, seen: ++this.tick });
					return this.release(d => d.pid === child);
				}
				return [];
			}
			case 'chdir': {
				const path = str(a[0]);
				if (ok && path !== undefined) {
					const p = this.get(r.pid);
					p.cwd = path.startsWith('/') ? path : p.cwd ? `${p.cwd.replace(/\/$/, '')}/${path}` : undefined;
				}
				return [];
			}
			case 'execve': case 'execveat': {
				const path = str(r.name === 'execve' ? a[0] : a[1]);
				const argvArg = r.name === 'execve' ? a[1] : a[2];
				const argv = argvArg?.t === 'arr' ? argvArg.v.map(x => (x.t === 'str' ? x.v : x.t === 'raw' ? x.v : '?')) : [];
				if (!ok) {
					// PATH lookups fail with ENOENT all the time; only report real refusals.
					if (r.errno === 'ENOENT' || r.errno === 'ENOTDIR') {
						return [];
					}
					return [{ class: 'process.exec', priority: 'notice', proc: { ...proc(), exe: path, argv }, summary: `exec ${path ?? '?'} refused (${result})`, detail: { result }, sensorTime }];
				}
				const p = this.get(r.pid);
				p.exe = path;
				p.argv = argv;
				const name = base(path ?? argv[0] ?? '?');
				const draft = {
					class: 'process.exec', priority: NETWORK_TOOLS.test(name) ? 'notice' : 'informational',
					summary: `exec ${summarizeArgv(argv.length ? argv : [path ?? '?'], 200)}`, sensorTime,
				} as const;
				if (p.ppid === undefined && this.deferred.length < MAX_DEFERRED) {
					// Parent's clone() line not seen yet: wait briefly so lineage is complete.
					this.deferred.push({ pid: r.pid, ts: r.ts, draft, snapshot: { exe: p.exe, argv: p.argv } });
					return [];
				}
				return [{ ...draft, proc: proc() }];
			}
			case 'socket': {
				const fd = Number(r.ret);
				const type = raw(a[1]) ?? '';
				if (ok && Number.isInteger(fd) && fd >= 0) {
					const kind = /\bSOCK_STREAM\b/.test(type) ? 'tcp' : /\bSOCK_DGRAM\b/.test(type) ? 'udp' : undefined;
					const key = `${r.pid}:${fd}`;
					this.sockets.delete(key);
					if (kind) {
						if (this.sockets.size >= MAX_PIDS * 4) {
							this.sockets.delete(this.sockets.keys().next().value!);
						}
						this.sockets.set(key, kind);
					}
				}
				return [];
			}
			case 'connect': {
				const sa = a[1];
				const proto = this.sockets.get(`${r.pid}:${Number(raw(a[0]))}`);
				const fam = raw(field(sa, 'sa_family'));
				let addr: string | undefined, port: number | undefined, family: 'inet' | 'inet6' | 'unix' | 'other' = 'other';
				if (fam === 'AF_INET') {
					family = 'inet';
					const ia = field(sa, 'sin_addr');
					addr = ia?.t === 'call' ? str(ia.v[0]) : undefined;
					port = callNum(field(sa, 'sin_port'));
				} else if (fam === 'AF_INET6') {
					family = 'inet6';
					const pton = sa?.t === 'obj' ? sa.v.find(([k, v]) => k === null && v.t === 'call' && v.name === 'inet_pton')?.[1] : undefined;
					addr = pton?.t === 'call' ? str(pton.v[1]) : undefined;
					port = callNum(field(sa, 'sin6_port'));
				} else if (fam === 'AF_UNIX') {
					family = 'unix';
					addr = str(field(sa, 'sun_path')) ?? '(abstract)';
				} else {
					return [];
				}
				const pending = r.errno === 'EINPROGRESS';
				const res = ok ? 'ok' : pending ? 'pending' : result;
				let priority: Priority = family === 'unix' ? 'debug' : 'informational';
				if (family === 'unix' && /docker\.sock|containerd|podman/.test(addr ?? '')) {
					priority = 'warning';
				}
				const net = { addr: addr ?? '?', port, family, result: res, ...(proto && family !== 'unix' ? { proto } : {}) };
				if (this.procs.get(r.pid)?.ppid === undefined && this.deferred.length < MAX_DEFERRED) {
					// A new thread or child whose clone() line isn't in yet (e.g. a resolver thread):
					// wait briefly so the connect carries the process and its lineage.
					this.deferred.push({ pid: r.pid, ts: r.ts, draft: { class: 'net.connect', priority, net, summary: `connect ${family === 'unix' ? addr : `${addr}:${port}`} ${res}`, sensorTime }, snapshot: {} });
					return [];
				}
				return [{
					class: 'net.connect', priority, proc: proc(), net,
					summary: `connect ${family === 'unix' ? addr : `${addr}:${port}`} ${res} by ${base(this.get(r.pid).exe ?? String(r.pid))}`, sensorTime,
				}];
			}
			case 'openat': case 'openat2': {
				const path = this.abs(r.pid, str(a[1]));
				if (path === undefined) {
					return [];
				}
				const flags = r.name === 'openat' ? raw(a[2]) ?? '' : raw(field(a[2], 'flags')) ?? '';
				const write = /O_WRONLY|O_RDWR|O_CREAT|O_TRUNC/.test(flags);
				const sensitive = this.o.sensitivePath?.(path) ?? false;
				if (!ok && !sensitive) {
					return [];
				}
				return [{
					class: write ? 'file.write' : 'file.open', priority: sensitive ? 'warning' : 'debug', proc: proc(),
					file: { path, op: write ? 'write' : 'read' }, detail: { flags: flags.slice(0, 128), result },
					summary: `${write ? 'write' : 'open'} ${path}${ok ? '' : ` (${result})`}`, sensorTime,
				}];
			}
			case 'unlinkat': case 'unlink': case 'rmdir': {
				const path = this.abs(r.pid, str(r.name === 'unlinkat' ? a[1] : a[0]));
				if (path === undefined || !ok) {
					return [];
				}
				return [{ class: 'file.delete', priority: 'informational', proc: proc(), file: { path, op: 'delete' }, summary: `delete ${path}`, sensorTime }];
			}
			case 'renameat': case 'renameat2': case 'rename': case 'linkat': case 'link': case 'symlinkat': case 'symlink': {
				let from: string | undefined, to: string | undefined;
				if (r.name === 'rename' || r.name === 'link') {
					[from, to] = [this.abs(r.pid, str(a[0])), this.abs(r.pid, str(a[1]))];
				} else if (r.name === 'symlink') {
					[from, to] = [str(a[0]), this.abs(r.pid, str(a[1]))];
				} else if (r.name === 'symlinkat') {
					[from, to] = [str(a[0]), this.abs(r.pid, str(a[2]))];
				} else {
					[from, to] = [this.abs(r.pid, str(a[1])), this.abs(r.pid, str(a[3]))];
				}
				if (to === undefined || !ok) {
					return [];
				}
				const op = r.name.startsWith('rename') ? 'rename' : r.name.startsWith('sym') ? 'symlink' : 'link';
				return [{ class: 'file.rename', priority: 'informational', proc: proc(), file: { path: to, op }, detail: { from: from ?? '?' }, summary: `${op} ${from ?? '?'} -> ${to}`, sensorTime }];
			}
			case 'fchmodat': case 'fchmodat2': case 'chmod': {
				const path = this.abs(r.pid, str(r.name === 'chmod' ? a[0] : a[1]));
				const mode = raw(r.name === 'chmod' ? a[1] : a[2]) ?? '';
				if (path === undefined || !ok) {
					return [];
				}
				const exec = /^0?[0-7]*[1357][0-7]{0,2}$/.test(mode) && (parseInt(mode, 8) & 0o111) !== 0;
				return [{ class: 'file.chmod', priority: exec ? 'notice' : 'debug', proc: proc(), file: { path, op: 'chmod' }, detail: { mode: mode.slice(0, 16), executable: exec }, summary: `chmod ${mode} ${path}`, sensorTime }];
			}
			case 'ptrace': {
				const req = raw(a[0]) ?? '?';
				const target = Number(raw(a[1]));
				if (req === 'PTRACE_TRACEME') {
					return [{ class: 'proc.ptrace', priority: 'notice', proc: proc(), detail: { request: req, result }, summary: `ptrace TRACEME (${result})`, sensorTime }];
				}
				if (!/^PTRACE_(ATTACH|SEIZE)$/.test(req)) {
					return [];
				}
				const tamper = this.o.collectorPids?.().has(target) ?? false;
				return [{
					class: 'proc.ptrace', priority: tamper ? 'critical' : 'warning', proc: proc(),
					detail: { request: req, target: Number.isInteger(target) ? target : -1, result, tamper },
					summary: `${req} pid ${target} (${result})${tamper ? ' targeting the sensor' : ''}`, sensorTime,
				}];
			}
			case 'kill': case 'tkill': case 'tgkill': {
				const target = Number(raw(a[0]));
				const sig = raw(r.name === 'tgkill' ? a[2] : a[1]) ?? '?';
				if (sig === '0' || target === r.pid) {
					return [];
				}
				// PID 1 broadcasting TERM (-1) is the sandbox shutting down, not tampering.
				const tamper = (this.o.collectorPids?.().has(target) ?? false) || ((target === 1 || target === -1) && r.pid !== 1);
				const priority: Priority = tamper ? 'critical' : r.errno === 'EPERM' ? 'warning' : 'debug';
				return [{
					class: 'proc.signal', priority, proc: proc(), detail: { target: Number.isInteger(target) ? target : 0, signal: sig.slice(0, 16), result, tamper },
					summary: `${sig} to pid ${target} (${result})${tamper ? ' targeting the sensor or init' : ''}`, sensorTime,
				}];
			}
			default:
				if (PRIV_CALLS.has(r.name)) {
					const toRoot = a.some(x => raw(x) === '0');
					return [{
						class: 'priv.change', priority: toRoot && ok ? 'critical' : toRoot ? 'warning' : 'notice', proc: proc(),
						detail: { call: r.name, args: a.map(x => raw(x) ?? '?').join(',').slice(0, 64), result },
						summary: `${r.name}(${a.map(x => raw(x) ?? '?').join(', ').slice(0, 64)}) ${result}`, sensorTime,
					}];
				}
				if (SENSITIVE_CALLS.has(r.name)) {
					const first = a[0];
					const what = first?.t === 'str' ? first.v : first?.t === 'raw' ? first.v : '';
					return [{
						class: 'proc.sensitive', priority: 'warning', proc: proc(),
						detail: { call: r.name, arg: what.slice(0, 128), result },
						summary: `${r.name}(${what.slice(0, 80)}) ${result}`, sensorTime,
					}];
				}
				return [];
		}
	}

	private abs(pid: number, p: string | undefined): string | undefined {
		if (p === undefined) {
			return undefined;
		}
		if (p.startsWith('/')) {
			return p;
		}
		const cwd = this.procs.get(pid)?.cwd;
		return cwd ? `${cwd.replace(/\/$/, '')}/${p}` : p;
	}
}

function callNum(a: Arg | undefined): number | undefined {
	if (a?.t !== 'call') {
		return undefined;
	}
	const n = Number(raw(a.v[0]));
	return Number.isInteger(n) && n >= 0 && n <= 65535 ? n : undefined;
}

function base(p: string): string {
	return p.slice(p.lastIndexOf('/') + 1) || p;
}

export function summarizeArgv(argv: readonly string[], max: number): string {
	const s = argv.map(a => (/^[\w./:=@%+,-]+$/.test(a) ? a : JSON.stringify(a))).join(' ');
	return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

function isoFromEpoch(ts: number): string | undefined {
	const d = new Date(ts * 1000);
	return Number.isFinite(d.getTime()) ? d.toISOString() : undefined;
}
