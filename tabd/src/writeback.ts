// Write-back gate engine (ADR 20261104-write-back-gate). The only writer of a tab's changes
// to the host checkout. Input: changes the driver reads from the tab's overlay upper layer:
// attacker-controlled names, modes, links and content. Output: ordinary files copied back,
// code-running ones held for the user's approval. Fails closed: held state lives in the
// tab's upper layer plus this engine's state file; nothing held is ever applied implicitly.
//
// Host writes: every path component is lstat'ed (never followed) from the workspace root
// tabd pinned at claim (dev/ino re-checked); a symlink or non-directory component refuses
// the write; files go to an exclusively created temp file (O_NOFOLLOW) whose directory is
// re-verified against the walked one, then fsync and rename. The attacker controls only
// the tab's upper layer, never host directories; the residual race needs a host tool to
// swap a directory for a link mid-write (review W-10), narrowed by that re-verification.

import { createHash, randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { hostGitIgnored } from './gitignore.ts';
import { WRITEBACK_POLICY } from './writeback-policy.ts';

export type UpperKind = 'file' | 'deleted' | 'symlink' | 'special' | 'dir';
/** One change in the tab's upper layer, as reported by the driver. Untrusted. */
export interface UpperChange {
	path: string;
	kind: UpperKind;
	mode?: number;
	nlink?: number;
	content?: Buffer;
	target?: string;
}
export type PendingKind = 'new' | 'modified' | 'deleted' | 'mode' | 'link' | 'special' | 'conflict';
export interface PendingChange {
	path: string;
	kind: PendingKind;
	reasons: string[];
	/** Binding of what was shown: kind, mode, link target and content (review W-3). */
	sig: string;
	/** sha256 of the host file when held ('absent' if none). */
	hostHash: string;
	size?: number;
	mode?: number;
	target?: string;
}
export interface SyncResult {
	applied: string[];
	held: PendingChange[];
	refused: Array<{ path: string; reason: string }>;
}
interface State {
	version: 2;
	pending: PendingChange[];
	/** Host stat signature the tab's view is based on, keyed by folded path (W-4). */
	baseline: Record<string, string>;
	/** Baseline seeded from a full walk at start (missing key = absent then). */
	seeded: boolean;
	/** "Always allow for this tab and path" rules (exact paths, safe kinds only). */
	always: string[];
	/** Upper entries already synced (applied or decided), by path: their signature (2b). */
	synced?: Record<string, string>;
}

export class WriteBackError extends Error {}

const sha = (b: Buffer) => createHash('sha256').update(b).digest('hex');
/** Binding of an upper entry: kind, mode, link target, content hash, link count (review W-3). */
export function metaSig(m: { kind: string; mode?: number; target?: string; sha?: string; nlink?: number }): string {
	return sha(Buffer.from(JSON.stringify({ k: m.kind, m: (m.mode ?? 0) & 0o7777, t: m.target ?? null, c: m.kind === 'file' ? m.sha ?? null : null, n: m.nlink ?? 1 })));
}
/** Default-ignorable and bidi code points (HFS+ ignores some in names: CVE-2014-9390). */
const IGNORABLE = /[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u202a-\u202e\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\u{1bca0}-\u{1bca3}\u{1d173}-\u{1d17a}\u{e0000}-\u{e0fff}]/gu;
const STRUCTURAL = ['symlink', 'special file', 'directory change', 'hardlink', 'larger than the per-file cap', 'newly executable', 'host file is executable', 'invisible characters in name', 'native code module'];
/** Loaded by dlopen without +x, and found before .py by Python's import system (review Z-1). */
const NATIVE = /\.(?:so(?:\.\d+)*|dylib|bundle|node|pyd|dll|exe)$/;

/** Workspace-relative, '/'-separated, no empty/./.. segments, no NUL, bounded. */
export function checkRel(p: unknown): string {
	if (typeof p !== 'string' || p.length === 0 || p.length > 4096 || p.includes('\0') || p.startsWith('/') || /^[A-Za-z]:/.test(p)) {
		throw new WriteBackError('invalid path');
	}
	for (const seg of p.split('/')) {
		if (seg === '' || seg === '.' || seg === '..' || Buffer.byteLength(seg) > 255) {
			throw new WriteBackError('invalid path');
		}
	}
	return p;
}

/** Minimal glob: `**` = any number of segments, `*` = within one segment. */
export function globMatch(glob: string, p: string): boolean {
	const segs = glob.split('/');
	let re = '';
	segs.forEach((seg, i) => {
		const last = i === segs.length - 1;
		if (seg === '**') {
			re += last ? '.+' : '(?:[^/]+/)*';
		} else {
			re += seg.replace(/[.+^${}()|[\]\\?]/g, '\\$&').replace(/\*/g, '[^/]*') + (last ? '' : '/');
		}
	});
	return new RegExp(`^${re}$`).test(p);
}

/**
 * One name as a case-insensitive, normalising, ignorable-dropping host FS would see it
 * (APFS/HFS+), plus NTFS-style trailing dots/spaces and the GIT~1 short name.
 */
function foldSeg(seg: string, form: 'NFC' | 'NFD' | 'NFKC'): string {
	const s = seg.replace(IGNORABLE, '').normalize(form).toLowerCase().replace(/[. ]+$/, '');
	return s === 'git~1' ? '.git' : s;
}
export function foldPath(p: string, form: 'NFC' | 'NFD' | 'NFKC' = 'NFC'): string {
	return p.split('/').map(s => foldSeg(s, form)).join('/');
}
function foldedForms(p: string): string[] {
	return [...new Set((['NFC', 'NFD', 'NFKC'] as const).map(f => foldPath(p, f)))];
}
/**
 * Policy globs match at any directory depth (review Z-2): agents, editors and build tools are
 * started in subdirectories of a monorepo too, and each reads its own `.github/hooks`,
 * `.claude/`, `Makefile`, … So `a/b/.claude/x` is tested as itself, `b/.claude/x` and `.claude/x`.
 */
function matchesAtAnyDepth(globs: readonly string[], rel: string): boolean {
	for (const f of foldedForms(rel)) {
		const segs = f.split('/');
		for (let i = 0; i < segs.length; i++) {
			const s = segs.slice(i).join('/');
			if (globs.some(g => globMatch(g.toLowerCase(), s))) {
				return true;
			}
		}
	}
	return false;
}

/** A git-config line up to its first unquoted, unescaped `#` or `;`. */
function stripGitComment(l: string): string {
	let q = false;
	for (let i = 0; i < l.length; i++) {
		const ch = l[i];
		if (ch === '\\') {
			i++;
		} else if (ch === '"') {
			q = !q;
		} else if (!q && (ch === '#' || ch === ';')) {
			return l.slice(0, i);
		}
	}
	return l;
}

/**
 * Minimal git-config reader for the keys the gate needs (review Y-5): sections (lowercased,
 * subsection kept as `name"sub"` → `name`), a key on the same line as its `[section]`
 * header, backslash continuation lines, quoted values, and `#`/`;` comments.
 */
export function parseGitConfig(lines: readonly string[]): Array<{ section: string; key: string; value: string }> {
	const out: Array<{ section: string; key: string; value: string }> = [];
	const joined: string[] = [];
	let acc = '';
	for (const l of lines) {
		// Comments (whole-line or inline, unquoted) never continue (Z-3, AA-3); an odd run of
		// trailing backslashes outside a comment does.
		const code = stripGitComment(l);
		const trailing = /(\\*)\s*$/.exec(code)?.[1].length ?? 0;
		if (code.length === l.length && trailing % 2 === 1) {
			acc += l.replace(/\\\s*$/, '');
			continue;
		}
		joined.push(acc + l);
		acc = '';
	}
	if (acc) {
		joined.push(acc);
	}
	let section = '';
	for (let line of joined) {
		const sec = /^\s*\[\s*([A-Za-z0-9.-]+)(?:\s+"(?:[^"\\]|\\.)*")?\s*\]/.exec(line);
		if (sec) {
			section = sec[1].toLowerCase();
			line = line.slice(sec[0].length);
		} else if (/^\s*\[/.test(line)) {
			section = ''; // malformed header: nothing after it belongs to the previous section
			continue;
		}
		const kv = /^\s*([A-Za-z][A-Za-z0-9-]*)\s*(?:=\s*(.*))?$/.exec(line);
		if (!kv || !section) {
			continue;
		}
		const v = (kv[2] ?? '').trim();
		let val = '';
		let q = false;
		for (let i = 0; i < v.length; i++) {
			const ch = v[i];
			if (ch === '"') {
				q = !q;
			} else if (ch === '\\' && i + 1 < v.length) {
				const n = v[++i];
				val += n === 't' ? '\t' : n === 'n' ? '\n' : n === 'b' ? '\b' : n;
			} else if (!q && (ch === '#' || ch === ';')) {
				break;
			} else {
				val += ch;
			}
		}
		out.push({ section, key: kv[1].toLowerCase(), value: val.trim() });
	}
	return out;
}

/** Git index (.git/index): auto only if it parses as v2/v3 and has no gitlink (submodule) entry (W-1). */
export function indexIsSafe(b: Buffer): boolean {
	if (b.length < 12 + 20 || b.toString('latin1', 0, 4) !== 'DIRC') {
		return false;
	}
	const version = b.readUInt32BE(4);
	const count = b.readUInt32BE(8);
	if ((version !== 2 && version !== 3) || count > 5_000_000) {
		return false;
	}
	let off = 12;
	for (let i = 0; i < count; i++) {
		if (off + 62 > b.length) {
			return false;
		}
		const mode = b.readUInt32BE(off + 24);
		if ((mode & 0o170000) === 0o160000) {
			return false; // gitlink
		}
		const flags = b.readUInt16BE(off + 60);
		let hdr = 62;
		if (flags & 0x4000) {
			if (version < 3 || off + 64 > b.length) {
				return false;
			}
			hdr = 64;
		}
		const nul = b.indexOf(0, off + hdr);
		if (nul < 0) {
			return false;
		}
		off += Math.ceil((nul - off + 1) / 8) * 8;
	}
	return off <= b.length;
}

/** True if a JSON object text repeats a top-level key (tools disagree on which wins; W-11). */
export function hasDuplicateTopLevelKeys(text: string): boolean {
	const keys = new Set<string>();
	let depth = 0;
	let expectKey = false;
	for (let i = 0; i < text.length; i++) {
		const ch = text[i];
		if (ch === '"') {
			let j = i + 1;
			let s = '';
			for (; j < text.length && text[j] !== '"'; j++) {
				if (text[j] === '\\') {
					s += text[j] + (text[j + 1] ?? '');
					j++;
				} else {
					s += text[j];
				}
			}
			if (depth === 1 && expectKey) {
				// Compare decoded keys: "scr\u0069pts" is "scripts".
				let key = s;
				try {
					key = JSON.parse(`"${s}"`) as string;
				} catch { /* malformed: JSON.parse of the whole text fails anyway */ }
				if (keys.has(key)) {
					return true;
				}
				keys.add(key);
				expectKey = false;
			}
			i = j;
		} else if (ch === '{' || ch === '[') {
			depth++;
			if (depth === 1 && ch === '{') {
				expectKey = true;
			}
		} else if (ch === '}' || ch === ']') {
			depth--;
		} else if (ch === ',' && depth === 1) {
			expectKey = true;
		}
	}
	return false;
}

export interface EngineOptions {
	/** Canonical workspace root (as claimed). */
	root: string;
	/** Root identity pinned at claim; re-checked before every host write. */
	rootIdentity: { dev: string; ino: string };
	/** tabd state file for this tab's write-back (0600, outside every tab). */
	statePath: string;
	policy?: typeof WRITEBACK_POLICY;
	now?: () => number;
	/** Which paths the host's git ignores (null = unknown → fail closed). Default: hostGitIgnored. */
	ignoredBy?: (root: string, paths: readonly string[]) => Set<string> | null;
}

export class WriteBackEngine {
	private readonly o: EngineOptions;
	private readonly policy: typeof WRITEBACK_POLICY;
	private readonly now: () => number;
	private readonly ignoredBy: (root: string, paths: readonly string[]) => Set<string> | null;
	private state: State;
	private syncTimes: number[] = [];
	private deleteTimes: number[] = [];

	constructor(o: EngineOptions) {
		this.o = o;
		this.policy = o.policy ?? WRITEBACK_POLICY;
		this.now = o.now ?? Date.now;
		this.ignoredBy = o.ignoredBy ?? hostGitIgnored;
		this.state = this.load();
		if (!this.state.seeded) {
			this.seedBaseline();
		}
	}

	/** Pending (held) changes: persisted, re-listed after any restart, never auto-applied. */
	pending(): PendingChange[] {
		return this.state.pending.map(p => ({ ...p, reasons: [...p.reasons] }));
	}

	/** Process one batch from the tab's upper layer. */
	sync(changes: readonly UpperChange[]): SyncResult {
		const res: SyncResult = { applied: [], held: [], refused: [] };
		const t = this.now();
		this.syncTimes = this.syncTimes.filter(x => t - x < 60_000);
		if (this.syncTimes.length >= this.policy.caps.maxSyncsPerMinute) {
			throw new WriteBackError('write-back rate limit reached; retry later');
		}
		this.syncTimes.push(t);
		// Names that collide on a case-insensitive/normalising host are all held (W-4).
		const byFold = new Map<string, number>();
		const batchNames = new Set<string>();
		for (const c of changes) {
			if (typeof c.path === 'string') {
				const f = foldPath(c.path);
				byFold.set(f, (byFold.get(f) ?? 0) + 1);
				batchNames.add(f);
			}
		}
		let files = 0;
		let bytes = 0;
		let deletes = 0;
		// Files the host's git ignores are invisible to review: tab-local unless the policy holds
		// them anyway (then the prompt shows them). Unknown → held (Z-1, fail closed).
		const reviewable = (rel: string) => this.isGitPath(rel) || this.isHeldPath(rel);
		const probe = changes.map(c => c.path).filter((p): p is string => {
			try {
				checkRel(p);
				return !this.isTabLocal(p) && !reviewable(p);
			} catch {
				return false;
			}
		});
		const ignored = this.ignoredBy(this.o.root, probe);
		for (const c of changes) {
			let rel: string;
			try {
				rel = checkRel(c.path);
			} catch (e) {
				res.refused.push({ path: String(c.path).slice(0, 200), reason: (e as Error).message });
				continue;
			}
			if (this.isSynced(rel, this.sig(c))) {
				continue; // unchanged since it was last synced (the upper layer keeps applied entries)
			}
			files++;
			bytes += c.content?.length ?? 0;
			if (this.isTabLocal(rel)) {
				res.refused.push({ path: rel, reason: 'tab-local (generated or installed; never written back)' });
				this.markSynced(rel, c);
				continue;
			}
			if (ignored?.has(rel) && !reviewable(rel)) {
				res.refused.push({ path: rel, reason: 'tab-local (ignored by the host\'s git, so invisible to review)' });
				this.markSynced(rel, c);
				continue;
			}
			const extra: string[] = [];
			if (ignored === null && !reviewable(rel)) {
				extra.push('could not check the host\'s .gitignore');
			}
			if (files > this.policy.caps.maxFilesPerSync || bytes > this.policy.caps.maxBytesPerSync) {
				extra.push('over the per-sync cap (held, not dropped)');
			}
			if ((byFold.get(foldPath(rel)) ?? 0) > 1) {
				extra.push('conflict: names collide on a case-insensitive host');
			}
			if (c.kind === 'deleted') {
				deletes++;
				this.deleteTimes = this.deleteTimes.filter(x => t - x < this.policy.deleteWindowMs);
				if (deletes > this.policy.maxAutoDeletesPerSync || this.deleteTimes.length >= this.policy.maxAutoDeletesPerWindow) {
					extra.push('mass deletion (held beyond the deletion limit)');
				}
			}
			try {
				const out = this.one(rel, c, extra, batchNames);
				if (out === 'applied') {
					res.applied.push(rel);
					this.markSynced(rel, c);
					if (c.kind === 'deleted') {
						this.deleteTimes.push(t);
					}
				} else if (out) {
					res.held.push(out);
				}
			} catch (e) {
				res.refused.push({ path: rel, reason: (e as Error).message });
			}
		}
		this.save();
		return res;
	}

	/**
	 * Apply a held change the user approved. `c` is re-read from the tab and must match what
	 * was shown (kind, mode, link target, content), with no new structural reason (W-3).
	 */
	approve(rel: string, c: UpperChange): void {
		checkRel(rel);
		const p = this.state.pending.find(x => x.path === rel);
		if (!p) {
			throw new WriteBackError('no such pending change');
		}
		if (c.path !== rel || this.sig(c) !== p.sig) {
			throw new WriteBackError('the tab changed this entry since it was shown; review again');
		}
		const now = this.holdReasons(rel, c, this.hostHash(rel), new Set()).filter(r => STRUCTURAL.includes(r));
		const shown = p.reasons.filter(r => STRUCTURAL.includes(r));
		if (now.some(r => !shown.includes(r))) {
			throw new WriteBackError('the entry gained a new risk since it was shown; review again');
		}
		if (this.hostHash(rel) !== p.hostHash) {
			p.kind = 'conflict';
			p.reasons = [...new Set([...p.reasons, 'conflict: the host file changed since it was shown'])];
			this.save();
			throw new WriteBackError('the host file changed since it was shown; review the conflict');
		}
		this.apply(rel, c, true);
		this.markSynced(rel, c);
		this.state.pending = this.state.pending.filter(x => x.path !== rel);
		this.save();
	}

	/** Reject: drop it from pending; returns the host's version for the driver to restore into the tab's view. */
	reject(rel: string): { content: Buffer | null; mode: number } {
		checkRel(rel);
		this.state.pending = this.state.pending.filter(x => x.path !== rel);
		this.save();
		const f = this.resolveOrNull(rel);
		const st = f ? lstatOrNull(f) : null;
		if (!f || !st || !st.isFile()) {
			return { content: null, mode: 0 };
		}
		return { content: fs.readFileSync(f), mode: st.mode & 0o777 };
	}

	/** "Always allow for this tab and path": never for git metadata, hooks, or host-executable files (W-5). */
	alwaysAllow(rel: string): void {
		checkRel(rel);
		if (this.isGitPath(rel) || this.isHookish(rel) || (this.hostMode(rel) & 0o111) || matchesAtAnyDepth(this.policy.neverAlways, rel)) {
			throw new WriteBackError('"always allow" is not available for git metadata, hooks, agent configuration or executable files');
		}
		if (!this.state.always.includes(rel)) {
			this.state.always.push(rel);
			this.save();
		}
	}

	// ---- classification ------------------------------------------------------------------

	private one(rel: string, c: UpperChange, extra: string[], batchNames: Set<string>): 'applied' | PendingChange | undefined {
		const hostHash = this.hostHash(rel);
		const reasons = [...this.holdReasons(rel, c, hostHash, batchNames), ...extra];
		const key = foldPath(rel);
		const sigNow = this.hostSig(rel);
		const base = this.state.baseline[key] ?? (this.state.seeded ? 'absent' : undefined);
		if (base === undefined) {
			this.state.baseline[key] = sigNow;
		} else if (base !== sigNow) {
			reasons.push('conflict: the host file changed since the tab read it');
		}
		if (reasons.length === 0) {
			this.apply(rel, c, false);
			this.state.pending = this.state.pending.filter(x => x.path !== rel);
			return 'applied';
		}
		const kind: PendingKind = reasons.some(r => r.startsWith('conflict')) ? 'conflict'
			: c.kind === 'deleted' ? 'deleted' : c.kind === 'symlink' ? 'link' : c.kind === 'special' || c.kind === 'dir' ? 'special'
				: hostHash === 'absent' ? 'new' : reasons.includes('newly executable') ? 'mode' : 'modified';
		const p: PendingChange = { path: rel, kind, reasons, sig: this.sig(c), hostHash, size: c.content?.length, mode: c.mode, target: c.target?.slice(0, 1024) };
		const prev = this.state.pending.find(x => x.path === rel);
		if (prev && prev.sig === p.sig && prev.hostHash === hostHash) {
			return undefined; // unchanged, already pending
		}
		this.state.pending = [...this.state.pending.filter(x => x.path !== rel), p];
		return p;
	}

	private sig(c: UpperChange): string {
		return metaSig({ kind: c.kind, mode: c.mode, target: c.target, sha: c.kind === 'file' ? sha(c.content ?? Buffer.alloc(0)) : undefined, nlink: c.nlink });
	}

	// ---- incremental feed (increment 2b) ------------------------------------------------------

	/** True if this entry is exactly what was last synced (applied or decided): skip it. */
	isSynced(rel: string, entrySig: string): boolean {
		return this.state.synced?.[rel] === entrySig;
	}

	/**
	 * Host edits to files the tab hasn't touched since they were synced would be shadowed by the
	 * upper copy: return in-place mirror operations (compare-and-swap on the upper sha).
	 */
	mirrorPlan(entries: ReadonlyArray<{ path: string; sha: string; mode: number; nlink: number }>): Array<{ path: string; expect: string; content: Buffer }> {
		const ops: Array<{ path: string; expect: string; content: Buffer }> = [];
		for (const e of entries) {
			if (!this.isSynced(e.path, metaSig({ kind: 'file', mode: e.mode, sha: e.sha, nlink: e.nlink }))) {
				continue;
			}
			try {
				const f = this.resolveOrNull(e.path);
				const st = f ? lstatOrNull(f) : null;
				if (!f || !st?.isFile() || st.size > this.policy.caps.maxFileBytes) {
					continue; // host deleted or replaced it: not mirrored while mounted (EDR)
				}
				const content = fs.readFileSync(f);
				if (sha(content) !== e.sha) {
					ops.push({ path: e.path, expect: e.sha, content });
				}
			} catch { /* unreadable: leave it */ }
		}
		return ops;
	}

	/** A mirror landed: the upper entry now holds the host's content. */
	noteMirrored(rel: string, upperSha: string, mode: number, nlink: number): void {
		checkRel(rel);
		this.state.synced = { ...this.state.synced, [rel]: metaSig({ kind: 'file', mode, sha: upperSha, nlink }) };
		this.state.baseline[foldPath(rel)] = this.hostSig(rel);
		this.save();
	}

	/** Entries no longer in the upper layer (the tab removed a never-applied file): forget them. */
	forgetAbsent(present: ReadonlySet<string>): void {
		const synced = this.state.synced ?? {};
		this.state.synced = Object.fromEntries(Object.entries(synced).filter(([p]) => present.has(p)));
		this.state.pending = this.state.pending.filter(p => present.has(p.path));
		this.save();
	}

	private markSynced(rel: string, c: UpperChange): void {
		this.state.synced = { ...this.state.synced, [rel]: this.sig(c) };
	}

	private holdReasons(rel: string, c: UpperChange, hostHash: string, batchNames: Set<string>): string[] {
		const r: string[] = [];
		if (c.kind === 'symlink') {
			r.push('symlink');
		} else if (c.kind === 'special') {
			r.push('special file');
		} else if (c.kind === 'dir') {
			r.push('directory change');
		}
		if ((c.nlink ?? 1) > 1) {
			r.push('hardlink');
		}
		if (c.kind === 'file' && (c.content?.length ?? 0) > this.policy.caps.maxFileBytes) {
			r.push('larger than the per-file cap');
		}
		const hostMode = this.hostMode(rel);
		if (c.kind === 'file' && ((c.mode ?? 0o644) & 0o111) && !(hostMode & 0o111)) {
			r.push('newly executable');
		}
		if (hostMode & 0o111) {
			r.push('host file is executable'); // its content runs (W-2a)
		}
		if (rel.split('/').some(s => s.replace(IGNORABLE, '') !== s)) {
			r.push('invisible characters in name');
		}
		if (c.kind === 'file' && NATIVE.test(foldPath(rel))) {
			r.push('native code module');
		}
		if (c.kind === 'deleted' && hostHash !== 'absent' && this.hostIsDir(rel)) {
			r.push('directory deletion');
		}
		// Git metadata anywhere (W-1): only the exact root .git auto set passes, and never deletions.
		const gitPath = this.isGitPath(rel);
		if (gitPath) {
			const headOk = rel !== '.git/HEAD' || (c.kind === 'file' && /^(?:ref: refs\/[\x21-\x7e]{1,1024}|[0-9a-f]{40}|[0-9a-f]{64})\n?$/.test((c.content ?? Buffer.alloc(0)).toString('latin1')));
			// Only into an existing host repository: a tab must not create one (2b finding: a
			// `git init` in the tab would otherwise make the host folder a repo).
			const hostRepo = lstatOrNull(path.join(this.o.root, '.git'))?.isDirectory() === true;
			const rootAuto = hostRepo && this.isRootGitAuto(rel) && c.kind !== 'deleted' && headOk; // AA-1: a broken HEAD is held
			const indexOk = hostRepo && rel === '.git/index' && c.kind === 'file' && indexIsSafe(c.content ?? Buffer.alloc(0));
			if (!rootAuto && !indexOk) {
				r.push('git metadata');
			}
		} else if (this.looksLikeGitMeta(rel, c, batchNames)) {
			r.push('looks like git metadata (a gitdir in disguise)');
		}
		// Path-based reasons can be waived per tab and path; the structural ones above never are,
		// and neither are manifest key changes: "always" covers content, not scripts/deps (Y-6).
		if (!this.state.always.includes(rel) && !gitPath && this.isHeldPath(rel)) {
			r.push('runs code (code-running path)');
		}
		for (const [glob, keys] of Object.entries(this.policy.heldWhenKeysChange)) {
			if (foldedForms(rel).some(f => globMatch(glob, f))) {
				r.push(...this.manifestReasons(rel, c, keys));
			}
		}
		return [...new Set(r)];
	}

	private isTabLocal(rel: string): boolean {
		return matchesAtAnyDepth(this.policy.tabLocal, rel);
	}

	private isGitPath(rel: string): boolean {
		return foldedForms(rel).some(f => f.split('/').includes('.git'));
	}

	private isRootGitAuto(rel: string): boolean {
		return rel.startsWith('.git/') && (this.policy.gitAuto.some(g => globMatch(g, rel)) || this.policy.gitObjectName.test(rel));
	}

	/** A gitdir needn't be called .git: HEAD/commondir/gitdir files, config beside a HEAD, gitfile content. */
	private looksLikeGitMeta(rel: string, c: UpperChange, batchNames: Set<string>): boolean {
		if (c.kind === 'file' && /^\s*gitdir:/i.test((c.content ?? Buffer.alloc(0)).subarray(0, 64).toString('latin1'))) {
			return true;
		}
		const f = foldPath(rel);
		const base = path.posix.basename(f);
		const dir = path.posix.dirname(f);
		if (['head', 'commondir', 'gitdir', 'orig_head', 'fetch_head', 'packed-refs'].includes(base)) {
			return true;
		}
		if (base === 'config' || base === 'objects' || base === 'refs') {
			const head = dir === '.' ? 'head' : `${dir}/head`;
			return batchNames.has(head) || this.hostHash(path.posix.join(path.posix.dirname(rel), 'HEAD')) !== 'absent';
		}
		return false;
	}

	private isHookish(rel: string): boolean {
		const f = foldPath(rel);
		const hp = this.hostHooksPath();
		return matchesAtAnyDepth(['.husky/**', '.lefthook/**', '.githooks/**', 'lefthook.yml', 'lefthook.yaml', '.lefthook.yml', '.lefthook.yaml'], rel)
			|| (!!hp && (f === hp || f.startsWith(hp + '/')));
	}

	private isHeldPath(rel: string): boolean {
		const forms = foldedForms(rel);
		if (matchesAtAnyDepth(this.policy.held, rel)) {
			return true;
		}
		if (this.isHookish(rel)) {
			return true;
		}
		// Workspace files the host's git config includes are as dangerous as .git/config (W-2f).
		return this.hostConfigIncludes().some(inc => forms.includes(inc));
	}

	/**
	 * The host's git config files (read-only, bounded): the workspace's .git/config, or for a
	 * gitfile checkout (worktree, submodule) the real gitdir's config and its commondir's
	 * (review X-4/W-9). If the workspace has no .git, the nearest enclosing checkout's (BB-1).
	 * Each entry: the config's directory, its lines, and that checkout's worktree root.
	 */
	private hostConfigs(): Array<{ dir: string; lines: string[]; top: string }> {
		const read = (dir: string, top: string) => {
			try {
				const st = lstatOrNull(path.join(dir, 'config'));
				return st?.isFile() && st.size <= 1 << 20 ? [{ dir, top, lines: fs.readFileSync(path.join(dir, 'config'), 'utf8').split('\n') }] : [];
			} catch {
				return [];
			}
		};
		try {
			for (let top = this.o.root; ; top = path.dirname(top)) {
				const dotgit = path.join(top, '.git');
				const st = lstatOrNull(dotgit);
				if (st?.isDirectory()) {
					return read(dotgit, top);
				}
				if (st?.isFile() && st.size <= 4096) {
					const m = /^gitdir:\s*(.+?)\s*$/m.exec(fs.readFileSync(dotgit, 'utf8'));
					if (m) {
						const gitdir = path.resolve(top, m[1]);
						let common: Array<{ dir: string; lines: string[]; top: string }> = [];
						try {
							const cd = fs.readFileSync(path.join(gitdir, 'commondir'), 'utf8').trim();
							common = read(path.resolve(gitdir, cd), top);
						} catch { /* not a worktree */ }
						return [...read(gitdir, top), ...common];
					}
				}
				if (st || path.dirname(top) === top) {
					return [];
				}
			}
		} catch { /* unreadable: nothing */ }
		return [];
	}

	/** Host's current core.hooksPath (workspace-relative, folded). */
	private hostHooksPath(): string | undefined {
		for (const { lines, top } of this.allHostConfigs()) {
			for (const e of parseGitConfig(lines)) {
				if (e.section === 'core' && e.key === 'hookspath') {
					// Relative hooksPath is relative to the working tree root.
					const v = this.toWorkspaceRel(e.value, top);
					if (v) {
						return foldPath(v);
					}
				}
			}
		}
		return undefined;
	}

	/** Workspace-relative files the host's git config pulls in via include.path / includeIf.*.path. */
	private hostConfigIncludes(): string[] {
		return this.allHostConfigs().filter(c => c.rel !== undefined).map(c => c.rel as string);
	}

	/**
	 * The host configs plus, recursively to a bounded depth, included config files that live in
	 * the workspace (review Y-5): an included workspace file may itself include another.
	 */
	private allHostConfigs(): Array<{ dir: string; lines: string[]; top: string; rel?: string }> {
		const out: Array<{ dir: string; lines: string[]; top: string; rel?: string }> = this.hostConfigs();
		const seen = new Set<string>();
		for (let i = 0; i < out.length && i < 32; i++) {
			const cfg = out[i];
			for (const e of parseGitConfig(cfg.lines)) {
				if (!(e.section === 'include' || e.section.startsWith('includeif')) || e.key !== 'path') {
					continue;
				}
				const rel = this.toWorkspaceRel(e.value, cfg.dir);
				if (!rel || seen.has(foldPath(rel))) {
					continue;
				}
				seen.add(foldPath(rel));
				let lines: string[] = [];
				try {
					const f = this.resolveOrNull(rel);
					const st = f ? lstatOrNull(f) : null;
					if (f && st?.isFile() && st.size <= 1 << 20) {
						lines = fs.readFileSync(f, 'utf8').split('\n');
					}
				} catch { /* unreadable: still held by name */ }
				out.push({ dir: path.dirname(path.join(this.o.root, rel)), top: cfg.top, lines, rel: foldPath(rel) });
			}
		}
		return out;
	}

	/** A config path (absolute, or relative to `base`) as a workspace-relative path, if inside. */
	private toWorkspaceRel(v: string, base: string): string | undefined {
		if (!v || v.startsWith('~')) {
			return undefined;
		}
		const abs = path.resolve(base, v);
		let root = this.o.root;
		try {
			root = fs.realpathSync.native(this.o.root);
		} catch { /* keep */ }
		// The host FS may be case-insensitive: compare folded prefixes, slice the original (Y-5).
		for (const r of [this.o.root, root]) {
			if (abs.toLowerCase().startsWith(r.toLowerCase() + path.sep)) {
				return abs.slice(r.length + 1).split(path.sep).join('/').replace(/\/+$/, '');
			}
		}
		return undefined;
	}

	private manifestReasons(rel: string, c: UpperChange, keys: readonly string[]): string[] {
		const parse = (s: string | null): Record<string, unknown> | null | 'bad' => {
			if (s === null) {
				return null;
			}
			try {
				const v = JSON.parse(s);
				return v && typeof v === 'object' && !Array.isArray(v) && !hasDuplicateTopLevelKeys(s) ? v as Record<string, unknown> : 'bad';
			} catch {
				return 'bad';
			}
		};
		const f = this.resolveOrNull(rel);
		const st = f ? lstatOrNull(f) : null;
		if ((st?.isFile() && st.size > this.policy.caps.maxJsonBytes) || (c.content?.length ?? 0) > this.policy.caps.maxJsonBytes) {
			return ['manifest too large to compare'];
		}
		const host = parse(f && st?.isFile() ? fs.readFileSync(f, 'utf8') : null);
		const tab = parse(c.kind === 'file' ? (c.content ?? Buffer.alloc(0)).toString('utf8') : null);
		if (host === 'bad' || tab === 'bad') {
			return ['manifest unparsable or has duplicate keys'];
		}
		const r: string[] = [];
		const changed = keys.filter(k => JSON.stringify(host?.[k] ?? null) !== JSON.stringify(tab?.[k] ?? null));
		if (changed.length) {
			r.push(`changes ${changed.join('/')} in a manifest`);
		}
		// Any added or changed dependency runs its install scripts on the host's next install (X-2).
		for (const sect of this.policy.dependencyKeys) {
			if (JSON.stringify(host?.[sect] ?? null) !== JSON.stringify(tab?.[sect] ?? null)) {
				const td = tab?.[sect];
				const hd = host?.[sect];
				const added = td && typeof td === 'object' ? Object.keys(td).filter(k => !hd || typeof hd !== 'object' || JSON.stringify((hd as Record<string, unknown>)[k]) !== JSON.stringify((td as Record<string, unknown>)[k])) : [];
				// A section that is not a plain object (string, array, …) may still be normalised into deps (Y-4).
				if (added.length || !td || typeof td !== 'object' || Array.isArray(td)) {
					r.push(`adds or changes ${sect}${added.length ? `: ${added.slice(0, 10).join(', ')}` : ''}`);
				}
			}
		}
		return r;
	}

	// ---- host side (trusted writer) -------------------------------------------------------

	private checkRoot(): void {
		const st = fs.lstatSync(this.o.root, { bigint: true });
		if (!st.isDirectory() || st.dev.toString() !== this.o.rootIdentity.dev || st.ino.toString() !== this.o.rootIdentity.ino) {
			throw new WriteBackError('workspace root identity changed; refusing to write');
		}
	}

	/**
	 * Host path for `rel`, walking from the pinned root without following any link. With
	 * `create`, missing directories are created (0755). Returns the final path and the
	 * identity of its directory (re-verified around the write).
	 */
	private resolve(rel: string, create: boolean): { file: string; dir: string; dirId: string } | null {
		this.checkRoot();
		const segs = checkRel(rel).split('/');
		let cur = this.o.root;
		let st = fs.lstatSync(cur);
		for (const seg of segs.slice(0, -1)) {
			const p = path.join(cur, seg);
			let s = lstatOrNull(p);
			if (!s) {
				if (!create) {
					return null;
				}
				fs.mkdirSync(p, { mode: 0o755 });
				s = fs.lstatSync(p);
			}
			if (s.isSymbolicLink() || !s.isDirectory()) {
				throw new WriteBackError('a path component is a link or not a directory');
			}
			cur = p;
			st = s;
		}
		const real = fs.realpathSync.native(cur);
		const realRoot = fs.realpathSync.native(this.o.root);
		if (real !== realRoot && !real.startsWith(realRoot + path.sep)) {
			throw new WriteBackError('path resolves outside the workspace');
		}
		return { file: path.join(cur, segs[segs.length - 1]), dir: cur, dirId: `${st.dev}:${st.ino}` };
	}

	private resolveOrNull(rel: string): string | null {
		return this.resolve(rel, false)?.file ?? null;
	}

	private hostHash(rel: string): string {
		const f = this.resolveOrNull(rel);
		const st = f ? lstatOrNull(f) : null;
		if (!f || !st) {
			return 'absent';
		}
		if (!st.isFile()) {
			return st.isDirectory() ? 'dir' : 'non-file';
		}
		return sha(fs.readFileSync(f));
	}

	private hostSig(rel: string): string {
		const f = this.resolveOrNull(rel);
		const st = f ? lstatOrNull(f) : null;
		return st ? sigOf(st) : 'absent';
	}

	private hostMode(rel: string): number {
		try {
			const f = this.resolveOrNull(rel);
			const st = f ? lstatOrNull(f) : null;
			return st?.isFile() ? st.mode & 0o777 : 0;
		} catch {
			return 0;
		}
	}

	private hostIsDir(rel: string): boolean {
		const f = this.resolveOrNull(rel);
		return !!f && !!lstatOrNull(f)?.isDirectory();
	}

	private apply(rel: string, c: UpperChange, approved: boolean): void {
		const r = this.resolve(rel, c.kind === 'file' || c.kind === 'symlink')!;
		const final = r.file;
		const existing = lstatOrNull(final);
		const sameDir = () => {
			const d = fs.lstatSync(r.dir);
			if (d.isSymbolicLink() || `${d.dev}:${d.ino}` !== r.dirId) {
				throw new WriteBackError('a directory changed during the write');
			}
		};
		if (c.kind === 'deleted') {
			if (existing) {
				if (!existing.isFile()) {
					throw new WriteBackError('refusing to delete a non-file');
				}
				sameDir();
				fs.unlinkSync(final);
			}
		} else if (c.kind === 'file') {
			if (existing && !existing.isFile()) {
				throw new WriteBackError('refusing to replace a non-file');
			}
			const buf = c.content ?? Buffer.alloc(0);
			// An exec bit only by approval; otherwise keep the host's (or 0644 for new files).
			const exec = approved ? ((c.mode ?? 0) & 0o111) !== 0 : ((existing?.mode ?? 0) & 0o111) !== 0;
			const tmp = path.join(r.dir, `.seclab-wb.${randomBytes(8).toString('hex')}.tmp`);
			const fd = fs.openSync(tmp, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
			try {
				fs.writeSync(fd, buf);
				fs.fsyncSync(fd);
				fs.fchmodSync(fd, exec ? 0o755 : 0o644);
			} finally {
				fs.closeSync(fd);
			}
			try {
				sameDir();
				fs.renameSync(tmp, final);
			} catch (e) {
				fs.rmSync(tmp, { force: true });
				throw e;
			}
		} else if (c.kind === 'symlink' && approved) {
			const t = c.target ?? '';
			// Only relative links that stay inside the workspace, even when approved.
			const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(rel), t));
			if (!t || path.isAbsolute(t) || t.includes('\0') || resolved.startsWith('../') || resolved === '..') {
				throw new WriteBackError('refusing a link that points outside the workspace');
			}
			if (existing) {
				throw new WriteBackError('refusing to replace an existing entry with a link');
			}
			sameDir();
			fs.symlinkSync(t, final);
		} else {
			throw new WriteBackError(`refusing to apply a ${c.kind}`);
		}
		this.state.baseline[foldPath(rel)] = this.hostSig(rel);
	}

	// ---- state ------------------------------------------------------------------------------

	/** Host state at tab start, by folded path (stat signature only; W-4). */
	private seedBaseline(): void {
		const base: Record<string, string> = {};
		let n = 0;
		let complete = true;
		const walk = (dir: string, rel: string) => {
			let entries: fs.Dirent[];
			try {
				entries = fs.readdirSync(dir, { withFileTypes: true });
			} catch {
				return;
			}
			for (const e of entries) {
				if (++n > this.policy.caps.maxBaselineEntries) {
					complete = false;
					return;
				}
				const p = path.join(dir, e.name);
				const r = rel ? `${rel}/${e.name}` : e.name;
				const st = lstatOrNull(p);
				if (!st) {
					continue;
				}
				base[foldPath(r)] = sigOf(st);
				if (st.isDirectory()) {
					walk(p, r);
				}
			}
		};
		this.checkRoot();
		walk(this.o.root, '');
		this.state.baseline = base;
		this.state.seeded = complete; // incomplete: unknown paths fall back to first-sight baselines
		this.save();
	}

	private load(): State {
		try {
			const s = JSON.parse(fs.readFileSync(this.o.statePath, 'utf8')) as State;
			if (s.version === 2 && Array.isArray(s.pending) && s.baseline && Array.isArray(s.always)) {
				return s;
			}
		} catch { /* none yet */ }
		return { version: 2, pending: [], baseline: {}, seeded: false, always: [] };
	}

	private save(): void {
		const tmp = `${this.o.statePath}.${process.pid}.tmp`;
		fs.writeFileSync(tmp, JSON.stringify(this.state), { mode: 0o600 });
		fs.renameSync(tmp, this.o.statePath);
	}
}

function sigOf(st: fs.Stats): string {
	return st.isFile() ? `f:${st.size}:${Math.floor(st.mtimeMs)}:${st.ino}` : st.isDirectory() ? 'd' : st.isSymbolicLink() ? 'l' : 'o';
}

function lstatOrNull(p: string): fs.Stats | null {
	try {
		return fs.lstatSync(p);
	} catch {
		return null;
	}
}
