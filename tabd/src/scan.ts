// Pre-mount secret scanning (ADR 20261104-pre-mount-secret-scan). Runs gitleaks from a
// digest-pinned image in a throwaway, network-less, read-only container BEFORE a workspace
// is mounted into a tab. Secret values are held only in supervisor memory (for "move to
// broker"); clients and logs only ever see redacted findings.

import { createHmac, randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Runner } from './run.ts';

export const GITLEAKS_IMAGE = 'ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f'; // v8.30.1

// Default rules plus our test canary shape (test/canary/canary.ts).
const CONFIG = `[extend]
useDefault = true

[[rules]]
id = "seclab-canary"
description = "seclab canary secret (tests)"
regex = '''seclabcanary_[A-Z0-9]{0,16}_[0-9a-f]{32}'''
`;

export interface Finding {
	readonly id: string;
	readonly source: 'worktree' | 'git-config' | 'history' | 'objects';
	/**
	 * Workspace-relative path for display. Untrusted text (the tab can name files):
	 * control/format characters are escaped as \u{..}; clients must still treat it as data.
	 */
	readonly file: string;
	/** 1-based; for `objects` it is a position in the object stream, not a file line. */
	readonly line: number;
	readonly rule: string;
	readonly commit?: string;
	/** Can be rewritten in place (current regular files with a plain name only). */
	readonly movable: boolean;
}

export interface ScanResult {
	readonly complete: boolean;
	readonly error?: string;
	/** The report exceeded what we will parse: possibly stuffed to hide real findings. */
	readonly overflow?: boolean;
	readonly findings: Finding[];
	/** finding id -> secret value. Never serialised. */
	readonly secrets: Map<string, string>;
}

interface RawFinding { File?: unknown; StartLine?: unknown; RuleID?: unknown; Commit?: unknown; Secret?: unknown }

const MAX_REPORT_BYTES = 64 << 20;
const MAX_GIT_DIRS = 64;

// Runs inside the gitleaks container as `bash -c`. Fixed text: hostile names only ever
// reach it as data (find -print0), and leave it hex-encoded. Every pass runs even if an
// earlier one fails; each emits a frame `SECLAB1 <kind> <hex rel> <exit> <bytes>\n<report>`.
// Suppression inputs from the workspace are neutralised (review round 5, S2):
// - gitleaks config and ignore file come from our tmpfs (--config / --gitleaks-ignore-path);
//   gitleaks also loads <source>/.gitleaksignore unconditionally (cmd/root.go:317 at
//   83d9cd6), so no pass uses the workspace itself as <source>: worktree scans /scan
//   (parent of /scan/ws), history uses an empty source dir with GIT_DIR;
// - --ignore-gitleaks-allow drops inline `gitleaks:allow`;
// - git: --text (beats -diff/binary attributes), no textconv/ext-diff, and the
//   GIT_CONFIG_* overrides below beat repo config that would blind `git log -p`.
// The object-store pass (every blob/commit/tag, incl. reflog-only, stash, index and
// dangling objects) is the backstop for history rewriting tricks (S3).
const $ = '$'; // bash ${...} inside a JS template literal
const SCRIPT = String.raw`set -u
O=/seclab
printf '%s' "$SECLAB_GITLEAKS_TOML" > "$O/gitleaks.toml"; unset SECLAB_GITLEAKS_TOML
: > "$O/ignore"; mkdir "$O/empty"; cd "$O/empty" || exit 3
GL="--config $O/gitleaks.toml --gitleaks-ignore-path $O/ignore --ignore-gitleaks-allow --no-banner --report-format json --exit-code 0 --log-level error"
hex() { printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n'; }
emit() { [ -f "$4" ] || : > "$4"; printf 'SECLAB1 %s %s %s %s\n' "$1" "$(hex "$2")" "$3" "$(wc -c < "$4" | tr -d ' ')"; cat "$4"; rm -f "$4"; }
timeout 300 gitleaks dir /scan $GL --max-target-megabytes 10 --report-path "$O/r.json"; emit worktree . $? "$O/r.json"
n=0
while IFS= read -r -d '' h; do
  gd=${$}{h%/HEAD}
  { [ -d "$gd/objects" ] && [ -d "$gd/refs" ]; } || continue
  n=$((n+1)); if [ "$n" -gt ${MAX_GIT_DIRS} ]; then printf 'SECLAB1 toomany 2d 1 0\n'; break; fi
  rel=${$}{gd#/scan/ws}; rel=${$}{rel#/}; [ -n "$rel" ] || rel=.
  if [ -f "$gd/config" ] && [ ! -L "$gd/config" ]; then
    timeout 60 gitleaks dir "$gd/config" $GL --report-path "$O/r.json"; emit config "$rel" $? "$O/r.json"
  fi
  GIT_DIR=$gd timeout 300 gitleaks git "$O/empty" $GL --log-opts="--all --reflog --text --no-textconv --no-ext-diff" --report-path "$O/r.json"
  emit history "$rel" $? "$O/r.json"
  ( set -o pipefail; export GIT_DIR=$gd
    git cat-file --batch-all-objects --batch-check='%(objectname) %(objecttype) %(objectsize)' \
      | awk '($2=="blob"||$2=="commit"||$2=="tag") && $3<10485760 {print $1}' \
      | git cat-file --batch | timeout 300 gitleaks stdin $GL --report-path "$O/r.json" )
  emit objects "$rel" $? "$O/r.json"
done < <(find /scan/ws -xdev -name HEAD -type f -print0)
printf 'SECLAB1 end 2d 0 0\n'
`;

const GIT_OVERRIDES: Array<[string, string]> = [
	['safe.directory', '*'], ['core.bigFileThreshold', '512m'], ['core.attributesFile', '/dev/null'],
	['core.fsmonitor', 'false'], ['core.hooksPath', '/dev/null'], ['color.ui', 'never'], ['color.diff', 'never'],
	['diff.noprefix', 'false'], ['diff.mnemonicPrefix', 'false'], ['diff.srcPrefix', 'a/'], ['diff.dstPrefix', 'b/'],
	['diff.relative', 'false'], ['format.pretty', 'medium'], ['log.showRoot', 'true'], ['log.showSignature', 'false'],
	['log.decorate', 'no'], ['log.abbrevCommit', 'false'], ['i18n.logOutputEncoding', 'UTF-8'],
];

const KINDS: Record<string, Finding['source'] | 'end' | 'toomany'> = {
	worktree: 'worktree', config: 'git-config', history: 'history', objects: 'objects', end: 'end', toomany: 'toomany',
};

export async function scanWorkspace(runner: Runner, docker: string, hostPath: string): Promise<ScanResult> {
	const env = GIT_OVERRIDES.flatMap(([k, v], i) => ['-e', `GIT_CONFIG_KEY_${i}=${k}`, '-e', `GIT_CONFIG_VALUE_${i}=${v}`]);
	const args = ['run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
		'--user', '65534:65534', '--pids-limit', '256', '--memory', '1g',
		'--tmpfs', '/seclab:rw,noexec,nosuid,nodev,size=256m,mode=0700,uid=65534,gid=65534', '--workdir', '/',
		'-e', 'HOME=/seclab', '-e', 'GIT_CONFIG_NOSYSTEM=1', '-e', 'GIT_CONFIG_GLOBAL=/dev/null', '-e', 'GIT_ATTR_NOSYSTEM=1',
		'-e', 'GIT_NO_REPLACE_OBJECTS=1', '-e', 'GIT_TERMINAL_PROMPT=0', '-e', `GIT_CONFIG_COUNT=${GIT_OVERRIDES.length}`, ...env,
		'-e', `SECLAB_GITLEAKS_TOML=${CONFIG}`,
		'--mount', `type=bind,src=${hostPath},dst=/scan/ws,readonly`,
		'--entrypoint', 'bash', GITLEAKS_IMAGE, '-c', SCRIPT];
	const r = await runner.run(docker, args, { timeoutMs: 1_200_000, maxOutputBytes: MAX_REPORT_BYTES });
	return parseFrames(r.stdoutBytes ?? Buffer.from(r.stdout), r.code, !!r.truncated);
}

/** Exported for tests. Keeps every finding it can parse, even when the scan is incomplete. */
export function parseFrames(buf: Buffer, exitCode: number | null, truncated: boolean): ScanResult {
	const findings: Finding[] = [];
	const secrets = new Map<string, string>();
	const seenValues = new Set<string>();
	const errors: string[] = [];
	let overflow = truncated;
	let ended = false;
	let off = 0;
	while (off < buf.length) {
		const nl = buf.indexOf(0x0a, off);
		const m = nl < 0 ? null : /^SECLAB1 ([a-z]+) ([0-9a-f]*) (\d+) (\d+)$/.exec(buf.subarray(off, nl).toString('latin1'));
		const kind = m ? KINDS[m[1]] : undefined;
		if (!m || !kind) {
			errors.push('malformed scanner output');
			break;
		}
		const len = Number(m[4]);
		const body = buf.subarray(nl + 1, nl + 1 + len);
		off = nl + 1 + len;
		if (kind === 'end') {
			ended = true;
			break;
		}
		if (kind === 'toomany') {
			overflow = true;
			errors.push(`more than ${MAX_GIT_DIRS} git repositories`);
			continue;
		}
		const rel = Buffer.from(m[2], 'hex').toString('utf8');
		if (body.length < len) {
			break; // truncated mid-frame
		}
		if (m[3] !== '0') {
			errors.push(`${kind} pass (${displayPath(rel)}) exited ${m[3]}`);
		}
		let raw: RawFinding[] = [];
		try {
			raw = len === 0 ? [] : JSON.parse(body.toString('utf8')) as RawFinding[];
			if (!Array.isArray(raw)) {
				throw new Error('not an array');
			}
		} catch {
			errors.push(`${kind} pass (${displayPath(rel)}) report unreadable`);
			continue;
		}
		for (const f of raw) {
			addFinding(kind, rel, f, findings, secrets, seenValues);
		}
	}
	if (!ended && !overflow) {
		errors.push(exitCode === null ? 'scanner did not finish (timeout or not runnable)' : `scanner exited ${exitCode} before finishing`);
	}
	if (overflow) {
		errors.unshift('scanner report too large to review');
	}
	const complete = ended && !overflow && errors.length === 0;
	return { complete, error: complete ? undefined : `secret scan incomplete: ${errors.join('; ')}`, overflow: overflow || undefined, findings, secrets };
}

const ID_KEY = randomBytes(32);

function addFinding(source: Finding['source'], repoRel: string, f: RawFinding, findings: Finding[], secrets: Map<string, string>, seenValues: Set<string>): void {
	const secret = String(f.Secret ?? '');
	const rule = String(f.RuleID ?? 'unknown').replace(/[^A-Za-z0-9._-]/g, '').slice(0, 64);
	const commit = typeof f.Commit === 'string' && /^[0-9a-f]{7,64}$/.test(f.Commit) ? f.Commit : undefined;
	const line = Number(f.StartLine);
	const rawFile = String(f.File ?? '');
	let file: string;
	let plain = false;
	if (source === 'objects') {
		file = repoRel === '.' ? '.git (object store)' : `${repoRel} (object store)`;
	} else if (source === 'history') {
		const repoDir = repoRel === '.' ? '' : repoRel.replace(/(^|\/)\.git$/, '');
		file = path.posix.join(repoDir || '.', rawFile);
	} else {
		const rel = rawFile.startsWith('/scan/ws/') ? rawFile.slice('/scan/ws/'.length) : '';
		const norm = path.posix.normalize(rel);
		file = !rel || norm.startsWith('..') || path.posix.isAbsolute(norm) ? '(unknown file)' : norm;
		plain = file === norm && file === displayPath(file);
	}
	// A value already reported by an earlier pass is not repeated (worktree first). After a
	// move, the rescan reports whatever copies remain (history, objects). Unattributable
	// findings still block; they are just never movable.
	if (secret && seenValues.has(secret)) {
		return;
	}
	if (secret) {
		seenValues.add(secret);
	}
	const okLine = Number.isInteger(line) && line >= 1;
	const movable = plain && okLine && !!secret && (source === 'worktree' || source === 'git-config');
	pushFinding(source, displayPath(file), okLine ? line : 1, rule, commit, movable, secret, findings, secrets);
}

function pushFinding(source: Finding['source'], file: string, line: number, rule: string, commit: string | undefined, movable: boolean,
	secret: string, findings: Finding[], secrets: Map<string, string>): void {
	// Keyed per supervisor run: stable across rescans (so "accept" ids still match), not a
	// usable hash of the secret for anyone who sees the id.
	const id = createHmac('sha256', ID_KEY).update(`${source}\0${file}\0${source === 'objects' ? '' : line}\0${rule}\0${commit ?? ''}\0${secret}`).digest('hex').slice(0, 20);
	if (secrets.has(id)) {
		return;
	}
	findings.push({ id, source, file, line, rule, commit, movable });
	secrets.set(id, secret);
}

/** Escape control, format (bidi), line/paragraph separators and lone surrogates; cap length. */
export function displayPath(s: string): string {
	const esc = s.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}\\]/gu, c => c === '\\' ? '\\\\' : `\\u{${c.codePointAt(0)!.toString(16)}}`);
	return esc.length > 240 ? `${esc.slice(0, 120)}…${esc.slice(-110)}` : esc;
}

export interface VaultEntry {
	readonly id: string;
	readonly file: string;
	readonly line: number;
	readonly rule: string;
	readonly sentinel: string;
	readonly secret: string;
	readonly bind: { readonly host: string; readonly path: string };
	readonly movedAt: string;
}

export function mintSentinel(rule: string): string {
	return `seclab_sentinel_${rule.replace(/[^a-z0-9]/gi, '').slice(0, 24)}_${randomBytes(16).toString('hex')}`;
}

/**
 * Replace `from` with `to` on `line` of `file` inside the workspace (used both ways: move
 * and restore). Byte-exact: works on the raw bytes, never decodes the file or interprets
 * replacement patterns. Refuses anything that is not a regular, non-symlinked file inside
 * the workspace, and anything where `from` is no longer on that line. Atomic (temp file +
 * rename), mode kept, and verified by reading back before returning.
 */
export function rewriteSecret(hostPath: string, file: string, line: number, from: string, to: string): void {
	if (!from || from.length < 8) {
		throw new Error('refusing to rewrite: value unavailable');
	}
	const abs = path.resolve(hostPath, file);
	if (!abs.startsWith(hostPath + path.sep)) {
		throw new Error('refusing to rewrite outside the workspace');
	}
	const st = fs.lstatSync(abs);
	if (!st.isFile() || st.size > 10 << 20 || fs.realpathSync.native(abs) !== abs) {
		throw new Error(`refusing to rewrite ${file}: not a regular non-symlinked file`);
	}
	const buf = fs.readFileSync(abs);
	let start = 0;
	for (let k = 1; k < line && start >= 0; k++) {
		const nl = buf.indexOf(0x0a, start);
		start = nl < 0 ? -1 : nl + 1;
	}
	const end = start < 0 ? -1 : buf.indexOf(0x0a, start) < 0 ? buf.length : buf.indexOf(0x0a, start);
	const needle = Buffer.from(from, 'utf8');
	const at = start < 0 || line < 1 ? -1 : buf.subarray(start, end).indexOf(needle);
	if (at < 0) {
		throw new Error(`value no longer at ${file}:${line}; rescan`);
	}
	const out = Buffer.concat([buf.subarray(0, start + at), Buffer.from(to, 'utf8'), buf.subarray(start + at + needle.length)]);
	const tmp = `${abs}.seclab-${randomBytes(4).toString('hex')}`;
	fs.writeFileSync(tmp, out, { mode: st.mode & 0o777, flag: 'wx' });
	fs.renameSync(tmp, abs);
	if (!fs.readFileSync(abs).equals(out)) {
		throw new Error(`rewrite of ${file} could not be verified`);
	}
}
