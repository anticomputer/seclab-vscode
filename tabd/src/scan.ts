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
	readonly source: 'worktree' | 'git-dir' | 'history' | 'objects';
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
	/** Links (scanner paths) that did not resolve inside the workspace in the scanner. */
	readonly externalLinks?: string[];
}

interface RawFinding { File?: unknown; StartLine?: unknown; RuleID?: unknown; Commit?: unknown; Secret?: unknown }

const MAX_REPORT_BYTES = 64 << 20;
const MAX_GIT_DIRS = 64;
/** Files/blobs above this (decimal MB, as gitleaks counts) are reported as unscanned, never silently skipped. */
const LIMIT_MB = 64;

// Runs inside the gitleaks container as `bash -c`. Fixed text: hostile names only ever
// reach it as data (find -print0), and leave it hex-encoded. Every pass runs even if an
// earlier one fails; each emits a frame `SECLAB1 <kind> <hex rel> <exit> <bytes>\n<body>`.
// Suppression inputs from the workspace are neutralised (review rounds 5-6):
// - gitleaks config and ignore file come from our tmpfs (--config / --gitleaks-ignore-path);
//   gitleaks also loads <source>/.gitleaksignore unconditionally (cmd/root.go:317 at
//   83d9cd6), so no pass uses workspace content as <source>: the worktree pass scans /scan
//   (parent of /scan/ws), git dirs are copied under /seclab/g/x and scanned as /seclab/g,
//   history uses an empty source dir with GIT_DIR;
// - --ignore-gitleaks-allow drops inline `gitleaks:allow`;
// - symlinks: a link the tab planted (`.env -> node_modules/.cache/x`) could steer a later
//   host write into a path gitleaks skips (its allowlist applies to the resolved path), so
//   every in-workspace link target is copied to a neutral name and scanned, reported
//   under the link's path. The workspace is also mounted at its real path so absolute
//   links resolve as they do in the tab;
// - oversize files/blobs are listed as findings ("unscanned"), not dropped;
// - git dirs are found the way git finds them (HEAD file or symlink; commondir), validated
//   with `git rev-parse`; anything that looks like a git dir but doesn't validate blocks;
//   each git dir and its common dir is scanned whole (except objects/modules/worktrees/lfs,
//   which are covered by the object pass or discovered as git dirs themselves);
// - git: --text (beats -diff/binary attributes), no textconv/ext-diff, and the
//   GIT_CONFIG_* overrides below beat repo config that would blind `git log -p`.
// The object-store pass (every blob/commit/tag, incl. reflog-only, stash, index and
// dangling objects) is the backstop for history rewriting tricks.
const $ = '$'; // bash ${...} inside a JS template literal
const SCRIPT = String.raw`set -u
O=/seclab
printf '%s' "$SECLAB_GITLEAKS_TOML" > "$O/gitleaks.toml"; unset SECLAB_GITLEAKS_TOML
: > "$O/ignore"; mkdir "$O/empty" "$O/g"; cd "$O/empty" || exit 3
GL="--config $O/gitleaks.toml --gitleaks-ignore-path $O/ignore --ignore-gitleaks-allow --no-banner --report-format json --exit-code 0 --log-level error"
LIM=${LIMIT_MB}
hex() { printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n'; }
emit() { [ -f "$4" ] || : > "$4"; printf 'SECLAB1 %s %s %s %s\n' "$1" "$(hex "$2")" "$3" "$(wc -c < "$4" | tr -d ' ')"; cat "$4"; rm -f "$4"; }
flag() { printf 'SECLAB1 %s %s %s 0\n' "$1" "$(hex "$2")" "$3"; }
cap() { local c=0; : > "$1"; while IFS= read -r -d '' x; do c=$((c+1)); [ "$c" -le 200 ] || return 1; printf '%s\0' "$x" >> "$1"; done; }
# Workspace path as the scanner sees it: /scan/ws, or its real path (mounted too, so
# absolute links and an absolute commondir resolve as they do in the tab).
inws() { case "$1" in "$SECLAB_WS"|"$SECLAB_WS"/*) printf '/scan/ws%s' "${$}{1#"$SECLAB_WS"}" ;; /scan/ws|/scan/ws/*) printf '%s' "$1" ;; *) return 1 ;; esac; }
# Copy a git dir (or a linked dir) for scanning: everything except well-formed object and
# pack files (the object pass reads those), so files planted under objects/ are scanned.
h=[0-9a-f]; h38=; h64=; for k in $(seq 38); do h38=$h38$h; done; for k in $(seq 64); do h64=$h64$h; done
OBJX=("--exclude=*/objects/$h$h/$h38" "--exclude=*/lfs/objects/$h$h/$h$h/$h64")
for e in pack idx rev bitmap promisor keep mtimes; do OBJX+=("--exclude=*/objects/pack/pack-$h*.$e"); done
copy() { ( set -o pipefail; tar -C "$1" "${$}{OBJX[@]}" -cf - . | tar -C "$2" -xf - ); }
timeout 300 gitleaks dir /scan $GL --max-target-megabytes $LIM --report-path "$O/r.json"; emit worktree . $? "$O/r.json"
find /scan/ws -xdev -type f -size +$((LIM*1000000))c -print0 | cap "$O/r.json"; emit large . $? "$O/r.json"
# Paths the scanner can't read or list (the tab may chmod its own files): blocking, never
# silent. A real open per file (access(2) lies on Docker Desktop file sharing), plus every
# path find itself could not stat or list (from its stderr).
( set -o pipefail; find /scan/ws -xdev -name node_modules -prune -o -type f -print0 2>"$O/finderr" \
  | while IFS= read -r -d '' p; do { : < "$p"; } 2>/dev/null || printf '%s\0' "$p"; done \
  | cap "$O/r.json" ); emit unreadable . $? "$O/r.json"
head -c 65536 "$O/finderr" > "$O/r.json"; [ ! -s "$O/finderr" ]; emit finderr . $? "$O/r.json"; rm -f "$O/finderr"
# Symlinks: a planted link can steer a later host write into a path gitleaks skips (its
# allowlist applies to the resolved path). Scan each target under the link's name. Links
# that don't resolve inside the workspace here are listed for tabd to resolve on the host
# (case-insensitive APFS, firmlinks).
mkdir -p "$O/l/x" "$O/l/d"; : > "$O/links"; : > "$O/biglinks"; : > "$O/extlinks"; i=0; lf=0; ne=0
while IFS= read -r -d '' l; do
  if ! r=$(readlink -f "$l" 2>/dev/null) || ! t=$(inws "$r") || [ ! -e "$t" ]; then
    ne=$((ne+1)); if [ "$ne" -gt 500 ]; then flag manylinks . 1; break; fi
    printf '%s\0' "$l" >> "$O/extlinks"; continue
  fi
  if [ -f "$t" ]; then
    if [ "$(stat -c %s "$t")" -gt $((LIM*1000000)) ]; then printf '%s\0' "$l" >> "$O/biglinks"; continue; fi
    i=$((i+1)); if [ "$i" -gt 500 ]; then flag manylinks . 1; break; fi
    cp "$t" "$O/l/x/$i" || lf=1
  elif [ -d "$t" ]; then
    # Only targets in places the worktree pass skips (git dirs, allowlisted trees); and
    # never a link into its own ancestor (that content is the worktree itself).
    case "$l/" in "$t"/*) continue ;; esac
    case "$t/" in */.git/*|*/node_modules/*|*/bower_components/*|*/vendor/*|*/venv/*|*/.venv/*|*/env/*|*/virtualenv/*|*/lib/python*|*/lib64/python*|*.dist-info/*) ;; *) continue ;; esac
    i=$((i+1)); if [ "$i" -gt 500 ]; then flag manylinks . 1; break; fi
    mkdir "$O/l/d/$i" && copy "$t" "$O/l/d/$i" || lf=1
  else
    continue
  fi
  printf '%s\0' "$l" >> "$O/links"
done < <(find /scan/ws -xdev -name node_modules -prune -o -type l -print0 | sort -z)
emit links . 0 "$O/links"
timeout 300 gitleaks dir "$O/l" $GL --max-target-megabytes $LIM --report-path "$O/r.json"; rc=$?; [ "$lf" = 0 ] || rc=1; emit linked . $rc "$O/r.json"
emit large . 0 "$O/biglinks"
emit extlinks . 0 "$O/extlinks"
rm -rf "$O/l"
declare -A seen
n=0
while IFS= read -r -d '' h; do
  gd=${$}{h%/HEAD}
  # A HEAD git itself would accept (validate_headref): a symlink into refs/, "ref:...", or
  # an object id; plus objects/ or commondir, as is_git_directory requires.
  if [ -L "$h" ]; then case "$(readlink "$h")" in refs/*) ;; *) continue ;; esac
  else first=; IFS= read -r first < "$h" 2>/dev/null
    case "$first" in "ref:"*) ;; *) [[ "$first" =~ ^[0-9a-f]{40} ]] || continue ;; esac
  fi
  { [ -e "$gd/objects" ] || [ -e "$gd/commondir" ]; } || continue
  rel=${$}{gd#/scan/ws}; rel=${$}{rel#/}; [ -n "$rel" ] || rel=.
  if ! common=$(GIT_DIR=$gd git rev-parse --path-format=absolute --git-common-dir 2>/dev/null) || ! common=$(inws "$common") || [ ! -d "$common" ]; then
    flag badgit "$rel" 1; continue
  fi
  for d in "$gd" "$common"; do
    [ -z "${$}{seen[$d]:-}" ] || continue
    seen[$d]=1
    n=$((n+1)); if [ "$n" -gt ${MAX_GIT_DIRS} ]; then flag toomany . 1; break 2; fi
    drel=${$}{d#/scan/ws}; drel=${$}{drel#/}; [ -n "$drel" ] || drel=.
    rm -rf "$O/g/x"; mkdir "$O/g/x"
    copy "$d" "$O/g/x" && timeout 120 gitleaks dir "$O/g" $GL --max-target-megabytes $LIM --report-path "$O/r.json"
    emit gitdir "$drel" $? "$O/r.json"
  done
  [ -z "${$}{seen[repo:$common]:-}" ] || continue
  seen[repo:$common]=1
  GIT_DIR=$gd timeout 300 gitleaks git "$O/empty" $GL --log-opts="--all --reflog --text --no-textconv --no-ext-diff" --report-path "$O/r.json"
  emit history "$rel" $? "$O/r.json"
  ( set -o pipefail; export GIT_DIR=$gd
    git cat-file --batch-all-objects --batch-check='%(objectname) %(objecttype) %(objectsize)' \
      | awk -v L=$((LIM*1000000)) -v B="$O/big" '($2=="blob"||$2=="commit"||$2=="tag") { if ($3 <= L) print $1; else print $1 > B }' \
      | git cat-file --batch | timeout 300 gitleaks stdin $GL --report-path "$O/r.json" )
  emit objects "$rel" $? "$O/r.json"
  if [ -s "$O/big" ]; then head -n 200 "$O/big" > "$O/r.json"; [ "$(wc -l < "$O/big")" -le 200 ]; emit largeobj "$rel" $? "$O/r.json"; fi
  rm -f "$O/big"
done < <(find /scan/ws -xdev -name HEAD \( -type f -o -type l \) -print0 | sort -z)
printf 'SECLAB1 end 2d 0 0\n'
`;

const GIT_OVERRIDES: Array<[string, string]> = [
	['safe.directory', '*'], ['core.bigFileThreshold', '512m'], ['core.attributesFile', '/dev/null'],
	['core.fsmonitor', 'false'], ['core.hooksPath', '/dev/null'], ['color.ui', 'never'], ['color.diff', 'never'],
	['diff.noprefix', 'false'], ['diff.mnemonicPrefix', 'false'], ['diff.srcPrefix', 'a/'], ['diff.dstPrefix', 'b/'],
	['diff.relative', 'false'], ['format.pretty', 'medium'], ['log.showRoot', 'true'], ['log.showSignature', 'false'],
	['log.decorate', 'no'], ['log.abbrevCommit', 'false'], ['i18n.logOutputEncoding', 'UTF-8'],
];

type Kind = 'worktree' | 'large' | 'unreadable' | 'finderr' | 'links' | 'linked' | 'extlinks' | 'manylinks' | 'gitdir' | 'history' | 'objects' | 'largeobj' | 'badgit' | 'toomany' | 'end';
const KINDS = new Set<Kind>(['worktree', 'large', 'unreadable', 'finderr', 'links', 'linked', 'extlinks', 'manylinks', 'gitdir', 'history', 'objects', 'largeobj', 'badgit', 'toomany', 'end']);

/** The scanner runs as whoever can read the workspace like its owner (see scanUser). */
function scanUser(hostPath: string): string {
	// Docker Desktop presents bind mounts as owned by the accessing uid; a native Linux
	// engine does not, so a file the tab chmod'ed 0600 would be skipped (silently, by
	// gitleaks) unless we scan as the owner. Never as root.
	if (process.platform !== 'linux') {
		return '65534:65534';
	}
	const st = fs.statSync(hostPath);
	return st.uid === 0 || st.gid === 0 ? '65534:65534' : `${st.uid}:${st.gid}`;
}

export async function scanWorkspace(runner: Runner, docker: string, hostPath: string): Promise<ScanResult> {
	const env = GIT_OVERRIDES.flatMap(([k, v], i) => ['-e', `GIT_CONFIG_KEY_${i}=${k}`, '-e', `GIT_CONFIG_VALUE_${i}=${v}`]);
	const user = scanUser(hostPath);
	const [uid, gid] = user.split(':');
	const args = ['run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
		'--user', user, '--pids-limit', '256', '--memory', '1g',
		'--tmpfs', `/seclab:rw,noexec,nosuid,nodev,size=256m,mode=0700,uid=${uid},gid=${gid}`, '--workdir', '/',
		'-e', 'HOME=/seclab', '-e', 'GIT_CONFIG_NOSYSTEM=1', '-e', 'GIT_CONFIG_GLOBAL=/dev/null', '-e', 'GIT_ATTR_NOSYSTEM=1',
		'-e', 'GIT_NO_REPLACE_OBJECTS=1', '-e', 'GIT_TERMINAL_PROMPT=0', '-e', `GIT_CONFIG_COUNT=${GIT_OVERRIDES.length}`, ...env,
		'-e', `SECLAB_GITLEAKS_TOML=${CONFIG}`, '-e', `SECLAB_WS=${hostPath}`,
		'--mount', `type=bind,src=${hostPath},dst=/scan/ws,readonly`,
		// hostPath is canonical with no ',' (validate.ts), and lives under the user's allowed root.
		'--mount', `type=bind,src=${hostPath},dst=${hostPath},readonly`,
		'--entrypoint', 'bash', GITLEAKS_IMAGE, '-c', SCRIPT];
	const r = await runner.run(docker, args, { timeoutMs: 1_200_000, maxOutputBytes: MAX_REPORT_BYTES });
	const res = parseFrames(r.stdoutBytes ?? Buffer.from(r.stdout), r.code, !!r.truncated);
	checkExternalLinks(res, hostPath);
	return res;
}

/**
 * Links that didn't resolve inside the workspace in the (case-sensitive, Linux) scanner may
 * still do so on the host: case-insensitive APFS (`Node_Modules/x`), firmlinks
 * (`/System/Volumes/Data/...`), other spellings of the real path. Resolve each on the
 * host and block any that land inside the workspace: their target was not scanned under
 * the link. Only stat-level calls; no content is read on the host.
 */
export function checkExternalLinks(res: ScanResult, hostPath: string): void {
	const root = fs.statSync(hostPath);
	for (const l of res.externalLinks ?? []) {
		const rel = workspaceRel(l, '/scan/ws/');
		if (!rel) {
			continue;
		}
		let real: string;
		try {
			real = fs.realpathSync.native(path.join(hostPath, rel));
		} catch {
			continue; // dangling on the host too: a write through it fails or lands nowhere the tab sees
		}
		for (let p = real; ; p = path.dirname(p)) {
			let st: fs.Stats | undefined;
			try {
				st = fs.statSync(p);
			} catch { /* keep walking up */ }
			if (st && st.dev === root.dev && st.ino === root.ino) {
				pushFinding('worktree', displayPath(rel), 1, 'unscanned-link-alias', undefined, false, '', res.findings, res.secrets);
				break;
			}
			if (path.dirname(p) === p) {
				break;
			}
		}
	}
}

/** Exported for tests. Keeps every finding it can parse, even when the scan is incomplete. */
export function parseFrames(buf: Buffer, exitCode: number | null, truncated: boolean): ScanResult {
	const findings: Finding[] = [];
	const secrets = new Map<string, string>();
	const seenValues = new Set<string>();
	const errors: string[] = [];
	let overflow = truncated;
	let ended = false;
	let links: string[] = [];
	const externalLinks: string[] = [];
	let off = 0;
	while (off < buf.length) {
		const nl = buf.indexOf(0x0a, off);
		const m = nl < 0 ? null : /^SECLAB1 ([a-z]+) ([0-9a-f]*) (\d+) (\d+)$/.exec(buf.subarray(off, nl).toString('latin1'));
		if (!m || !KINDS.has(m[1] as Kind)) {
			errors.push('malformed scanner output');
			break;
		}
		const kind = m[1] as Kind;
		const len = Number(m[4]);
		const body = buf.subarray(nl + 1, nl + 1 + len);
		off = nl + 1 + len;
		if (kind === 'end') {
			ended = true;
			if (off !== buf.length) {
				errors.push('trailing scanner output');
			}
			break;
		}
		if (body.length < len) {
			break; // truncated mid-frame
		}
		const rel = Buffer.from(m[2], 'hex').toString('utf8');
		const failed = m[3] !== '0';
		const unscanned = (src: Finding['source'], file: string, rule: string, commit?: string) =>
			pushFinding(src, displayPath(file), 1, rule, commit, false, '', findings, secrets);
		switch (kind) {
			case 'toomany':
				overflow = true;
				errors.push(`more than ${MAX_GIT_DIRS} git directories`);
				continue;
			case 'manylinks':
				overflow = true;
				errors.push('more than 500 symlinks');
				continue;
			case 'links':
				links = body.toString('utf8').split('\0').filter(Boolean);
				continue;
			case 'extlinks':
				externalLinks.push(...body.toString('utf8').split('\0').filter(Boolean));
				continue;
			case 'unreadable':
				for (const p of body.toString('utf8').split('\0').filter(Boolean)) {
					unscanned('worktree', workspaceRel(p, '/scan/ws/') ?? '.', 'unscanned-unreadable');
				}
				if (failed) {
					errors.push('some paths could not be listed or read');
				}
				continue;
			case 'finderr':
				// "find: <path>: <reason>" per line; the path may itself contain ': '.
				for (const lineText of body.toString('utf8').split('\n')) {
					const fm = /^find: (\/scan\/ws\/.*): [^:]+$/.exec(lineText);
					if (fm) {
						unscanned('worktree', workspaceRel(fm[1], '/scan/ws/') ?? '.', 'unscanned-unreadable');
					}
				}
				if (failed && !errors.includes('some paths could not be listed or read')) {
					errors.push('some paths could not be listed or read');
				}
				continue;
			case 'badgit':
				// Looks like a git dir (HEAD + objects/refs/commondir) but git rejects it: the tab
				// may have built it to dodge discovery. Block until the user decides.
				unscanned('git-dir', rel, 'unrecognised-git-dir');
				continue;
			case 'large':
				for (const p of body.toString('utf8').split('\0').filter(Boolean)) {
					unscanned('worktree', workspaceRel(p, '/scan/ws/') ?? '(unknown file)', 'unscanned-large-file');
				}
				if (failed) {
					overflow = true;
					errors.push('more than 200 files too large to scan');
				}
				continue;
			case 'largeobj':
				for (const sha of body.toString('latin1').split('\n').filter(s => /^[0-9a-f]{40,64}$/.test(s))) {
					unscanned('objects', objectStoreLabel(rel), 'unscanned-large-object', sha);
				}
				if (failed) {
					overflow = true;
					errors.push('more than 200 git objects too large to scan');
				}
				continue;
		}
		if (failed) {
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
		// gitleaks reports in nondeterministic (concurrent) order, and dedupe-by-value keeps
		// the first copy: sort, so finding ids are stable across rescans ("accept" must match).
		const mapped = raw.map(f => {
			if (kind !== 'linked') {
				return f;
			}
			// Content of a symlink target, copied to /seclab/l/x/<n> (file) or
			// /seclab/l/d/<n>/<path> (directory): report it under the link.
			const n = /^\/seclab\/l\/(x|d)\/(\d+)(\/.+)?$/.exec(String(f.File ?? ''));
			const link = n ? links[Number(n[2]) - 1] : undefined;
			return { ...f, File: link && n ? (n[1] === 'x' ? link : `${link}${n[3] ?? ''}`) : '' };
		}).sort((a, b) => cmp(String(a.File ?? ''), String(b.File ?? '')) || Number(a.StartLine) - Number(b.StartLine)
			|| cmp(String(a.RuleID ?? ''), String(b.RuleID ?? '')) || cmp(String(a.Commit ?? ''), String(b.Commit ?? '')) || cmp(String(a.Secret ?? ''), String(b.Secret ?? '')));
		for (const f of mapped) {
			if (kind === 'linked') {
				addFinding('worktree', '.', f, findings, secrets, seenValues, false);
			} else {
				addFinding(kind, rel, f, findings, secrets, seenValues);
			}
		}
	}
	if (!ended && !overflow) {
		errors.push(exitCode === null ? 'scanner did not finish (timeout or not runnable)' : `scanner exited ${exitCode} before finishing`);
	}
	if (overflow) {
		errors.unshift('scanner report too large to review');
	}
	const complete = ended && !overflow && errors.length === 0;
	return { complete, error: complete ? undefined : `secret scan incomplete: ${errors.join('; ')}`, overflow: overflow || undefined, findings, secrets, externalLinks };
}

const ID_KEY = randomBytes(32);

const cmp = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;

/** `/scan/ws/a/b` -> `a/b` (undefined if not strictly inside the prefix). */
function workspaceRel(p: string, prefix: string): string | undefined {
	if (!p.startsWith(prefix)) {
		return undefined;
	}
	const norm = path.posix.normalize(p.slice(prefix.length));
	return !norm || norm === '.' || norm.startsWith('..') || path.posix.isAbsolute(norm) ? undefined : norm;
}

function objectStoreLabel(repoRel: string): string {
	return repoRel === '.' ? '.git (object store)' : `${repoRel} (object store)`;
}

function addFinding(kind: 'worktree' | 'gitdir' | 'history' | 'objects', repoRel: string, f: RawFinding, findings: Finding[], secrets: Map<string, string>, seenValues: Set<string>, canMove = true): void {
	const secret = String(f.Secret ?? '');
	const rule = String(f.RuleID ?? 'unknown').replace(/[^A-Za-z0-9._-]/g, '').slice(0, 64);
	const commit = typeof f.Commit === 'string' && /^[0-9a-f]{7,64}$/.test(f.Commit) ? f.Commit : undefined;
	const line = Number(f.StartLine);
	const rawFile = String(f.File ?? '');
	let source: Finding['source'];
	let file: string;
	let plain = false;
	if (kind === 'objects') {
		source = 'objects';
		file = objectStoreLabel(repoRel);
	} else if (kind === 'history') {
		source = 'history';
		const repoDir = repoRel === '.' ? '' : repoRel.replace(/(^|\/)\.git$/, '');
		file = path.posix.join(repoDir || '.', rawFile);
	} else {
		// Current files: the worktree (reported under /scan/ws/, or the symlink target) or a
		// git dir copy (/seclab/g/x/<path inside the git dir>).
		source = kind === 'gitdir' ? 'git-dir' : 'worktree';
		const inner = kind === 'gitdir' ? workspaceRel(rawFile, '/seclab/g/x/') : workspaceRel(rawFile, '/scan/ws/');
		const rel = inner === undefined ? undefined : kind === 'gitdir' ? path.posix.join(repoRel, inner) : inner;
		file = rel ?? '(unknown file)';
		plain = rel !== undefined && rel === displayPath(rel);
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
	const movable = canMove && plain && okLine && !!secret && (source === 'worktree' || source === 'git-dir');
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
