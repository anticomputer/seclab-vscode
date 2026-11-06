// Pre-mount secret scanning (ADR 20261104-pre-mount-secret-scan). Runs gitleaks, built from
// pinned source, in a throwaway, network-less, read-only container BEFORE a workspace
// is mounted into a tab. Secret values are held only in supervisor memory (for "move to
// broker"); clients and logs only ever see redacted findings.

import { createHmac, randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Runner } from './run.ts';

// Built from the pinned gitleaks source by `./seclab tool gitleaks` (build/tools/tools.json:
// commit + reproducible binary sha256, attested in CI); never pulled. A missing image makes the
// scan fail, and opens fail closed (EDR 20261105-pinned-tools).
export const GITLEAKS_IMAGE = 'seclab-tool-gitleaks:8.30.1';
/** The reproducible binaries' sha256 (build/tools/tools.json binarySha256; a unit test keeps them equal). */
export const GITLEAKS_BIN_SHA256: Readonly<Record<string, string>> = {
	arm64: '6949cfae1df1f37a89c6b72d0e118115ea3bb2761d384ddd12d48b45fd48b701',
	amd64: 'e0e51d58e7592cd4f373043333cc2cd84c6564625bce5acd6d10a04985cce637',
};

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
: > "$O/ignore"; mkdir "$O/empty" "$O/g" "$O/tmp"; cd "$O/empty" || exit 3
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
# gitleaks skips a file (or a whole stdin stream) whose FIRST chunk carries an
# application/* magic (sources/file.go at 83d9cd6), so a tab could blind .env with a zip
# header and wait for the user to append a token. Every stdin stream starts with 128 KiB of
# newlines (a pipe read is at most 100 KB, so the first chunk is blank), and every file a
# dir pass skipped as binary is rescanned as text, mapped back by line offsets.
PADL=131072
pad() { head -c $PADL /dev/zero | tr '\0' '\n'; }
# zerolog (console) Go-quotes a value with spaces, non-ASCII, control chars, '"' or '\'.
gounquote() {
  local q=$1 r
  case "$q" in \"*\") ;; *) printf '%s' "$q"; return ;; esac
  q=${$}{q:1:-1}; q=${$}{q//\\\\/$'\001'}; q=${$}{q//\\\"/\"}; q=${$}{q//$'\001'/\\\\}
  r=$(printf '%b' "$q"; printf x); printf '%s' "${$}{r%x}"
}
gdir() {
  timeout 300 gitleaks dir "$3" $GL --no-color --log-level debug --max-archive-depth 8 --max-target-megabytes $LIM --report-path "$O/r.json" 2>&1 >/dev/null \
    | grep -a -E ' (WRN|ERR) |skipping binary file' > "$O/glog"; local rc=${$}{PIPESTATUS[0]}
  emit "$1" "$2" "$rc" "$O/r.json"
  # Every gitleaks warning/error (unopenable archive, temp-file failure, permission, ...)
  # blocks on its path, or makes the scan incomplete: never an allow-list of messages.
  # (Only its normal summary line "leaks found: N" is not a warning about coverage.)
  grep -a -E ' (WRN|ERR) ' "$O/glog" | grep -a -v -E ' WRN leaks found: [0-9]+$' > "$O/warn"
  emit warnings "$1:$2" 0 "$O/warn"
  grep -a 'skipping binary file' "$O/glog" > "$O/binlog"
  rm -f "$O/glog" "$O/warn"
  [ -s "$O/binlog" ] || { rm -f "$O/binlog"; return 0; }
  : > "$O/binmap"; : > "$O/binbad"; : > "$O/amap"; : > "$O/unarch"; rm -rf "$O/a"; mkdir -p "$O/a"
  { pad; local L=$((PADL+1)) p n line mime ext k=0
    while IFS= read -r line; do
      p=$(gounquote "${$}{line#* path=}")
      if [ ! -f "$p" ]; then
        # An archive member ("outer.zip!inner"): a user never appends to one, so a magic
        # header there can't hide a later secret. Anything else unexpected: incomplete.
        case "$p" in *'!'*) [ -f "${$}{p%%!*}" ] && continue ;; esac
        echo 1 > "$O/binbad"; continue
      fi
      # Archives gitleaks didn't recognise by name (.jar, .docx, .whl, renamed .gz, ...):
      # scan them as archives under a name it does recognise.
      mime=${$}{line#*mime_type=}; mime=${$}{mime%% *}
      case "$mime" in
        application/zip|application/java-archive|application/epub+zip|application/vnd.openxmlformats*|application/vnd.oasis.opendocument*|application/x-zip*) ext=zip ;;
        application/gzip|application/x-gzip) ext=gz ;; application/x-xz) ext=xz ;; application/zstd) ext=zst ;;
        application/x-bzip2) ext=bz2 ;; application/x-7z-compressed) ext=7z ;; application/vnd.rar|application/x-rar*) ext=rar ;;
        application/x-tar) ext=tar ;;
        application/x-compress|application/x-lzip|application/x-lz4|application/vnd.ms-cab-compressed|application/x-deb|application/vnd.debian.binary-package|application/x-rpm|application/x-cpio|application/x-unix-archive|application/x-archive)
          # Compressed/archive formats gitleaks can't open: block (via a synthetic warning).
          ext=; printf 'X WRN unsupported archive type path=%s\n' "$p" >> "$O/unarch" ;;
        *) ext= ;;
      esac
      if [ -n "$ext" ]; then
        k=$((k+1)); cp "$p" "$O/a/$k.$ext" || echo 1 > "$O/binbad"; printf '%s\0' "$p" >> "$O/amap"
      fi
      # Also as text: a fake archive (magic header + plain text) must not hide its content.
      printf '%s\0%s\0' "$p" "$((L+1))" >> "$O/binmap"
      n=$(tr -cd '\n' < "$p" | wc -c); L=$((L+n+2))
      printf '\n'; cat "$p"; printf '\n'
    done < "$O/binlog"; } | timeout 300 gitleaks stdin $GL --report-path "$O/rb.json"; rc=$?
  [ ! -s "$O/binbad" ] || rc=1
  # Archive pass first, so a member finding ("app.jar!x") wins over the raw-bytes copy.
  if [ -s "$O/amap" ]; then
    emit amap "$1" 0 "$O/amap"
    timeout 300 gitleaks dir "$O/a" $GL --no-color --log-level warn --max-archive-depth 8 --max-target-megabytes $LIM --report-path "$O/r.json" 2>"$O/warn"
    emit arch "$2" $? "$O/r.json"
    grep -a -E ' (WRN|ERR) ' "$O/warn" | grep -a -v -E ' WRN leaks found: [0-9]+$' > "$O/warn2"; emit warnings "arch:$2" 0 "$O/warn2"; rm -f "$O/warn" "$O/warn2"
  fi
  emit binmap "$1" 0 "$O/binmap"
  emit bin "$2" "$rc" "$O/rb.json"
  if [ -s "$O/unarch" ]; then emit warnings "$1:$2" 0 "$O/unarch"; fi
  rm -rf "$O/binlog" "$O/binbad" "$O/amap" "$O/a" "$O/unarch"
}
gdir worktree . /scan
# gitleaks reads nothing (and logs nothing) from an archive nested inside a tar-family
# archive (zip-in-tar.gz, tgz-in-tgz): block those outer archives as unscanned.
: > "$O/nest"
while IFS= read -r -d '' f; do
  lf=$(printf '%s' "$f" | tr 'A-Z' 'a-z')
  case "$lf" in
    *.tar) m=$(tar -tf "$f" 2>/dev/null) ;; *.tgz|*.tar.gz) m=$(tar -tzf "$f" 2>/dev/null) ;;
    *.tbz|*.tbz2|*.tar.bz2) m=$(tar -tjf "$f" 2>/dev/null) ;; *.txz|*.tar.xz) m=$(tar -tJf "$f" 2>/dev/null) ;;
    *) continue ;;
  esac
  printf '%s\n' "$m" | grep -qiE '\.(zip|jar|war|ear|apk|aar|whl|nupkg|vsix|docx|xlsx|pptx|odt|ods|epub|tar|tgz|tbz2?|txz|gz|bz2|xz|zst|7z|rar)$' \
    && printf '%s\0' "$f" >> "$O/nest"
done < <(find /scan/ws -xdev -name node_modules -prune -o -type f -print0)
emit nested . 0 "$O/nest"
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
    # Never a link into its own ancestor (that content is the worktree itself). Every other
    # directory target is copied and scanned under the link (bounded by the tmpfs; running
    # out makes the scan incomplete, never silent).
    case "$l/" in "$t"/*) continue ;; esac
    i=$((i+1)); if [ "$i" -gt 500 ]; then flag manylinks . 1; break; fi
    mkdir "$O/l/d/$i" && copy "$t" "$O/l/d/$i" || lf=1
  else
    continue
  fi
  printf '%s\0' "$l" >> "$O/links"
done < <(find /scan/ws -xdev -name node_modules -prune -o -type l -print0 | sort -z)
emit links . 0 "$O/links"
gdir linked . "$O/l"
[ "$lf" = 0 ] || flag linkcopy . 1
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
    if copy "$d" "$O/g/x"; then gdir gitdir "$drel" "$O/g"; else flag gitdir "$drel" 1; fi
  done
  [ -z "${$}{seen[repo:$common]:-}" ] || continue
  seen[repo:$common]=1
  GIT_DIR=$gd timeout 300 gitleaks git "$O/empty" $GL --log-opts="--all --reflog --text --no-textconv --no-ext-diff" --report-path "$O/r.json"
  emit history "$rel" $? "$O/r.json"
  ( set -o pipefail; export GIT_DIR=$gd
    git cat-file --batch-all-objects --batch-check='%(objectname) %(objecttype) %(objectsize)' \
      | awk -v L=$((LIM*1000000)) -v B="$O/big" '($2=="blob"||$2=="commit"||$2=="tag") { if ($3 <= L) print $1; else print $1 > B }' \
      | { pad; git cat-file --batch; } | timeout 300 gitleaks stdin $GL --report-path "$O/r.json" )
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

type Kind = 'worktree' | 'large' | 'unreadable' | 'finderr' | 'links' | 'linked' | 'linkcopy' | 'extlinks' | 'manylinks' | 'warnings' | 'nested' | 'amap' | 'arch' | 'binmap' | 'bin' | 'gitdir' | 'history' | 'objects' | 'largeobj' | 'badgit' | 'toomany' | 'end';
const KINDS = new Set<Kind>(['worktree', 'large', 'unreadable', 'finderr', 'links', 'linked', 'linkcopy', 'extlinks', 'manylinks', 'warnings', 'nested', 'amap', 'arch', 'binmap', 'bin', 'gitdir', 'history', 'objects', 'largeobj', 'badgit', 'toomany', 'end']);

/** Scanner path of a file seen by a dir pass -> workspace-relative path ("a.zip!m" kept). */
function mapScannerPath(parent: string, rel: string, p: string, links: string[]): string | undefined {
	if (parent === 'gitdir') {
		const inner = workspaceRel(p, '/seclab/g/x/');
		return inner === undefined ? undefined : path.posix.join(rel, inner);
	}
	if (parent === 'linked') {
		// /seclab/l/x/<n>[!member] (file link) or /seclab/l/d/<n>/<path> (directory link)
		const n = /^\/seclab\/l\/(x|d)\/(\d+)(.*)$/.exec(p);
		const link = n ? links[Number(n[2]) - 1] : undefined;
		return link && n ? workspaceRel(`${link}${n[3]}`, '/scan/ws/') : undefined;
	}
	return workspaceRel(p, '/scan/ws/');
}

/** Decode a Go strconv.Quote'd value (as zerolog's console writer emits); raw otherwise. */
export function goUnquote(v: string): string {
	if (!(v.length >= 2 && v.startsWith('"') && v.endsWith('"'))) {
		return v;
	}
	const s = v.slice(1, -1);
	const bytes: number[] = [];
	const simple: Record<string, number> = { a: 7, b: 8, f: 12, n: 10, r: 13, t: 9, v: 11, '\\': 92, '"': 34, '\'': 39 };
	for (let i = 0; i < s.length; i++) {
		if (s[i] !== '\\') {
			bytes.push(...Buffer.from(String.fromCodePoint(s.codePointAt(i)!), 'utf8'));
			if (s.codePointAt(i)! > 0xffff) {
				i++;
			}
			continue;
		}
		const e = s[++i];
		if (e in simple) {
			bytes.push(simple[e]);
		} else if (e === 'x') {
			bytes.push(parseInt(s.slice(i + 1, i + 3), 16));
			i += 2;
		} else if (e === 'u' || e === 'U') {
			const len = e === 'u' ? 4 : 8;
			bytes.push(...Buffer.from(String.fromCodePoint(parseInt(s.slice(i + 1, i + 1 + len), 16)), 'utf8'));
			i += len;
		}
	}
	return Buffer.from(bytes).toString('utf8');
}

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

// The image is trusted by name only as far as its scanner binary is the pinned one (TT-2): any
// local `docker tag` or another worktree's build can produce the name. The name is resolved to
// an image id once, the binary is checked in that exact image, and every scan runs by that id,
// so a later retag of the name changes nothing (UU-4). Re-checked after a failure.
let scannerCheck: Promise<{ problem?: string; image?: string }> | undefined;
function checkScanner(runner: Runner, docker: string): Promise<{ problem?: string; image?: string }> {
	scannerCheck ??= (async () => {
		const unavailable = `secret scanner image ${GITLEAKS_IMAGE} unavailable (run ./seclab tool gitleaks)`;
		const inspect = await runner.run(docker, ['image', 'inspect', '--format', '{{.Id}}', GITLEAKS_IMAGE], { timeoutMs: 30_000 });
		const id = inspect.stdout.trim();
		if (inspect.code !== 0 || !/^sha256:[0-9a-f]{64}$/.test(id)) {
			return { problem: unavailable };
		}
		const r = await runner.run(docker, ['run', '--rm', '--pull', 'never', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
			'--security-opt', 'no-new-privileges', '--user', '65534:65534', '--entrypoint', 'sha256sum', id, '/usr/bin/gitleaks'], { timeoutMs: 60_000 });
		const got = /^([0-9a-f]{64})\s/.exec(r.stdout)?.[1];
		if (r.code !== 0 || !got) {
			return { problem: unavailable };
		}
		return Object.values(GITLEAKS_BIN_SHA256).includes(got) ? { image: id }
			: { problem: `secret scanner image ${GITLEAKS_IMAGE} does not carry the pinned gitleaks binary (sha256 ${got.slice(0, 12)}…); rebuild with ./seclab tool gitleaks` };
	})().catch((e: Error) => ({ problem: `secret scanner check failed: ${e.message}` })).then(c => {
		if (c.problem) {
			scannerCheck = undefined;
		}
		return c;
	});
	return scannerCheck;
}

export async function scannerProblem(runner: Runner, docker: string): Promise<string | undefined> {
	return (await checkScanner(runner, docker)).problem;
}

export async function scanWorkspace(runner: Runner, docker: string, hostPath: string): Promise<ScanResult> {
	const scanner = await checkScanner(runner, docker);
	if (!scanner.image) {
		return { complete: false, error: scanner.problem ?? 'secret scanner unavailable', findings: [], secrets: new Map() };
	}
	const env = GIT_OVERRIDES.flatMap(([k, v], i) => ['-e', `GIT_CONFIG_KEY_${i}=${k}`, '-e', `GIT_CONFIG_VALUE_${i}=${v}`]);
	const user = scanUser(hostPath);
	const [uid, gid] = user.split(':');
	const args = ['run', '--rm', '--pull', 'never', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
		'--user', user, '--pids-limit', '256', '--memory', '2g',
		// Nested zip/7z members are extracted to $TMPDIR; the root filesystem is read-only.
		'--tmpfs', `/seclab:rw,noexec,nosuid,nodev,size=768m,mode=0700,uid=${uid},gid=${gid}`, '--workdir', '/',
		'-e', 'HOME=/seclab', '-e', 'TMPDIR=/seclab/tmp', '-e', 'GIT_CONFIG_NOSYSTEM=1', '-e', 'GIT_CONFIG_GLOBAL=/dev/null', '-e', 'GIT_ATTR_NOSYSTEM=1',
		'-e', 'GIT_NO_REPLACE_OBJECTS=1', '-e', 'GIT_TERMINAL_PROMPT=0', '-e', `GIT_CONFIG_COUNT=${GIT_OVERRIDES.length}`, ...env,
		'-e', `SECLAB_GITLEAKS_TOML=${CONFIG}`, '-e', `SECLAB_WS=${hostPath}`,
		'--mount', `type=bind,src=${hostPath},dst=/scan/ws,readonly`,
		// hostPath is canonical with no ',' (validate.ts), and lives under the user's allowed root.
		'--mount', `type=bind,src=${hostPath},dst=${hostPath},readonly`,
		'--entrypoint', 'bash', scanner.image, '-c', SCRIPT];
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
	let links: string[] = [];
	let binmap: Array<{ path: string; start: number }> = [];
	let binParent = '';
	let amap: string[] = [];
	let amapParent = '';

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
				// A link that doesn't resolve inside the workspace in the scanner can't be shown
				// harmless without resolving tab-chosen paths on the host (automount/DNS, review
				// round 8 D2) or enumerating every spelling of the host path (round 9 E1): block.
				for (const p of body.toString('utf8').split('\0').filter(Boolean)) {
					unscanned('worktree', workspaceRel(p, '/scan/ws/') ?? '(unknown link)', 'unscanned-link');
				}
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
				// "find: <path>: <reason>" per line; the path may itself contain ': '. GNU find
				// quotes the path C-style inside '…' (\\ \' \n \t, \ooo octal bytes; TT-3); busybox
				// prints it bare. Any other find: line still counts, against the workspace as a whole.
				for (const lineText of body.toString('utf8').split('\n')) {
					const fm = /^find: (?:'(\/scan\/ws\/(?:[^'\\]|\\.)*)'|(\/scan\/ws\/.*)): [^:]+$/.exec(lineText);
					if (fm) {
						const p = fm[1] !== undefined ? unquoteFindPath(fm[1]) : fm[2];
						unscanned('worktree', workspaceRel(p, '/scan/ws/') ?? '.', 'unscanned-unreadable');
					} else if (lineText.startsWith('find: ')) {
						unscanned('worktree', '.', 'unscanned-unreadable');
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
			case 'linkcopy':
				errors.push('some symlink targets could not be copied for scanning');
				continue;
			case 'warnings': {
				// "<parent kind>:<rel>" (or "arch:<rel>" for the renamed-archive pass). Any gitleaks
				// WRN/ERR line blocks on its path; one without a path makes the scan incomplete.
				const sep = rel.indexOf(':');
				const parent = rel.slice(0, sep);
				const prel = rel.slice(sep + 1);
				for (const lineText of body.toString('utf8').split('\n').filter(Boolean)) {
					const at = lineText.indexOf(' path=');
					if (at < 0) {
						errors.push(`scanner warning: ${displayPath(lineText.replace(/^\S+ (WRN|ERR) /, '')).slice(0, 160)}`);
						continue;
					}
					let scannerPath = goUnquote(lineText.slice(at + ' path='.length)).split('!')[0];
					let kindOf = parent;
					if (parent === 'arch') {
						const a = /^\/seclab\/a\/(\d+)\.[a-z0-9]+$/.exec(scannerPath);
						scannerPath = a ? amap[Number(a[1]) - 1] ?? '' : '';
						kindOf = amapParent;
					}
					const rule = /archive|compressed|tmp file/i.test(lineText) ? 'unscanned-archive' : 'unscanned-warning';
					unscanned('worktree', mapScannerPath(kindOf, prel, scannerPath, links) ?? '(unknown file)', rule);
				}
				continue;
			}
			case 'nested':
				for (const p of body.toString('utf8').split('\0').filter(Boolean)) {
					unscanned('worktree', workspaceRel(p, '/scan/ws/') ?? '(unknown archive)', 'unscanned-archive');
				}
				continue;
			case 'amap':
				amap = body.toString('utf8').split('\0').filter(Boolean);
				amapParent = rel;
				continue;
			case 'binmap': {
				// Pairs "<scanner path>\0<first stream line>\0" for the rescan of files the
				// <rel>-kind dir pass skipped as binary.
				const parts = body.toString('utf8').split('\0');
				binmap = [];
				for (let k = 0; k + 1 < parts.length; k += 2) {
					binmap.push({ path: parts[k], start: Number(parts[k + 1]) });
				}
				binParent = rel;
				continue;
			}
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
		let as: 'worktree' | 'linked' | 'gitdir' | 'history' | 'objects';
		if (kind === 'bin') {
			// Map stream lines back to the binary-looking file they came from.
			if (binParent !== 'worktree' && binParent !== 'linked' && binParent !== 'gitdir') {
				errors.push('binary rescan without a map');
				continue;
			}
			as = binParent;
			const map = binmap;
			raw = raw.map(f => {
				const line = Number(f.StartLine);
				let hit: { path: string; start: number } | undefined;
				for (const e of map) {
					if (e.start <= line && (!hit || e.start > hit.start)) {
						hit = e;
					}
				}
				return hit ? { ...f, File: hit.path, StartLine: line - hit.start + 1 } : { ...f, File: '' };
			});
		} else if (kind === 'arch') {
			// Renamed archives copied to /seclab/a/<n>.<ext>: map back to the original file.
			if (amapParent !== 'worktree' && amapParent !== 'linked' && amapParent !== 'gitdir') {
				errors.push('archive rescan without a map');
				continue;
			}
			as = amapParent;
			raw = raw.map(f => {
				const a = /^\/seclab\/a\/(\d+)\.[a-z0-9]+(!.*)?$/.exec(String(f.File ?? ''));
				const orig = a ? amap[Number(a[1]) - 1] : undefined;
				return { ...f, File: orig ? `${orig}${a?.[2] ?? ''}` : '' };
			});
		} else {
			as = kind;
		}
		// gitleaks reports in nondeterministic (concurrent) order, and dedupe-by-value keeps
		// the first copy: sort, so finding ids are stable across rescans ("accept" must match).
		const mapped = raw.map(f => {
			if (as !== 'linked') {
				return f;
			}
			// Content of a symlink target, copied to /seclab/l/x/<n>[!member] (file) or
			// /seclab/l/d/<n>/<path> (directory): report it under the link.
			const n = /^\/seclab\/l\/(x|d)\/(\d+)(.*)$/.exec(String(f.File ?? ''));
			const link = n ? links[Number(n[2]) - 1] : undefined;
			return { ...f, File: link && n ? `${link}${n[3]}` : '' };
		}).sort((a, b) => cmp(String(a.File ?? ''), String(b.File ?? '')) || Number(a.StartLine) - Number(b.StartLine)
			|| cmp(String(a.RuleID ?? ''), String(b.RuleID ?? '')) || cmp(String(a.Commit ?? ''), String(b.Commit ?? '')) || cmp(String(a.Secret ?? ''), String(b.Secret ?? '')));
		for (const f of mapped) {
			if (as === 'linked') {
				addFinding('worktree', '.', f, findings, secrets, seenValues, false);
			} else {
				addFinding(as, rel, f, findings, secrets, seenValues, kind !== 'bin');
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
	return { complete, error: complete ? undefined : `secret scan incomplete: ${errors.join('; ')}`, overflow: overflow || undefined, findings, secrets };
}

const ID_KEY = randomBytes(32);

/** GNU find's C-style quoting inside '…' (gnulib quotearg, c_maybe style), back to the raw path. */
export function unquoteFindPath(s: string): string {
	const bytes: number[] = [];
	const C: Record<string, number> = { a: 7, b: 8, f: 12, n: 10, r: 13, t: 9, v: 11, '\\': 92, '\'': 39, '"': 34, '?': 63 };
	for (let i = 0; i < s.length; i++) {
		if (s[i] !== '\\' || i + 1 >= s.length) {
			bytes.push(...Buffer.from(s[i], 'utf8'));
			continue;
		}
		const oct = /^[0-7]{1,3}/.exec(s.slice(i + 1))?.[0];
		if (oct) {
			bytes.push(parseInt(oct, 8) & 0xff);
			i += oct.length;
		} else if (C[s[i + 1]] !== undefined) {
			bytes.push(C[s[i + 1]]);
			i++;
		} else {
			bytes.push(92);
		}
	}
	return Buffer.from(bytes).toString('utf8');
}

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
	// Archive members ("a.tar.gz!inner") can't be rewritten in place.
	const movable = canMove && plain && okLine && !!secret && !file.includes('!') && (source === 'worktree' || source === 'git-dir');
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
