#!/bin/sh
# Release-artifact check (EDR patch-series): a shipped build must contain no test hooks.
#   build/check-release.sh [--desktop] PATH...   (.app/Contents/Resources/app dir, a dir, or .tar.gz/.zip)
# Fails on:
#   - test-hook markers: SECLAB_TEST_ONLY / seclab-test-hook / rogue-reh / rogue-extension
#     (any code meant only for tests must carry SECLAB_TEST_ONLY so this finds it), and
#     `seclabTestBuild`, the positive marker every test build variant's product.json carries
#     (build/test-variant.sh; EDR test-build-variants);
#   - environment-controlled module loading: require()/import() of a path taken from
#     process.env (a classic test hook that becomes a backdoor in a release);
#   - a path with no JS at all (wrong path = no check), or any scan error (fail closed).
# --desktop (the trusted app, never the REH; invariant I8, EDR agent-runtimes-exception): also
# fails on any agent runtime, on disk or listed in an asar header (the Copilot SDK and its
# platform package, runtime.node, Codex, the Claude agent SDK), and on `agentSdks` in product.json.
# Locally it runs in a container (nothing on the host). On CI runners without docker
# (hosted macOS) it runs the same POSIX sh/find/grep logic natively.
set -eu

# The RPC filter stamp this tree's patches/series implies (prepare.sh step 7): "absent" unless
# 0005 is listed, else the sha256 of the policy table 0005 creates, taken from its new-file hunk.
# A series where another patch also touches the table can't be derived here: fail closed.
RPC_POLICY_REL=src/vs/workbench/services/extensions/common/seclabPolicyData.ts
sha256_file() { # no pipeline: a missing or failing hasher must fail, not print nothing
	if command -v sha256sum >/dev/null 2>&1; then s=$(sha256sum "$1") || return 1; else s=$(shasum -a 256 "$1") || return 1; fi
	printf '%s\n' "${s%% *}"
}
rpc_expect() { # $1 = patches dir, $2 = scratch file; prints absent|<sha256>, or fails
	[ -f "$1/series" ] || { echo "check-release: no patches/series at $1" >&2; return 1; }
	sed -e 's/#.*//' "$1/series" > "$2.series" || return 1
	listed=$(tr -d ' \t\r' < "$2.series" | grep -v '^$' || true)
	p=$(printf '%s\n' "$listed" | grep -E '^0005-[A-Za-z0-9._-]+\.patch$' | head -1 || true)
	[ -n "$p" ] || { echo absent; return 0; }
	for q in $listed; do
		[ "$q" = "$p" ] && continue
		if grep -q "^+++ b/$RPC_POLICY_REL" "$1/$q"; then echo "check-release: $q also changes $RPC_POLICY_REL" >&2; return 1; fi
	done
	# No pipeline: dash has no pipefail, and a failed extraction must not hash to a value.
	awk -v hdr="+++ b/$RPC_POLICY_REL" '
		index($0, hdr) == 1 { f = 1; next }
		f && /^diff / { exit }
		f && /^@@ / { if ($0 !~ /^@@ -0,0 /) bad = 1; next }
		f && /^\\ No newline/ { nonl = 1; next }
		f && /^\+/ { l[n++] = substr($0, 2); next }
		f { bad = 1 }
		END { if (bad || !n) exit 3; for (i = 0; i < n; i++) { printf "%s", l[i]; if (i < n - 1 || !nonl) printf "\n" } }' "$1/$p" > "$2" \
		|| { echo "check-release: cannot read $RPC_POLICY_REL from $p as a new file" >&2; return 1; }
	sha256_file "$2"
}
if [ "${1:-}" = "--self-test" ]; then
	# The RPC stamp both ways (prepare.sh step 7), on fixture roots and fake patch queues.
	SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
	T="${SECLAB_SCRATCH:-$(cd "$(dirname "$SELF")/.." && pwd)/.work}/check-release-self-test"
	rm -rf "$T"; mkdir -p "$T/root" "$T/no5" "$T/with5" "$T/two" "$T/nonl"
	trap 'rm -rf "$T"' EXIT
	echo 'var x=1;' > "$T/root/a.js"
	printf '0001-a.patch\n' > "$T/no5/series"; : > "$T/no5/0001-a.patch"
	mk5() { # $1 dir, $2 trailing line(s) after the hunk
		printf '0001-a.patch\n0005-rpc.patch # comment\n' > "$1/series"; : > "$1/0001-a.patch"
		printf 'diff -ruN a/%s b/%s\n--- a/%s\t1970-01-01\n+++ b/%s\t2026-11-06\n@@ -0,0 +1,2 @@\n+a\n+b\n%b' "$RPC_POLICY_REL" "$RPC_POLICY_REL" "$RPC_POLICY_REL" "$RPC_POLICY_REL" "$2" > "$1/0005-rpc.patch"
	}
	mk5 "$T/with5" 'diff -ruN a/x b/x\n'
	mk5 "$T/nonl" '\\ No newline at end of file\n'
	mk5 "$T/two" ''; printf '0001-a.patch\n0005-rpc.patch\n0006-b.patch\n' > "$T/two/series"; printf '+++ b/%s\n' "$RPC_POLICY_REL" > "$T/two/0006-b.patch"
	hab=$(printf 'a\nb\n' | { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi; } | cut -c1-64)
	habn=$(printf 'a\nb' | { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi; } | cut -c1-64)
	stamp() { printf '{\n\t"nameShort": "x",\n\t"seclabRpcPolicy": {\n\t\t"sha256": "%s",\n\t\t"file": "%s"\n\t}\n}\n' "$1" "$RPC_POLICY_REL" > "$T/root/product.json"; }
	run() { # $1 patches dir, $2 expect pass|fail, $3 what, $4 mode (default release)
		if SECLAB_PATCHES="$1" sh "$SELF" --inner "$T/w" "${4:-release}" "$T/root" >"$T/out" 2>&1; then r=pass; else r=fail; fi
		rm -rf "$T/w"
		[ "$r" = "$2" ] || { cat "$T/out" >&2; echo "check-release self-test: $3: got $r, want $2" >&2; exit 1; }
	}
	echo '{"nameShort":"x"}' > "$T/root/product.json"
	run "$T/no5" pass "no 0005, no stamp"
	run "$T/with5" fail "0005 listed, no stamp"
	stamp "$hab"; run "$T/with5" pass "0005 listed, its table's hash"
	run "$T/no5" fail "a stamp without 0005"
	stamp "$habn"; run "$T/with5" fail "0005 listed, another hash"
	run "$T/nonl" pass "0005 without a final newline, its hash"
	stamp "$hab"; run "$T/two" fail "another patch also changes the table"
	# DDD: a commented-out 0005 is absent; CRLF in series still lists it; a duplicate key fails.
	printf '0001-a.patch\n# 0005-rpc.patch\n' > "$T/no5/series"
	echo '{"nameShort":"x"}' > "$T/root/product.json"; run "$T/no5" pass "0005 only in a comment: absent"
	printf '0001-a.patch\r\n0005-rpc.patch\r\n' > "$T/with5/series"
	stamp "$hab"; run "$T/with5" pass "CRLF series still lists 0005"
	printf '{"seclabRpcPolicy":{"sha256":"%s"},"x":{"seclabRpcPolicy":{"sha256":"%s"}}}\n' "$hab" "$hab" > "$T/root/product.json"
	run "$T/with5" fail "a duplicate nested seclabRpcPolicy"
	# The RPC filter's enforcing marker, each defect injected first: missing from the app with
	# 0005 listed, naming another table, present without 0005; then the right one passes, and
	# the REH (no workbench) needs none.
	stamp "$hab"
	run "$T/with5" fail "desktop, 0005 listed, enforcing marker missing" desktop
	echo "var m=\"seclabRpcFilterEnforcing:$habn\";" > "$T/root/m.js"
	run "$T/with5" fail "an enforcing marker naming another table" desktop
	echo "var m=\"seclabRpcFilterEnforcing:$hab\";" > "$T/root/m.js"
	# Background windows (patch 0012): the bootstrap policy, the guard's policy and the window
	# level must all be in the desktop app; each missing one fails.
	bgfix() { printf 'var g="[background windows] activation policy: prohibited (guard)";var w="is below normal windows";\n' > "$T/root/g.js"; printf 'var b="[background windows] activation policy: prohibited (bootstrap)";\n' > "$T/root/b.js"; }
	bgfix; rm "$T/root/b.js"
	run "$T/with5" fail "desktop without the bootstrap background policy" desktop
	bgfix; printf 'var w="is below normal windows";\n' > "$T/root/g.js"
	run "$T/with5" fail "desktop with the bootstrap policy but not the guard's (review QQQ-2)" desktop
	bgfix; printf 'var g="[background windows] activation policy: prohibited (guard)";\n' > "$T/root/g.js"
	run "$T/with5" fail "desktop without the below-normal window level" desktop
	bgfix
	run "$T/with5" pass "desktop, 0005 listed, its enforcing marker" desktop
	rm "$T/root/g.js" "$T/root/b.js"
	echo '{"nameShort":"x"}' > "$T/root/product.json"
	run "$T/no5" fail "an enforcing marker without 0005"
	rm "$T/root/m.js"; stamp "$hab"
	run "$T/with5" pass "the REH (release mode), 0005 listed, no workbench marker needed"
	rm -rf "$T/root"; mkdir -p "$T/root"; echo 'var x=1;' > "$T/root/a.js"
	run "$T/no5" fail "no product.json at all"
	echo "check-release self-test: ok"
	exit 0
fi

if [ "${1:-}" = "--inner" ]; then
	shift
	WORK="$1"; MODE="$2"; shift 2
	mkdir -p "$WORK"; : > "$WORK/roots"; n=0
	for p in "$@"; do
		n=$((n+1)); d="$WORK/$n"
		case "$p" in
			*.tar.gz|*.tgz) mkdir -p "$d"; tar -xzf "$p" -C "$d" ;;
			*.zip) mkdir -p "$d"; unzip -q "$p" -d "$d" ;;
			*) d="$p" ;;
		esac
		echo "$d" >> "$WORK/roots"
	done
	bad=0
	# The RPC stamp every app product.json must carry (or must not): from SECLAB_PATCHES (the
	# container's read-only mount) or the patches/ next to this script.
	pdir="${SECLAB_PATCHES:-$(cd "$(dirname "$0")/.." && pwd)/patches}"
	if ! rpc_exp=$(rpc_expect "$pdir" "$WORK/rpc-policy-table"); then
		echo "check-release: cannot derive the expected RPC policy stamp"; bad=1; rpc_exp=""
	fi
	# Only "absent" or a sha256 is an expectation; anything else (an empty hash) fails (DDD-1).
	case "$rpc_exp" in
		absent|"") ;;
		*) printf '%s' "$rpc_exp" | grep -Eq '^[0-9a-f]{64}$' || { echo "check-release: bad RPC policy expectation"; bad=1; rpc_exp=""; } ;;
	esac
	[ -n "$rpc_exp" ] || bad=1
	scan() { # $1 = ERE, $2 = label; grep exit 1 = no match, >1 = error (fail closed)
		set +e
		# -a: a NUL byte must not hide a file. JS/JSON plus shell launchers (bin/, *.sh).
		out=$(find "$d" -type f \( -name "*.js" -o -name "*.mjs" -o -name "*.cjs" -o -name "*.json" -o -name "*.sh" -o -path "*/bin/*" \) -exec grep -HaoE "$1" {} + 2>&1)
		rc=$?
		set -e
		if [ "$rc" -gt 1 ]; then echo "check-release: scan error ($2): $(echo "$out" | head -3)"; bad=1; return 0; fi
		[ -z "$out" ] || { echo "check-release: $2:"; echo "$out" | head -20; bad=1; }
	}
	while IFS= read -r d; do
		[ -n "$(find "$d" -type f -name "*.js" | head -1)" ] || { echo "check-release: no JS files under $d (wrong path?)"; bad=1; }
		scan "SECLAB_TEST_ONLY|seclab-test-hook|rogue-reh|rogue-extension|seclabTestBuild" "test-hook marker"
		scan "(require|import)\([[:space:]]*process\.env(\.[A-Za-z_]+|\[)[^)]{0,80}\)" "env-controlled module load"
		# The RPC filter stamp (prepare.sh step 7), both directions, in every app product.json.
		prods=$(find "$d" -type f -name product.json -not -path "*/extensions/*" -not -path "*/node_modules/*" 2>/dev/null)
		[ -n "$prods" ] || { echo "check-release: no product.json under $d"; bad=1; }
		while IFS= read -r pj; do
			[ -n "$pj" ] && [ -n "$rpc_exp" ] || continue
			flat=$(tr -d ' \t\r\n' < "$pj")
			# Exactly one seclabRpcPolicy key when stamped, none otherwise (DDD-2).
			rest=${flat#*\"seclabRpcPolicy\"}
			case "$flat" in *'"seclabRpcPolicy"'*) has=1 ;; *) has=0 ;; esac
			case "$rest" in *'"seclabRpcPolicy"'*) has=2 ;; esac
			got=$(printf '%s' "$flat" | sed -n 's/.*"seclabRpcPolicy":{"sha256":"\([0-9a-f]\{64\}\)".*/\1/p')
			if [ "$rpc_exp" = absent ]; then
				[ "$has" = 0 ] || { echo "check-release: RPC policy stamp in $pj, but patches/series has no 0005"; bad=1; }
			elif [ "$has" != 1 ]; then
				echo "check-release: $pj must carry exactly one seclabRpcPolicy (found ${has})"; bad=1
			elif [ "$got" != "$rpc_exp" ]; then
				echo "check-release: RPC policy stamp in $pj is '${got:-missing}', expected $rpc_exp (0005's table)"; bad=1
			fi
		done <<EOF
$prods
EOF
		# The RPC filter's enforcing marker (seclabRpcFilterEnforcing:<sha256 of the table>, emitted
		# by seclabRpcFilter.ts): without 0005, none anywhere; with it, every one names the table's
		# hash (so equals the product.json stamp), and the desktop app, where the workbench lives,
		# must carry one. The REH has no workbench, so there it is only checked when present.
		set +e
		marks=$(find "$d" -type f \( -name "*.js" -o -name "*.mjs" -o -name "*.cjs" \) -exec grep -hoaE 'seclabRpcFilterEnforcing:[0-9a-f]{0,64}' {} + 2>&1)
		rc=$?
		set -e
		if [ "$rc" -gt 1 ]; then
			echo "check-release: scan error (RPC enforcing marker)"; bad=1
		elif [ -n "$rpc_exp" ]; then
			marks=$(printf '%s\n' "$marks" | grep -v '^$' | sort -u || true)
			if [ "$rpc_exp" = absent ]; then
				[ -z "$marks" ] || { echo "check-release: RPC enforcing marker in $d, but patches/series has no 0005"; bad=1; }
			else
				wrong=$(printf '%s\n' "$marks" | grep -v '^$' | grep -vx "seclabRpcFilterEnforcing:$rpc_exp" || true)
				[ -z "$wrong" ] || { echo "check-release: RPC enforcing marker names another table: $(printf '%s' "$wrong" | head -1)"; bad=1; }
				if [ "$MODE" = desktop ] && [ -z "$marks" ]; then
					echo "check-release: RPC filter enforcing marker missing from the desktop app (0005 is listed)"; bad=1
				fi
			fi
		fi
		if [ "$MODE" = desktop ]; then
			set +e
			out=$(find "$d" \( -path "*/@github/copilot*" -o -path "*copilot-shim*" -o -name copilot -o -name runtime.node -o -name "copilot-runtime*" -o -path "*/@openai/codex*" -o -name codex -o -name "codex-*" -o -path "*claude-agent-sdk*" -o -path "*/@anthropic-ai/claude-code*" -o -name "*agent-sdk*" -o -name "*agent-runtime*" -o -name "*agentsdk*" \) -print 2>&1)
			rc=$?
			hdr=$(find "$d" -type f -name "*.asar" -exec grep -HaoE '"(copilot|copilot-shim|copilot-sdk[^"]*|copilot-runtime[^"]*|claude-agent-sdk[^"]*|claude-code|codex|codex-[^"]*|runtime\.node|[^"]*agent-?(sdk|runtime)[^"]*)":\{' {} + 2>&1)
			hrc=$?
			prod=$(find "$d" -type f -name product.json -exec grep -lE '"agentSdks"[[:space:]]*:' {} + 2>&1)
			prc=$?
			set -e
			if [ "$rc" -ne 0 ] || [ "$hrc" -gt 1 ] || [ "$prc" -gt 1 ]; then echo "check-release: scan error (agent runtime)"; bad=1; fi
			[ -z "$out" ] || { echo "check-release: agent runtime in the desktop app (I8):"; echo "$out" | head -20; bad=1; }
			[ -z "$hdr" ] || { echo "check-release: agent runtime listed in an asar (I8):"; echo "$hdr" | sort -u | head -20; bad=1; }
			[ -z "$prod" ] || { echo "check-release: product.json has agentSdks (runtime download path):"; echo "$prod"; bad=1; }
			# Structural focus guarantee (patch 0012, EDR background-windows): background mode makes
			# the app background-only at bootstrap and in the guard, and puts every window below
			# normal ones. These are what make the OS-level activation paths (click, window close,
			# Space change) impossible, so a desktop app without any of them fails.
			for m in '[background windows] activation policy: prohibited (bootstrap)' '[background windows] activation policy: prohibited (guard)' 'is below normal windows'; do
				set +e
				hit=$(find "$d" -type f \( -name "*.js" -o -name "*.mjs" \) -exec grep -lF -- "$m" {} + 2>/dev/null | head -1)
				set -e
				[ -n "$hit" ] || { echo "check-release: background-windows guard missing from the desktop app (no \"$m\")"; bad=1; }
			done
		fi
	done < "$WORK/roots"
	[ "$bad" = 0 ] || exit 1
	echo "check-release: clean ($n)"
	exit 0
fi

MODE=release
if [ "${1:-}" = "--desktop" ]; then MODE=desktop; shift; fi
[ $# -ge 1 ] || { echo "usage: check-release.sh [--desktop] PATH..." >&2; exit 2; }
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
if ! command -v docker >/dev/null 2>&1 && [ -n "${CI:-}" ]; then
	W="$(cd "$(dirname "$SELF")/.." && pwd)/.work/check-release"
	rm -rf "$W"
	exec sh "$SELF" --inner "$W" "$MODE" "$@"
fi
set --  "$@"
mounts=""; args=""; i=0
for p in "$@"; do
	abs="$(cd "$(dirname "$p")" && pwd)/$(basename "$p")"
	[ -e "$abs" ] || { echo "check-release: no such path: $p" >&2; exit 2; }
	mounts="$mounts -v $abs:/in/$i/$(basename "$abs"):ro"
	args="$args /in/$i/$(basename "$abs")"
	i=$((i+1))
done
# shellcheck disable=SC2086 # paths are repo/build paths without spaces; split on purpose
exec docker run --rm --network none -v "$SELF:/check-release.sh:ro" -v "$(dirname "$SELF")/../patches:/patches:ro" -e SECLAB_PATCHES=/patches $mounts alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f sh /check-release.sh --inner /x "$MODE" $args
