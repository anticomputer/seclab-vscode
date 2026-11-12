#!/usr/bin/env bash
# Publish gate driver (EDR 20261112-publish-gate). Sourced, never executed, by:
#   - the pre-push hook (from its install-time copy, whose sha256 the hook checks first),
#   - build/ci-denylist.sh (CI: the `denylist` job of workflow-lint.yml on a push to main;
#     branches are not scanned with the list in CI),
#   - `./seclab lint publish` and `./seclab scan-text`.
# One engine (build/publish-gate.ts) for all of them, so they cannot drift apart.
#
# publish_gate IMAGE GATE_DIR DATA LIST SUMS -- SCANNER-ARGS...
#   DATA is the git directory for git-push/git-tree, the allowlist file for text.
#   Runs the scanner in IMAGE (by ID or pinned ref) with no network, a read-only root, no
#   capabilities, as nobody, with GATE_DIR, DATA and the LIST file mounted read-only. If SUMS
#   is set (sha256sum lines for GATE_DIR's files) the container checks them before running.
#   Then every repository reference it lists is checked live with
#   `gh api repos/<owner>/<name> --jq .visibility`: only `public` passes; private, internal, not
#   found, malformed, or the API unreachable blocks. Results are cached for this run only.
#   Prints locations, never values. For `text`, stdin is passed to the scanner.
# Returns 0 clean, 1 blocked (a finding, a non-public repository, or a scan that could not run),
# 3 review needed (conversation text only).
# Bash 3.2 compatible (macOS /bin/bash): no associative arrays.

# The known-names list: one local secrets directory for the project (the broker keeps cfs.json
# there too). Never in the repo.
publish_gate_list_path() {
	printf '%s' "${SECLAB_DENYLIST_FILE:-$HOME/.config/seclab/denylist.txt}"
}

# The list must be a non-empty regular file (not a symlink) owned by this user, with no group or
# other permission bits (chmod 600). Anything else fails closed.
publish_gate_list_ok() {
	local f="$1" mode owner
	[[ -f "$f" && ! -L "$f" && -s "$f" ]] || { echo "publish-gate: no known-names list at $f; blocked (AGENTS.md: the gate is mandatory)" >&2; return 1; }
	# GNU stat first: on Linux `stat -f` succeeds with file-system data instead of failing.
	mode="$(stat -c '%a' "$f" 2>/dev/null || stat -f '%Lp' "$f" 2>/dev/null)"
	owner="$(stat -c '%u' "$f" 2>/dev/null || stat -f '%u' "$f" 2>/dev/null)"
	if [[ "$owner" != "$(id -u)" || ! "$mode" =~ ^[0-7]*[0-7]00$ ]]; then
		echo "publish-gate: $f must be owned by you and private (chmod 600); blocked" >&2
		return 1
	fi
}

publish_gate_repos() {
	local kind nwo loc vis cache='' status=0
	while IFS=$'\t' read -r kind nwo loc; do
		[[ -z "$kind" ]] && continue
		if [[ "$kind" != repo ]]; then
			echo "publish-gate: unexpected scanner output; blocked" >&2
			status=1
			continue
		fi
		if ! [[ "$nwo" =~ ^[a-z0-9-]{1,39}/[a-z0-9._-]{1,100}$ ]]; then
			echo "publish-gate: repo: $loc (malformed reference); blocked" >&2
			status=1
			continue
		fi
		vis="$(printf '%s' "$cache" | awk -F'\t' -v k="$nwo" '$1 == k { print $2; exit }')"
		if [[ -z "$vis" ]]; then
			vis="$(publish_gate_visibility "$nwo")"
			cache+="$nwo"$'\t'"$vis"$'\n'
		fi
		if [[ "$vis" != public ]]; then
			case "$vis" in
				missing) why='not found, or not visible to this token' ;;
				unreachable) why='the GitHub API could not be reached; retry' ;;
				*) why='not public' ;;
			esac
			echo "publish-gate: repo: $loc (a repository reference that is not verifiably public: $why); blocked" >&2
			status=1
		fi
	done
	return "$status"
}

# public | private | internal | missing (404) | unreachable (anything else, after three tries)
publish_gate_visibility() {
	local out try
	for try in 1 2 3; do
		if out="$(GH_HOST=github.com GH_PROMPT_DISABLED=1 gh api "repos/$1" --jq .visibility 2>&1)" && [[ "$out" =~ ^[a-z]+$ ]]; then
			printf '%s' "$out"
			return 0
		fi
		if [[ "$out" == *'HTTP 404'* ]]; then
			printf missing
			return 0
		fi
		sleep "$try"
	done
	printf unreachable
}

publish_gate() {
	local image="$1" gate="$2" data="$3" list="$4" sums="$5" out rc mode
	shift 5
	[[ "${1:-}" == -- ]] && shift
	mode="${1:-}"
	command -v docker >/dev/null || { echo "publish-gate: no docker; the scan can't run; blocked" >&2; return 1; }
	command -v gh >/dev/null || { echo "publish-gate: no gh; the live repository check can't run; blocked" >&2; return 1; }
	publish_gate_list_ok "$list" || return 1
	local mounts=(--mount "type=bind,src=$gate,dst=/gate,readonly" --mount "type=bind,src=$list,dst=/list,readonly")
	local args=("$@")
	if [[ "$mode" == text ]]; then
		# DATA is the allowlist file; the text arrives on stdin.
		mounts+=(--mount "type=bind,src=$data,dst=/allow.json,readonly")
		args+=(--allow /allow.json)
	else
		# DATA is the git directory (a worktree's common dir); the hook's own stdin stays its own.
		mounts+=(--mount "type=bind,src=$data,dst=/git,readonly")
	fi
	rc=0
	local attempt
	# A scan that could not run (exit 2) is retried: Docker Desktop's bind mounts can briefly miss
	# a file git just replaced (HEAD after a checkout). Still blocked after three tries.
	for attempt in 1 2 3; do
		rc=0
		if [[ "$mode" == text ]]; then
			out="$(docker run --rm -i --network none --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
				--user 65534:65534 --pull never "${mounts[@]}" -e "SUMS=$sums" -w /gate "$image" \
				sh -c "$PUBLISH_GATE_ENTRY" sh "${args[@]}" --list /list)" || rc=$?
			break # stdin is consumed; never replay it
		fi
		out="$(docker run --rm --network none --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
			--user 65534:65534 --pull never "${mounts[@]}" -e "SUMS=$sums" -w /gate "$image" \
			sh -c "$PUBLISH_GATE_ENTRY" sh "${args[@]}" --list /list </dev/null)" || rc=$?
		[[ "$rc" -eq 2 ]] || break
		[[ "$attempt" -lt 3 ]] && { echo "publish-gate: the scan could not run; retrying" >&2; sleep "$attempt"; }
	done
	case "$rc" in
		0 | 1 | 3) ;;
		*) echo "publish-gate: the scan could not run (exit $rc); blocked" >&2; return 1 ;;
	esac
	printf '%s\n' "$out" | publish_gate_repos || rc=1
	return "$rc"
}

# In the container: check the pinned sums (when given), then run the engine.
PUBLISH_GATE_ENTRY='if [ -n "$SUMS" ]; then printf "%s\n" "$SUMS" | sha256sum -c --quiet --strict - >/dev/null 2>&1 || { echo "publish-gate: the installed gate does not match its pinned sha256; re-run ./seclab hooks install" >&2; exit 2; }; fi
exec node /gate/publish-gate.ts "$@"'
