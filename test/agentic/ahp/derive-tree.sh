# Sourced by the agentic probe runners. Derives a patched tree from the verified pinned source.
#
#   derive_tree DEST [SKIP]
#
# DEST becomes a worktree of the pinned upstream at exactly $UPSTREAM_SHA, pristine, plus every
# patch `patches/series` lists in order, except those whose file name matches the regex SKIP.
# A reused DEST is reset to $UPSTREAM_SHA, never to its own HEAD: after a pin update its HEAD is
# the OLD upstream, and a tree probed there would not be the tree that ships (PR #43 review).
# Needs ROOT, SRC (the verified pinned checkout) and upstream.lock's variables.

derive_tree() {
	local dest="$1" skip="${2:-}" applied=0 p
	if [[ -e "$dest/.git" ]]; then
		git -C "$dest" checkout -q --detach "$UPSTREAM_SHA" \
			&& git -C "$dest" reset -q --hard "$UPSTREAM_SHA" \
			&& git -C "$dest" clean -fdxq
	else
		git -C "$SRC" worktree prune
		git -C "$SRC" worktree add -q --detach "$dest" "$UPSTREAM_SHA"
	fi
	[[ "$(git -C "$dest" rev-parse HEAD)" == "$UPSTREAM_SHA" ]] || { echo "derive_tree: $dest is not at $UPSTREAM_SHA" >&2; return 2; }
	# --ignored too: an ignored leftover would survive `clean` without -x and still be bundled.
	[[ -z "$(git -C "$dest" status --porcelain --ignored)" ]] || { echo "derive_tree: $dest is not pristine after the reset" >&2; return 2; }
	while read -r p; do
		case "$p" in \#*|'') continue ;; esac
		if [[ -n "$skip" && "$p" =~ $skip ]]; then continue; fi
		git -C "$dest" apply -p1 "$ROOT/patches/$p" || { echo "derive_tree: $p does not apply" >&2; return 2; }
		applied=$((applied + 1))
	done < "$ROOT/patches/series"
	echo "derive_tree: $(basename "$dest") = pinned upstream + $applied patch(es)${skip:+ (without $skip)}"
}
