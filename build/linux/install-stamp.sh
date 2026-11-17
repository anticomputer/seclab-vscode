# Sourced by build/linux/build.sh. The install stamp keys a cached node_modules: every lockfile
# npm ci's postinstall installs from (built-in extensions bundle their own node_modules), plus
# the pinned upstream commit, so a pin bump never keeps an install its audit didn't see
# (review FU-2). sha256sum frames each file as hash plus name (newline-safe); a symlinked
# lockfile is refused rather than skipped (review FU-11).
install_stamp() { # KIND SRC
	local kind="$1" src="$2" head links sums
	head="$(git -C "$src" rev-parse HEAD)" || return 1
	links="$(cd "$src" && find . -name node_modules -prune -o -name package-lock.json -type l -print)" || return 1
	[[ -z "$links" ]] || { echo "install-stamp: a symlinked package-lock.json (refusing)" >&2; return 1; }
	sums="$(cd "$src" && find . -name node_modules -prune -o -name package-lock.json -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum)" || return 1
	printf '%s-%s\n' "$kind" "$(printf '%s\n%s\n' "$head" "$sums" | sha256sum | cut -c1-16)"
}
