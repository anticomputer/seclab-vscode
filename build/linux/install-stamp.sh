# Sourced by build/linux/build.sh. The install stamp keys a cached node_modules: every lockfile
# npm ci's postinstall installs from (built-in extensions bundle their own node_modules), plus
# the pinned upstream commit, so a pin bump never keeps an install its audit didn't see
# (review FU-2).
install_stamp() { # KIND SRC
	local kind="$1" src="$2"
	printf '%s-%s\n' "$kind" "$({
		git -C "$src" rev-parse HEAD
		(cd "$src" && find . -name node_modules -prune -o -name package-lock.json -type f -print | LC_ALL=C sort | while IFS= read -r f; do printf '%s\n' "$f"; cat "$f"; done)
	} | sha256sum | cut -c1-16)"
}
