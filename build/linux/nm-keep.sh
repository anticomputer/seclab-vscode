# Sourced by build/linux/build.sh (EDR local-install-cache): a failed install must not destroy a
# working one. nm_keep_aside moves every node_modules under SRC (root, build/, remote/,
# extensions/*, ...) to KEEP, which must be on the same filesystem and outside the tree that
# fetch-upstream cleans. nm_restore puts them back, replacing whatever a failed install left.
# Tested by build/linux/nm-keep.test.ts.

nm_keep_aside() { # SRC KEEP
	local src="$1" keep="$2" d rel
	mkdir -p "$keep"
	while IFS= read -r d; do
		rel="${d#"$src"/}"
		mkdir -p "$keep/$(dirname "$rel")"
		mv "$d" "$keep/$rel"
	done < <(find "$src" -name .git -prune -o -type d -name node_modules -prune -print)
}

nm_restore() { # SRC KEEP
	local src="$1" keep="$2" rel
	while IFS= read -r rel; do
		rm -rf "${src:?}/${rel#./}"
	done < <(cd "$src" && find . -name .git -prune -o -type d -name node_modules -prune -print)
	while IFS= read -r rel; do
		rel="${rel#./}"
		mkdir -p "$src/$(dirname "$rel")"
		mv "$keep/$rel" "$src/$rel"
	done < <(cd "$keep" && find . -type d -name node_modules -prune -print)
	rm -rf "$keep"
}
