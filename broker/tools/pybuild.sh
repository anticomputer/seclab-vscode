# Sourced by the broker's build scripts: `pybuild <docker build args...>` builds an image
# whose Python wheels are fetched by tools/pip-fetch.py (see broker/Dockerfile).
#
# The index is explicit, never inferred from whether a token is present:
#   SECLAB_PIP_SOURCE=cfs     GitHub's CFS feed via `gh cfs -- docker build` (local default;
#                             public PyPI is unavailable locally)
#   SECLAB_PIP_SOURCE=public  pypi.org (hosted CI, which can't use CFS; default when CI is set)
# Both keep --require-hashes, so the artifacts are the same files either way.
pybuild() {
	_src=${SECLAB_PIP_SOURCE:-}
	if [ -z "$_src" ]; then
		if [ -n "${CI:-}" ]; then _src=public; else _src=cfs; fi
	fi
	case "$_src" in
	cfs)
		command -v gh >/dev/null || { echo "pybuild: SECLAB_PIP_SOURCE=cfs needs gh with the cfs extension (gh cfs)" >&2; return 1; }
		# The real feed URL comes from the host-side config (build/cfs-config.ts), never the tree,
		# and goes in as a BuildKit secret so it never lands in image history. It only chooses the
		# index: every wheel is still hash-locked.
		_root=${SECLAB_REPO_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null)} || _root=
		[ -n "$_root" ] && [ -f "$_root/build/cfs-config.ts" ] \
			|| { echo "pybuild: can't find build/cfs-config.ts (run from the repo, or set SECLAB_REPO_ROOT)" >&2; return 1; }
		_idx=$("${SECLAB_NODE:-node}" "$_root/build/cfs-config.ts" get pypiIndex) \
			|| { echo "pybuild: local builds need the host CFS config: run ./seclab cfs config" >&2; return 1; }
		SECLAB_CFS_FEED_INDEX=$_idx gh cfs -- docker build --build-arg PIP_SOURCE=cfs \
			--secret id=cfs_feed_index,env=SECLAB_CFS_FEED_INDEX "$@"
		;;
	public) docker build --build-arg PIP_SOURCE=public "$@" ;;
	*) echo "pybuild: SECLAB_PIP_SOURCE must be cfs or public" >&2; return 2 ;;
	esac
}
