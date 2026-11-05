# Sourced by the broker's build scripts: `pybuild <docker build args...>` builds an image
# whose Python wheels are fetched by tools/pip-fetch.py (see broker/Dockerfile).
#
# The index is explicit, never inferred from whether a token is present:
#   SECLAB_PIP_SOURCE=cfs     GitHub's CFS feed via `gh cfs -- docker build` (local default;
#                             public PyPI is blocked on managed endpoints)
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
		gh cfs -- docker build --build-arg PIP_SOURCE=cfs "$@"
		;;
	public) docker build --build-arg PIP_SOURCE=public "$@" ;;
	*) echo "pybuild: SECLAB_PIP_SOURCE must be cfs or public" >&2; return 2 ;;
	esac
}
