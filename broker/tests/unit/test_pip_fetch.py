"""pip-fetch's CFS index rule runs the same vectors as build/cfs-config.ts (--self-test), so
the TS validator and this mirror can't drift. The real feed URL comes from the host-side
config as a BuildKit secret; the tree holds example values only."""

import importlib.util
import json
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[2] / "tools"


def _pip_fetch():
    spec = importlib.util.spec_from_file_location("pip_fetch", TOOLS / "pip-fetch.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_cfs_index_rule_matches_the_shared_vectors():
    pf = _pip_fetch()
    vectors = json.loads((TOOLS / "cfs-config.vectors.json").read_text())
    base = vectors["valid"][0]
    for v in vectors["valid"]:
        assert pf.valid_cfs_index(v["pypiIndex"]), v["pypiIndex"]
    checked = 0
    for case in vectors["invalid"]:
        if "pypiIndex" in case["patch"] and case["patch"]["pypiIndex"] is not None and not case.get("crossField"):
            assert not pf.valid_cfs_index(case["patch"]["pypiIndex"]), case["why"]
            checked += 1
    assert checked >= 5
    # The other fields' valid URLs are never a valid index.
    for k in ("npmRegistry", "pypiDownload"):
        assert not pf.valid_cfs_index(base[k]), k
    # No index in the tree: only the secret supplies one.
    assert not hasattr(pf, "CFS_INDEX")
