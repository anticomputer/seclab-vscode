"""Supply-chain pin check for the broker tree (offline; run by broker/docs-check.sh).

  * every Dockerfile is free of parser directives, ADD, ONBUILD, RUN flags, foreign
    COPY --from and pip configuration; every `FROM` names an earlier stage or is pinned
    `image@sha256:<64 hex>` and recorded in broker/deps.json;
  * every Python install is the one canonical hash-checked, binary-only pip command, and
    installs a checked requirements file;
  * every requirements*.txt parses strictly (plain `name==version` plus
    `--hash=sha256:` only), every pin is in broker/deps.json, every file is installed
    by some Dockerfile, and its pip-compile source (requirements*.in), if any, pins the
    same versions.
The parsing rules are in tools/supplychain.py. Online provenance checks (PyPI
attestations, image signatures) are in broker/provenance-check.sh.
"""

from __future__ import annotations

import json
import re
import sys

from supplychain import (BROKER, SupplyChainError, install_targets, norm, parse_requirements, rel,
                         requirement_files, self_test)


def source_drift(req, locked: dict[str, str]) -> list[str]:
    """A lock's pip-compile source (requirements.txt <- requirements.in) must pin the same
    versions, or the next recompile silently undoes a re-pin. Only `name==version` lines
    are allowed in the source."""
    src = req.with_suffix(".in")
    if not src.exists():
        return []
    errors = []
    for n, raw in enumerate(src.read_text().splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9.+!-]+)", line)
        if not m:
            errors.append(f"{rel(src)}:{n}: only plain name==version lines are allowed")
        elif locked.get(norm(m[1])) != m[2]:
            errors.append(f"{rel(src)}:{n}: {m[1]}=={m[2]} but {rel(req)} pins "
                          f"{locked.get(norm(m[1]), 'nothing')}")
    return errors


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        failures = self_test()
        for f in failures:
            print("pin-check self-test: " + f, file=sys.stderr)
        print(f"pin-check self-test: {'ok' if not failures else 'FAILED'}", file=sys.stderr)
        return 1 if failures else 0
    errors: list[str] = []
    register = json.loads((BROKER / "deps.json").read_text())
    image_refs = {i["ref"] for i in register["images"]}
    py_pins = {(norm(p["name"]), p["version"]) for p in register["python"]}
    targets, errs = install_targets(image_refs)
    errors += errs
    for req in requirement_files():
        try:
            pins = parse_requirements(req)
        except SupplyChainError as e:
            errors.append(str(e))
            continue
        for n, name, version, _ in pins:
            if (name, version) not in py_pins:
                errors.append(f"{rel(req)}:{n}: {name}=={version} is not in broker/deps.json")
        if req.resolve() not in targets:
            errors.append(f"{rel(req)}: not installed by any Dockerfile (its target interpreter is unknown)")
        errors += source_drift(req, {name: version for _, name, version, _ in pins})
    for e in errors:
        print("pin-check: " + e, file=sys.stderr)
    if not errors:
        print(f"pin-check: ok ({len(requirement_files())} requirements files, "
              f"{sum(len(v) for v in targets.values())} installs)", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
