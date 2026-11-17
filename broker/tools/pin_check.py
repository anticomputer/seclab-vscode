"""Supply-chain pin check for the broker tree (offline; run by broker/docs-check.sh).

  * every Dockerfile is free of parser directives, ADD, ONBUILD, RUN flags, foreign
    COPY --from and pip configuration; every `FROM` names an earlier stage or is pinned
    `image@sha256:<64 hex>` and recorded in broker/deps.json;
  * every Python install is the one canonical hash-checked, binary-only pip command, and
    installs a checked requirements file;
  * every requirements*.txt parses strictly (plain `name==version` plus
    `--hash=sha256:` only), every pin is in broker/deps.json, every file is installed
    by some Dockerfile, and its pip-compile source (requirements*.in) pins the same
    versions (registered in broker/deps.json `lockSources`; every .in must be).
(broker/docs-check.sh also refuses tracked paths under broker/ that git would quote,
because broker/build.sh refuses them.)
The parsing rules are in tools/supplychain.py. Online provenance checks (PyPI
attestations, image signatures) are in broker/provenance-check.sh.
"""

from __future__ import annotations

import json
import re
import sys

from supplychain import (BROKER, SupplyChainError, install_targets, norm, parse_requirements, rel,
                         requirement_files)
from supplychain import self_test as supplychain_self_test


def source_drift(req, locked: dict[str, str], source=None) -> list[str]:
    """A lock's pip-compile source (requirements.txt <- requirements.in) must pin the same
    versions, or the next recompile silently undoes a re-pin. The pairing is registered in
    broker/deps.json `lockSources` (`source`, the registered path, required), not inferred
    from the lock's own comments; an unregistered lock with `# via` annotations also needs a
    sibling `.in`. The source must pin something, and every direct requirement
    (`via -r <source>`) must be pinned there. Only `name==version` lines are allowed."""
    required = source is not None
    src = source if required else req.with_suffix(".in")
    text = req.read_text()
    direct, cur = set(), None
    for raw in text.splitlines():
        m = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)==", raw)
        if m:
            cur = norm(m[1])
        elif cur and re.fullmatch(r"\s*#\s+(?:via\s+)?-r\s+" + re.escape(src.name) + r"\s*", raw):
            direct.add(cur)
    compiled = required or re.search(r"^\s*#\s+via\b", text, re.M) is not None
    if not src.exists():
        return [f"{rel(req)}: pip-compiled lock, but its source {src.name} is missing"] if compiled else []
    errors, sourced = [], set()
    for n, raw in enumerate(src.read_text().splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9.+!-]+)", line)
        if not m:
            errors.append(f"{rel(src)}:{n}: only plain name==version lines are allowed")
            continue
        sourced.add(norm(m[1]))
        if locked.get(norm(m[1])) != m[2]:
            errors.append(f"{rel(src)}:{n}: {m[1]}=={m[2]} but {rel(req)} pins "
                          f"{locked.get(norm(m[1]), 'nothing')}")
    if not sourced:
        errors.append(f"{rel(src)}: pins nothing")
    for name in sorted(direct - sourced):
        errors.append(f"{rel(src)}: {rel(req)} says {name} is a direct requirement, but it isn't pinned here")
    return errors


def lock_drift(req, locked: dict[str, str], register: dict, root=None) -> list[str]:
    """source_drift for a lock, against its source registered in broker/deps.json `lockSources`
    (paths relative to broker/), or the sibling `.in` when it has none (finding 11-9). `root` is
    the repository root; the self-test passes a scratch tree."""
    import os
    from pathlib import Path
    root = Path(root) if root is not None else BROKER.parent
    sources = {"broker/" + e["lock"]: "broker/" + e["source"] for e in register.get("lockSources", [])}
    # Lexical paths, as requirement_files() finds them: resolving would follow a symlinked lock
    # to its target and miss the registration (review of #36).
    try:
        key = Path(os.path.abspath(req)).relative_to(Path(os.path.abspath(root))).as_posix()
    except ValueError:
        key = None
    reg = sources.get(key) if key else None
    return source_drift(req, locked, source=(root / reg) if reg else None)


def self_test() -> list[str]:
    """The supply-chain vectors, then named lock-drift cases (findings 10-4, 10b-5 and 10c-1):
    each must fail, or pass, exactly as named."""
    import tempfile
    from pathlib import Path

    failures = supplychain_self_test()
    h = "a" * 64
    lock = (f"pkga==1.0 --hash=sha256:{h}\n    # via -r requirements.in\n"
            f"pkgb==2.0 --hash=sha256:{h}\n    # via pkga\n")
    bare = f"pkga==1.0 --hash=sha256:{h}\npkgb==2.0 --hash=sha256:{h}\n"
    # Compiled (it has `# via`), but names no direct requirement: only "pins nothing" can fail it.
    indirect = f"pkga==1.0 --hash=sha256:{h}\n    # via pkgb\npkgb==2.0 --hash=sha256:{h}\n"
    locked = {"pkga": "1.0", "pkgb": "2.0"}
    # (name, lock text, source text or None for no file, registered, the error the case's own rule
    # must report, or None for a pass). A crash fails the case (review BRK20-3).
    cases = [
        ("drift: a source that pins what its lock pins passes", lock, "pkga==1.0\n", False, None),
        ("10-4: a source pinning a superseded version fails", lock, "pkga==0.9\n", False, "pkga==0.9 but"),
        ("10b-5: a compiled lock whose source is missing fails", lock, None, False, "is missing"),
        ("10b-5: an empty source fails", indirect, "", False, "pins nothing"),
        ("10b-5: a comment-only source fails", indirect, "# pkga==1.0\n", False, "pins nothing"),
        ("10c-1: a registered source that is missing fails, with no # via comments left", bare, None, True,
         "is missing"),
        ("10c-1: a direct requirement the source doesn't pin fails", lock, "pkgb==2.0\n", False,
         "pkga is a direct requirement"),
        ("drift: a source line that isn't name==version fails", lock, "pkga>=1.0\n", False,
         "only plain name==version"),
    ]
    with tempfile.TemporaryDirectory() as d:
        for i, (name, ltext, stext, registered, want) in enumerate(cases):
            case = Path(d) / str(i)
            case.mkdir()
            req = case / "requirements.txt"
            req.write_text(ltext)
            src = case / "requirements.in"
            if stext is not None:
                src.write_text(stext)
            try:
                errors = source_drift(req, locked, source=src if registered else None)
            except Exception as e:  # noqa: BLE001 - any crash fails the case
                failures.append(f"{name}: raised {type(e).__name__}")
                continue
            if want is None and errors:
                failures.append(f"{name}: errors {errors}")
            elif want is not None and not any(want in e for e in errors):
                failures.append(f"{name}: no error containing {want!r} in {errors}")
        # 11-9: the production lookup (lock_drift, what main() calls) compares the source the
        # register names, not the lock's `<lock>.in` sibling: a drifting registered source next
        # to a matching sibling must be reported.
        name = "11-9: the registered source is compared, not the sibling .in"
        root = Path(d) / "repo"
        x = root / "broker" / "x"
        x.mkdir(parents=True)
        (x / "requirements.txt").write_text(lock)
        (x / "requirements.in").write_text("pkga==1.0\n")
        (x / "deps.in").write_text("pkga==0.9\n")
        register = {"lockSources": [{"lock": "x/requirements.txt", "source": "x/deps.in"}]}
        try:
            errors = lock_drift(x / "requirements.txt", locked, register, root=root)
            if not any("deps.in" in e and "pkga==0.9 but" in e for e in errors):
                failures.append(f"{name}: no drift reported against deps.in in {errors}")
            if lock_drift(x / "requirements.txt", locked, {"lockSources": []}, root=root):
                failures.append(f"{name}: control (unregistered, matching sibling) reported drift")
            # A symlinked lock is looked up by its own (registered) path, not its target's.
            y = root / "broker" / "y"
            y.mkdir()
            (y / "actual.txt").write_text(lock)
            (y / "requirements.txt").symlink_to("actual.txt")
            (y / "requirements.in").write_text("pkga==1.0\n")
            (y / "deps.in").write_text("pkga==0.9\n")
            errors = lock_drift(y / "requirements.txt", locked,
                                {"lockSources": [{"lock": "y/requirements.txt", "source": "y/deps.in"}]}, root=root)
            if not any("deps.in" in e and "pkga==0.9 but" in e for e in errors):
                failures.append(f"{name}: a symlinked lock missed its registration: {errors}")
        except Exception as e:  # noqa: BLE001 - any crash fails the case
            failures.append(f"{name}: raised {type(e).__name__}")
    return failures


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
    lock_sources = {"broker/" + e["lock"]: "broker/" + e["source"] for e in register.get("lockSources", [])}
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
        errors += lock_drift(req, {name: version for _, name, version, _ in pins}, register)
    for lock, src in lock_sources.items():
        if not (BROKER.parent / lock).exists() or not (BROKER.parent / src).exists():
            errors.append(f"broker/deps.json lockSources: {lock} <- {src}: missing file")
    for src in sorted(BROKER.rglob("requirements*.in")):
        if ".work" not in src.parts and rel(src) not in lock_sources.values():
            errors.append(f"{rel(src)}: not registered in broker/deps.json lockSources")
    for e in errors:
        print("pin-check: " + e, file=sys.stderr)
    if not errors:
        print(f"pin-check: ok ({len(requirement_files())} requirements files, "
              f"{sum(len(v) for v in targets.values())} installs)", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
