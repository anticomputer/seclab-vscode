"""Provenance check for every pinned Python dependency of the broker.

  python provenance.py report [REQ...]  JSON facts from PyPI (for writing the register)
  python provenance.py check            metadata check against broker/deps.json
  python provenance.py verify           check + cryptographic verification of attestations
Run inside the broker/tools/attest image (it has `packaging`, pypi-attestations, sigstore).
`check` and `verify` always cover every requirements*.txt under broker/, discovered and
parsed by tools/supplychain.py exactly as pin_check.py does (strict: anything pip would
honour that the parser does not understand is an error).

For each pin:
  * every pinned hash must be a file PyPI serves for that release, so the lock points at
    official artifacts;
  * the files that apply are the ones pip could install into the lockfile's target
    interpreter. A lockfile installed into the verifier's own base image (tools/attest)
    is matched against this interpreter's tags. A lockfile installed into any other base
    (the mitmproxy image) must pin pure `py3-none-any` wheels only, so every file that
    could be installed is the one verified. At least one pinned wheel must apply (installs
    use --only-binary=:all:);
  * for applicable files, the PEP 740 publisher (kind, repository, workflow) must equal the
    one recorded in broker/deps.json;
  * `verify` checks every attestation of every applicable file cryptographically:
    sigstore DSSE verification of the provenance fetched once (the same bytes whose
    publisher was compared above) against a Distribution whose digest is the **pinned
    sha256**, with a GitHub Trusted Publisher policy built from the **register's**
    repository and workflow. So the signature must cover exactly the pinned bytes and come
    from the registered workflow; neither link relies on PyPI metadata being honest.
Unattested dependencies are tier "hash-pinned": exact files from the project's official
index, enforced at install time by pip --require-hashes.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from supplychain import (BROKER, SupplyChainError, install_targets, norm, parse_requirements, rel,
                         requirement_files, verifier_base)


def get(url: str) -> dict | None:
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.pypi.integrity.v1+json, application/json"})
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code < 500 and e.code != 429:
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            pass
        time.sleep(2 ** attempt)
    raise RuntimeError(f"PyPI unreachable after retries: {url}")


def is_pure(filename: str) -> bool:
    from packaging.utils import parse_wheel_filename
    if not filename.endswith(".whl"):
        return False
    tags = parse_wheel_filename(filename)[3]
    return all(t.abi == "none" and t.platform == "any" and t.interpreter.startswith("py3") for t in tags)


def applies_here(filename: str) -> bool:
    if not filename.endswith(".whl"):
        return False
    from packaging.tags import sys_tags
    from packaging.utils import parse_wheel_filename
    return bool(set(parse_wheel_filename(filename)[3]) & set(sys_tags()))


def facts(name: str, version: str, hashes: set[str], pure_hashes: set[str]) -> dict:
    meta = get(f"https://pypi.org/pypi/{name}/{version}/json") or {}
    served = {u["digests"]["sha256"]: u["filename"] for u in meta.get("urls", [])}
    files = []
    for h in sorted(hashes):
        fn = served.get(h)
        entry = {"sha256": h, "filename": fn, "pure": bool(fn) and is_pure(fn),
                 "pureRequired": h in pure_hashes, "applies": bool(fn) and applies_here(fn)}
        if entry["applies"]:
            prov = get(f"https://pypi.org/integrity/{name}/{version}/{fn}/provenance")
            entry["provenance"] = prov
            entry["publishers"] = [
                {k: (b.get("publisher") or {}).get(k) for k in ("kind", "repository", "workflow")}
                for b in (prov or {}).get("attestation_bundles", [])]
        files.append(entry)
    return {"name": name, "version": version, "files": files}


def summary(f: dict) -> dict:
    here = [x for x in f["files"] if x["applies"]]
    pubs = [p for x in here for p in x.get("publishers", [])]
    uniq = [dict(t) for t in {tuple(sorted(p.items())) for p in pubs}]
    attested = bool(here) and all(x.get("publishers") for x in here)
    return {"name": f["name"], "version": f["version"], "files": len(f["files"]), "filesApplicable": len(here),
            "allServed": all(x["filename"] for x in f["files"]),
            "allPure": all(x["pure"] for x in f["files"] if x["pureRequired"]),
            "attested": attested, "partiallyAttested": bool(pubs) and not attested,
            "publisher": uniq[0] if len(uniq) == 1 else (uniq or None)}


def verify_file(x: dict, publisher: dict) -> int:
    """Number of attestations verified; raises on any failure."""
    from pypi_attestations import Distribution, GitHubPublisher, Provenance
    if publisher.get("kind") != "GitHub":
        raise ValueError(f"register publisher kind {publisher.get('kind')!r} is not supported")
    policy = GitHubPublisher(repository=publisher["repository"], workflow=publisher["workflow"])
    dist = Distribution(name=x["filename"], digest=x["sha256"])
    prov = Provenance.model_validate(x["provenance"])
    n = 0
    for bundle in prov.attestation_bundles:
        for att in bundle.attestations:
            att.verify(policy, dist)
            n += 1
    if n == 0:
        raise ValueError("provenance has no attestations")
    return n


def collect(files: list[Path], pure_files: set[Path]) -> tuple[dict, list[str]]:
    pins: dict[tuple[str, str], dict] = {}
    errors = []
    for f in files:
        try:
            parsed = parse_requirements(f)
        except SupplyChainError as e:
            errors.append(str(e))
            continue
        for _, name, version, hashes in parsed:
            p = pins.setdefault((name, version), {"hashes": set(), "pure": set()})
            p["hashes"].update(hashes)
            if f.resolve() in pure_files:
                p["pure"].update(hashes)
    return pins, errors


def main() -> int:
    mode, args = sys.argv[1], sys.argv[2:]
    if mode not in ("report", "check", "verify") or (args and mode != "report"):
        print(__doc__, file=sys.stderr)
        return 2
    register_doc = json.loads((BROKER / "deps.json").read_text())
    targets, errors = install_targets({i["ref"] for i in register_doc["images"]})
    native = verifier_base()
    pure_files = {p for p, bases in targets.items() if bases - {native}}
    files = [Path(a) for a in args] or requirement_files()
    for f in files:
        if f.resolve() not in targets:
            errors.append(f"{rel(f.resolve())}: not installed by any Dockerfile (its target interpreter is unknown)")
    pins, errs = collect(files, pure_files)
    errors += errs
    all_facts = [facts(n, v, p["hashes"], p["pure"]) for (n, v), p in sorted(pins.items())]
    if mode == "report":
        json.dump([dict(summary(f), detail={**f, "files": [{k: v for k, v in x.items() if k != "provenance"}
                                                            for x in f["files"]]}) for f in all_facts],
                  sys.stdout, indent=1)
        print()
        return 0
    register = {norm(d["name"]): d for d in register_doc["python"]}
    verified = 0
    for f in all_facts:
        s, e = summary(f), register.get(f["name"])
        tag = f"{f['name']} {f['version']}"
        if e is None:
            errors.append(f"{tag}: not in broker/deps.json")
            continue
        if e["version"] != f["version"]:
            errors.append(f"{tag}: register says {e['version']}")
        if not s["allServed"]:
            errors.append(f"{tag}: a pinned hash is not a file PyPI serves")
        if not s["allPure"]:
            errors.append(f"{tag}: pinned in a lockfile installed into a base other than the verifier's; "
                          "only pure py3-none-any wheels may be pinned there")
        if s["filesApplicable"] == 0:
            errors.append(f"{tag}: no pinned wheel installs on the target interpreter (installs are binary-only)")
        if e["tier"] == "attested":
            if not s["attested"]:
                errors.append(f"{tag}: register expects PyPI attestations, PyPI has none (or not for every file)")
            elif s["publisher"] != e["publisher"]:
                errors.append(f"{tag}: publisher {s['publisher']} != expected {e['publisher']}")
        elif s["attested"]:
            print(f"provenance: note: {tag} now publishes attestations ({s['publisher']}); "
                  "consider raising its tier", file=sys.stderr)
        if mode == "verify" and e["tier"] == "attested" and s["attested"]:
            for x in f["files"]:
                if not x["applies"]:
                    continue
                try:
                    verified += verify_file(x, e["publisher"])
                except Exception as err:  # noqa: BLE001 - any failure fails the gate
                    errors.append(f"{tag}: attestation verification failed for {x['filename']}: "
                                  f"{type(err).__name__}: {str(err)[:300]}")
    for x in errors:
        print("provenance: " + x, file=sys.stderr)
    print(f"provenance: {'ok' if not errors else 'FAILED'} ({len(files)} files, {len(all_facts)} pins"
          + (f", {verified} attestations verified against pinned digests" if mode == "verify" else "") + ")",
          file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
