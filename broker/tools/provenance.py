"""Provenance check for every pinned Python dependency of the broker.

  python provenance.py report REQ...   JSON facts from PyPI (for writing the register)
  python provenance.py check  REQ...   metadata check against broker/deps.json
  python provenance.py verify REQ...   check + cryptographic verification of attestations
Run inside the broker/tools/attest image (it has `packaging`, pypi-attestations, sigstore).

For each `name==version` pin, with one or more `--hash=sha256:` lines (single-line or
pip-compile format):
  * every pinned hash must be a file PyPI serves for that release, so the lock points at
    official artifacts, and at least one pinned wheel must install on this platform (no
    source builds);
  * for the files pip could install here, the PEP 740 publisher (kind, repository,
    workflow) must equal the one recorded in broker/deps.json. A dropped attestation or a
    release published from a different repository or workflow fails;
  * `verify` additionally runs `pypi-attestations verify pypi --repository <expected>`
    for every attested pinned file that applies to this platform. The expected
    repository comes from the register, never from the provenance being checked.
Unattested dependencies are tier "hash-pinned": exact files from the project's official
index, enforced at install time by pip --require-hashes.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

BROKER = Path(__file__).resolve().parents[1]
REQ_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)")
HASH_RE = re.compile(r"--hash=sha256:([0-9a-f]{64})")


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


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse(files: list[str]) -> dict[tuple[str, str], set[str]]:
    pins: dict[tuple[str, str], set[str]] = {}
    for f in files:
        current = None
        for raw in Path(f).read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = REQ_RE.match(line)
            if m:
                current = (norm(m.group(1)), m.group(2))
                pins.setdefault(current, set())
            if current:
                pins[current].update(HASH_RE.findall(line))
            if not line.endswith("\\"):
                current = None
    return pins


def facts(name: str, version: str, hashes: set[str]) -> dict:
    meta = get(f"https://pypi.org/pypi/{name}/{version}/json") or {}
    served = {u["digests"]["sha256"]: u["filename"] for u in meta.get("urls", [])}
    files = []
    for h in sorted(hashes):
        fn = served.get(h)
        entry = {"sha256": h, "filename": fn, "appliesHere": bool(fn) and applies_here(fn)}
        # Provenance is checked for the files pip could install here (the use-time artifact);
        # every pinned hash is still checked to be a file PyPI serves.
        if entry["appliesHere"]:
            prov = get(f"https://pypi.org/integrity/{name}/{version}/{fn}/provenance")
            entry["publishers"] = [
                {k: (b.get("publisher") or {}).get(k) for k in ("kind", "repository", "workflow")}
                for b in (prov or {}).get("attestation_bundles", [])]
        files.append(entry)
    return {"name": name, "version": version, "files": files}


def summary(f: dict) -> dict:
    here = [x for x in f["files"] if x["appliesHere"]]
    pubs = [p for x in here for p in x.get("publishers", [])]
    uniq = [dict(t) for t in {tuple(sorted(p.items())) for p in pubs}]
    attested = bool(here) and all(x.get("publishers") for x in here)
    return {"name": f["name"], "version": f["version"], "files": len(f["files"]), "filesHere": len(here),
            "allServed": all(x["filename"] for x in f["files"]),
            "attested": attested, "partiallyAttested": bool(pubs) and not attested,
            "publisher": uniq[0] if len(uniq) == 1 else (uniq or None)}


def applies_here(filename: str) -> bool:
    if not filename.endswith(".whl"):
        return False
    from packaging.tags import sys_tags
    from packaging.utils import parse_wheel_filename
    return bool(set(parse_wheel_filename(filename)[3]) & set(sys_tags()))


def main() -> int:
    mode, reqs = sys.argv[1], sys.argv[2:]
    all_facts = [facts(n, v, h) for (n, v), h in sorted(parse(reqs).items())]
    if mode == "report":
        json.dump([dict(summary(f), detail=f) for f in all_facts], sys.stdout, indent=1)
        print()
        return 0
    register = {norm(d["name"]): d for d in json.loads((BROKER / "deps.json").read_text())["python"]}
    errors, verified = [], 0
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
        if s["filesHere"] == 0:
            errors.append(f"{tag}: no pinned wheel installs on this platform (pip would build from source)")
        if e["tier"] == "attested":
            if not s["attested"]:
                errors.append(f"{tag}: register expects PyPI attestations, PyPI has none (or not for every file)")
            elif s["publisher"] != e["publisher"]:
                errors.append(f"{tag}: publisher {s['publisher']} != expected {e['publisher']}")
        elif s["attested"]:
            print(f"provenance: note: {tag} now publishes attestations ({s['publisher']}); "
                  "consider raising its tier", file=sys.stderr)
        if mode == "verify" and e["tier"] == "attested" and s["attested"]:
            repo = "https://github.com/" + e["publisher"]["repository"]
            for x in f["files"]:
                if not x["appliesHere"]:
                    continue
                p = subprocess.run(["pypi-attestations", "verify", "pypi", "--repository", repo,
                                    "pypi:" + x["filename"]], capture_output=True, text=True)
                if p.returncode != 0:
                    errors.append(f"{tag}: attestation verification failed for {x['filename']}: "
                                  f"{(p.stdout + p.stderr).strip()[-300:]}")
                else:
                    verified += 1
    for x in errors:
        print("provenance: " + x, file=sys.stderr)
    print(f"provenance: {'ok' if not errors else 'FAILED'} ({len(all_facts)} pins"
          + (f", {verified} attestations cryptographically verified" if mode == "verify" else "") + ")",
          file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
