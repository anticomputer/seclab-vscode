"""Supply-chain pin check for the broker tree (offline; run by broker/docs-check.sh).

  * every Dockerfile `FROM` names an earlier build stage, or is pinned `image@sha256:<64 hex>`
    and recorded in broker/deps.json;
  * every `pip install` in a Dockerfile uses `--require-hashes`;
  * every requirements*.txt pin carries a `--hash=sha256:` and is recorded in broker/deps.json.
Online provenance checks (PyPI attestations, image signatures) are in broker/provenance-check.sh.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

BROKER = Path(__file__).resolve().parents[1]
FROM_RE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", re.I)
PINNED = re.compile(r"^[\w./:-]+@sha256:[0-9a-f]{64}$")
REQ_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)")


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def main() -> int:
    errors = []
    register = json.loads((BROKER / "deps.json").read_text())
    image_refs = {i["ref"] for i in register["images"]}
    py_pins = {(norm(p["name"]), p["version"]) for p in register["python"]}
    for df in sorted(BROKER.rglob("Dockerfile")):
        rel = df.relative_to(BROKER.parent)
        stages: set[str] = set()
        text = df.read_text()
        for n, line in enumerate(text.splitlines(), 1):
            m = FROM_RE.match(line)
            if m:
                image, alias = m.group(1), m.group(2)
                if image.lower() not in stages:
                    if not PINNED.match(image):
                        errors.append(f"{rel}:{n}: base image {image!r} is not pinned by digest")
                    elif image not in image_refs:
                        errors.append(f"{rel}:{n}: base image {image!r} is not in broker/deps.json")
                if alias:
                    stages.add(alias.lower())
        for n, line in enumerate(text.splitlines(), 1):
            if "pip install" in line and "--require-hashes" not in line:
                errors.append(f"{rel}:{n}: pip install without --require-hashes")
    for req in sorted(BROKER.rglob("requirements*.txt")):
        rel = req.relative_to(BROKER.parent)
        lines = req.read_text().splitlines()
        for n, line in enumerate(lines, 1):
            s = line.strip()
            m = REQ_RE.match(s)
            if not m:
                continue
            block = s + "".join(x.strip() for x in lines[n:n + 200] if x.strip().startswith("--hash="))
            if "--hash=sha256:" not in block:
                errors.append(f"{rel}:{n}: requirement without --hash")
            if (norm(m.group(1)), m.group(2)) not in py_pins:
                errors.append(f"{rel}:{n}: {m.group(1)}=={m.group(2)} is not in broker/deps.json")
    for e in errors:
        print("pin-check: " + e, file=sys.stderr)
    if not errors:
        print("pin-check: ok", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
