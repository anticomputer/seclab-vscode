"""Supply-chain pin check for the broker tree (run by broker/docs-check.sh).

  * every Dockerfile `FROM` names an earlier build stage or is pinned `image@sha256:<64 hex>`;
  * every `pip install` in a Dockerfile uses `--require-hashes`, and every
    requirements*.txt line carries a `--hash=sha256:`.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

BROKER = Path(__file__).resolve().parents[1]
FROM_RE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", re.I)
PINNED = re.compile(r"^[\w./:-]+@sha256:[0-9a-f]{64}$")


def main() -> int:
    errors = []
    for df in sorted(BROKER.rglob("Dockerfile")):
        rel = df.relative_to(BROKER.parent)
        stages: set[str] = set()
        text = df.read_text()
        for n, line in enumerate(text.splitlines(), 1):
            m = FROM_RE.match(line)
            if m:
                image, alias = m.group(1), m.group(2)
                if image.lower() not in stages and not PINNED.match(image):
                    errors.append(f"{rel}:{n}: base image {image!r} is not pinned by digest")
                if alias:
                    stages.add(alias.lower())
        for n, line in enumerate(text.splitlines(), 1):
            if "pip install" in line and "--require-hashes" not in line:
                errors.append(f"{rel}:{n}: pip install without --require-hashes")
    for req in sorted(BROKER.rglob("requirements*.txt")):
        rel = req.relative_to(BROKER.parent)
        for n, line in enumerate(req.read_text().splitlines(), 1):
            if line.strip() and not line.startswith("#") and "--hash=sha256:" not in line:
                errors.append(f"{rel}:{n}: requirement without --hash")
    for e in errors:
        print("pin-check: " + e, file=sys.stderr)
    if not errors:
        print("pin-check: ok", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
