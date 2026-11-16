"""Finding provenance #5: attestation verification binds the verified bytes to the pinned hash
and the signer to the register's publisher. Runs `verify_file` (tools/provenance.py) offline,
in the attest image, against a real PyPI provenance recorded beside this file (platformdirs 4.14.5,
published by tox-dev/platformdirs release.yaml; test input, read on every run, so a missing or
changed file fails the test). The correct pin verifies; a different digest, repository or
workflow must raise.
    broker/tests/provenance/run.sh
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from provenance import verify_file  # noqa: E402

FIXTURE = Path(__file__).parent / "platformdirs-4.14.5-py3-none-any.whl.provenance.json"
WHEEL = "platformdirs-4.14.5-py3-none-any.whl"
PINNED = "8e778c6fa421516f4d3369449f8df3b0e1b72c0e0005fe88e3ec772d0a14e750"
PUBLISHER = {"kind": "GitHub", "repository": "tox-dev/platformdirs", "workflow": "release.yaml"}


def file_facts(sha256: str) -> dict:
    return {"filename": WHEEL, "sha256": sha256, "provenance": json.loads(FIXTURE.read_text())}


def raises(fn) -> bool:
    try:
        fn()
    except Exception:  # noqa: BLE001 - any failure is a refusal
        return True
    return False


CASES = [
    ("provenance #5: the pinned digest and the registered publisher verify",
     lambda: verify_file(file_facts(PINNED), PUBLISHER, offline=True) >= 1, True),
    ("provenance #5: a digest other than the pinned one is refused",
     lambda: raises(lambda: verify_file(file_facts("0" * 64), PUBLISHER, offline=True)), True),
    ("provenance #5: another repository than the registered one is refused",
     lambda: raises(lambda: verify_file(file_facts(PINNED), dict(PUBLISHER, repository="example/platformdirs"),
                                        offline=True)), True),
    ("provenance #5: another workflow than the registered one is refused",
     lambda: raises(lambda: verify_file(file_facts(PINNED), dict(PUBLISHER, workflow="other.yaml"),
                                        offline=True)), True),
    ("provenance #5: a non-GitHub register publisher is refused",
     lambda: raises(lambda: verify_file(file_facts(PINNED), dict(PUBLISHER, kind="GitLab"), offline=True)), True),
    ("provenance #5: a provenance with no attestations is refused",
     lambda: raises(lambda: verify_file({"filename": WHEEL, "sha256": PINNED,
                                         "provenance": {"version": 1, "attestation_bundles": []}},
                                        PUBLISHER, offline=True)), True),
]


def main() -> int:
    failed = [name for name, check, want in CASES if check() is not want]
    for name in failed:
        print(f"provenance binding: FAIL: {name}", file=sys.stderr)
    if failed:
        return 1
    print(f"provenance binding: ok ({len(CASES)} cases)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
