"""Finding provenance #5: attestation verification binds the verified bytes to the pinned hash
and the signer to the register's publisher. Runs `verify_file` (tools/provenance.py) offline,
in the attest image, against a real PyPI provenance recorded beside this file (platformdirs 4.14.5,
published by tox-dev/platformdirs release.yaml; test input, read on every run, so a missing or
changed file fails the test). The correct pin verifies; a different digest, repository or
workflow must raise. Finding provenance #6: a pin in a lockfile installed into another base than
the verifier's must be a pure py3-none-any wheel (checked against a fake index, offline).
    broker/tests/provenance/run.sh
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import provenance  # noqa: E402
from provenance import verify_file  # noqa: E402

FIXTURE = Path(__file__).parent / "platformdirs-4.14.5-py3-none-any.whl.provenance.json"
WHEEL = "platformdirs-4.14.5-py3-none-any.whl"
PINNED = "8e778c6fa421516f4d3369449f8df3b0e1b72c0e0005fe88e3ec772d0a14e750"
PUBLISHER = {"kind": "GitHub", "repository": "tox-dev/platformdirs", "workflow": "release.yaml"}


def file_facts(sha256: str) -> dict:
    return {"filename": WHEEL, "sha256": sha256, "provenance": json.loads(FIXTURE.read_text())}


def purity(filename: str, pure_required: bool) -> bool:
    """Finding provenance #6: summary()'s allPure for one pinned file PyPI serves as `filename`,
    pinned in a lockfile installed into another base than the verifier's (pure_required) or not.
    PyPI is replaced by a fake index; nothing leaves the container."""
    h = "c" * 64
    real = provenance.get
    provenance.get = lambda url: {"urls": [{"digests": {"sha256": h}, "filename": filename}]} \
        if url.endswith("/json") else None
    try:
        return provenance.summary(provenance.facts("pkg", "1.0", {h}, {h} if pure_required else set()))["allPure"]
    finally:
        provenance.get = real


def pure_marked(in_pure_file: bool) -> bool:
    """collect() marks a pin's hashes pure-required only when its lockfile is in pure_files."""
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "requirements.txt"
        f.write_text(f"pkg==1.0 --hash=sha256:{'d' * 64}\n")
        pins, errors = provenance.collect([f], {f.resolve()} if in_pure_file else set())
        assert not errors, errors
        return bool(pins[("pkg", "1.0")]["pure"])


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
    ("provenance #6: a pure py3-none-any wheel passes the purity rule",
     lambda: purity("pkg-1.0-py3-none-any.whl", True), True),
    ("provenance #6: a platform wheel pinned for another base than the verifier's is refused",
     lambda: purity("pkg-1.0-cp313-cp313-manylinux_2_17_aarch64.whl", True), False),
    ("provenance #6: an sdist pinned for another base than the verifier's is refused",
     lambda: purity("pkg-1.0.tar.gz", True), False),
    ("provenance #6: a py2-only wheel pinned for another base than the verifier's is refused",
     lambda: purity("pkg-1.0-py2-none-any.whl", True), False),
    ("provenance #6: a platform wheel pinned only for the verifier's own base needs no purity",
     lambda: purity("pkg-1.0-cp313-cp313-manylinux_2_17_aarch64.whl", False), True),
    ("provenance #6: a lockfile installed into another base marks its pins pure-required",
     lambda: pure_marked(True), True),
    ("provenance #6: a lockfile installed only into the verifier's base doesn't",
     lambda: pure_marked(False), False),
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
