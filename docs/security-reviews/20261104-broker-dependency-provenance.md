# Security review: broker dependency provenance gate

- **Date:** 2026-11-04
- **Scope:**
  - Round 4: `6fa796a` (the dependency register, `tools/pin_check.py`,
    `tools/provenance.py`, `tools/verify-images.sh`, `tools/attest/`,
    `provenance-check.sh`, `build.sh`, `test.sh`, the EDR).
  - Threat model: a change to a lockfile or Dockerfile that installs
    unregistered or swapped code while both gates pass; a compromised or
    dishonest index, CDN or registry; and fail-open gate behaviour.
- **Reviewer:** `security-review` agent (default model; it did not refuse).
  It confirmed each bypass with pip 25 in the pinned `python:3.13` image, the
  repo's own parsers, and the exact `verify-images.sh` pipeline. Triage and
  fixes by the broker session.
- **Related:** [EDR dependency provenance](../edr/20261104-broker-dependency-provenance.md)

## Findings
| # | Severity | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| 1 | High | Lockfile parsing | Both gates matched `^name==version` and skipped any other line. pip still installs extras (`pkg[x]==…`), `pkg == …`, direct URLs, `-r`/`-c` includes, and index or find-links options, so unregistered or swapped code could install while pin-check and provenance both printed "ok". `provenance-check.sh` hard-coded five files; Dockerfile checks only looked at lines containing `pip install`. | fixed | New `tools/supplychain.py`, shared by both gates. Strict requirements grammar: plain pin plus `--hash=sha256:<lowercase hex>`; anything else is an error. Both gates discover every `requirements*.txt`. Dockerfiles must use one canonical `pip install … -r <path>`, and `<path>` must be a `COPY` of a checked file; other installers (`uv`, `python -m pip`, `sh -c 'pip …'`) are rejected. Every lockfile must be installed by some Dockerfile. | `pin_check.py --self-test` (run by `docs-check.sh`) |
| 2 | High | Hash forms | Only lowercase `--hash=sha256:` was collected. pip also honours sha384/sha512, uppercase digests and `--hash sha256:`. A sha512 hash of an evil wheel from an extra index would pass both gates. | fixed | The strict grammar accepts only `--hash=sha256:` with 64 lowercase hex; any other hash token is an error. Index options are banned (finding 1). | `pin_check.py --self-test` |
| 3 | Medium | Fail-open gate | `verify-images.sh` piped the register reader into `while read` under `sh`. A failing reader (pull failure, assertion, malformed entry) gave an empty loop and exit 0, and `build.sh` then built unverified. | fixed | List produced and validated first (`set -e` applies). Unsupported kind or malformed fields exit 1. An empty list fails. "ok" only when verified count equals the attested count. Also `--deny-self-hosted-runners` (design note). | manual: unsupported kind exits 1 (EDR evidence) |
| 4 | Medium | Unpinned frontend | `# syntax=docker/dockerfile:1` made BuildKit pull and run a mutable-tag frontend that controls the whole build graph; it was not pinned or registered. | fixed | Directive removed. `supplychain.py` rejects any parser directive, plus `ADD`, `ONBUILD`, `RUN` flags (`--mount`), `COPY --from=` a non-stage, and pip configuration (`PIP_*`, `pip.conf`). | `pin_check.py --self-test` |
| 5 | Medium | Verification binding | `pypi-attestations verify pypi pypi:<file>` re-downloaded the file named by PyPI's JSON for the pinned hash; nothing tied the verified bytes to the pin. The workflow was checked only against unsigned publisher metadata from a separate request. A dishonest index could pass a legit file and its provenance to the verifier while pip got another. | fixed | Verify in-process: provenance fetched once; each attestation verified against `Distribution(name, digest=<pinned sha256>)` with a `GitHubPublisher` policy built from the register's repository and workflow. | manual: wrong digest, workflow or repo each raise `VerificationError` (EDR evidence) |
| 6 | Low | Target interpreter | `applies_here()` used the verifier's tags, but two lockfiles install into the mitmproxy image (a different Python). A future binary pin could verify one wheel while pip installs another, or an sdist. | fixed | Every install is `--only-binary=:all:`. Lockfiles installed into a base other than the verifier's must pin pure `py3-none-any` wheels only; their purity is checked per lockfile. | `provenance-check.sh` |
| 7 | Low | Dockerfile scope | Line-based checks missed continuations, `uv pip`, and Dockerfiles not literally named `Dockerfile`. | fixed | Instruction-level parsing with continuations joined. `Dockerfile.*`, `*.Dockerfile` and `Containerfile*` are discovered. Installer detection works on shell-tokenised commands. | `pin_check.py --self-test` |
| 8 | Low | apt freeze/rollback | Test-image apt versions float, and trixie's `InRelease` has no `Valid-Until`, so an older signed index can be replayed over `http://deb.debian.org`. | accepted (exception) | Test-only images, never shipped; recorded as an explicit exception in the EDR instead of "no exception needed". Snapshot pinning was tried and rejected (EDR). | n/a |

Confirmed sound by the reviewer:
- tag plus digest in `FROM`: Docker ignores the tag;
- index digest versus per-platform manifest: the index digest is attested, and
  it references the platform manifest by digest;
- no time-of-check/time-of-use gap between `verify-images.sh` and `docker build`;
- Docker Official Images meet the hash-pinned tier.

**After fixes:** no high or critical findings remain.
`broker/provenance-check.sh`: `provenance: ok (5 files, 43 pins, 32
attestations verified against pinned digests)`, `verify-images: ok (1 attested
image(s))`.
