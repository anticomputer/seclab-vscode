# The 7-day rule: no pin newer than the feed's hold

- **Status:** accepted
- **Date:** 2026-11-06
- **Deciders:** the user ("I'm not sitting here for a week doing nothing, use versions that are available instead"); the coordinator (policy, and exemptions 1A and 2A). Fork-build session: implementation.
- **Related:** [CFS local builds](20261105-cfs-local-builds.md), [ADR supply-chain provenance](../adr/20261104-supply-chain-provenance.md), [pinned tools](20261105-pinned-tools.md)

## Context
GitHub CFS holds newly published npm and PyPI versions for 7 days. Local builds go through CFS,
so a pin younger than that can't be fetched locally. On 2026-11-05 that blocked the broker image
and the attestation verifier for days. The user's direction is to use versions that are
available rather than wait.

## Decision
- **No pin may be younger than 7 days.** This applies to every pin in the register, not only
  CFS feeds, so the rule is one rule.
- **Mechanical check:** `build/pin-age.ts` (`./seclab lint pin-age`), run in CI's `lint` job.
  It dates each register pin as follows:
  - `upstream:` and `git:` sources and actions: the commit date. For actions this is a lower
    bound on the release's age; Dependabot's cooldown covers the release date.
  - Tool releases and the ripgrep prebuilt: the GitHub release's publish date.
  - Images: the config's `created` (linux/amd64).
  - pip: every `==` pin in the registered requirements files, by first upload to PyPI.
  - npm: exact-version installs in tracked Dockerfiles (vsce), by publish time. The transport
    is chosen by environment, never by fallback. Locally, `./seclab lint pin-age` reads the
    CFS feed's packument (`gh cfs -- npm view <name> time --json`; gh cfs injects the
    credential, which never reaches argv or logs) and passes the dates in. In CI, the public
    registry is its only transport (EDR cfs-local-builds). A version CFS doesn't serve fails
    locally, with a `gh cfs doctor --auth` hint.
  - pip uses the PyPI JSON API on pypi.org, which isn't blocked; wheels are never fetched.

  An unknown date fails. Debian apt sets and debs are exempt, and printed as such: they come
  from the apt-signed Debian archive, not a CFS feed.
- **Recorded exemptions** (`ageExempt` in the register; `build/deps.ts` requires a reason and
  this EDR to list the entry):
  - `code-oss` (1A): the upstream git commit isn't fetched through CFS. Its npm tree is dated
    as a whole: a lockfile can't name a version published after its commit, and the local CFS
    fetch fails on any lockfile entry CFS won't serve.
  - `img-sbx-shell-kit` (2A): host-dictated. The template must match the kit the installed
    sbx release runs.
- **Updates respect the rule:**
  - Dependabot has `cooldown: default-days: 7` for every ecosystem, and now also watches
    `broker/tools/attest` (pip and docker).
  - The weekly `deps outdated` report suggests only releases and moved tags at least 7 days
    old, and only a release published after the pinned one. Until 2026-11-09 a pin newer than
    every release past the cooldown (`code-oss` 1.145.0) was reported with the older one as
    "new"; `./seclab deps outdated --self-test` (ci-unit) covers that case.
- **`deps-updates` never ran until 2026-11-09.** Its container mounts single files (review
  EE-2), and `build/release-dates.ts`, imported by `deps-outdated.ts` for this rule, was never
  added. The first scheduled run failed with `ERR_MODULE_NOT_FOUND`. The mount lists are now
  named arrays in `seclab`, and `./seclab lint mounts` (ci-unit) fails when a list misses part
  of its entry's import closure (`build/import-closure.ts`). The same applies to the image
  verifier's mounts.
- **Re-pinned 2026-11-06** to the newest builds at least 7 days old:
  - `golang:1.27.2-trixie`, which rebuilt gitleaks: binaries `6949cfae…` (arm64) and
    `e0e51d58…` (amd64), updated in `build/tools/tools.json` and tabd's scanner pin;
  - `rust:1.99.0-slim-trixie` (lychee);
  - `zizmor:1.31.1` (signature re-verified for both platforms; workflows clean).

  The broker session re-pins its own held pins (`docker:29-cli` and six pip pins).
  On 2026-11-09 it bumped `fastjsonschema` to 2.22.3 and `platformdirs` to 4.14.3, the
  newest CFS served; `dnspython`, `pypi-attestations` and `typing-inspection` had nothing
  newer on CFS, and `docker:29.9.3-cli` was still under 7 days old.

## Consequences
- **Security fixes are adopted a week late.** An urgent fix that must land sooner is a
  recorded `ageExempt` with an EDR, never a CFS bypass.
- **CI and local transports differ** (EDR cfs-local-builds), but both now resolve only
  versions CFS serves.
