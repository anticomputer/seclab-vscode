# The 7-day rule: no pin newer than the feed's hold

- **Status:** accepted
- **Date:** 2026-11-06
- **Deciders:** Project owner (2026-11-06): use versions that are available instead of waiting a week for the hold to pass; the coordinator (policy, and exemptions 1A and 2A). Fork-build session: implementation.
- **Related:** [CFS local builds](20261105-cfs-local-builds.md), [ADR supply-chain provenance](../adr/20261104-supply-chain-provenance.md), [pinned tools](20261105-pinned-tools.md)
- **Editorial redaction (2026-11-12):** quotations of project conversations replaced with neutral statements; decisions unchanged.

## Context
GitHub CFS holds newly published npm and PyPI versions for 7 days. Local builds go through CFS,
so a pin younger than that can't be fetched locally. On 2026-11-05 that blocked the broker image
and the attestation verifier for days. The project owner's direction is to use versions that are
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
  added. The first scheduled run failed with `ERR_MODULE_NOT_FOUND`; `391c0d3` added the
  mount. To catch the next one, the mount lists are now named arrays in `seclab`, and
  `./seclab lint mounts` (ci-unit) fails when a list differs from its entry's import closure
  (`build/import-closure.ts`). The same applies to the image verifier's mounts.
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

## Addendum (review BMP-1, 2026-11-18)
An image pinned by an index digest is dated by the **newest** config `created` over the
images we pull from it, linux/amd64 (hosted runners) and linux/arm64 (Docker Desktop on Apple
silicon), not by linux/amd64 alone (`imageDate` in `build/release-dates.ts`; tests in
`build/release-dates.test.ts`). An index with neither platform is dated over every image in it.
- **Why not every platform:** the hold protects the bytes we run, and a platform we never pull
  doesn't reach a build. Dating every image also multiplies the anonymous Docker Hub manifest
  reads the required `lint` check makes on every push (8 or more per index instead of 3); a
  trial run of that rule hit HTTP 429 locally.
- **Residual:** an index digest can be younger than the hold when only a platform we don't pull
  was added or rebuilt (the `nginx:alpine` pin `fed7e14b…` holds a riscv64 image from
  2026-11-13, while its amd64 and arm64 images are from 2026-11-05). Accepted: those bytes are
  never fetched.

## Addendum (review of PR 74, 2026-11-20): publication dates, for new and changed pins only
The 7-day hold is about publication: nothing lands before it has been public for a week. The
2026-11-18 addendum dated an index by the newest `created` of its linux/amd64 and linux/arm64
images, and no image field is a publication date. `golang:1.27.4-trixie` was first pushed on
2026-11-10 and re-pushed on 2026-11-16, under a new index digest, when riscv64 was added. Docker
Official Images keep `created` across rebuilds, so the new digest read as 10 days old while Docker
Hub's record said 4. Build times in provenance attestations fail the same way: a new index made of
old images carries old build times however recently it was published.

Decided by the coordinator, 2026-11-20 (option (a)):
- **An image pin is dated only by a publication record.** For a tagged Docker Hub pin, that is the
  tag's `tag_last_pushed` (`hub.docker.com/v2/repositories/<repo>/tags/<tag>`), and only while
  the pinned digest is the tag's current one (`imageDate` in `build/release-dates.ts`). A digest
  the tag has moved on from, a failed Hub lookup, an untagged pin and any other registry are
  undated, and an undated pin fails. A tag record proves nothing about another digest, since
  `tag@digest` pulls the digest whatever the tag says.
- **Other registries** use a real publication date where one exists. None does today without a
  credential: ghcr's packages API (version `created_at`) needs a token with `read:packages`, and an
  anonymous request is refused. When such a pin is bumped (zizmor on ghcr), its entry needs an
  `ageExempt`.
- **`ageExempt` is a supply-chain exception** and needs the owner's approval, brought to the
  coordinator one at a time with its reason. It covers only the exact pins it lists
  (`ageExempt.pins`, review IMB-9): a bump falls outside it and is judged like any other pin, so
  each new pin needs a new approval. pin-age and `build/deps.ts` refuse an exemption with no
  reason (fewer than 20 characters), with no pins, or naming a pin the entry no longer holds.
- **Only image pins that are new or changed are judged**, against main's register at the merge
  base (`imagePinsToJudge`; `./seclab lint pin-age` reads `deps/registry.json` at
  `git merge-base origin/main HEAD` and fails if there is no base). Locally `PIN_AGE_BASE`
  overrides the base; CI ignores it. Each run prints the base commit and the pins it judged
  (review IMB-11).

**The change in guarantee for unchanged pins.** Before, every run re-dated every image pin, so
pin-age asserted that every image on main was at least 7 days old by its build date, as of that
run. Now an unchanged image pin isn't re-dated. From this change on, an image pin lands only with a
publication record at least 7 days old, or an owner-approved exemption naming it: that is checked
once, when it lands. A re-check can't do better, because once its tag moves on, Docker Hub holds
no publication record for the pinned digest.

The image pins already on main when this rule landed (2026-11-20) are grandfathered (review
IMB-10). They were judged by build date (`created`, then provenance build times), which this
addendum says isn't publication evidence, so for them the rule asserts nothing about publication.
Two could not be dated under it at all: `ghcr.io/zizmorcore/zizmor` (another registry) and
`nginx:alpine` (its tag has moved on). Each is judged by publication date, or brought to the owner
for an exemption, at its next bump. pin-age reports them as "unchanged since the base and not
re-judged", not as dated. On a push to main the merge base is main itself, so no image pin is judged
there; the PR that added each pin was judged on a head containing current main (the ruleset's
strict up-to-date rule). Non-image pins (commits, releases, PyPI and npm versions) are still
re-dated on every run: their dates are publication facts that don't change.

This also closes the 2026-11-18 residual (platforms we don't pull): Hub's record dates the push of
the whole index. Tests (`build/release-dates.test.ts`): the re-pushed golang digest is dated
inside the hold; a re-indexed digest of old images is undated and fails (the injected case, also
run through `./seclab lint pin-age` with the 2026-11-10 golang index pinned); an old tag with a new
digest; Hub down; another registry and an untagged pin; only the pins main lacks are judged; an
exemption without a reason is refused.
