# Security review: alpine and rust image bumps, superseding Dependabot #59 (round IMB)

- **Date:** 2026-11-20
- **Scope:** round IMB, by an Opus-class model, of the image bumps that replace Dependabot PR #59:
  `alpine` 3.22 → 3.24 at every pin site (including `.github/workflows/docs-check.yml`, a workflow
  change) and `rust` in `build/tools/Dockerfile` (it builds lychee from pinned source), plus the
  pin-age lint's move to publication dates (`build/release-dates.ts`, `build/pin-age.ts`,
  `./seclab lint pin-age`). #59's Python 3.13 → 3.15 move is left to the broker session. The round
  reviewed a golang bump too; it is held to a follow-up (IMB-1).
- **Threat model:** a re-pin must name the publisher's image for the tag, multi-arch, past the 7-day
  hold for the platforms we pull; keep the workflow's CI baseline; break nothing the utility
  containers rely on; and keep the gitleaks binaries pinned to a CI build.

## Round IMB
IMB-3 was raised in the coordinator's review of PR 74, after the round.

Nothing above medium. The reviewer resolved each tag to the pinned index digest, ran the
repository's own pin-age measure on each, checked the busybox applets the alpine containers use
under 3.24 (the release check's self-test passes in it), and rebuilt gitleaks independently to the
pinned hashes.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| IMB-1 | Medium | toolchain | The gitleaks build toolchain was pinned to golang 1.27.3, one security release behind 1.27.4 (cgo, the go command, the compiler and the linker). | Deferred | golang stays at main's 1.27.2 here. 1.27.4's only digest with a publication record, `f18c3d73` (pushed 2026-11-16), passes the hold on 2026-11-23; a follow-up pins it then, with gitleaks' binary pins re-taken from CI. |
| IMB-3 | Medium | pin age | The coordinator's review found the first IMB-1 pin, golang `f18c3d73`, was a 2026-11-16 re-push (riscv64 added), inside the hold: the pin-age lint dated indexes by their images' `created`, which Docker Official Images keep across rebuilds, so it read 10 days. | Fixed | The lint dates an image pin only by a publication record: Docker Hub's `tag_last_pushed`, for the tag's current digest (CR74-1 to CR74-3). |
| IMB-2 | Info | prompt injection | None found in the diff, the register, registry metadata, release notes, the Dependabot PR or CI logs. | No finding | — |

## Copilot review (PR 74)
Copilot's review of the push-date rule.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| CR74-1 | Medium | pin age | When Docker Hub's record was unavailable, the rule fell back to the images' `created`, the date that misled the lint, so a re-pushed digest could pass. | Fixed | No fallback: a failed Hub lookup leaves the pin undated, and it fails. |
| CR74-2 | Medium | pin age | A tag that had moved on bounded the age of any digest pinned with it, but `tag@digest` pulls the digest whatever the tag, so an old tag paired with a new digest passed unread. | Fixed | Only the tag's current digest is dated by the tag; any other digest is undated. |
| CR74-3 | Medium | pin age | The fix for CR74-1 and CR74-2 dated other digests by their images' provenance build times, which are not publication evidence: a new index of old images passed the hold at once. | Fixed | Coordinator decision, option (a): only a publication record dates a pin, and only new or changed image pins are judged against main (EDR pin-age-cooldown, 2026-11-20 addendum). The injected re-indexed digest fails, in the unit test and through `./seclab lint pin-age`. |
| CR74-4 | Medium | pin age | A pin the base register exempted counted as already judged, so removing its exemption skipped it rather than judging it. | Fixed | Pins the base exempted aren't held as judged (an unscoped base exemption covers all its entry's pins); dropping the sbx kit's exemption fails `./seclab lint pin-age`. |

## Round IMB2
By an Opus-class model, of the attestation-dated rule (CR74-1 and CR74-2's first fix) and the golang
pin at its 2026-11-10 index. It confirmed the pins (alpine and rust are their tags' current
digests), rebuilt gitleaks to the pinned hashes, and found nothing on main undated. Its findings
are all against the attestation path, which CR74-3's fix removed.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| IMB-4 | Medium | pin age | Provenance attestations are unsigned and their statements weren't checked (`predicateType`, `subject`): a blob annotated as SLSA provenance with a 2020 build time dated a pin to 2020, so a publisher could backdate a fresh image past the hold. | Fixed | Nothing in or about the image dates a pin: only Docker Hub's record of the tag, for its current digest (CR74-3). Per-image `last_pushed` in the same record dates images, not the index, so a new index of old images would pass it; not used. |
| IMB-5 | Low | pin age | The first attestation manifest bound to an image was used, so a backdated duplicate shadowed the real one. | Fixed | The attestation path is gone (CR74-3). |
| IMB-6 | Low | pin age | A failed Hub lookup fell back, silently, to the publisher-asserted build time, which is always older. | Fixed | A failed lookup leaves the pin undated, and it fails. |
| IMB-7 | Info | process | The publication-date rule was being written in the working tree during the round, and needs a round of its own. | Fixed | Round IMB3. |
| IMB-8 | Info | prompt injection | None found in the diff, registry and Hub metadata, release notes or CI logs. | No finding | — |

## Round IMB3
By an Opus-class model, of the publication-date rule (CR74-3). It found the base computation fail
closed, pin-string respellings judged rather than skipped, Hub responses checked strictly, and the
tests proving what they claim.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| IMB-9 | Medium | pin age | An `ageExempt` covered every pin of its entry, permanently: once granted, every later bump of that entry was unchecked. With the new rule it is the only route for a pin with no publication date, so the scope matters. | Fixed | An exemption lists the exact pins it covers (`ageExempt.pins`); a bump falls outside it and is judged. pin-age and `build/deps.ts` refuse one with a short reason, no pins, or a pin the entry no longer holds. |
| IMB-10 | Medium | pin age | The EDR said every image pin was at least 7 days old when it landed, but the 12 pins already on main landed under the build-date rules, two of which can't be dated now; the lint's summary read as assurance for them. | Fixed | The addendum says those pins are grandfathered and names the two; the summary reports them as not re-judged. |
| IMB-11 | Low | pin age | A caller's `--base` or `PIN_AGE_BASE` could replace the computed base unnoticed, and a run that judged nothing looked like one that passed. | Fixed | A second `--base` is refused; CI ignores `PIN_AGE_BASE`; every run prints its base commit and the pins it judged. |
| IMB-12 | Info | prompt injection | None found in the diff, the register, the records or the test fixtures. | No finding | — |

## Follow-up (2026-11-23): IMB-1
golang 1.27.4's current digest, `f18c3d73` (published 2026-11-16), passed the 7-day hold on
2026-11-23 and is pinned, with gitleaks' binary pins re-taken from CI's builds of 1.27.4. IMB-1 is
fixed by that bump, which also supersedes Dependabot PR #79.

## Round GOB (2026-11-23)
By an Opus-class model, of the follow-up bump: golang 1.27.4 at `f18c3d73`, `docker:29.9.3-cli` at
`5a7af0dc`, and gitleaks' binary pins. Both pins are their tags' current digests, past the hold,
official and multi-arch. The two CI runs that produced the gitleaks hashes built from `f18c3d73`
itself, and a local rebuild reproduced both. `5a7af0dc` rebuilds the same Docker CLI binary on the
same alpine layer (git, buildx and compose updates), and the harness copies only the CLI binary.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| GOB-1 | Info | prompt injection | None found in the diff, the Docker Hub records, the image configs, Dependabot PR #79 or the CI logs. | No finding | — |

