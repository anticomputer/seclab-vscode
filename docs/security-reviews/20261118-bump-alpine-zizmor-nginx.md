# Security review: alpine, zizmor and nginx pin bumps (round BMP)

- **Date:** 2026-11-18
- **Scope:** round BMP, by an Opus-class model, of the pin bumps for `alpine:3.22` (including
  its pin in `.github/workflows/docs-check.yml`, a workflow change), `zizmor` 1.31.1 → 1.32.0
  with its signature identity, and `nginx:alpine`.
- **Threat model:** a re-pin must name the publisher's image for the tag, keep its provenance
  bar (zizmor stays signed-verified), weaken no lint the tool feeds, keep the workflow's CI
  baseline, and respect the 7-day hold for everything under the pinned digest.

## Round BMP
Nothing at medium or above. The reviewer resolved each tag to the pinned index digest, decoded
both zizmor signature bundles (identity, issuer, workflow repository, `refs/tags/v1.32.0`), read
the 1.32.0 changes against `./seclab lint workflows` (nothing weakened; the root-aware input
collection doesn't apply, because the lint passes `.github/workflows`), and found the
workflow's change limited to the digest-pinned `ALPINE` literal.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| BMP-1 | Low | pin age | The pin-age lint dated an image index by its linux/amd64 config only. The `nginx:alpine` index holds a riscv64 image 4.9 days old, so its digest is younger than the hold, and an arm64 image rebuilt later than amd64 would have passed the same way. | Fixed | `imageDate` takes the newest `created` over the index's linux/amd64 and linux/arm64 images, the ones we pull. Platforms we never pull stay out (residual accepted in the EDR pin-age-cooldown addendum): their bytes never reach a build, and dating every image multiplied the Docker Hub reads of the required `lint` check until a trial run hit HTTP 429. The nginx pin passes on its amd64 and arm64 dates. |
| BMP-2 | Low | register | `img-alpine.used` omitted `build/linux/Dockerfile.npm-fetch`, a fourth pin site. | Fixed | Listed. The pin scan already caught a missed site; only the human-facing list was short. |
| BMP-3 | Info | prompt injection | None found in the diff, the register entries, the release notes or the image and certificate metadata. | No finding | — |
