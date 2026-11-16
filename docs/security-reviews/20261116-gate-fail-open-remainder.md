# Security review: the remaining gate fail-open findings and the write-back mount (round FBA)

- **Date:** 2026-11-16
- **Scope:** round FBA, by an Opus-class model:
  - GATE-13 to GATE-17 (gate fail-open audit): `build/hooks/pre-push`, `build/pin-age.ts`,
    `build/check-pins.ts`, `build/check-source.ts`, the image prune in `seclab`;
  - review OR-R3: `sandbox/rootfs/opt/seclab/bin/seclab-wb-mount` (link-free resolution and the
    share's mount point pinned after mounting), `sandbox/test/test_wb_mount.py`.
- **Threat model:** a gate must never report success while checking nothing, and must not
  block normal work so that people bypass it. The write-back helper runs as root in the tab's
  VM, possibly after tab code ran; tab code must not be able to make it mount the overlay
  anywhere but over the host share at the workspace path.

## Round FBA
One medium. Confirmed:
- GATE-14 refuses before any network (run in a `--network none` container), including the
  `--list-npm` path that `./seclab lint pin-age` calls first;
- GATE-15 and GATE-16 close their fail-opens, GATE-17 is accurate, and the real repository
  passes each new check;
- `test_wb_mount.py`'s moved-share case is a true negative control (the replaced count-only
  check passed it); mountinfo parsing and escaping are sound;
- tab code can't make its own bind or FUSE mounts (no setuid `fusermount`; the guard refuses
  new user and mount namespaces), and the measured sbx layout holds: the tab-owned parent sits
  in a root-owned 1755 directory, so it can't be renamed;
- the OCI driver doesn't use the helper (its write-back is ungated), so OCI tabs are unaffected.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| FBA-1 | Medium | pre-push | The GATE-13 block stopped every up-to-date push: git runs the hook with no ref lines then, and nothing is published, so the block bought nothing and invited `--no-verify`, which drops both scans. | Fixed | With no ref lines the hook passes, says nothing was checked and nothing is published, and never claims "0 ref(s) checked". |
| FBA-2 | Low | wb-mount | The overlay was recognised by filesystem type only, so an overlay the helper didn't mount would have been accepted. | Fixed | The helper records its overlay's device in its root-only state directory and refuses an idempotent call on any other. Checked in a real sbx tab: a forged record is refused. |
| FBA-3 | Low | wb-mount | The link-free walk's file descriptor isn't used for the mount; later steps re-resolve the path by name. | Accepted | Nothing can win that race in the measured layout (the parent can't be renamed and the workspace is a mount point), and the post-mount pin catches a moved share. |
| FBA-4 | Low | check-source | An empty `patches/series` scanned no patch line and reported clean; the self-test didn't cover the wiring. | Fixed | It fails on an empty `patches/series` or a missing patch; the self-test runs the run's own `initialFindings` on an empty checkout. |
| FBA-5 | Info | check-pins | The purity probe depended on the supplied file list. | Fixed | It runs whenever the parser is listed or on disk. |
