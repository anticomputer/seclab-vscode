# Probe records hold facts, the clipboard is a canary, and nothing internal enters the repo

- **Status:** accepted
- **Date:** 2026-11-12
- **Deciders:** Repository owner. RPC core landing session: implementation.
- **Related:** [fixture safety](20261104-fixture-safety.md), [test build variants](20261106-test-build-variants.md), [ordinary-session RPC trace](20261106-ordinary-session-rpc-trace.md), [CI hardening](20261104-ci-hardening.md)

## Context
Probes run against real builds on a real machine. Before this, three things depended on
convention rather than structure:
- the clipboard probe read whatever clipboard the app under test exposed;
- run records (evidence files the payloads write) could carry any value a probe read, and
  that text reached reports and logs;
- a test could capture the screen or drive the UI, which needs privacy grants a test should
  never depend on.

The repository is public, so an identifier internal to the user's organisation must not
enter it or a run record, and a list of such identifiers must not be published either. A
hash of a short identifier can be recovered by a dictionary attack, so a hashed list in the
repo would still disclose it.

## Decision
- **The clipboard is a canary.** The `containment` test build variant gets a desktop hook,
  `canary-clipboard` (`test/containment/canary-clipboard/nativeHostMainService-hook.patch`,
  bundle `out/mainImpl.js`). Every clipboard call the renderer can make lands in
  `NativeHostMainService`. In that build none of them touches the system clipboard: they use
  an in-memory store seeded with the run's canary (`SECLAB_TEST_CLIPBOARD_CANARY`), and a
  native paste is a no-op. Like every test hook it never ships: check-release fails any
  artifact carrying its marker.
- **Only that clipboard is ever read.**
  - `check-evidence.ts prepare` verifies the app under test carries the hook
    (`SECLAB_TEST_APP`, marker in the built bundle). Only then does it write
    `clipboard=variant` into the run's targets and the seed into the launch line.
  - `test/window.ts launch` refuses a workspace whose targets claim the canary clipboard,
    or a seed, unless the app carries the hook. So a forged targets line or a swapped
    `--app` cannot turn a probe into a read of the system clipboard.
  - In the payloads, every clipboard read goes through `safety.withCanaryClipboard`. It
    refuses without the verified flag and returns canary tokens only.
  - No harness, tool or probe uses the system pasteboard.
- **Run records hold facts, never values.** `safety.recordJson` is the only way a payload
  serialises a record. It accepts booleans, finite numbers, null, canary tokens and source
  literals (`safety.lit`), and throws on any other string. Probes return facts: whether a
  canary crossed, counts, whether a call returned. Failures are recorded as a kind, never a
  message. A window session is kept as a numeric fingerprint. The benign control, the rogue
  extension, the rogue REH and the restart probe all write this way, and `check-probes.ts`
  and `check-evidence.ts` read facts.
- **Structural, not conventional.** `rpc-filter/tools/lint_probes.py` fails on:
  - any use of the `clipboard` identifier in a payload's code outside a
    `withCanaryClipboard(...)` call, and any paste action or page-side clipboard API
    (`clipboard-outside-canary`);
  - any pasteboard use in the harness tree (`pasteboard`);
  - a record write whose data is not `recordJson(...)` or a literal (`raw-record`);
  - a `lit()` whose argument is not a literal (`lit-not-literal`);
  - a probe id that is not a literal, `v.id` or a constant (`probe-id-not-literal`);
  - a computed key in a record writer (`computed-record-key`).

  The fixture lint fails on screen capture, accessibility and synthetic-input APIs
  (`screen-automation`). The harness's capture helper, the window-capture mode and the
  Space-switching focus probe are removed.
- **No internal identifiers, and no published list of them.**
  - `build/check-denylist.ts` scans the tracked tree, and any run-record directory passed
    with `--extra`. Matching is by normalised token sequences (NFKC, format characters
    dropped), so case, punctuation and compatibility forms don't hide an identifier. A finding
    prints file and line only. Skipped files are named, and an unreadable text file fails a
    required scan. It catches accidents; it is not an adversary filter.
  - The list lives in the `SECLAB_DENYLIST` secret of the `denylist` GitHub environment,
    whose deployment-branch rule admits main only. The `denylist` job of workflow-lint.yml runs
    only on a push to main, so no code a branch or pull request controls runs with the secret
    (review round 17). `build/ci-denylist.sh`:
    - fails closed without the secret;
    - masks every entry;
    - hands the list to a container with no network, as a private temp file outside the
      checkout.

    Every other event, forks included, gets a notice.
  - Developers keep the list outside the repo (`SECLAB_DENYLIST_FILE`, default
    `~/.config/seclab/denylist.txt`, private) and the mandatory pre-push hook runs it before
    anything leaves the machine. The scan and its CI jobs are now layers of the publish gate
    ([EDR](20261112-publish-gate.md)).

## Evidence
- `lint_probes.py` over a snapshot of the payloads before this change fails every new rule:
  - `clipboard-outside-canary` on the clipboard probe and the observed-sources read;
  - `pasteboard` on the old clipboard seeding;
  - `raw-record` on every evidence write;
  - `probe-id-not-literal` on the templated laundering ids.

  The current tree is clean. `test_lint_probes.py` (18 tests) holds each rule in both
  directions.
- `probe-safety.test.ts` covers the record validator, `lit`, `canaryTokens` and
  `withCanaryClipboard`. That includes that the reader is never called without the canary
  clipboard, and that a forged targets value does not enable it.
- The denylist check was built against a test list of obviously fake entries:
  - an injected matching string in a tracked file failed the scan, naming only file and line;
  - with the string removed it passed;
  - a fullwidth form was caught;
  - a text file hidden behind a NUL prefix was named as skipped and failed the required scan;
  - with no secret, the CI script failed closed.

  On every event other than a push to main the workflow only prints a notice (verified by
  actionlint and zizmor, not run on Actions under the freeze).
- Both containment hooks apply on top of `patches/series` (`build/test-variant.sh check-all`).
- The hook's runtime evidence comes from the next containment build. The liveness register
  records it then.

## Consequences
- A baseline (unfiltered) run of `clipboard-read` needs a containment build of main, which
  carries the hook once this lands. Until then no run includes `clipboard-read`.
- Records are less descriptive: a failure says what kind it was, not what the message said.
  Debugging uses the editor's own logs, which stay in the run's profile and are removed with
  it.
- The denylist check depends on a secret. A missing secret blocks pushes to main by design.
