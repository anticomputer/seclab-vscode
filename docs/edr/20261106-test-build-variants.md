# Test build variants (containment, and agentic U/F)

- **Status:** accepted
- **Date:** 2026-11-06
- **Deciders:** Coordinator (2026-11-06; project owner requirements: an attested containment build variant, and a containment variant that fails loudly if the hook is absent; shared with the agentic plan's U and F builds). Fork-build session: implementation.
- **Related:** [branch test builds](20261106-branch-test-builds.md), [patch series](20261104-patch-series.md), [RPC escape probes](20261104-rpc-escape-probes.md), [agentic implementation plan §2](../plans/agentic-implementation.md)
- **Editorial redaction (2026-11-12):** quotations of project conversations replaced with neutral statements; decisions unchanged.

## Context
The rogue-REH probes never ran: nothing applied the test-only hook
`test/containment/rogue-reh/serverServices-hook.patch`, although `patches/README.md` said the
containment harness did. The hook gated on `SECLAB_ROGUE_REH=1` in the REH's environment,
which can never be set, because the tab runs everything under `env -i`. The agentic plan's U
and F builds have the same needs: a deliberately unsafe build that can't pass as a release,
lands in its own place, and records what it contains.

## Decision
- **One mechanism, one manifest.** `test/builds/variants.json` lists each variant's test-only
  hooks:
  - `id`;
  - `patch`, a regular file under `test/`;
  - `target`, `desktop` or `reh`;
  - `marker`, a `SECLAB_TEST_ONLY:<name>` string literal the hook's code emits;
  - `bundle`, the built file that code lands in (`out/server-main.js` for rogue-REH). The
    marker must be in that file. It is never written to product.json, which the build inlines
    into other bundles (review CCC-1).

  Each variant names its review record. Adding a variant or a hook needs a review round.
  `containment` has one REH hook, `rogue-reh`. The agentic session adds U and F as entries.
- **Build** (`build/test-variant.sh`):
  - `apply`, after `prepare.sh`: applies the target's hooks, failing on any that doesn't
    apply. It writes the positive marker `seclabTestBuild {variant, target, hooks[{id, patch,
    sha256, marker}]}` into product.json.
  - For the desktop app, `apply` also changes the identity:
    - name `seclab-vscode-TEST-<variant>`;
    - bundle id `dev.seclab.vscode.test.<variant>`;
    - its own data folder and URL scheme.

    The REH keeps its server names, which tabd and the tab image use.
  - `verify`, after the build, fails unless:
    - every hook's marker is in its bundle;
    - the built product.json records exactly those hooks;
    - `check-release` refuses the artifact on the test markers and nothing else, so the I8
      agent-runtime scan still has to come back clean.
- **Release gate:** `check-release` fails on `seclabTestBuild`, in addition to the existing
  markers. Release and branch fetches also refuse a build-info with `testBuild`.
- **CI:**
  - `build-macos` `workflow_dispatch` takes `test_variant`, a choice that defaults to `none`.
  - With a variant set, the macOS job builds the renamed app, and a `reh-test` job on
    `ubuntu-24.04-arm` builds the hooked arm64 REH with `./seclab build linux reh`. Both
    are attested.
  - They upload only as `seclab-vscode-darwin-arm64-test-<variant>` and
    `seclab-reh-linux-arm64-test-<variant>`. The release and branch uploads exclude
    variants, including a variant dispatched on main.
  - patch-build checks that every variant's hooks still apply on top of the series, so a
    series change that breaks a hook fails on the PR.
  - ci-unit runs the `require-hooks` self-test.
- **Fetch:** `./seclab fetch macos-<variant> RUN` checks the run, both artifacts' hashes and
  attestations (build-macos.yml at that branch and commit), that the run's commit is HEAD or an
  ancestor of it (review CCC-3), and that both build-info files record exactly the hooks this
  checkout's manifest lists. It extracts into `.work/test-builds/<variant>/` only.
- **Local REH:** `SECLAB_TEST_VARIANT=<v> ./seclab build linux reh` uses its own volume,
  `seclab-test-<v>`, and output directory. `./seclab image oci --test-variant <v>` builds
  only `seclab-tab-oci:test-<v>`, refusing a tarball whose REH records a different
  variant. The release tag `:local` refuses any test REH.
- **Harness:** `test/builds/require-hooks.ts` refuses to proceed unless the tab image (or a
  REH directory) is that variant's test build, records each requested hook, and contains its
  marker in code. REH probe runs call it first.
- **Arming:** the hook is disarmed until the harness stages a run in the tab:
  `~/.seclab-test/rogue-reh/targets` holding the per-run nonce `arm`, a run directory `run`
  and an unexpired `until`, with `probes.js` and `probe-safety.js` next to it. That is the
  same route the in-tab rogue extension arms by.
  - The hook polls for that file every 2 s until armed, and stops on server shutdown.
  - It loads the payload from that fixed path and writes evidence under it. No path comes
    from the environment.
  - As `probe-safety.js` says, arming is not a boundary, because the tab can write its own
    home. It keeps the hook inert outside a harness run. The boundary is that nothing but a
    test variant contains the hook.

## Consequences
- Proven on run 42252088798 (branch commit `66af5e9`):
  - both halves built, verified and attested, and check-release refuses each;
  - `fetch macos-containment` refused the run from a checkout without that commit, and
    verified and extracted it from one with it;
  - the app is `dev.seclab.vscode.test.containment`;
  - `image oci --test-variant` built `seclab-tab-oci:test-containment` and refused to tag
    that REH `:local`;
  - `require-hooks` accepted the test image and refused `:local`;
  - `test/builds/rogue-reh-arming.ts`, in a real OCI tab of that image: no targets, an
    expired run and a malformed nonce leave the hook disarmed, and a valid run loads the
    payload once, with the socket server and router.
- The macOS half of a variant with no desktop hooks (containment today) is the release app
  renamed and marked. That gives a client from the same commit and upstream, which pairs with
  the variant REH, and a visibly different app.
- sbx tabs don't take a variant REH yet; only OCI does (`--image`). The sbx template builds
  from `.work/out`, which a variant never writes to.
- The hook adds a 2 s poll to the test REH only.
- `patches/README.md` should point at this record (the RPC session is correcting its claims).
