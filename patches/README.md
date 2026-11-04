# Core patch queue

`NNNN-short-concern.patch` files, applied with `git apply` by
`build/apply-patches.sh` (called by `build/prepare.sh`) **in the order listed in
[`series`](series)** against the commit in `upstream.lock`.
- A patch that doesn't apply fails the build.
- Any file here not listed in `series` (other than this README) fails the build, so a
  test-only patch can't ship by being dropped in the directory
  ([EDR](../docs/edr/20261104-patch-series.md)).
- Test-only hooks never go here; they belong to the test harness.
- `build/apply-patches.sh --check` validates the queue without a checkout (CI).

Rules ([ADR](../docs/adr/20261104-vscodium-style-fork.md)):
- One concern per patch, under about 50 lines.
- Write an EDR (or ADR, if it changes the design) for each patch, and run a
  security review on each new or changed patch.
- Policy that can be expressed in `product.json` goes in
  `build/product/overrides.json`, not here.

Current queue:
- `0001-build-skip-copilot-shim-without-extension.patch`: build only; the
  built-in Copilot extension is removed ([EDR](../docs/edr/20261104-remove-builtin-copilot.md)).
- `0002-extensionkind-product-default.patch`: `extensionKind["*"]` default, so
  every non-built-in extension runs in the tab. Explicit entries apply only to
  scanned system extensions, and the user setting can't override it
  ([ADR](../docs/adr/20261104-extension-placement-hardening.md)).
- `0003-no-workspace-extensions-in-local-windows.patch`: windows without a
  remote run only `ui`-kind (built-in) extensions.
- `0004-extension-description-computed-fields-win.patch`: a `package.json`
  can't override computed description fields such as `isBuiltin`.
- `0005-test-only-rogue-reh-hook.patch`: **test fixture, not behaviour.** Loads
  the rogue-REH probe payload, and only when `SECLAB_ROGUE_REH=1` and
  `SECLAB_ROGUE_REH_PAYLOAD` are both set, which only the containment harness
  does. It exists because the REH server runs inside the tab and is hostile
  under our threat model, so the probes need the server's own handle on the
  channels the *client* registers — a surface the extension host cannot reach
  at all ([EDR](../docs/edr/20261104-rpc-escape-probes.md)).

Expected later patches (M4): the RPC capability filter, auth mediation, storage
partitioning, webview egress, and main-process folder routing (proposed).
