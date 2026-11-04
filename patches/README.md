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

- `0005-seclab-rpc-capability-filter.patch`: the RPC choke point in
  `rpcProtocol.ts` plus the filter module and its generated policy. The module
  carries the logic for all three enforcement points; 0006 and 0007 only wire
  the other two in, so each core file is touched by exactly one patch
  ([ADR](../docs/adr/20261104-rpc-filter-enforcement-points.md)).
- `0006-seclab-channel-guard.patch`: `ipc.ts` only. Guards the channels the
  client serves to a hostile REH, on `ChannelServer` rather than a wrapper a
  caller can bypass.
- `0007-seclab-command-taint.patch`: `commandService.ts` only. Tab-originated
  commands carry the tab identity into everything they trigger
  ([ADR](../docs/adr/20261104-tab-command-taint.md)).

Test-only patches are **not** kept here. `build/prepare.sh` applies this
directory unconditionally, so a fixture placed here would ship in release
builds. The rogue-REH hook lives at
`test/containment/rogue-reh/serverServices-hook.patch` and is applied by the
containment harness for a dedicated probe build
([EDR](../docs/edr/20261104-rpc-escape-probes.md)).

Expected later patches (M4): the RPC capability filter, auth mediation,
partitioning, webview egress, and main-process folder routing (proposed).
