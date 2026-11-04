# Security review: RPC lockdown design (Phase 2)

- **Date:** 2026-11-04
- **Round:** 1 (design), plus re-review after changes
- **Reviewer:** independent `security-review` agent, `cvp-claude-opus-5`
- **Subject:** [docs/RPC-LOCKDOWN.md](../RPC-LOCKDOWN.md),
  [rpc-filter/policy/policy.json](../../rpc-filter/policy/policy.json),
  [rpc-filter/tools/check_drift.py](../../rpc-filter/tools/check_drift.py),
  the inventory generator
- **Upstream:** `microsoft/vscode@a717861c07586a53d83b80d742cd3f59b20a6273`
- **Outcome:** design changed in response; no high or critical findings left
  open. Several accepted as recorded residual risk with named follow-up.

## Scope

The reviewer was asked to break the stated guarantee, not to comment on style,
and was given the pinned upstream checkout to verify claims. Priority order:
choke-point bypasses; argument smuggling; commands that launder verdicts;
channels and server-initiated paths; remaining routes for a real secret into a
tab; and whether the drift gate can pass while the real surface grows.

## Findings and disposition

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | **Critical** | The command allow set was produced by a substring heuristic over command ids, and `check_invariants` did not run over it. 389 commands resolved to `allow` with no individual review, including ids with host authority. | **Fixed.** Category rules may now only carry `deny`, enforced by the drift check. Reachability is granted per id in `commands.exact`, with an impact assessment. Invariants now run over the whole resolved mapping. Reachable surfaces dropped 444 → 14. |
| 2 | High | `editor-local` captured `editor.action.accessibilityHelpOpenHelpLink` (opens an external link) and `_workbench.editor.configureDefaultEditor` (matched `editor.` before the underscore rule). | **Fixed** by finding 1's change. Verified against `coverage.json`. |
| 3 | High | `workbench.action.terminal.newLocal` and `sendSequence` were **absent** from a 2792-id inventory: they register via `registerTerminalAction`, a helper the scanner did not model. The policy's explicit deny entries therefore matched nothing. | **Fixed.** Scanner now matches the *shape* `register*({ id: … })` rather than named helpers, and resolves constants and enum members. +413 commands. New `keys` check rejects a `commands.exact` entry absent from the inventory, so this class of miss fails the build. |
| 4 | High | Commands that call other commands launder verdicts; `_remoteCLI.windowOpen` → `_files.windowOpen`. | **Accepted as residual risk 1**, flagged as the most likely bypass. Mitigation (tainting the execution context for the dynamic extent of a tab-originated command) is named but not designed. Must be designed before the filter ships. |
| 5 | Medium | `AbstractRemoteAgentService.registerChannel` is a convenience wrapper, not the mechanism; a connection holder can register directly on `ChannelServer`, as upstream does elsewhere. | **Fixed in design.** The guard moves to `ChannelServer`/`IPCClient.registerChannel`, and an unresolvable receiver in the scanner is a hard failure, not a skip. |
| 6 | Medium | The gate can pass while the surface grows: the digest pinned ids and verdicts only, so editing `residual_impact` or weakening a `constraint` changed nothing; and the gate compares policy against a committed inventory rather than the built source. | **Partly fixed.** Reachable surfaces are now pinned by a hash of their whole policy entry. CI regenerating the inventory from the built source is **open**, recorded as residual risk 3. |
| 7 | Medium | A validator walking arguments differently from `marshalling.revive` is a bypass: the depth-200 cap and `$mid: Regexp` handling in particular. | **Fixed in design** (§2.5.1): the walker shares code with `revive`, rejects graphs deeper than the cap rather than matching truncation, and rejects own `__proto__` properties. |
| 8 | Medium | Filter attachment was fail-open by shape: `remoteAuthority` is `null` for local and worker hosts, so an unknown authority yielded "no filter". | **Fixed in design** (§2.2): throws for an unregistered `seclab+*` authority, deny-all for anything that is not a known tab or the trusted local kind, and non-`$` method names are rejected. |

## Confirmed correct, no change

- Keying on the wire `sid`. `nid` is load-order dependent, and the
  `sid`/property-name divergences are real.
- The requirement that `$registerCommand` must not shadow. Verified:
  `CommandsRegistry.registerCommand` does `commands.unshift(...)` and
  `getCommand` returns the head, so a later registration beats a built-in
  ([commands.ts L99-L110](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/commands/common/commands.ts#L99-L110)).
- Denying both client-served channels, and the assessment that
  `mcpGatewayToolBroker.callToolForServer` is a direct confused-deputy path.
- There is exactly one `new RPCProtocol(` outside tests, on the single path for
  every `ExtensionHostKind` including restart, so there is no second
  construction site and no pre-filter dispatch window.
- Splitting `impact` from `residual_impact` is the right model; the problem was
  that nothing validated the claim, which finding 6 addresses.

## Re-review after changes

The changes were verified mechanically rather than by assertion:

- `rpc-filter/tools/check.sh` passes: 3768 surfaces, 14 reachable, 3754 denied.
- Reachability now requires a per-item reviewed entry; a category rule with a
  non-`deny` verdict fails the build.
- Drift detection proven: injecting a new RPC method and a new command into the
  inventory exits 1 and names both as `NEW … -> deny`; the clean tree exits 0.
- `workbench.action.terminal.newLocal` and `sendSequence` are present in the
  regenerated inventory.

## Carried into Phase 3

Each becomes a probe in the rogue extension or the rogue REH fixture:

1. Command-chaining bypass (residual risk 1) — must be designed first.
2. CI regeneration of the inventory from built source (residual risk 3).
3. Differential testing of the argument walker against `marshalling.revive`.
4. Behaviour-pinning for reachable surfaces (residual risk 2).
