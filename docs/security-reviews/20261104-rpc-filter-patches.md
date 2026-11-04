# Security review: the RPC filter patches 0005–0007 (Phase 3, increment 3)

- **Date:** 2026-11-04
- **Round:** 5 (core enforcement patches)
- **Reviewer:** independent `security-review` agent, an Opus-class model
- **Subject:** `patches/0005-seclab-rpc-capability-filter.patch`,
  `0006-seclab-channel-guard.patch`, `0007-seclab-command-taint.patch`, and
  `rpc-filter/patch-src/seclabRpcFilter.ts`
- **Upstream:** `microsoft/vscode@a717861c07586a53d83b80d742cd3f59b20a6273`
- **Verdict: DO-NOT-LAND.** One finding is fixed; the rest are open. The
  patches branch stays off main until a re-review passes.

## Why this round mattered

This was the first review of the enforcement itself rather than the tooling
around it. It found that three of the four things the control is supposed to do
were inverted or unreachable. The structure is right — the choke point is
genuinely the only path to a `MainThread*` actor, the guard is on the mechanism
rather than a wrapper, identity comes from the connection — but structure is not
enforcement.

## Findings

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | **Critical** | **`rewrite` permitted the call while the rewriting half did not exist.** A `rewrite` verdict is a promise that the customer substitutes a tab-scoped value — a sentinel token, a partitioned storage key. Nothing implements that yet, so the filter was passing `$getSession` and the whole `$getPassword` family through **unmodified**: a rogue extension reads another extension's stored secret and obtains a real `accessToken`. That is a straight inversion of *no real secret may ever enter a tab*, caused by the filter treating an unkept promise as a permission. | **Fixed.** A rewrite now denies unless its implementation has registered itself via `seclabRegisterRewrite`. Nothing registers today, so all seven rewrite surfaces deny. |
| 2 | **Critical** | **The argument walker can be made to disagree with `marshalling.revive`**, so a `file:` URI reaches `MainThreadFileSystem.$readFile`/`$writeFile` — host file read and host write, and therefore host code execution, from inside a tab. Demonstrated executably against the shipped walker. | **Open.** The fix is not a patch to `eachUri`: the walker has to be rebuilt so it *cannot* diverge from `URI.revive`, with the differential test the design review already scheduled. |
| 3 | **Critical** | Same mechanism, the write direction. | **Open.** |
| 4 | **High** | **`seclabRegisterTab` has no caller.** The Tab Manager never registers an authority, so `seclabFilterFor` throws for every `seclab+` host. | **Open.** The wiring must ship in the series. |
| 5 | **High** | **The entire taint in 0007 is dead code.** Nothing passes an `origin` into `_tryExecuteCommand`, because `MainThreadCommands.$executeCommand` was never routed to `seclabExecuteFromTab`. The `launder-*` probes would have reported green for a reason unrelated to the mechanism they test. | **Open.** |
| 6 | Medium | The channel guard binds the guard at **registration** time, so a channel registered before the filter module loads escapes it; and `listen` throwing synchronously may not match `ChannelServer`'s error handling. | **Open.** |

### Confirmed sound, no change

- The choke point is genuinely the only path to a `MainThread*` actor.
- `ctx.remoteAuthority` is the right discriminator: every other `IPCClient` in
  the workbench uses a string context, so shared-process and Electron-main
  connections are correctly untouched, and `mcpGatewayToolBrokerContribution`
  registering straight on the connection is still covered — which is exactly
  why the guard belongs on `ChannelServer` and not on the wrapper.
- `_checkUri` cannot be fooled by case, encoding, UNC or sub-authority tricks in
  the *granting* direction: `new Uri(components)` skips normalisation, so every
  divergence points at deny.
- Keying on the wire `sid` is load-order independent, and refusing non-`$`
  method names correctly covers the `actor[methodName]` dispatcher.
- The decision stream's key cardinality is bounded by the policy table, not by
  anything a tab chooses, and a throwing listener cannot break the filter.

## What I got wrong, recorded deliberately

Two of these are the same mistake in different places: **I shipped a mechanism
and described it as implementing a decision, without verifying it was reachable.**
The taint has no caller, and the tab registry has no caller. Both type-check,
both are covered by the patch, and neither runs. My commit message for 0007 said
it "implements the user's decision"; it does not, yet.

The `rewrite` finding is worse, because the failure direction was wrong. I
treated a verdict that *names* a mitigation as though the mitigation existed.
A verdict is a promise about behaviour, and until the behaviour exists the only
safe reading is deny.

## Before re-review

1. `rewrite` fails closed — **done**.
2. Rebuild the URI validation so it cannot diverge from `URI.revive`, with a
   differential test.
3. Ship `seclabRegisterTab` wiring from the Tab Manager.
4. Route `$executeCommand` to `seclabExecuteFromTab` so the taint is live, and
   correct the backstop predicate.
5. Move the channel guard lookup to call time.
6. Demonstrate at least one probe succeeding unpatched and failing patched, so
   the attachment path is proven live rather than assumed.
