# Security review: the RPC filter patches 0005–0007 (Phase 3, increment 3)

- **Date:** 2026-11-04
- **Round:** 5 (core enforcement patches)
- **Reviewer:** independent `security-review` agent, an Opus-class model
- **Subject:** `patches/0005-seclab-rpc-capability-filter.patch`,
  `0006-seclab-channel-guard.patch`, `0007-seclab-command-taint.patch`, and
  `rpc-filter/patch-src/seclabRpcFilter.ts`
- **Upstream:** `microsoft/vscode@a717861c07586a53d83b80d742cd3f59b20a6273`
- **Verdict: DO-NOT-LAND** at the time of the round. Findings 1-5 are now fixed; 6 (the channel guard binding at registration time) remains open and still blocks landing. The
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
| 2 | **Critical** | **The argument walker can be made to disagree with `marshalling.revive`**, so a `file:` URI reaches `MainThreadFileSystem.$readFile`/`$writeFile` — host file read and host write, and therefore host code execution, from inside a tab. Demonstrated executably against the shipped walker. | **Fixed**, and tracing it sharpened the diagnosis. `revive` is never called on RPC arguments at all: they arrive as plain `JSON.parse` output, get `transformIncomingURIs` (which transforms but does not revive), and a URI materialises only when the target calls `URI.revive` on a fixed argument position. `URI.revive` does not check `$mid` — it builds a URI from any truthy object — while the walker required `$mid` to be a number, so marker-less `{scheme:'file',path:…}` was invisible to it and revived by the consumer. A shape search could never agree with a positional consumer, so it was replaced rather than patched: the filter now checks exactly the `UriComponents` positions declared in `extHost.protocol.ts`, generated into `SECLAB_URI_ARGS` (71 methods, 36 services) so they follow upstream through the drift gate. `test/containment/uri-constraint.test.ts` adds the differential test, with a negative control running the old walker to prove it missed the payload. |
| 3 | **Critical** | Same mechanism, the write direction. | **Fixed** by the same change; `$writeFile` and both URI positions of `$copy`/`$rename` are covered, and the test asserts the destination argument is checked. |
| 4 | **High** | **`seclabRegisterTab` has no caller.** The Tab Manager never registers an authority, so `seclabFilterFor` throws for every `seclab+` host. | **Fixed** by removing the mechanism rather than wiring it. The authority a remote window connects to *is* `seclab+<tabId>` (`docs/edr/20261104-tab-manager-routing.md`), so the registry only restated identity already present in the connection; `seclabResolveTabId` now derives it. There is no longer anything to forget to call, and the property that mattered is unchanged: the tab id comes from the connection, never from a call argument. |
| 5 | **High** | **The entire taint in 0007 is dead code.** Nothing passes an `origin` into `_tryExecuteCommand`, because `MainThreadCommands.$executeCommand` was never routed to `seclabExecuteFromTab`. The `launder-*` probes would have reported green for a reason unrelated to the mechanism they test. | **Fixed.** Patch 0008 routes `$executeCommand` through `seclabExecuteCommandFromTab`, with the origin captured from `extHostContext.remoteAuthority` in the customer's constructor rather than from any call argument. It fails closed: if `seclabExecuteFromTab` is absent the call is refused, because falling back to a plain `executeCommand` would run the tab's command *untainted* while the probes passed. |
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
