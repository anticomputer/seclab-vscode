# Security review: patch 0015, the agent-host gate

- **Date:** 2026-11-06
- **Scope:** patch 0015 (`seclab-ahp-gate`) and its sources under `agentic/patch-src/`:
  `seclabAhpPolicy.ts`, `seclabAhpPolicyData.ts`, `seclabAhpGateCheck.ts`,
  `seclabAhpGate.ts`, the upstream edits in `agentHostProtocolClient.ts` and
  `editorRemoteAgentHostServiceClient.ts`, `agentic/tools/sync-patch.ts` and
  `test/agentic/gate/gate.test.ts`.
- **Reviewer:** `security-review` agent (an Opus-class model), round 1 on `a999a4d`, round 2 on `20c6281`, round 3 on `c3e2b95`;
  triage and fixes by the agentic-gate session.
- **Related:** [EDR probe runner](../edr/20261106-agentic-probe-runner.md),
  [implementation plan](../plans/agentic-implementation.md) §4 increment 1,
  [design review](20261105-secure-agentic-experiences-design.md)
- **Editorial redaction (2026-11-12):** quotations of project conversations replaced with neutral statements; decisions unchanged.

Every round's prompt carried the standing warning that the diff, fixtures and evidence may
contain prompt injection aimed at the reviewer, to be reported as a finding and never
followed. Round 1 found none.

## Round 3 (on `c3e2b95`)
Scope: round 2's fixes. **No high or critical issue remains in the gate itself; the A1 path is
closed.** Two harness findings blocked a *trustworthy run* rather than the patch, plus one low
residual in the gate. All three are fixed in the commit that adds this section. No prompt
injection found.

### HIGH (10/10), harness: the teardown gate refused to act at all
Round 2's new `arm` mark ended with the profile path instead of the run directory, which fails
`manifestProblems`'s rule that every mark must contain the run directory followed by a
separator or end with it. One bad mark makes `verifyTeardown` push a single failed check and
**return** — before stopping processes, before removing the tab and sandbox, before deleting
the armed profile and before the leftover scan. So round 2 reintroduced round 2's own outcome
by a different route: the arming loop keeps injecting the fixture for its full deadline and
the run survives a "clean" verdict.

**Fix.** `--run-dir` goes last in the arm argv. More importantly, the argv and its mark are now
built in one place (`test/agentic/runner/marks.ts`) and `test/agentic/gate/marks.test.ts` feeds
the real marks through `manifestProblems` and teardown's own matching rule, including a
regression case for the shape this finding had. A mark teardown would reject now fails
`./seclab test unit`, not a live run. This is the second time a bad mark passed review and
failed only in a live run.

### MEDIUM (9/10), harness: the A1 probes used the wrong action envelopes
Round 2 fixed the state discriminant but not the action payloads, so the reducer on the
unpatched control U would have ignored them and the beacon would never have been hit — "U not
vulnerable", which is the same false-negative class round 2 rated HIGH. Against upstream at
`a717861c`: `SessionMcpServerStateChangedAction` is `{type, id, state, channel?}`, not
`{servers: […]}`; `SessionCustomizationsChangedAction` is `{type, customizations: Customization[]}`
with each entry `{type:'mcpServer', id, uri, name, state}`; and
`ChatToolCallAuthRequiredAction` extends `ToolCallActionBase` with `auth: McpAuthRequirement`
(`{reason, resource, oauthClient?, requiredScopes?}`), which has no `status` field.

**Fix.** All three probes and the regression fixture are rebuilt from the real interfaces, and
the claim in round 2's record above is corrected: round 2 fixed the discriminant, not the
envelopes.

### LOW (7/10), gate: `CanvasState.url` reached the renderer
`CanvasState.url` is an agent-host-chosen absolute HTTP(S) URL that arrives through the allowed
`chat/canvasesChanged` and `canvas/stateChanged` path and ends up at
`createExternalBrowserView`. It has no discriminant and no distinctive key, so the sanitiser
passed it verbatim. It stayed low because the view's `networkOwner` is the agent host, so the
page loads on the tab's network rather than the host's, and `chat.canvases.enabled` defaults
off. **Fix:** both are denied inbound. The gate should not rest on an upstream default plus an
experiment flag; canvases in tab windows are increment 6's to design.

### Confirmed sound in round 3
The A1 trigger is closed at the only place the renderer checks it:
`_isAutoAuthenticatingMcpServer` gates on `state.kind === McpServerStatus.AuthRequired`, which
is exactly the literal the sanitiser replaces. The other entries are `registerMcpAuthenticationHandler`
(a server→client request, blanket-refused), `auth/required` (denied) and
`AgentInfo.protectedResources` (stripped). The reviewer enumerated the whole allowed inbound
surface — `action`, `root/*`, `channel/frame`, `channel/credit`, `channel/snapshot` and
responses — and confirmed every one passes through the sanitiser, reassembled fragments
included. `ProtectedResourceMetadata` appears nowhere else with a live renderer consumer. The
replacement node satisfies `McpServerErrorState` and `ErrorInfo`, and `describeMcpServerState`
handles it. Evasions tested against the shipped filter: `session/customizationUpdated`,
`channel/snapshot`, `session/inputNeededSet`, arrays of states and a fragmented frame, all
neutralised. The A1 test is non-tautological: disabling the replacement branch makes it fail
and leaves the other tests passing. Round 2's run-directory fix is genuinely in place before
the recursive delete, and the arming-nonce binding stops a stale fixture self-arming.

## Round 2 (on `20c6281`)
Scope: the round 1 fixes, the two new upstream hunks, `build/source-allowlist.txt`, the probe
runner (`test/agentic/runner/`), `test/window.ts --app` and the gate tests. One high, one
medium, two low. All four are fixed in the commit that adds this section. No prompt injection
found.

### HIGH (9/10): round 1's fix was dead code, and the real carrier key was not stripped
The reviewer ran the shipped sanitiser on a real-shaped message and got **zero** removals.
- Upstream's MCP server discriminant is `kind: 'authRequired'` (`McpServerStatus.AuthRequired`),
  not `kind: 'auth-required'`. The hyphenated literal exists only as
  `ToolCallStatus.AuthRequired`, under the key `status`. So round 1's replacement branch never
  ran against real traffic.
- `McpAuthRequirement` carries the metadata under the key **`resource`**, which was not in
  `STRIP_KEYS`. Worse, stripping `authorization_servers` is what *forces* the discovery fetch:
  with no authorization server, `resolveMcpServerAuthentication` calls `resolveResource`, which
  requests the attacker's URL on the host network and falls back to that URL's origin as a
  dynamic OAuth provider.
- `agentHostCustomizationService` reaches `autoAuthenticateMcpServer` while merely mapping the
  MCP server list, with no turn and no user interaction.
- The round 1 regression test and the runner's A1 probe both used the non-existent shape, so
  neither would have caught this, on G or on U.

**Fix.**
- The sanitiser now matches `kind` of `authRequired` or `auth-required` **and** `status` of
  `auth-required` or `authRequired`, i.e. both spellings in both positions.
- The replacement is well formed: `McpServerErrorState` needs `error: ErrorInfo`, so the inert
  node is `{kind|status: 'error', error: {errorType: 'seclab-ahp-gate', message}}` rather than
  a bare `message`, which would have left the renderer dereferencing `state.error.message` on
  `undefined`.
- Belt and braces, because key-name matching is the wrong last line of defence here:
  `session/mcpServerStateChanged` and `session/customizationsChanged` are now **denied**
  inbound. They were already denied outbound. The sanitiser still covers the same state where
  it is embedded in an allowed result (`initialize`, `listSessions`, `resolveSessionConfig`).
- The regression test and the A1 probe were rewritten to the real shapes.

### MEDIUM (9/10): the runner's teardown marks never matched
`teardownGate` matches a command mark with whitespace or a line edge on each side, but the
beacon and the arming loop are spawned with **absolute** script paths, so the marks
`beacon.ts start …` and `runner.ts arm …` could never match. Both helpers are detached and
reparented, so the descendant walk missed them too, and `arm` passed the profile as a bare
positional so the `--user-data-dir` matcher missed it as well. The arming loop therefore
survived a "clean" teardown and kept injecting the hostile fixture into the tab for its full
ten-minute deadline. This is exactly the orphaned-hostile-process regression the teardown gate
exists to prevent.

**Fix.** Marks are derived from the very argv used to spawn each helper (`markFor`), `arm`
takes `--user-data-dir`, and the loop stops once the tab's sandbox has been gone for ten
seconds.

### LOW (9/10): `prepare` deleted its run directory before validating it
`base` comes from `--run-dir` or `SECLAB_AGENTIC_RUN_DIR` and was passed straight to a
recursive `rmSync`. **Fix:** `checkIsolatedProfile` is applied to `base` as soon as it is
resolved, which confines it to `~/.seclab-test/` or this worktree's `.work/`, symlinks
resolved.

### LOW (9/10): the fixture's arming check was tautological
`mitm.js` compared `cfg.arm` with `cfg.runNonce`, two copies of the same value in the same
config file, which sits in the tab's own workspace. **Fix:** the nonce must also match the one
the host passes on the command line, and `cfg.log` and `cfg.pid` must resolve inside `cfg.run`.

### Confirmed sound in round 2
The MEDIUM fix from round 1 was verified end to end: `policyValue` is out of a tab's reach;
`defaultValue` cannot be overridden by an extension's `configurationDefaults`, because the
setting is `APPLICATION` scope and
[`configurationExtensionPoint.ts#L217`](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/api/common/configurationExtensionPoint.ts#L217)
allows defaults overrides only for narrower scopes; and the stamp in `updateConfiguration` runs
before `configObjectUrl.update`, which is the only thing the renderer reads, so a value carried
in through `_remoteCLI.windowOpen` or any other opener is overwritten unconditionally. The
structural cast fails closed, because the browser environment service has no `configuration`.

Also re-checked and sound: the sanitiser's prototype, array and nesting behaviour (`JSON.parse`
makes `__proto__` an own property, so `delete` removes it); the construction invariant and its
`WeakMap` brand; the blanket refusal of agent-host→client requests, which independently blocks
the `RequestAgentHostMcpAuthentication` reverse-request route; `test/window.ts --app` (resolved,
existence-checked, no shell, focus protection untouched). The four carried-forward items from
round 1 were re-rated and stay below threshold.

## Round 1 (on `a999a4d`)
One high, one medium, no critical. Both are fixed in the commit that adds this record.

### HIGH (8/10): A1 is only half closed, MCP auth metadata gets past the sanitiser
`McpAuthRequirement.resource` is a `ProtectedResourceMetadata` carrying `resource`,
`authorization_servers` and `oauthClient`. None of those keys was in `STRIP_KEYS`, and the
carriers `chat/toolCallAuthRequired`, `session/mcpServerStateChanged` and
`session/customizationsChanged` were all `allow` inbound, as were the `initialize`,
`listSessions` and `resolveSessionConfig` results that embed `McpServerState`.

With no user interaction the trusted window then reaches
`_autoAuthenticateMcpServer` → `stateToProgressAdapter` (builds the request from
`auth.resource`) → `agentHostAuth.resolveResource` →
`agentHostMcpOAuthMetadataService`, which issues a **host-network** `requestService.request`
to a URL the agent host chose (`127.0.0.1`, `169.254.169.254`), and with
`authorization_servers` set instead registers a dynamic OAuth provider from the agent host's
origin. That is broker bypass and SSRF from the trusted side. Token exfiltration stayed
blocked, because `authenticate` is denied.

The reviewer ran the shipped filter on both messages and both were forwarded verbatim.

**Fix.**
- `chat/toolCallAuthRequired` is `deny` inbound: it exists only to drive that path.
- `seclabAhpSanitize` now replaces any object with `kind: 'auth-required'` by an inert
  `{kind: 'error', message}`, so the trigger itself never reaches the window.
- `STRIP_KEYS` gained `auth`, `authorization_servers`, `oauthClient` and
  `protectedResourceMetadata`, so the metadata is removed wherever it appears.
- Regression test `A1 (round 1 HIGH)` covers every carrier plus the bare keys.

### MEDIUM (9/10): `seclab.agents.enabled` was writable from the tab
`MainThreadConfiguration.$updateConfigurationOption` does no scope check, and `USER`
resolves to `USER_LOCAL`, so a rogue tab extension calling
`update('seclab.agents.enabled', true, Global)` persisted the value in the host's
`settings.json`. This confirms A23. `APPLICATION` scope does not help: it constrains the
remote-user layer, not this path.

**Fix.** `seclabAgentHostAllowed` no longer calls `getValue`, which merges every layer. It
accepts only sources a tab cannot write:
- `inspect().policyValue` (enterprise policy);
- `inspect().defaultValue`, when no policy value is set;
- `SECLAB_AGENTS_ENABLED=1` in the environment of the **host's main process**, read once at
  startup in `windowImpl.ts` and stamped onto `INativeWindowConfiguration` by
  `updateConfiguration` on **every** load, so a value carried in by whoever asked for the
  window is overwritten.

A host environment variable was chosen over a CLI flag (project owner, 2026-11-06): a tab's
`code` CLI forwards through the remote CLI (`_remoteCLI.windowOpen`), so a flag is the
larger surface. The pattern matches patch 0012's `SECLAB_BACKGROUND_WINDOWS`, and the new
read is registered in `build/source-allowlist.txt`.

The setting stays registered at `APPLICATION` scope so policy can target it; its
description now says that user, remote and workspace values are ignored.

### Below threshold, carried forward
Recorded here so they are not lost; each is tracked for round 2 or a later increment.
- Fragment buffering reorders channel data; upstream rejects interleaving.
- `pending` is keyed by `String(id)`, so a response with `id:"7"` consumes numeric 7.
- The decision-log cap resets per connection, so forced reconnects grow the log.
- `connect` options pass through unfiltered (`env` is `{}` for the seclab resolver).

### Checked and sound
Bypass paths (a single `_transport` assignment site; the reconnect path also goes through
`_installTransport`), parse differentials, the `_meta` allowlist, the outbound tables, the
construction invariant (it fails closed), and log-line integrity.

## Round 4 (2026-11-06): the probe validator and the teardown reap
Scope: `test/agentic/ahp/probe-validate.ts`, `validate-probes.sh`, `rogue-agent-host.ts`,
`test/agentic/runner/{probes.js,mitm.js,runner.ts}`, `test/containment/teardown{.ts,.test.ts}`,
`test/agentic/gate/marks.test.ts`, `seclab`. Patch 0015 itself was not re-reviewed.

The reviewer found no prompt injection, and confirmed the probes are fixture-safe:
loopback-only, `seclabcanary_` values only, every path under the run directory, and the
container runs `--rm --network none` as the invoking uid against a digest-pinned image with
a pristine-upstream check.

Five findings, all fixed in this round. Three are the same failure mode the gate itself is
about: **a check that cannot fail**.

1. **HIGH, the validator's catch-all could not fail.** Five notification probes fell into a
   `default:` arm whose whole predicate was `newUrls.length === 0`, so they asserted that
   *nothing happened*. Reverting the channel fix, dropping `serverSeq`, or sending `{}`
   all passed, and a new probe typed `lands` with no check would have been counted as proof
   that probes land. Fixed: every probe id needs an explicit case and an unknown one fails;
   notification probes now assert a positive observable (the client parsed and dispatched
   the envelope, via `onDidAction`); `RogueAgentHost.notify` throws instead of returning
   quietly when disarmed or unattached, because a silent no-op was indistinguishable from a
   dispatched frame. Verified by reverting `ROOT_CHANNEL` to the old `'c'`: the suite now
   fails, where before it passed.
2. **HIGH, a test pointed a recursive delete at the user's `~/Documents`.** The negative
   test handed `reapPreviousRun` a manifest naming a real home directory and asserted it
   survived, so a regression in `checkIsolatedProfile` (there was one in this very change)
   would have deleted it with `force: true`, from a command AGENTS.md tells people to run on
   the host. Fixed: the bait is a directory the test creates and owns, and the guard is
   asserted directly on a real path without handing it to anything that deletes.
3. **MEDIUM, "at least one probe can decide vulnerable" was satisfiable by a probe that
   cannot.** `A1-protected` was typed `lands` but produces no host marker, beacon hit or
   canary, so the runner's verdict cannot read it. Fixed: the kinds are now `host-effect`,
   `renderer` and `surface`, and the suite requires a **named** host-effect probe
   (`A20-mcp-auth`) to be present and passing, not merely a non-zero count.
4. **MEDIUM, `reapPreviousRun` failed open and silently.** Every failure path returned an
   empty array with no log, and the caller wiped the run directory immediately after, which
   reproduces the incident it was written to fix. It also omitted `runDirProblems` (R-2) and
   ran before `lockRun`. Fixed: it returns `{ stopped, refused, problems, survivors }`,
   applies R-2, and `prepare` now takes the lock first and exits rather than wiping over a
   run it could not reap.
5. **MEDIUM, the MCP handler stub diverged from the workbench.** The validator registers the
   handler itself, unconditionally; the real contribution registers it only for a connection
   it has adopted. Fixed as far as a harness can: the same `{ authenticate }` shape and the
   same `{ scheme: AGENT_HOST_SCHEME, authority: '' }` identity. The remaining gap is
   recorded as an explicit precondition in the file and in the EDR: this proves the
   client-side half, and whether a `seclab+` window registers a handler at all is what the
   pending U run must show.

No high or critical issue remains in the reviewed paths.

## Round 5 (2026-11-06): the host effect that makes U fire
Scope: the change that plants a host-only value in the window profile's `http.proxy`, which
upstream mirrors into the agent host, plus the verdict and takeover changes around it
(`test/agentic/runner/{runner.ts,mitm.js}`) and the new EDR sections. No prompt injection
found. Fixture safety judged sound: the value matches no real credential format,
`proxy.invalid` is RFC 2606 reserved so every attempt dies at name resolution and no TCP
connection is made, and the setting is confined to the isolated profile.

Three findings, all fixed. Two are again the project's recurring failure mode.

1. **HIGH, the "unforgeable" evidence rule was forgeable.** The change claimed the canary
   existed only in the host profile. It did not: the runner wrote it into the takeover's
   `mitm.json`, which `vsce` packages into `takeover.vsix` in the **mounted workspace** and
   installs into the tab's extension directory. The deciding fact is computed over the log
   the tab writes, and the only thing licensing that exception was unforgeability, which did
   not hold. The measured leak was almost certainly genuine, but the rule could not
   distinguish it from a tab echoing its own config.
   Fixed: the tab is given **no canary value**. It receives a per-run salt and salted
   hashes, scans frames for canary-shaped tokens, and reports a token only when its salted
   hash matches; a 64-bit random token is not recoverable from its hash, so a report is
   proof the window sent it. The host matches the reported token against what `prepare`
   recorded. The vsix is also removed from the workspace once installed, so no self-arming
   copy is left on disk for the rest of the run.
2. **HIGH, two silent-pass paths on the G side.** The settings canary was recovered with a
   regex that yields `undefined` when the setting is missing, which was then dropped by a
   `filter` -- so a canary that was never planted made "no canary reported" true, and G
   would pass for a reason unrelated to the gate (the file canary, by contrast, throws).
   And nothing asserted the A19 vector was exercised on G at all: the general deny check
   counts only rules ending `:deny`, while the configuration mirror is a `strip`.
   Fixed: `prepare` records what it planted in `canaries.json`; `check` asserts on **both**
   builds that every canary is still armed where the window reads it, and G additionally
   requires at least one `ahp-gate.root-config:strip` decision.
3. **MEDIUM, the record overclaimed.** The EDR asserted "a forged report is impossible" on
   the strength of the broken argument in finding 1. Rewritten to describe the asymmetry
   that actually holds, and to say what the first version got wrong.

Re-measured after the fixes: **U 7/7 vulnerable, G 11/11 contained.** No high or critical
issue remains.

## Round 6 (2026-11-06): patch 0017, settings fixed in a tab window
Scope: `patches/0017-seclab-fixed-tab-settings.patch`, its module under `agentic/patch-src`,
`test/agentic/gate/fixed-settings.test.ts`, and the increment 2 EDR. No prompt injection found.
The reviewer confirmed `seclabScrubFixedSettings` itself is sound: it copies on write at every
level, the key paths are constants so no `__proto__` path is attacker-reachable, arrays and
scalars on the path are skipped consistently, and an absent key is not invented.

Four findings, all addressed.

1. **HIGH, forcing `enableRemoteProxy` false would have made one path worse.** The EDR's
   measurement found two open paths; there is a third. The browser tools (`openBrowserTool`,
   `navigateBrowserTool`) resolve the network with the **public** `resolveNetwork`, which
   returns `undefined` when the proxy is off, so the page loads on the **host** network for a
   model-chosen URL, with `allowAutoConfirm: true`. The caveat that would have voided this
   does not hold: `getNetworkStatus` returns `proxySupported: true` unconditionally for the
   window's own authority. **Fixed by removing the key from 0017** rather than guessing a
   value: the two automations keys ship now, and `enableRemoteProxy` is recorded in the EDR
   with three candidate resolutions for the user to choose. Forcing `true` now looks the most
   likely, since it matches the design's own end state for that row.
2. **MEDIUM, `inspect` dropped every per-layer field.** `{ ...result }` spreads a class whose
   layer fields are prototype getters, so for a fixed key `policyValue`, `defaultValue`,
   `userRemoteValue` and the rest all became `undefined`, and the raw configuration models
   were exposed as enumerable own properties instead. That also broke `updateValue`'s target
   derivation, which reads `inspect`. Fixed with `Object.create(result, { value })`, which
   keeps the prototype and so the getters. A unit test now models upstream's getter shape and
   asserts the spread form fails, so the regression is named rather than described.
3. **MEDIUM, the claimed single chokepoint was not one.** `getConfigurationData()` was not
   overridden, and that snapshot is what `MainThreadConfiguration` ships to every extension
   host, which `ExtHostConfiguration` then answers reads from. Fixed by scrubbing each layer's
   `contents` there too, with a test.
4. **LOW, the `seclab+` prefix was declared twice.** Sharing it by import does not work here:
   a value import across patch modules uses a `.js` specifier that `node --test`'s type
   stripping cannot resolve, which would make the module untestable. Resolved the other way:
   the prefix stays local and a unit test imports both modules and asserts they are equal, so
   drift fails the build.

Also noted and fixed: the first test asserted the key map against itself and was tautological.
It now asserts the keys literally.

No high or critical issue remains in 0017 as it now stands. The held-back key is a decision,
not a defect.

## Round 7 (2026-11-06): 0017's browser keys, after the decision to force `true`
Scope: the change that forces `workbench.browser.enableRemoteProxy` to `true` and
`workbench.browser.dataStorage` to `ephemeral`. No prompt injection found.

**No high or critical issue.** The reviewer checked `true` adversarially and found it is the
safer of the two reachable values, and not a behaviour change by itself: the registered
default is already on in these builds, so the pin only removes the tab's ability to select
`false`. Specifically confirmed sound: `$openNetworkConnection` is restricted to the local
extension host and an existing agent-host connection; the tunnel proxy binds loopback with
random-credential auth and a pinned cert; the Electron session sets
`proxyBypassRules: '<-loopback>'`, so a model-chosen `http://127.0.0.1:…` does **not** fall
back to host loopback; ephemeral sessions are per view; and a proxy that fails to start fails
view creation rather than falling back. `ephemeral` is the right one of the two
network-keeping scopes.

Four findings, all addressed.

1. **MEDIUM, the record claimed brokering that does not happen.** The patch comment and the
   EDR said this traffic goes "behind that tab's broker". It does not: the destination socket
   is a raw TCP connect from inside the sbx, which does not honour the tab's proxy env vars,
   and those variables are the only path to the broker. The containment is the **fence**,
   which allows the broker port alone, so an external destination is denied and a tab-local
   one is reached directly. Load-bearing, because a later grant that widens a fence would let
   this traffic leave unmediated while the record said it was brokered. Corrected in both
   places.
2. **MEDIUM, a restored browser editor bypassed the pin.** `_resolveSessionRequest` returns a
   saved request verbatim when it carries a scope, and a browser editor restored from a
   previous window carries one. A view stored while a tab could still choose `global` came
   back with `global` and no network: the host network and the host's shared cookie jar,
   exactly what the pin is for. Fixed in 0017: a `seclab+` window drops the saved session
   request and rebuilds it under the fixed setting.
3. **LOW, two overclaims in the EDR.** It said the decision "matches" the design's §3.5 row;
   it matches that row's traffic direction but not its gate, since the row says the setting is
   pinned "so only the grant opens it" and the grant is unimplemented. And the `Consequences`
   section still argued the superseded `false` case, so the record contradicted its own
   decision. Both fixed, with fresh consequences for `true` + `ephemeral` including the cost
   that no browser view in a tab window can persist logins.
4. **LOW, the tests could pass while the named property was broken.** The security property is
   an **upstream** invariant (`global` drops the view's network, `ephemeral` keeps it) that
   nothing in the repo pinned, so an upstream rename would leave every test green. It cannot
   live in a unit test, because the unit container has no upstream checkout, so it is now an
   upstream-invariant rule in `patches/sole-consumer.json`, enforced over the patched tree by
   `build/check-sole-consumer.ts` from inside the check `patch-build` already runs. Verified
   by renaming the enum member in a scratch tree: the check fails. Two asserts that could not
   fail were also removed or made literal.

## Round 8 (2026-11-10): the increment 2 U-vs-F proof
Scope: `test/agentic/browser/run.ts`, `test/agentic/browser-drive/browserView-hook.patch` and
the measured section of the increment 2 EDR. No prompt injection found.

The reviewer confirmed the central comparison: U and F differ only by 0017 (same upstream SHA,
same variant, same hook hash; the only src-affecting delta is the patch and its module), and
the readiness sentinel is sound because upstream's registered default is `activeGroup`, so
`sideGroup` can only come from the tab's remote layer.

**Two HIGH findings, both of which invalidated claims I had already written down.** They are
recorded rather than quietly fixed, because the EDR had been published with them.

1. **HIGH: the restored-editor phase measured nothing.** `readWindowLog` concatenates every
   log in the profile and takes the last `opening` line, so the restore phase re-read the
   first launch's lines. The retained artifacts prove it: both phases report `hookLines: 3`,
   one window's full sequence, so the relaunched window contributed none. The restore
   assertion was also identical to the first-phase one, so it added no independent fact. The
   round 7 restore gap is therefore **unverified at runtime**, and a fresh hook-driven open
   would not verify it anyway, because the restore path is about a persisted session request
   and the hook supplies its own.
2. **HIGH: the `dataStorage` half is never exercised.** The hook opens with an explicit
   `session: { scope: Agent, … }`, and upstream's `_resolveSessionRequest` returns early for a
   request that already carries a scope, without reading `workbench.browser.dataStorage`. So
   the setting was never consulted on either build, and the F check "`dataStorage: global` did
   not take the network away" is implied by the check above it and cannot fail independently.
   The pin remains justified by the source reading, but these runs do not measure it.

Three more, all recorded in the EDR as limits rather than fixed in place:

3. **MEDIUM: EDR overclaims.** "the network resolved **for the page**" is really the value
   `resolveNetwork()` returned before `createBrowserView`, which `_resolveViewSession` can
   still drop; and `ERR_EMPTY_RESPONSE` was read as the fence refusing, when from inside the
   tab `127.0.0.1` is the guest's own loopback and never reaches the fence.
4. **MEDIUM: F has no beacon liveness control.** The beacon is spawned detached with no
   readiness probe and no end-of-run self-hit, so a beacon that failed to bind produces F's
   evidence exactly. U's working beacon is a different process, port and run.
5. **MEDIUM: the probe target is outside the hook's reviewed envelope.** The hook's own review
   says it measures the tool faithfully only against a non-localhost target; the probe uses
   loopback, so this measures `resolveNetwork`, not the whole tool path.
6. **LOW: the arming file outlives a run stopped after phase 1**, because it is removed only
   on the restore phase, and `~/.seclab-test/` is invisible to the teardown snapshot because
   its parent is pre-created.

**What stands.** The `enableRemoteProxy` claim is proven at runtime with host-side evidence
and a working negative control: on U the host beacon recorded the fetch with the editor's own
Chromium user agent, on F it did not, and the builds differ only by 0017. The EDR has been
rewritten to claim that and nothing more. No high or critical issue remains **in patch 0017
itself**; the two HIGH findings are defects in the proof, and the work they gate is listed in
the EDR's Consequence section.

## Round 9 (2026-11-10): the corrected increment 2 proof
Scope: commit `a3b2666`, which was itself the fix for round 8. Eight findings, three HIGH, no
prompt injection. Two of the HIGHs are the same class of defect round 8 found, so they are
recorded in full rather than quietly fixed.

1. **HIGH: the cross-build restore phase could not be run at all.** The `switch-build` mode
   was written, reviewed and documented in the EDR's procedure, but the argument guard still
   accepted only `prepare` and `check`, so it printed usage and exited. Dead code that a
   record described as a working procedure. Fixed, and a test now parses the modes out of the
   usage line and asserts each one gets past the guard; that test was confirmed to fail
   against the real bug before being kept.
2. **HIGH: the restore attributability check was unsatisfiable on F.** It keyed off
   `requestedScope=global`, logged inside `_resolveViewSession` from the output of
   `_resolveSessionRequest` — but patch 0017 discards the saved request at the TOP of that
   method, so on a fixed build the line always reads `ephemeral`. A correct F run therefore
   read as inconclusive, and the phase could only go green if lines leaked in from the other
   launch: green exactly when attribution had been violated. Round 8's finding, inverted.
   Fixed by logging `savedScope=` in `_getOrCreateLazy`, before 0017 can touch it, and by
   adding the clean-F-restore test whose absence had hidden it.
3. **HIGH: the restore offsets were taken while the first window was still alive.** Snapshotted
   at the end of the first check, so that window's later writes were attributed to the
   relaunch — carrying exactly the `savedScope=global` lines the relaunch cannot produce
   itself. Moved into `switch-build`, which now refuses to proceed while the first editor is
   running. Lines are also sorted by their own timestamps rather than by `readdir` order, so
   a verdict cannot pair one launch's scope with another's saved scope.
4. **MEDIUM: "ran the requested build" could not fail.** It compared two harness files written
   from the same variable, i.e. it asserted the harness agreed with itself, while the whole
   cross-build claim rests on which bundle the operator actually launched. The variant build
   now stamps the repo SHA into `seclabTestBuild`, the hook logs it, and the check compares
   what RAN with what was asked for. (`product.commit` is upstream's SHA and is identical in
   both builds, so it could not serve.)
5. **MEDIUM: the record overclaimed about the browser tool.** The hook no longer opens "the
   way the tool does": the agent tool supplies its own session scope, so that path never reads
   `dataStorage`. Corrected in the EDR and in the variant's review; no claim about the browser
   tool may be made from the storage probe.
6. **MEDIUM: `network=none` was not specific to the setting.** It is also what a missing
   resolver or an unsupported authority produces. The U proxy check now additionally requires
   `requestedNetwork=seclab+<tab>` on the same launch, so it means "the tab's network was
   available and then dropped".
7. **MEDIUM: the fence was asserted in three places and measured in none.** `privateHostAddress`
   sorts lexicographically over every private IPv4, which on this host can include bridge and
   vmnet gateways that the guest CAN reach; such an address would silently reintroduce the
   ambiguity the non-loopback change was made to remove. The check phase now has the TAB try
   the beacon address: it must fail and leave no hit, as a check that can go red.
8. **LOW: `linesSince` failed quiet.** A rotated or truncated log was skipped silently, and an
   offset landing mid-line could parse half a line. It now raises on a shrunken file and drops
   the leading fragment.

The reviewer also noted that F's `scope === 'ephemeral'` is satisfiable by upstream's
workspace-trust downgrade. Trust is disabled host-side and U shows `global`, so the U control
rules it out empirically for this harness, but the verdict does not record trust state. Left
as a known limit rather than fixed, and noted here so a later profile change cannot turn that
check green unnoticed.

No finding in this round is a defect in patch 0017. All eight are defects in the proof.

## Round 10 (2026-11-10): the two-sided proof and the leak fixes
Scope: `5161f6a..6ec8ede`. No prompt injection. The reviewer confirmed the "exactly one side"
rule is sound, the build-identity stamp is trustworthy and fails closed, the cross-build
restore ordering is correct, and host hygiene is clean. Five findings, all in the plumbing.

1. **HIGH: the harness destroyed the restore phase's evidence.** `listen` respawned the tab
   listener every 1.5 s unconditionally, and the listener truncated its log on start, so every
   probe line the live instance recorded was erased within a second or two and the restore
   network check could never pass. Worse, the EDR had already attributed that result to a
   missing arming gate, so the record stated the wrong cause. Fixed: probe before starting,
   start only when nothing answers, append and never truncate, and exit cleanly on
   `EADDRINUSE`. The EDR carries an explicit correction.
2. **HIGH: tab-listener liveness was two point samples, not continuity.** A listener that died
   and was resurrected mid-phase passed the check. The listener now emits a heartbeat carrying
   its pid, and a phase is only accepted when heartbeats span it from a single instance.
3. **MEDIUM: the beacon logs were phase-scoped by line count with no shrink guard**, so a
   truncated log silently yielded "that side saw nothing" — evidence loss converted into
   evidence. They now use byte offsets and the same hard error as the window logs.
4. **MEDIUM: `switch-build` never told the operator to start `listen`.** Round 9's "a mode
   nobody can run", in a new shape: the mode existed and was reachable, but no printed
   procedure invoked it. The command is now printed before the relaunch.
5. **MEDIUM: the stray-helper net missed the one helper this design adds.** It matched the
   absolute worktree path, while every printed invocation is relative, so a backgrounded
   `listen` was invisible to both `teardown` and `clean-host` — and the regression test passed
   only because it spawned its decoy with an absolute path, validating the matcher against a
   shape no procedure produces. Both forms are matched now, the relative form only for a node
   process running a known helper script so it cannot claim another worktree, `run.ts` is in
   the helper list, and the decoy is spawned exactly as the procedure does.

The reviewer also noted that nothing in the harness asserts the U build LACKS 0017; "the
builds differ only by the patch" rests on the commit diff rather than on a check. Recorded as a
known limit.

No finding is a defect in patch 0017. The U and F first-phase results stand; the restore phase
needs a re-run under the corrected harness.

## Findings-baseline follow-up (2026-11-12): the live-only rules now have tests
Three findings in the baseline were `fixed-untested` or `open` because the rule they describe
was witnessed only by a live U/G or U/F run, which cannot run in CI. Nothing failed if the fix
were reverted. Each now has a test that injects the defect the rule exists to catch.

1. **The canary salt rule** (`the "unforgeable" evidence rule was forgeable`). The takeover's
   config ships into the tab inside the vsix, so a plaintext canary there is something in-tab
   code could echo back without the window ever having sent it, and the verdict could not tell
   a replay from a real leak. `takeoverCanaryConfig` and `plaintextCanariesIn` are now in
   `test/agentic/runner/verdict.ts`, which `runner.ts` calls, and `verdict.test.ts` fails if a
   plaintext value is added anywhere in the payload, nested included. It also pins that a
   canary *path* may ship, because the read probe asks the window to fetch a path, not a
   secret.
2. **The two silent-pass paths on the G side** (`fixed-untested`). The configuration mirror is
   the vector that actually leaks on U and it is recorded as a `strip`, not a `deny`, so
   counting only `:deny` left "contained" resting on absence. `proofChecks` now holds every
   G-side rule and the tests inject each defect separately: the strip decision missing, the
   canaries never recorded, a canary not armed where the window reads it, a gate that never
   ran, an opened-but-unverified connection, a positive control that failed, and a quiet U
   baseline. Fourteen tests, each asserting the matching check goes red.
3. **The `dataStorage` half is never exercised** (`open`). This one cannot be closed by a
   probe, because the agent tool supplies its own session scope and upstream returns a scoped
   request verbatim, so that path never reads the setting at all. The source reading it rests
   on is pinned instead, as two `__upstreamInvariants` rules checked over the patched tree by
   `patch-build`: `getAgentBrowserViewCreationDefaults` supplying
   `scope: BrowserViewStorageScope.Agent`, and `_resolveSessionRequest` returning early for a
   scoped request while still reading `workbench.browser.dataStorage` by that exact id in the
   other branch. Verified by injecting the upstream change and confirming the gate fails.

**A fail-open found while doing it.** `soleConsumerProblems` returned "no problems" when it
could not read its config, so a wrong path, a renamed file or a missing argument silently
passed the whole invariant gate — and it did: the first attempt to prove the new invariants
could fail reported success because the config argument was omitted. It now reports that as a
problem. The one legitimate caller with no config is the synthetic tree in
`patch-reach-imports.test.ts`, which supplies an explicit empty rule set.

**Still open, by design:** the restore path remains proven at resolution and not at the
network, and the `dataStorage` pin rests on the source reading above rather than on a tool
probe. Both are recorded as open in the baseline; the deferred-restore hook is a follow-up on
top of the headless driver.

## Gate fail-open audit: GATE-11 and GATE-1 (2026-11-12)
Two entries from the gate fail-open audit, both in checks this session owns. Each fix is
proven by reverting it and watching the test fail.

**GATE-11 — `ahp_inventory.py` exited 0 with a non-empty `problems` list.** `extract` records
scanner gaps as `problems`: a `CommandMap` that is no longer found, an `ActionType` that
moved, a server->client request with no client handler case. Every one of them *shrinks* the
inventory, and that inventory is what the agent-host attack surface is reasoned about from
(the agents-in-tab spike). The self-test already treated a non-empty `problems` as failure,
but the real run printed them and returned 0, so an upstream rename could reduce the surface
to near-nothing while the command reported success. The decision is now `exit_code()`, which
both the run and the self-test call, and the self-test injects a gap and asserts it exits
non-zero. Reverting the rule makes the self-test fail with
`a non-empty problems list must exit non-zero (GATE-11)`, and the exit code propagates through
`inventory.sh`. The argument handling was tightened at the same time: `--source` or `--out`
missing is now an argument error rather than a crash that could be mistaken for a bad tree.

**GATE-1 — `soleConsumerProblems` returned "no problems" for a config it could not read.**
Fixed in the previous change; it now has the regression test that makes it count as fixed.
The test drives both a missing file and an empty path, requires exactly one problem naming
the refusal, and then asserts that a readable config with no rules is still clean, so the
check cannot become always-failing. Reverting the guard fails it.

Worth stating plainly, because it is the same lesson as rounds 8 to 10: this fail-open was not
found by reading the code, it was found when a check reported success for work that had not
run. The first attempt to prove the patch-0017 upstream invariants could fail reported "no
problems" purely because the config argument had been omitted.
