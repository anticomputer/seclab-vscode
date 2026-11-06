# Security review: patch 0015, the agent-host gate

- **Date:** 2026-11-06
- **Scope:** patch 0015 (`seclab-ahp-gate`) and its sources under `agentic/patch-src/`:
  `seclabAhpPolicy.ts`, `seclabAhpPolicyData.ts`, `seclabAhpGateCheck.ts`,
  `seclabAhpGate.ts`, the upstream edits in `agentHostProtocolClient.ts` and
  `editorRemoteAgentHostServiceClient.ts`, `agentic/tools/sync-patch.ts` and
  `test/agentic/gate/gate.test.ts`.
- **Reviewer:** `security-review` agent (`cvp-claude-opus-5`), round 1 on `b4a3360`, round 2 on `7e0f0f6`, round 3 on `49cf550`;
  triage and fixes by the agentic-gate session.
- **Related:** [EDR probe runner](../edr/20261106-agentic-probe-runner.md),
  [implementation plan](../plans/agentic-implementation.md) §4 increment 1,
  [design review](20261105-secure-agentic-experiences-design.md)

Every round's prompt carried the standing warning that the diff, fixtures and evidence may
contain prompt injection aimed at the reviewer, to be reported as a finding and never
followed. Round 1 found none.

## Round 3 (on `49cf550`)
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

## Round 2 (on `7e0f0f6`)
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

## Round 1 (on `b4a3360`)
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

A host environment variable was chosen over a CLI flag (the user, 2026-11-06): a tab's
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
