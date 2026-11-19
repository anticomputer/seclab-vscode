# Security review: a tab's server names no host location (patch 0059)

- **Date:** 2026-11-18
- **Scope:** patch 0059 and its filter-module helpers (`seclabTabUris`, `seclabTabServerChannel`,
  `seclabTabExtensionsChannel`, `seclabTabMcpChannel`, `seclabUnrevivedManifest`), the policy rows
  `data:server-locations` and the `push:extensions:*`, `push:logger:*`, `push:mcpManagement:*` and
  `push:userDataProfiles:*` residuals, `check_drift.py`'s enforcement check, and the tests
  `test/containment/reh-environment.test.ts`, `test/containment/reh-environment.ts` and
  `rpc-filter/tools/test_enforcement.py`.
- **Reviewer:** the `security-review` agent on an Opus-class model, rounds 1 to 14; triage and fixes
  by the RPC follow-ups session. Finding IDs `ENV-n`; R5-17 comes from the DOCSYNC-R5 review.
- **Threat model:** a rogue extension owns its tab's extension host and its server (REH). The trusted
  side is the editor window and the host: its files, its network, its extension management. Nothing
  the tab's server names or sends over a channel the window opened may make the window read, write,
  watch, fetch or install a host location or host code.
- **Related:** [EDR tab-server-environment](../edr/20261118-tab-server-environment.md).
- **Prompt injection:** none found in any round.

## How the evidence was made
The branch keeps each reviewed version of the patch as its own commit, followed by the commit that
fixes that round's findings. The final unit test (`test/containment/reh-environment.test.ts`) runs
upstream's own code with whichever version of the patch a tree has. Its case "a tab window takes
none of them, and logs each refusal" fails on main and on every reviewed commit, each failing on
the leaks that round reported and later ones, and passes on the final version (run logs kept outside
the repo, under the session's `.work/`):

| Tree | Reviewed in | The final test's case |
|---|---|---|
| main (f00912bb) | none | fails |
| `remote: patch 0059 as reviewed in round 1` | round 1 | fails |
| `remote: patch 0059 round-1 fixes` | round 2 | fails |
| `remote: patch 0059 round-2 fixes` | round 3 | fails |
| `remote: patch 0059 round-3 fixes` | round 4 | fails |
| `remote: patch 0059 round-4 fixes` | round 5 | fails |
| `remote: patch 0059 round-5 fixes` | round 6 | fails |
| `remote: patch 0059 round-6 fixes` | round 7 | fails |
| `remote: patch 0059 round-7 fixes` | round 8 | fails |
| `remote: patch 0059 round-8 fixes` | round 9 | fails |
| `remote: patch 0059 round-9 fixes` | round 10 | fails |
| `remote: patch 0059 round-10 fixes` | round 11 | fails |
| `remote: patch 0059 round-11 fixes` | round 12 | fails |
| `remote: patch 0059 round-12 fixes` | round 13 | fails |
| `remote: patch 0059 round-13 fix` | none | passes |

On main (f00912bb) the case "a tab window takes none of them, and logs each refusal" fails, taking every lie, which is the evidence for each high found on main and fixed here.
On the commit round 1 reviewed the case "a tab window takes none of them, and logs each refusal" fails, with ENV-1's URI fields on the reply among its leaks.
On the commit round 2 reviewed the case "a tab window takes none of them, and logs each refusal" fails, with ENV-8's host files marked `$mid` other than 1 among its leaks.

The runtime proof (`test/containment/reh-environment.ts`) ran on two containment test builds that
differ only by patch 0059: on main plus the test hook, the tab's server served the lie and the host
file's canary reached it; on this branch the lie was served, no canary arrived and the window logged
two refusals ([EDR](../edr/20261118-tab-server-environment.md)).

## Findings

| # | Sev | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| R5-17 | High | environment | The window took the settings, storage, log and profile locations in its server's `getEnvironmentData` reply as given, so a tab's server could name the host user's settings file as the tab's, which the window then read and wrote. | fixed | Every location must be `vscode-remote` on the window's authority, rebuilt from its components; else the environment is refused. | test/containment/reh-environment.test.ts "a tab window takes none of them, and logs each refusal" |
| ENV-1 | Critical | filter | The first check stopped walking at a URI-shaped object, so URI fields set on the reply itself hid the whole reply. | fixed | Containers carry no URI keys; every object is walked. | same |
| ENV-2 | Medium | filter | A checked URI kept the server's `external` and `fsPath`, which `URI.revive` honours. | fixed | Each URI is rebuilt from scheme, authority, path, query and fragment. | same |
| ENV-3 | High | profiles | The `userDataProfiles` channel's replies and events named profile locations unchecked. | fixed | The channel is wrapped with the same check. | same |
| ENV-4 | Medium | environment | A refused environment read as "no remote", and callers fell back to host locations. | fixed | In a tab window it stays a failure. | same |
| ENV-5 | Medium | watcher | File change events named host files unchecked. | fixed | Changes outside the tab are dropped. | same |
| ENV-6 | Low | scanner | Scanned extensions' locations were unchecked. | fixed | Extensions outside the tab are dropped. | same |
| ENV-7 | Info | tests | The unit test stubbed `URI.revive` and had no decoy cases. | fixed | Decoys and rebuilt-URI checks added. | same |
| ENV-8 | Critical | filter | An object marked `$mid` other than 1 was walked as a container, though `URI.revive` ignores `$mid`. | fixed | Any URI key marks a candidate, which must be `$mid: 1`. | same |
| ENV-9 | Medium | watcher, scanner | Callers used the URI they were sent, not the rebuilt one. | fixed | They use the rebuilt value. | same |
| ENV-10 | Medium | extensions | The extension management channel was unchecked; a host `file:` location routes to host management. | fixed | The channel is wrapped. | same |
| ENV-11 | Medium | filter | A bare `{path}` object passed as a container but revives as a file URI. | fixed | `path` marks a candidate. | same |
| ENV-12 | Low | extensions | Genuine `getManifest` replies were refused (manifests carry `scheme` keys). | fixed | Manifests aren't walked where upstream doesn't revive them. | test/containment/reh-environment.test.ts "a tab window takes a genuine server unchanged" |
| ENV-13 | High | extensions | An install event's gallery `source` and a tab VSIX let the host install the tab's package ("Install Locally"). | fixed | Gallery sources removed; the host refuses a `vscode-remote` VSIX. | test/containment/reh-environment.test.ts "a tab window takes none of them, and logs each refusal" |
| ENV-14 | Low | policy | The enforcement entry named a symbol that doesn't exist, and the drift gate didn't check entries for constrained surfaces. | fixed | Real symbol; the gate checks every entry naming a patch or symbol. | rpc-filter/tools/test_enforcement.py "test_a_constrained_surface_entry_naming_a_missing_symbol_fails" |
| ENV-15 | High | extensions | A tab extension's manifest named packs and dependencies the host then installed. | fixed | Not installed on the host from a tab window. | test/containment/reh-environment.test.ts "a tab window takes none of them, and logs each refusal" |
| ENV-16 | Medium | scanner | The window retried the server's failed installs with options it chose. | fixed | Not retried in a tab window. | same |
| ENV-17 | Info | filter | `manifest` was skipped at any depth. | fixed | Skipped only where upstream leaves it unrevived. | same |
| ENV-18 | Info | extensions | A host VSIX inside the tab's workspace mount installed on the host. | fixed | Refused. | same |
| ENV-19 | High | MCP | The MCP discovery reply named host directories the window read and watched. | fixed | Checked at both callers. | same |
| ENV-20 | Medium | MCP | The MCP management channel was unchecked. | fixed | Wrapped. | same |
| ENV-21 | Low | extensions | The workspace check compared unresolved, unnormalised paths. | fixed | Resolved, NFC, case-folded. | same |
| ENV-22 | Medium | extensions | "Install Locally" and "Install Remote Extensions Locally" installed a tab-named gallery extension on the host. | fixed | Refused in a tab window. | same |
| ENV-23 | Medium | MCP | MCP servers' icon and link URLs reached the renderer, which fetched the icon over the host network. | fixed | Stripped. | same |
| ENV-24 | Info | MCP | Genuine `config.env` and `config.headers` keys named like URI parts were refused. | fixed | Checked as records. | test/containment/reh-environment.test.ts "a tab window takes a genuine server unchanged" |
| ENV-25 | High | extensions | A tab language-pack manifest fanned an update or uninstall out to the host. | fixed | Not fanned out from a tab's server. | test/containment/reh-environment.test.ts "a tab window takes none of them, and logs each refusal" |
| ENV-26 | Medium | MCP | A `local` key on a server object skipped the URL strip. | fixed | Both levels stripped. | same |
| ENV-27 | Low | MCP | Numeric and null env values were refused. | fixed | Accepted, as upstream's type allows. | test/containment/reh-environment.test.ts "a tab window takes a genuine server unchanged" |
| ENV-28 | High | extensions | Install-side language-pack and sync fan-out installs a tab-named gallery extension on the host ("Update All", a workspace recommendation). | fixed | Central: the host's extension management is read-only from a tab window. | test/containment/reh-environment.test.ts "a tab window takes none of them, and logs each refusal" |
| ENV-29 | Medium | extensions | A tab extension's pack list makes its uninstall remove host extensions. | fixed | Central: the host's extension management is read-only from a tab window. | test/containment/reh-environment.test.ts "a tab window takes none of them, and logs each refusal" |
| ENV-30 | Medium | extensions | A tab extension's pack and dependency lists change host extensions' enablement. | fixed | Central: the host's extension management is read-only from a tab window; enablement changes only the tab's extensions. | test/containment/reh-environment.test.ts "a tab window takes none of them, and logs each refusal" |
| ENV-31 | Medium | extensions | The unsupported-extensions migration acts on the tab's data. | fixed | Central: the host's extension management is read-only from a tab window; the migration is skipped. | test/containment/reh-environment.test.ts "a tab window takes none of them, and logs each refusal" |
| ENV-32 | Low | tests | The genuine case cleared the refusal log before its final check. | fixed | It asserts the refusals it expects. | test/containment/reh-environment.test.ts "a tab window takes a genuine server unchanged" |
| ENV-33 | Medium | enablement | Install and uninstall events from the tab reset the host's global enablement by id. | fixed | The host's global enablement is read-only in a tab window. | test/containment/reh-environment.test.ts "a tab window takes none of them, and logs each refusal" |
| ENV-34 | Medium | enablement | A tab extension claiming a host id could switch the host's copy with a click. | fixed | As ENV-33. | test/containment/reh-environment.test.ts "a tab window takes none of them, and logs each refusal" |
| ENV-35 | Low | extensions | The read-only host channel also refused `download`, which installs in the tab. | fixed | Allowed; it installs nothing on the host. | test/containment/reh-environment.test.ts "a tab window takes a genuine server unchanged" |
| ENV-36 | Low | localization | A tab install event prompted to change the host's display language. | fixed | The prompt ignores the tab's events. | test/containment/reh-environment.test.ts "a tab window takes none of them, and logs each refusal" |
| ENV-37 | Info | extensions | The host channel's authority came from the connection. | fixed | From the window's environment. | none |
| ENV-38 | Low | extensions | The marketplace token went to the tab's server; publisher trust granted in a tab window was kept. | fixed | No token; no trust kept. | test/containment/reh-environment.test.ts "a tab window takes none of them, and logs each refusal" |
| ENV-39 | Medium | profiles | Profile import built the unguarded enablement service. | fixed | Builds the guarded one. | test/containment/reh-environment.test.ts "a tab window takes none of them, and logs each refusal" |
| ENV-40 | Low | extensions | One-time migrations used up their host-shared flags in a tab window. | fixed | Skipped in a tab window. | test/containment/reh-environment.test.ts "a tab window takes none of them, and logs each refusal" |
| ENV-41 | Low | enablement | A refused global change reported success. | fixed | It throws. | test/containment/reh-environment.test.ts "a tab window takes none of them, and logs each refusal" |
| ENV-42 | Low | tests | The suite didn't cover the singleton registration, and silently skipped unlisted files. | fixed | Covered; every patched file must be listed. | test/containment/reh-environment.test.ts "a tab window takes none of them, and logs each refusal" |
| ENV-43 | Info | docs | ARCHITECTURE §4.8 misstated some losses. | fixed | Rewritten. | none |
| ENV-44 | Low | extensions | Extension Bisect from a tab window disabled host extensions by id. | fixed | Refused in a tab window. | test/containment/reh-environment.test.ts "a tab window takes none of them, and logs each refusal" |
| ENV-45 | Medium | extensions | Auto-update settings from a tab window changed the host's lists by tab-chosen id or publisher. | fixed | Refused in a tab window. | test/containment/reh-environment.test.ts "a tab window takes none of them, and logs each refusal" |
| ENV-46 | Low | extensions | Removing a trusted publisher from a tab window changed the host's list. | fixed | Refused (superseded by ENV-50: refused visibly). | test/containment/reh-environment.test.ts "a tab window takes none of them, and logs each refusal" |
| ENV-47 | Low | profiles | A profile from a template in a tab window dropped its disabled extensions. | fixed | Refused in a tab window. | test/containment/reh-environment.test.ts "a tab window takes none of them, and logs each refusal" |
| ENV-48 | Medium | extensions | "Sync This Extension" in a tab window wrote the host user's synced ignore list, by ids the tab chose. | fixed | Refused in a tab window. | test/containment/reh-environment.test.ts "a tab window takes none of them, and logs each refusal" |
| ENV-49 | Medium | extensions | A tab extension claiming the chat extension's id was offered the host user's "AI features" setting. | fixed | Not offered for an extension on a tab's server. | test/containment/reh-environment.test.ts "a tab window takes none of them, and logs each refusal" |
| ENV-50 | Low | extensions | A publisher-trust revocation in a tab window was dropped silently. | fixed | Refused visibly; both trust guards log. | test/containment/reh-environment.test.ts "a tab window takes none of them, and logs each refusal" |
| ENV-51 | Low | extensions | A tab window wrote the host's dismissed extension notifications, rebuilt from ids the tab chose. | fixed | Not written from a tab window. | test/containment/reh-environment.test.ts "a tab window takes none of them, and logs each refusal" |
| ENV-52 | Low | extensions | Extension feature access is kept by claimed id in host-shared storage; no caller reaches it today. | deferred | Latent: no feature asks for consent or can be toggled, and the one caller has no caller. Needs the same guard if that changes. | none |
| ENV-53 | Low | themes | A tab extension's theme, applied in a tab window, is cached in host-shared storage and painted briefly by the next host window. | deferred | Appearance only, the same for any remote window upstream, and not extension management; a follow-up. | none |
| ENV-54 | Info | docs | Two record rows had drifted from the code. | fixed | Corrected. | none |
| ENV-55 | Low | tests | A fault in the rogue-REH payload's early arming would escape into the test server's startup. | fixed-untested | Caught in the payload. | none |
| ENV-56 | Info | docs | The EDR described a runtime vector the harness no longer runs. | fixed | Corrected. | none |
| ENV-57 | Info | tests | The harness saved the REH log before the evidence, so a failed save lost the evidence. | fixed | Evidence first; the log best effort. | none |
| ENV-58 | Info | tests | The arming test didn't cover the hook's new startup path. | fixed | Three startup cases. | test/builds/rogue-reh-arming.ts "a run expired when the server starts: early not called" |
| ENV-59 | Info | tests | The saved REH log is the tab's text, unmarked. | fixed | Kept under `untrusted/` with a header. | none |
| ENV-60 | Low | extensions | The PR66-1 check compared ids only, but workspace enablement matches by uuid first, so a tab extension carrying a host extension's uuid under another id still changed the host copy's state for the workspace. | fixed | Round 16's fix: in a tab window a host extension takes its global state only. | test/containment/reh-environment.test.ts "a tab window takes none of them, and logs each refusal" |
| ENV-61 | Low | extensions | The PR66-1 check read the host's extensions from the window's combined list, which stays empty when the tab's server fails its part of the listing, so no id collided. | fixed | Same. | same |
| ENV-62 | Low | extensions | An uninstall the tab reports reset the workspace enablement of any extension with that identity, a host extension's included. | fixed | Same: a reset of a host extension's workspace entry changes nothing a tab window reads. | same |
| ENV-63 | Low | extensions | Round 15's check asked the host for the current profile's extensions, but workspace enablement holds for every profile, so a host extension installed only in another profile could still be claimed. | fixed | Round 16's fix: the read ignores the workspace's lists for host extensions, whichever profile. | test/containment/reh-environment.test.ts "a tab window takes none of them, and logs each refusal" |
| ENV-64 | Low | extensions | Round 15's check looked at what the host had installed when the entry was written, so an entry naming an extension the host installed later, or had uninstalled, still took effect. | fixed | Same: whenever the entry was written. | same |
| ENV-65 | Info | extensions | Round 15 made `_reset` asynchronous in tab windows, so a tab's own uninstalled extension briefly kept its workspace entry. | fixed-untested | Upstream's `_reset` is back. | none |
| ENV-66 | Low | extensions | A tab extension claiming a host extension's dependency id, with no API and reported invalid, turned the host extension off in the tab window through the dependency rule. | fixed | In a tab window a host extension doesn't take a tab extension as its dependency. | test/containment/reh-environment.test.ts "a tab window takes none of them, and logs each refusal" |
| ENV-67 | Low | extensions | An uninstall the tab's server reported, carried as a bare id, removed a running host extension sharing the id from the tab window. | fixed | Such an uninstall never removes a host extension. | same |
| PR66-4 | Low | extensions | Upstream's server sent install replies and a VSIX install's source as server-side file URIs, unlike its other replies, so a tab window refused a genuine install's reply and dropped its event after the install had happened. | fixed | The server transforms them like its other replies; the window's checks stay. | test/containment/reh-environment.test.ts "a tab window takes a genuine server unchanged" |
| PR66-5 | Low | mcp | Upstream's MCP server sent install and metadata-update replies untransformed, so a tab window refused them after the change had been written. | fixed | The server transforms them like `getInstalled`'s. | test/containment/reh-environment.test.ts "a tab window takes a genuine server unchanged" |
| PR66-6 | Low | tests | The runtime check read the environment probe's served count with `Number`, so a malformed count read as NaN and passed. | fixed | The count must be a positive safe integer. | test/containment/check-probes.test.ts "the environment probe needs the lie served and the canary on a baseline, and a logged refusal after patch 0059" |
| PR66-7 | Low | extensions | An update the tab's server reported queued a bare id for removal, which removed a running host extension sharing the id from the tab window. | fixed | In a tab window an update removes only the copy it updates. | test/containment/reh-environment.test.ts "a tab window takes none of them, and logs each refusal" |
| ENV-69 | Info | extensions | With the server's install replies transformed, an `installGalleryExtensions` reply reached the window with any gallery entry the tab's server named, which the install events already lose; nothing reads it today. | fixed | The reply loses a gallery entry too. | test/containment/reh-environment.test.ts "a tab window takes none of them, and logs each refusal" |
| ENV-68 | Low | extensions | A tab can make host extensions unavailable in its own window: the extension registry checks dependency loops by id across the host's and the tab's extensions, so a tab extension claiming an id that closes a cycle removes the host extension in it, and activation resolves a host extension's dependency through the tab's claimed id. An availability loss contained to that window, not an escape. Tab Manager can't be hit: the product pins it to the local host, so the local copy takes its id, and it has no dependencies. | deferred | Partition the extension description registry by tab in tab windows, tracked as its own item (coordinator, 2026-11-18). Cutting host-to-tab dependency links is ruled out, since it breaks genuine cross-host dependencies. test/containment/reh-environment.test.ts "Tab Manager stays out of reach of a tab claiming its id" keeps Tab Manager out of reach meanwhile. | none |
| PR66-1 | Low | extensions | Workspace enablement is kept by id, so a tab extension claiming a host extension's id, enabled or disabled for the workspace from a tab window, changed the host copy's state there too. | fixed | Round 16's fix: in a tab window a host extension takes its global state only, whatever the workspace's lists hold. | test/containment/reh-environment.test.ts "a tab window takes none of them, and logs each refusal" |
| PR66-2 | Medium | environment | When the environment was refused, local history fell back to the host's own history directory for the tab's files. | fixed | In a tab window local history is unavailable instead. | same |
| PR66-3 | Medium | environment | A location left out of the environment, or null, passed the check, and its consumers (local history, terminal history, the terminal and MCP sandboxes) fell back to the host's. | fixed | Every location a genuine server sends is required, each an object. | same |

PR66-1 to PR66-3 came from the automated pull request review on #66, after round 14. The final
test's case fails on the round-14 tree with exactly those five leaks (three missing locations,
local history and the shared id) and passes on the fix.

Round 15 reviewed the PR-review fixes and found ENV-60 to ENV-62, ways past the PR66-1 fix. They
are rated as PR66-1 is: the state reached is a host extension's enablement for the tab's workspace,
in the tab's window. The final test's case fails on the PR-review fix tree with exactly those three
leaks.

Round 16 reviewed the round-15 fix and found ENV-63 to ENV-65: every check on the write could be
raced or sidestepped. A tab window's workspace storage belongs to the tab's `vscode-remote`
workspace, which only tab windows open, and a tab window never sets a host extension's workspace
enablement, so the fix is at the read: in a tab window a host extension takes its global state
only, and the round-15 check goes. The final test's case fails on the PR-review fix tree and on the
round-15 fix tree, each with its two leaks (a workspace entry under a host id and under a host
uuid), and passes on the round-16 fix.

Round 17 reviewed the round-16 fix and found ENV-66 and ENV-67, two other ways a tab could turn a
host extension off in its own window. Both are rated as PR66-1 is. The final test's case fails on
the round-16 docs tree with exactly those two leaks and passes on the round-17 fix.

PR66-4 to PR66-7 came from the automated pull request review of the round-17 tree. The final test's
case "a tab window takes a genuine server unchanged" fails on the round-18 docs tree with seven
genuine replies and events refused (PR66-4, PR66-5), and "a tab window takes none of them, and
logs each refusal" fails there with PR66-7's leak; both pass on the fix. The check-probes case
fails on the previous predicate for every malformed count and passes on the fix (PR66-6).

Round 19 reviewed the PR66-4 to PR66-7 fixes and found no vulnerability; its one note is ENV-69,
fixed. The final test's case fails on the PR66 docs tree with exactly that leak and passes on the
fix.

Round 18 reviewed the round-17 fix and found it correct; it found ENV-68, deferred by coordinator
decision on 2026-11-18 as an availability loss contained to the tab's own window, with the
registry's partition by tab as its follow-up.

Round 14 reviewed the test-only rogue-REH hook change (`test/builds/variants.json` requires a round
for a hook change): the hook now arms a run staged before a server starts as that server starts,
still only for a well-formed, unexpired run, and still only in the containment test build.

## Decisions
Rounds 4 to 8 each found another workbench route by which a tab extension's identity or manifest
drove the host's own extension management. From round 8 the fix is central: a tab window's host
extension management is read-only, and the host-shared extension settings it could reach by id are
left alone. That makes host extension management a tab limitation (ARCHITECTURE §4.8), approved by the
project owner on 2026-11-18, including Extension Bisect, auto-update settings, the synced
extension ignore list, trusted-publisher management and profiles from a template, since each
changes host extension state. The per-route guards stay as defence in depth.
