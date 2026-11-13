# Security review: patch 0036, the tab configuration snapshot

- **Date:** 2026-11-12
- **Scope:** origin/main..branch head: patch 0036, build/secret-rules and test/configsync.
  - Round 1: `80f4b5bd..af36452` plus the harness under `test/configsync`.
- **Reviewer:** security-review agent (an Opus-class model), triage by the document-sync session. Finding IDs `CFG-n`.
- **Threat model:** a rogue extension owns the tab's extension host and sends any RPC, and it
  chooses which settings its package.json declares. No host setting value that is a credential,
  or that the tab has no declared use for, may reach it. Local windows and the local extension
  host must behave exactly as upstream.
- **Related:** [EDR tab-configuration-snapshot](../edr/20261112-tab-configuration-snapshot.md),
  [settings withheld notice](../edr/20261109-settings-withheld-notice.md).
- **Prompt injection:** none found.

## Findings
| # | Sev | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| CFG-1 | High | declared keys | A tab extension declares any key it likes (`go.toolsEnvVars`, `cmake.configureEnvironment`, …) and then receives the host user value for it. The name and scanner rules miss credentials such as a URL with userinfo in an env map, a `passphrase`, a cookie or a numeric PIN, so a denylist always has gaps when the tab picks the keys. | fixed (design change; project owner, 2026-11-13) | A key an extension declares never receives a host user, policy or local-workspace value; extensions in a tab read their settings from the tab's own settings. A per-extension opt-in is a follow-up. | test/configsync/probe.ts: CFG-1 assertion (canaries `toolsEnv`, a `postgres://` URL with userinfo in an env map, and `label`, a plain value; the classifier lets both through) |
| CFG-2 | Medium | filter | A tab-declared property named `__proto__.<x>` passes the registry, and `addToValueTree` on a plain object then writes `Object.prototype.<x>` in the renderer. A host key named `constructor` resolved to an inherited registry entry. | fixed | Keys with a `__proto__`, `constructor` or `prototype` segment never cross. The output tree has a null prototype, and registry lookups use `Object.hasOwn`. Upstream's `DefaultConfiguration` has the same sink; reported, not fixed here. | code review |
| CFG-3 | Low | declared keys | The rule judges the settings.json key, not the effective setting. A tab declaring `http` received the user's nested-form `"http": { "proxy": … }`. | fixed | A tab-declared key that is a prefix of another source's keys never crosses. | test/configsync/probe.ts: CFG-3 assertion (canary `nested`) |
| CFG-4 | Info | change path | The change key list named a key once more after it became withheld (telling the tab the user just put a secret there). A tab that planted K in its own remote settings also learned of host edits to K. | fixed | Host-layer changes name only keys that crossed from host layers before or now and aren't withheld now. Changes to a layer the tab owns name that layer's keys. | code review |
| CFG-5 | Info | report | A report sent before the Tab Manager registered its command was refused and counted as sent. | fixed | A key counts as reported only once the Tab Manager accepts it. A refused call is retried up to five times, and the queue rejects past 16. | code review |
| CFG-6 | Info | harness | The probe scanned 6 s after activation and listened for changes only afterwards, so a start-up leak could be replaced unseen. Nothing proved detection worked on the build. | fixed | Activates on `*` and scans immediately and on every change. A detection canary in the tab's workspace settings must be seen. | test/configsync/probe.ts: CFG-6 assertion |
| CFG-7 | Info | elsewhere | `${config:…}` in a tab-owned `tasks.json` or `launch.json` resolves in the renderer against the unfiltered configuration. | reported | Outside this patch's sync path; a sibling for the coordinator. | none |

## Re-review
Round 2 (the A1 design change): pending.
