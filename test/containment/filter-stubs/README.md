# Stand-ins for the four upstream modules `seclabRpcFilter.ts` imports

`test/containment/filter-module.test.ts` imports the SHIPPED filter module
(`rpc-filter/patch-src/seclabRpcFilter.ts`) and redirects only these imports here:

| Upstream | Stand-in | What the filter uses from it |
|---|---|---|
| `base/parts/ipc/common/ipc.js` | `ipc.mjs` | `setSeclabChannelGuard`, recorded so the test can call the installed guard |
| `base/common/uri.js` | `uri.mjs` | `URI.revive`, `URI.from`, `toString`, `fsPath` (components only; no cached forms) |
| `platform/commands/common/commands.js` | `commands.mjs` | `CommandsRegistry.getCommand` |
| `platform/contextkey/common/contextkey.js` | `contextkey.mjs` | `RawContextKey.all` |

The policy data and the argument validators are the real modules. Behaviour that depends on
upstream's real `URI` (canonical-form checks) is tested in `arg-validators.test.ts` and
`uri-constraint.test.ts`, not here.
