# Extension placement hardening: built-in-only `ui`, no `web` default, nothing runs in local windows

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** fork-build session (security review round 3)
- **Supersedes:** [20261104-extensionkind-default-workspace](20261104-extensionkind-default-workspace.md) (keeps its decision, closes three gaps it left)
- **Security review:** [round 3](../security-reviews/20261104-m0-tabd-code.md)

## Context
Round 3 showed that a product-wide `workspace` default isn't enough on its own:
1. **CRITICAL.** In a window with no remote (an empty local window, or the
   moment before a local folder window is rerouted), upstream runs
   `workspace`-kind extensions **locally**
   (`NativeExtensionHostKindPicker`: "workspace extensions also run locally if
   there is no remote"). An extension the user installs in an empty window
   therefore runs on the host.
2. **MEDIUM.** `ui` entries were keyed by ID. A gallery copy of an allowlisted
   ID (`vscode.github-authentication` is on Open VSX, and the `seclab`
   namespace is unclaimed there) would be `ui`.
3. Extensions with a `browser` entry would also gain `web` kind and could run
   in the local web-worker host.

## Decision
- **Patch 0002 (revised):**
  - explicit product `extensionKind` entries apply **only to built-in**
    extensions (`isBuiltin === true`); everything else gets `*`;
  - the user setting `remote.extensionKind` is ignored when `*` is set.
- **Patch 0003:** in a window without a remote authority (seclab mode), only
  `ui`-kind extensions may run. The picker drops `workspace` and `web`. With
  0002, `ui` means built-in auth providers, simple-browser, handlebars and the
  Tab Manager. Built-in git, tasks extensions, TypeScript and every installed
  extension are inert in local windows.
- **product.json:** `"*": ["workspace", "-web"]`, enforced by a jq invariant.
- **Operational:** claim the `seclab` namespace on Open VSX. This needs the
  user's account, so it is tracked as an open item.

## Consequences
- Local windows are plain editors (no language features from extensions).
  The only things meant to run code there are first-party UI built-ins.
- Installing an extension in an empty window writes it to the host extensions
  directory but never runs it. Blocking local installs outright needs a
  further patch in the shared process (open item, low).
- Core auto-tasks are not an extension, so they are not covered. The local
  folder window is closed before any dialog
  ([EDR](../edr/20261104-local-window-close-first.md)). The full fix is the
  proposed main-process routing.

## Evidence
- `nativeExtensionService.ts` `NativeExtensionHostKindPicker.pickExtensionHostKind` at a717861c (the "workspace extensions also run locally if there is no remote" branch).
- Open VSX: `{"error":"Namespace not found: seclab"}`; `vscode.github-authentication` is published there by `open-vsx` (reported by the reviewer).

## Addendum (2026-11-04, review round 4)
The decision is unchanged; this records how it is enforced.
- **`isBuiltin` alone is spoofable.** `toExtensionDescription` spread the
  manifest last, so a `package.json` could set `isBuiltin: true`.
  - **Patch 0004** spreads the manifest first, so computed fields win.
  - **0002 v3** also requires `isUserBuiltin !== true` and a real `URI`
    `extensionLocation`. Only scanned system extensions qualify.
- **0003 constructor fix.** `NativeExtensionService` constructs the picker
  directly, so 0003 passes `productService` at that call site.
- Review record: [round 4](../security-reviews/20261104-m0-tabd-code.md).

## Addendum (2026-11-05): no trusted-side extension agents in tab windows
The decision is unchanged; this records a check of it against extension agents.
- **Question.** A `ui`-kind extension that hosts its own agent would run on the trusted side
  of a tab window, untouched by the built-in chat disable. Does placement stop that?
- **By code.**
  - Product `extensionKind["*"]` forces every non-built-in extension to `workspace` (0002).
    Computed fields can't be spoofed (0004).
  - The `ui`-kind allowlist is first-party only: `seclab.tab-manager`,
    `vscode.github-authentication`, `vscode.microsoft-authentication`, `vscode.handlebars`,
    `vscode.simple-browser`. No Copilot Chat, agent or model provider is on it.
- **By probe (Level B, 2026-11-05, macOS app from main `7d1c94d`, sbx).** The rogue extension
  declares `extensionKind: ["ui"]`, contributes a chat participant, registers it with
  `vscode.chat.createChatParticipant`, and calls `vscode.lm.selectChatModels` and
  `vscode.lm.tools`. Its evidence shows that code ran in the tab: `ranIn: tab`,
  `remoteName: seclab` (check "ui-declared chat participant / vscode.lm caller ran in the tab,
  not trusted-side": PASS).
- **The same run also showed the known M4 gap.** The rogue extension's RPC probes opened a
  host terminal (`workbench.action.terminal.newLocal`) and typed into it
  (`…terminal.sendSequence`), creating the run's empty `PWNED` marker on the host. That is
  host code execution from a tab, closed by the RPC series' command patches (0007/0008), not
  yet on main.
