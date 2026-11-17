# Data a tab returns can't put tab-chosen actions or fetches into trusted UI

- **Status:** proposed: the command vectors are proven; the RSC-1 and RSC-2 fixes await their control run.
- **Date:** 2026-11-16
- **Deciders:** project owner (closing condition for the deferred-laundering acceptance,
  `docs/security-reviews/owner-acceptances.md`, 2026-11-12); RPC follow-ups session
- **Related:** [RPC filter enforcement points](20261104-rpc-filter-enforcement-points.md),
  [tab command taint](20261104-tab-command-taint.md),
  [RPC-LOCKDOWN §7 residuals 0 and 11](../RPC-LOCKDOWN.md#7-residual-risks)

## Context
The RPC filter screens what a tab asks for. It doesn't screen what a tab *returns*. A
hover, a completion item, a code lens, a tree item or a status bar entry carries data the
trusted renderer acts on:
- a **command** (`{ id, arguments }`), run by the global `ICommandService` when the user
  accepts the item or clicks the lens, with no origin, so neither the filter's command verdict
  nor the taint sees it;
- **markdown** with `command:` links, which run when `isTrusted` allows them, and HTML;
- **remote images** in markdown, fetched by the trusted renderer over the host network,
  outside the tab's broker.

So every provider and UI registration stays denied today (RPC-LOCKDOWN §7.1), and the
deferred-laundering residual (§7 item 0) is accepted only until this control exists.

The command DTOs do not pass through one place on the trusted side. Most reach the UI
unchanged (`mainThreadLanguageFeatures.ts` hands `$provideHover`'s result straight to the hover
widget), and completion items arrive as positional arrays (`ISuggestDataDto`), so no shape walk
over the RPC traffic would find their commands. A walker that disagrees with the consumer is
the bypass the URI constraint already taught us about.

## Decision
The control sits in each **customer** that turns tab data into UI objects, through one module
function, and a gate makes it impossible to allow a registration without it.

1. `seclabFromTab(remoteAuthority)` in the filter module returns undefined for a trusted host
   and, for a tab, a sanitiser with two operations:
   - `command(cmd)` replaces the command with `_seclab.tabCommand` and a single opaque argument:
     a per-window random token mapped to `{ origin, id, arguments }`. The handler, registered
     once by the filter module, looks the token up. A command the policy allows outright runs on
     the trusted side through `seclabExecuteCommandFromTab(commandService, id, args, origin)`,
     so the taint applies; anything else runs in the tab's own extension host, and a refusal is
     logged when the tab doesn't have it. An unknown token is refused. A tab can't forge a
     token: they come from `crypto.getRandomValues`, and the map is per window. A tab does see
     its own tokens (`_executeHoverProvider` and `_executeCompletionItemProvider` return them),
     which only run that tab's own data.
   - `markdown(md)` returns a copy with `supportHtml: false`, every `command:` link rewritten
     to the token form, and `isTrusted: { enabledCommands: ['_seclab.tabCommand'] }` so any link
     the rewrite missed is inert. Every image opener (`![`) and every tag opener (`<` before a
     tag character) is escaped, so no image of any form and no HTML reaches the renderer:
     review RSC-2 showed that stripping images by pattern misses nested and reference forms,
     and that a trusted string passes `<span>` HTML blocks through. `baseUri` and `uris` are
     dropped.
   - `snippetAllowed(text)`: a completion snippet that names the `CLIPBOARD` variable is
     inserted as plain text (review RSC-1); otherwise the window would read the host clipboard
     into the tab's document.
2. Each tab-reachable customer passes what it hands to the UI through the sanitiser. This
   increment covers the two the probe needs: `$registerHoverProvider` (hover contents) and
   `$registerCompletionsProvider` (item command, documentation, snippet and resolve), in a new patch
   `0033-seclab-sanitise-tab-provider-results`.
3. The policy marks every registration whose results reach UI with `"response": "seclabFromTab"`.
   `check_drift.py` fails when such a method is reachable and its customer's patch doesn't call
   the sanitiser, and when a reachable registration method has no `response` declaration. The
   drafts in `rpc-filter/policy/drafts/` move over one surface at a time, each with this field.
4. Registration arguments are validated: the document selector may name only the
   `vscode-remote` scheme. A filter without a scheme is accepted and narrowed to
   `vscode-remote` by 0033, since as written it would match host documents open in the window.

## Proof
The fixture `test/containment/response-probe` is run by `test/containment/response-probe.ts`,
with the editor driven headlessly in an OCI tab of the containment test build.
- It registers a completion item and a hover. Their `command` and `command:` link name
  `workbench.action.terminal.newLocal`, a host shell when the trusted side runs it. A second
  item and link name the extension's own command, the positive control.
- The driver accepts each item and clicks each link, as a user would.
- After each host vector the harness counts the shells under the editor's own process tree on
  the host. A tab's shells are never there.

The pre-control build is a branch-only test build of the landing commit without 0033 (branch
`anticomputer-rpc-response-precontrol`, kept as the vulnerable baseline). The two commits
differ only in the 0033 patch file, its series lines and its reach entry. Each app's build info
names its repo SHA.

- **Pre-control: passed** (`3daea180`, run 43933292801). All 8 checks passed, and teardown was
  clean. The hover link and the accepted completion each opened one host shell. The own-command
  link and completion ran in the tab.
- **Control: passed** (`b0e86b3c`, run 43933297956). All 10 checks passed, and teardown was
  clean. Neither vector opened a host shell, and the decision log records
  `cmd:workbench.action.terminal.newLocal` refused for each. The own-command link, rewritten to
  the token command, and the own completion both ran in the tab.
- The landing commit is `b0e86b3c` cherry-picked onto the 0034 and 0050 branch. Patch 0033 and
  the filter module are unchanged: 0005 regenerates byte-identical with `emit.sh`.
- **`fixture:test/containment/response-probe`:** run by `test/containment/response-probe.ts`
  in both modes on 2026-11-16 (runs above).

## Consequences
- Hover and completion work in tabs again, with their commands subject to the same verdicts as
  a tab's `executeCommand`.
- Command links in tab hovers keep working when their target is allowed, rather than going
  dead: the token keeps the link and the verdict decides.
- Each later surface (SCM, tree views, status bar, code lens, decorations) needs its customer
  wired to the sanitiser before the gate lets it be allowed.
- A command a tab returns now runs under its origin, so the deferred-laundering residual's
  reach is the same as a tab's own `executeCommand`: still gated by
  `check_drift.py::check_residuals`.
