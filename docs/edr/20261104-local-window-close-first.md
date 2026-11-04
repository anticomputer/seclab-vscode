# Local folder windows are closed before any dialog (routing hand-off)

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** fork-build session (security review round 3, finding 2)
- **Supersedes:** [20261104-tab-manager-routing](20261104-tab-manager-routing.md) (local-window part; the resolver binding, `isTrusted` and onboarding are unchanged)

## Decision
When the Tab Manager activates in a local window that has a folder or
workspace:
1. Record the request (`{hostPath | unsupported, at}`) in the extension's
   `globalState`.
2. **Immediately** run `workbench.action.closeFolder`, with no dialog first.
3. In the now-empty window, pick the request up if it is less than 60 s old:
   - if the folder isn't a known tab yet, confirm with a modal;
   - claim the tab (onboarding a projects folder if needed);
   - open `vscode-remote://seclab+<tabId><path>` in the same window.

   Multi-root and non-file workspaces get a warning only.

Level B of the containment harness opens the tab directly
(`--folder-uri vscode-remote://seclab+<tabId><ws>`), so the hostile fixture is
never opened in a local window.

## Consequences
- Together with patch 0003, nothing extension-based runs in the brief local
  window. The remaining residual is core auto-tasks in a previously trusted
  folder before `closeFolder` takes effect. That is closed only by
  main-process routing (proposed ADR).
- The projects-folder dialog now defaults to `$HOME`, not the requesting
  path's parent. tabd rejects roots that are sensitive, are ancestors of or
  inside sensitive paths, or are dot-directories directly under `$HOME`.
