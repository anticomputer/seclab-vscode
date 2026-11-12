# Automatic tasks stay off (upstream default, asserted at build)

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** Project owner (2026-11-04): for the `tasks.json` campaign, the threat model must specifically protect against it; fork-build session
- **Related:** [threat model ADR](../adr/20261104-threat-model-rogue-extension.md), [EDR ci-hardening](20261104-ci-hardening.md)
- **Editorial redaction (2026-11-12):** quotations of project conversations replaced with neutral statements; decisions unchanged.

## Context
The DPRK "Contagious Interview" campaign
([Jamf](https://www.jamf.com/blog/threat-actors-expand-abuse-of-visual-studio-code/),
[OpenSourceMalware](https://opensourcemalware.com/blog/latest-contagious-interview-malware-campaign-abuses-microsoft-vscode-tasks))
ships a `.vscode/tasks.json` with `runOptions.runOn: "folderOpen"` and hidden
presentation, so opening the repo runs a downloader. The coordinator asked for
`task.allowAutomaticTasks: off` by default via product.json `configurationDefaults`.

## Findings
- Code-OSS has no product.json `configurationDefaults`; the only off-the-shelf route
  would be an extension's `contributes.configurationDefaults`, and that rejects
  application-scoped settings
  ([configurationExtensionPoint.ts#L217-L231](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/api/common/configurationExtensionPoint.ts#L217-L231)).
- It isn't needed. At the pinned 1.145.0 the setting is already `default: 'off'`,
  `scope: APPLICATION`, `restricted: true`
  ([task.contribution.ts#L537-L548](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/contrib/tasks/browser/task.contribution.ts#L537-L548)).
  Application scope means workspace and folder settings can't turn it on; only the
  user's own settings can.

## Decision
- Keep the upstream default; no patch, no override.
- `build/prepare.sh` asserts it after the patch queue: if an upstream bump changes the
  default, scope or restriction, the build fails.
- Defence in depth, not reliance: even when a user turns it on, a folder-open task
  runs inside the tab, with the tab's fence and broker (containment suite `task`
  vector, run with `allowAutomaticTasks: on` as the worst case).

## Consequences (UX)
- A repo's folder-open tasks (watchers, dev servers) don't start by themselves; the
  user runs them (Run Task) or opts in once in their user settings. That is the
  upstream behaviour users of this version already have.
- The pre-open scan will list auto-executing workspace config (folder-open and
  hidden-presentation tasks, `curl | sh`, devcontainer lifecycle commands, MCP
  servers) in the open prompt, as information only.
