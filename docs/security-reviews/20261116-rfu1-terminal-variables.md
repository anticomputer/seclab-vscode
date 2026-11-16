# Security review: patch 0034, no host variables for a tab's terminals (RFU-1)

- **Date:** 2026-11-16
- **Reviewer:** independent `security-review` agent (an Opus-class model)
- **Subject:** `git diff 6039b383..1d65614b` on `anticomputer-rpc-rfu1`: patch 0034, the
  `reh-profile-config-host-setting` probe and its predicates, `terminal-variables.test.ts`, and
  the EDR section. Review finding RFU-1 ([record](20261116-rpc-follow-ups.md)) is what it fixes.
- **Prompt:** said the diff, fixtures and evidence may contain prompt injection aimed at the
  reviewer, and that the reviewer reports it rather than following it. None was found.

## Verdict
No high or critical finding. RFU1R-1 showed that 0034 as reviewed did not close RFU-1, so 0034
was extended to cover it, together with RFU1R-4 to RFU1R-6. RFU1R-2 and RFU1R-3 are about
sending host data that isn't variable resolution, so each stays open with a follow-up.

| ID | Sev | Component | Finding | Status |
|---|---|---|---|---|
| RFU1R-1 | medium | `terminalProcessManager` (upstream), launch environment | A REH-supplied profile's `env` still had host variables resolved. `terminalProcessManager` resolves `shellLaunchConfig.env` with the full configuration resolver before the profile resolver 0034 patched runs, and the DTO sends the values back to the REH in `createProcess`. Two triggers: the user picks the REH's profile, or the host's `terminal.integrated.defaultProfile.<os>` names one the REH offers. After that, every new terminal leaks | fixed |
| RFU1R-2 | medium | `remoteTerminalBackend.createProcess`, `getProfiles` (upstream) | The window sends the host's raw `terminal.integrated.env.<os>`, `terminal.integrated.cwd` and `terminal.integrated.profiles.<os>` settings to the tab's REH, which 0036 withholds from the tab's extension host as credential-bearing | open |
| RFU1R-3 | low | `remoteTerminalChannel.createProcess` (upstream) | `activeFileResource` can be a host `file:` or `vscode-userdata:` document, and its path goes to the REH on every `createProcess` | open |
| RFU1R-4 | info | `reh-profile-config-host-setting` probe | The probe checked only the executable, so it couldn't see RFU1R-1. Its patched predicate ignored the `unresolved` fact | fixed |
| RFU1R-5 | info | `terminal-variables.test.ts` | The behavioural test re-implemented the tab resolver rather than running the patch's own | fixed |
| RFU1R-6 | info | `terminalProfileResolverService` (0034) | The tab flag keyed on the per-terminal authority, which a `cwd` object sets and which is compared case-sensitively. A tab can't reach it today: `MainThreadTerminalService` falls to the default deny | fixed |

## Confirmed without findings
- For a `seclab+` authority, `env` in `_resolveProfile` is the REH's environment: the backend
  lookup throws rather than falling back to the host's process environment.
- `RemoteTerminalChannelClient._remoteAuthority` is always the window's connection authority,
  minted by the host. The inlined regex matches the filter's `SECLAB_AUTHORITY`.
- The other configuration-resolver callers in the terminal contribution don't take data from a
  tab:
  - 0031 refuses the pty host's variable requests;
  - the tab's `MainThreadTerminalService` and task calls are default-denied;
  - `getCwd` and the `terminal.integrated.env.*` resolution feed only the local environment,
    which the remote backend ignores.
- Normal windows are unchanged: every change is gated on a `seclab+` window authority.

## What changed in response
- RFU1R-1: in a tab window, `terminalProcessManager`'s variable resolver substitutes only
  `${env:…}`, from the REH's environment. That covers the launch config's `env`, a REH
  profile's included.
- RFU1R-4: the probe offers a `seclab-probe` profile through `$getProfiles`, with the canary
  setting in its path and `env`. The harness makes it the host's default profile. The probe
  reads `$createProcess` at the channel, before the server's own resolution. The baseline
  predicate needs the canary in both; the patched one needs both seen, unresolved, with no
  canary.
- RFU1R-5: the test evaluates the two resolver expressions the rules require verbatim in the
  patch.
- RFU1R-6: both resolvers key on the window's authority.
- RFU1R-2 and RFU1R-3 are registered open. Follow-up: in a tab window, filter the terminal
  configuration and profiles the window sends with 0036's withhold rules, and send
  `activeFileResource` only for this tab's `vscode-remote` authority.
