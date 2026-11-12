# Threat model: the primary attacker is a rogue extension the user installs

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** anticomputer (user: "our threat model is that of someone installing a rogue extension"); seclab-vscode coordinator
- **Supersedes:** the threat-model portion of [the containment-unit ADR](20261104-tab-is-the-containment-unit.md) (attacker list) and of ARCHITECTURE.md §2 as of f36f759
- **Related:** [no real secret ADR](20261104-no-real-secret-in-a-tab.md)

## Context
The earlier model listed malicious extensions, malicious workspaces and
prompt-injected agents as peers. The user narrowed and sharpened it.

## Decision
- **Primary attacker:** a rogue extension that the user installs, from a
  gallery or a VSIX, into a tab. It has **full control of that tab's extension
  host and REH server process**: it can replace the REH, speak the remote
  protocol to the UI as a hostile server, read and write everything in the
  tab, and run any code inside the tab sandbox.
- **Secondary:** malicious workspace content (tasks, git config,
  config-as-code, interpreter paths, MCP configs). It is contained by the same
  boundary, because it can do at most what a rogue extension in that tab can
  do.
- **Goal of the attacker:** reach anything outside its tab, namely host code
  execution, host files, real secrets, other tabs, ungranted network, or
  persistence into other tabs or the host.
- **Out of scope:** kernel and hypervisor escapes. Each driver's isolation is
  defence in depth: sbx gives one microVM per tab; OCI gives namespaces, with
  optional gVisor.

## Consequences
- Every channel from the tab to the host is hostile input: the REH server→client
  protocol, `MainThread*` RPC, the managed socket bytes, and files written to
  the shared workspace mount. That last one matters for later host-side reads,
  for example git on the host. It is why local windows must never open a tab's
  workspace unsandboxed (ADR route-folder-opens-in-main).
- Persistence is in scope. A rogue extension must not be able to install itself
  into other tabs or onto the host
  ([EDR extension persistence](../edr/20261104-extension-persistence.md)).

## Worked example: "Contagious Interview" (tasks.json abuse), 2026-11-04
The user asked that the model specifically defeat this DPRK campaign
([Jamf](https://www.jamf.com/blog/threat-actors-expand-abuse-of-visual-studio-code/),
[OpenSourceMalware](https://opensourcemalware.com/blog/latest-contagious-interview-malware-campaign-abuses-microsoft-vscode-tasks)).
A fake recruiter sends a take-home repo; opening and trusting it runs a hidden
folder-open task that pipes a fetched script into `node`, or runs JS hidden in a
"dictionary" file. The resulting node backdoor fingerprints the host, beacons to a C2,
evals tasking, steals wallets, browser data, `~/.config/solana/id.json` and keychains,
drops persistence into `~/.vscode`/`~/.n2`, and spreads through the repo.

Each step, the control that stops it, and the test that proves it. The test is
`./seclab test containment sbx|oci`, vector `contagious`, fixture
`test/containment/fixtures/contagious-interview` (inert; the loader is stored as parts
because endpoint protection quarantines a faithful one; EDR fixture-safety).

| # | Campaign step | Control | Proof |
|---|---|---|---|
| 1 | Folder-open task runs on open | `task.allowAutomaticTasks` stays `off` at application scope, so a workspace can't enable it ([EDR](../edr/20261104-automatic-tasks-off.md), build-asserted). If it runs anyway (user opt-in, or a manual run), it runs **in the tab** | `loader and stage ran inside the tab, not on the host` |
| 2 | Host fingerprint (hostname, MACs, OS) | The tab is a microVM or container: it only sees its own identity | `fingerprint returns tab values …, not the host's` |
| 3 | Public-IP lookup (ipify) | Default-deny egress; the broker denies IP-echo hosts before a user action ([ADR](20261104-defeat-folder-open-loaders.md)) | `IP-echo lookup denied` |
| 4 | Fetch of the stage and C2 beacon every 5 s (vercel.app, raw IP) | Fence plus broker: raw IPs and risky hosting denied, no prompt before user action | `every C2 beacon denied`, `no tasking ever reached the stage` |
| 5 | Credential theft (wallets, browser profiles, solana, keychain) | Only the workspace is mounted; no real secret enters a tab ([ADR](20261104-no-real-secret-in-a-tab.md)) | `host credential-store canaries unreadable from the tab` |
| 6 | Persistence in `~/.vscode`, `~/.n2` | Lands in the tab's own home, never the host's. Tabs persist, so the user-chosen **Reset tab** rebuilds the tab from its template | `persistence drops … exist only in the tab's home`, `Reset tab discards the persistence drops` |
| 7 | Long-running backdoor | Dies with the tab | `the background stage … dies when the tab stops` |
| 8 | Planting host-executed code in the repo (`.git/hooks`, `.envrc`) for the next host-side git or direnv run, and spreading | **Write-back gate** (user decision: watch and warn; [spike](../edr/20261104-write-back-gate-spike.md)). Code-running files a tab changes are held until approved | `planted … never live in the host checkout`: **XFAIL until the gate lands** |
| 9 | Attribution of the blocked activity to the task | Tab–broker integration and tab observability | `denials are attributed to the folder-open task`: **XFAIL (M2/M3)** |

Residual: step 8 is open until the write-back gate ships. A planted hook is inert in
the tab, but would run on the host's next `git commit`.
