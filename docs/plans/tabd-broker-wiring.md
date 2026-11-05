# Plan: wire tabs to their broker (M2, M3)

- **Status:** proposed
- **Date:** 2026-11-05
- **Owner:** fork-build session (tabd, drivers, Tab Manager). Broker: egress-and-credential-broker session.
- **Inputs:** [broker protocol](../broker-protocol.md), [broker policy](../broker-policy.md),
  [ADR tab supervisor](../adr/20261104-tab-supervisor.md), ARCHITECTURE §6 (M2, M3).

## Goal
Every tab reaches the network only through its own broker:
- with sentinels in place of real credentials;
- with egress prompts shown by the Tab Manager;
- with credentials from the host vault or keychain imported over the control protocol.

This is the critical path for the "cred sidecar" demo, the agentic spike in a real sbx tab,
the README's egress and credential screenshots, and the observability XFAIL (attribution).

## Fixed points (from code on main)
- **Control channel.** `docker exec -i <broker> seclab-broker control`, NDJSON JSON-RPC.
  Nothing listens on the host. tabd keeps one long-lived connection per tab and reconnects if
  it drops.
- **`broker.hello` first.** `tabd/src/broker.ts` `checkBrokerHello` fails closed on any
  protocol, tab or schema mismatch. Main's broker is now at policy schema revision 3 (derive,
  model access), so increment B1 bumps the pin, after reading the changelog for anything that
  grants more.
- **OCI.** The pod's placeholder sidecar (`oci.ts`, `--network-alias broker`) becomes the
  broker. It sits on the pod's `--internal` network plus its own ICC-off egress network, with
  the protocol §6 flags.
- **sbx.** The broker runs as a Docker Desktop container published on `127.0.0.1::8080`. The
  fence's only allow is `localhost:<P>` (`sbx.ts`, `brokerPort`), which is already enforced
  and checked.
- **No credential crosses into the tab.** The tab sees only sentinels. Real values go
  host → tabd → broker over the control channel and never through the environment.

## Increments (each one a working demo, a review round and an EDR)

| # | Increment | Done when |
|---|---|---|
| B1 | **OCI broker, default deny.** Broker image pinned by image ID (built by `broker/build.sh`, registered). tabd control client (JSON-RPC over the exec stdio, typed from `broker/schema/protocol.v1.json`), `hello`, `health`, `proxy.auth.set` with a fresh random password, `policy.load` (built-in deny-all policy), `ca.get`. CA installed in the workspace as root at create; proxy and CA variables in the REH launch environment, so extensions, terminals and tasks inherit them. `broker.shutdown` on close. | Containment: from the tab, a direct connection fails (no route); through the proxy, an unlisted host gets `403 X-Seclab-Broker: denied`; an allowed test host works; the broker never sees a real credential. Runs in `./seclab test containment oci` and CI `oci`. |
| B2 | **sbx broker.** The same client and policy, with the broker container on loopback; the fence check now requires the broker allow; proxy host `host.docker.internal:<P>`. | The same assertions in `containment sbx`; the fence probe shows only `<P>` reachable. |
| B3 | **Hold and prompt.** `approval.requested` → tabd → Tab Manager notification → modal prompt (`untrusted` text rendered as data, host shown prominently, default deny, exactly the offered `decisions`) → `approval.decide`. `tab.event opened` on open, `userAction` from the workbench, never from consent dialogs. Audit events feed the tab's observability log. | A scripted decider in the harness answers allow and deny; a folder-open loader fixture is auto-denied before the first user action; screenshot of the prompt (background window, per AGENTS). |
| B4 | **Credentials.** Host vault: macOS keychain items under a seclab service, read only by tabd after a Tab Manager prompt, imported with `bind` (`credential.import`, `source.kind: host`), sentinel persisted for restarts. Pre-mount scan findings imported unconfirmed (`workspace-scan`). The git credential helper or askpass in the tab returns the sentinel. | `git clone` and `git push` over HTTPS to a test remote with a sentinel; the canary suite finds no real token in the tab's memory, environment or files; a sentinel sent to an unbound host is blocked (`403`). |
| B5 | **GitHub auth in tabs (M3).** Tab-side extensions asking for a GitHub session get a sentinel session; the real token stays in the trusted side and is supplied to the broker just in time (`credential.provide`, with `credential.needed`). This likely needs a small auth-mediation patch; it goes through the patch-build gate and the reach check (`desktop`). | An extension in the tab calls the GitHub API through the broker with a sentinel and succeeds; the same sentinel sent elsewhere fails. |
| B6 | **Attribution.** Join the broker's audit events (request, decision) to the tab's process events. | Closes the observability XFAIL. |

B1 and B2 can merge into one landing if the client is the same. B5 depends on the RPC
series' auth decisions and comes last.

## Open questions (need a decision before the increment that needs it)
1. **Policy source (B1).** Proposal: a built-in default (deny-all, prompt on) shipped with
   tabd, plus an optional user policy in the host state directory. Never read policy from the
   workspace, which is attacker-controlled.
2. **Keychain access (B4).** Proposal: tabd reads keychain items only after a Tab Manager
   prompt that names the item and the binding host. Items are created by the user through the
   Tab Manager, never discovered by scanning the keychain.
3. **Prompt fatigue (B3).** The broker rate-limits prompts per tab. Should the Tab Manager
   also batch prompts per origin across tabs?
