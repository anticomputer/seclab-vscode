# Agents-in-the-tab spike, step 3: the shipped agent host in a real sbx tab behind its broker

- **Status:** accepted
- **Date:** 2026-11-06
- **Deciders:** coordinator ("Spike in a real tab. Run the §11.1 spike for real: agent host in an sbx tab, behind its broker, against a fake model endpoint, with no real credential anywhere. Measure the actual model-request fields and tool types"); secure-agentic-experiences session (spike).
- **Related:** [EDR step 1-2](20261105-agents-in-tab-spike.md) (extended by this record), [plan §4.2 and §11.1](../plans/secure-agentic-experiences.md#42-the-authenticate-rewrite), [ADR broker model access](../adr/20261105-broker-model-access.md), [implementation plan](../plans/agentic-implementation.md), [security review](../security-reviews/20261106-agentic-real-tab-spike.md)

## Context
The first spike ran the shipped agent host offline in a container that stood in for a
tab. It could not say what the Copilot runtime sends through a real broker, because tab
broker wiring had not landed. Now it has: sbx tabs run behind a per-tab broker by default
(B2), and the broker has its model-host body policy, the D7 derive rule and the
`/copilot_internal/user` exception. The broker's provider lists are drafts until confirmed
against real runtime traffic. This spike produces that traffic without any real
credential.

## Decision
Measure in a real tab, with every network peer a fixture we own.

- **Tab.** `test/agentic/ahp/tab-spike.ts` drives `seclab-tabd` exactly as
  `tabd/test/e2e-broker.ts` does: `--driver sbx --broker required`, the template
  `seclab-tab:local`, the policy from tabd's state directory, and the teardown gate at the
  end.
- **Broker.** A per-run image `FROM seclab-broker:dev` whose entrypoint also sets
  `SECLAB_EXTRA_UPSTREAM_CA_PEM` to the fixture CA (added to certifi, never replacing it).
  It is passed with `--broker-image`, so tabd is unchanged.
- **Fixture.** `fake-capi.mjs` is modelled on upstream's own e2e stubs (`capiStubs.ts`,
  `capiWireCodec.ts` at the pinned SHA).
  - It runs as a fake GitHub Enterprise and Copilot API under `ghe.example.test`,
    `api.ghe.example.test` and `capi.example.test`.
  - It sits on an `--internal` 11.250.x.0/24 network that only the broker joins.
    Docker's embedded DNS resolves the aliases; there is no DNS fixture.
  - It logs only the shape of each request: header names, a credential *class* by
    equality with this run's fake values, body key paths, and tool types and names.
- **Credential.** `credential.import` of a fake `seclabcanary_` GitHub value, with `bind`
  and `derive`. The tab is handed only the sentinel. The fixture rejects a request with
  401 unless it carries the fake value, so a failed swap shows rather than passes.
- **Agent host.** Started from the tab's own REH (`/opt/seclab-reh`) under
  `seclab-tab-env`, with root config `githubEnterpriseUri` so that every host is a
  `*.test` name. `tab-driver.mjs` speaks AHP 1.1.0 over loopback as upstream's e2e client
  does: initialize, authenticate every advertised resource with the sentinel, then one
  session per model. Each turn asks for one `view` call on a probe file in the workspace,
  then a text reply carrying the run nonce.
- **Two broker policies per run.**
  - A: plain allows for the fixture hosts, so the fixture sees raw requests.
  - B: `capi.example.test` declared as a provider with the broker's draft `copilot`
    lists, so the broker's own audit shows what the draft refuses.
- **Facts come from host-side sources only:** the fixture log and the broker audit. The
  tab-written driver report is kept apart and labelled tab-written. The redacted result
  is [`20261106-tab-spike.measured.json`](../../test/agentic/ahp/results/20261106-tab-spike.measured.json).

## Results
Run `20261106T034456Z` (the committed result; re-run after the review fixes as
`20261106T041229Z`, with the same outcome); template `seclab-tab:local`; broker
`seclab-broker:dev` as on main `0f8ac0d`; agent host from the shipped REH
(`copilot/1.0.103-unstable`).

**Phase A (plain allow).** All three model endpoints completed a turn. Each turn ran the
`view` tool in the tab and sent its result back to the model; the fixture saw the probe
marker in the follow-up request.

| Route (fixture) | Calls | Credential the fixture received |
|---|---|---|
| `GET ghe.example.test/api/v3/copilot_internal/user` (agent host) | 2 | GitHub (swapped from the sentinel) |
| `GET api.ghe.example.test/copilot_internal/user` (runtime) | 1 | GitHub |
| `GET capi.example.test/models` | 10 | GitHub |
| `POST capi.example.test/responses` (gpt-5.3-codex) | 2 | GitHub |
| `POST capi.example.test/v1/messages` (claude-sonnet-4.5) | 2 | GitHub |
| `POST capi.example.test/chat/completions` (gpt-4o) | 2 | GitHub |
| `POST capi.example.test/mcp/readonly` | 6 | GitHub (404 from the fixture; turns unaffected) |

Request bodies, top-level fields:

| Endpoint | Fields | Tools |
|---|---|---|
| `/responses` | `include`, `input`, `instructions`, `model`, `parallel_tool_calls`, `reasoning`, `store`, `stream`, `text`, `tools` | 30 `function` and 1 `custom` (`apply_patch`, `format.type=grammar`) |
| `/chat/completions` | `messages`, `model`, `reasoning_effort`, `snippy`, `stream`, `stream_options`, `temperature`, `tools` | 30 `function` and 1 `custom` |
| `/v1/messages` | `max_tokens`, `messages`, `model`, `stream`, `system`, `temperature`, `thinking`, `tools` | 32 untyped (Anthropic custom) |

Message item types seen:
- `/responses`: `message` with `input_text`, `function_call`, `function_call_output`.
- `/v1/messages`: `text`, `tool_use` and `tool_result`; `cache_control` ephemeral; `system[]` text.
- `/chat/completions`: `tool_calls[].type=function`.

No URL-bearing content type appeared. The tool set is the runtime's own (`bash`, `view`,
`glob`, `rg`, `apply_patch`, `web_fetch`, `task`, `sql`, the session tools and others);
none is a server-side tool.

**Broker decisions.**
- Phase A:
  - The backstop exempted `/copilot_internal/user` on both GitHub hosts.
  - It denied `GET api.ghe.example.test/copilot_internal/{managed_settings,team_customizations,content_exclusion}`
    ("endpoint can mint durable credentials").
- Phase B, with the draft `copilot` provider:
  - `/models` allowed and audited as `model.call`;
  - `/responses` denied: tool type `custom`;
  - `/chat/completions` denied: field `snippy`;
  - `/mcp/readonly` denied: endpoint not allowed.
  - Every turn failed with the runtime's "authorization error".

**Against the draft lists.**
- Endpoints missing: `POST /v1/messages`.
- Fields missing: `snippy`, `system`, `thinking`.
- Tool types missing: `custom`, and untyped tools on `/v1/messages`.
- Draft fields never sent: 19 of 34, listed in the result file.

## Findings
1. **The runtime never mints a Copilot token.** No request reached `v2/token`. Every CAPI
   call carried the GitHub credential itself. D7's derive rule did not fire, so the GitHub
   parent needs bindings on the Copilot API model endpoints. The tab still holds only a
   sentinel. This contradicted the premise of accepted decision D7; the user amended D7
   (Consequences).
2. **Two GitHub API hosts.** The agent host uses `<ghe>/api/v3`
   (`deriveGitHubEndpoints`). The runtime uses `api.<ghe>` with no `/api/v3`, the
   `ghe.com` shape. Bindings and the provider table must list both. On github.com both
   are `api.github.com` (inferred; not contactable under fixture rules).
3. **The `/copilot_internal/user` response check blocks upstream's own shape.** The
   broker's credential-name pattern matches `cloud_session_storage_enabled` and
   `token_based_billing`. For the run, the fixture stripped exactly the keys that pattern
   matches (read from the broker source) and recorded them. The broker is replacing the
   pattern with a field allowlist (its decision).
4. **Org-policy endpoints are denied.** `managed_settings`, `team_customizations` and
   `content_exclusion` carry restrictions an enterprise places on Copilot. With them
   denied, turns still work, so content exclusions silently stop applying in tabs. This
   was a policy regression, not a leak; the user accepted the three exceptions.
5. **The runtime calls GitHub's remote MCP server** (`/mcp/readonly`) with the GitHub
   credential: server-side tools acting on the user's GitHub. Decided: denied by default,
   with a per-tab Tier C grant.
6. **Requests carry identifying headers** to the model API: `x-github-repository-nwo`,
   `x-github-repository-host`, `x-client-machine-id` and `x-client-session-id`.
   Observability should know they exist; the broker forwards them.
7. **The protocol path works as upstream's real-SDK suite drives it.** Subscribe to the
   session URI at once; `root/sessionAdded` is not guaranteed before the first turn. An
   in-workspace `view` needed no approval (D5). No reverse request reached the client.

## Not done, and why
- **github.com.** Under fixture rules the spike may contact only `*.test` names, so the
  github.com route is inferred from the shared code path. Real response fields of
  `/copilot_internal/user` remain unmeasured, because no real credential may be used.
- **The editor.** The client here is a protocol driver, not the workbench. Running the
  workbench against a tab's agent host is the job of the probe runner (implementation
  plan, increment 0).
- **Codex and Claude SDK harnesses.** Only `copilotcli` was driven.

## Consequences
- The broker updates its draft provider (its own decisions).
- The user decided the three points that changed accepted decisions (2026-11-06, through
  the coordinator); the broker session implements them:
  - **D7 amended.** The GitHub credential is bound to the Copilot API model endpoints by
    exact path and method.
  - **Org-policy GETs exempt.** The three `GET` routes get the same strict checks as
    `/copilot_internal/user`.
  - **Remote MCP.** `/mcp/readonly` is denied by default, with a per-tab Tier C grant.
- Plan §4.2, §4.5 and §13 and the ADR carry dated amendments.
- `tab-spike.ts` is the template for the probe runner's tab half.

## Evidence
- Harness: `test/agentic/ahp/tab-spike.ts`, `fake-capi.mjs`, `tab-driver.mjs`.
- Result: [`test/agentic/ahp/results/20261106-tab-spike.measured.json`](../../test/agentic/ahp/results/20261106-tab-spike.measured.json),
  from the fixture log and the broker audit. Run directories are under
  `.work/agentic/runs/*-tab/` (not committed).
- Teardown gate: clean on every run (no surviving process, sandbox, container, network or
  volume; nothing outside the run directory changed).
  - The spike's own resources (fixture container, network, derived broker image) carry a
    per-run label, and all three are checked gone. `clean-host` also matches the derived
    image's name.
  - The tab-written workspace is recorded in `run.json` and deleted by teardown. Only the
    driver reports are kept, each a regular file under 1 MiB that passes the AV-shape
    check, and the fixture log passes the same check (review round 1).
  - Before phase A, the run fails closed unless every fixture name resolves, from the
    broker, inside the run's own subnet.
- Upstream: [`deriveGitHubEndpoints`](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/github/common/githubEndpoints.ts#L42-L72),
  [`ICopilotUserResponse`](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/node/shared/copilotApiService.ts#L84-L98),
  [`COPILOT_GH_HOST`](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/node/copilot/copilotAgent.ts#L4380-L4393),
  [e2e stubs](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/test/node/e2e/harness/capiStubs.ts),
  [real-SDK session flow](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/agentHost/test/node/e2e/suites/workspaceSuite.ts#L50-L57).
