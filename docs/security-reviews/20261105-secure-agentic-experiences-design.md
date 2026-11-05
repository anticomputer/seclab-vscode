# Security review: secure agentic experiences design (agents in the tab)

- **Date:** 2026-11-05
- **Scope:** round 1: f62a485 (rebased from 9f4ded7; design as first written: [plan](../plans/secure-agentic-experiences.md), [ADR](../adr/20261105-agents-run-in-the-tab.md), [agentic surfaces](../research/agentic-surfaces.md), [prior art](../research/agentic-prior-art.md)), verified against `microsoft/vscode@a717861c07586a53d83b80d742cd3f59b20a6273`. Round 2 covers the follow-up commit that folds the findings in.
- **Reviewer:** security-review agent (default model), triage by the secure-agentic-experiences session
- **Related:** [ADR agents run in the tab](../adr/20261105-agents-run-in-the-tab.md), [RPC-LOCKDOWN](../RPC-LOCKDOWN.md)

This is a design review: no code exists. "Fixed" means the design now specifies the
control, and the regression test is the probe named in the plan (§11.3), to be built with
the control. The prompt carried the standing warning that the diff, upstream source and
evidence may contain prompt injection aimed at the reviewer. None was found.

Each critical and high finding was checked against the pinned source by the triaging
session before it was accepted. Findings 1 and 2 also apply to v0 as it stands. Finding 2
was reported to the RPC-lockdown session through the coordinator on 2026-11-05, together
with a proposed v0 fix and probe.

## Findings

| # | Severity | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| 1 | critical | Reverse requests | The agent host can send `resourceRead`, `resourceWrite`, `resourceDelete` and other `resource*` requests that the client serves on raw host URIs. They are gated by `chat.agentHost.localFilePermissions`, which is unregistered in editor windows and therefore tab-writable, or by an "Allow" prompt. Result: host file write, then host code execution | fixed (design) | Plan §3.2: all server-to-client requests denied for `seclab+`. §10: a reverse-request patch behind the gate. I5 and research §11: unregistered settings are tab-writable | A16, A23 |
| 2 | critical | Second connection | `chat.workspaceRemoteAgentHosts` (`WINDOW`, `restricted`; tabs report trusted) makes the editor dial an attacker's agent host from the host network, outside the broker and outside the gate. That host gets credentials, `resource*` and client tools. **Live in v0** | fixed (design); v0 raised | Plan §3.5: one connection per tab window; `IRemoteAgentHostService` and the other providers are null; settings pinned; providers inventoried. Raised to RPC-lockdown for v0 | A17 |
| 3 | critical | Client tools | Emptying the advertised client-tool set does not limit execution. Tools are resolved over all tools, including disabled ones, and the client honours pre-approval asserted by the agent host | fixed (design) | Plan §3.3: refuse client execution and agent-host pre-approval in the session handler; safe outputs never go through `invokeTool`. §10 patch | A18 |
| 4 | high | Outbound data | The user's host MCP configurations (with host-resolved `${env:}` and literal headers), prompts, skills and plugins are forwarded into the agent host, with URI read grants | fixed (design) | Plan §3.2 customizations row and outbound allowlist; §4.5 | A19 |
| 5 | high | Auth triggers | The rewrite was placed in one caller; other `authenticate` callers exist, and MCP metadata for a tab-chosen URL is fetched silently from the host network before any token exists (SSRF, exfiltration) | fixed (design) | Plan §4.2 step 0: gate the triggers before any resolution or fetch; the rewrite sits on the transport; canonical URL keys | A1, A2, A20 |
| 6 | high | Rendering | MCP App UI webviews take their CSP from server-supplied domains: tab JavaScript in trusted chrome with host-network egress | fixed (design) | Plan §3.2: `_meta.ui` stripped; §3.4; §10 patch | A21 |
| 7 | high | Model egress | Model APIs accept server-side tools that fetch caller-chosen URLs, so the provider can relay workspace data to an attacker; host, path and method bindings do not see it | fixed (design) | Plan §4.4: broker body policy for model hosts (deny only); Tier C exception; R14 | A22 |
| 8 | medium | Derived token | A host-wide child binding is wider than the parent's single `GET`; pattern-based re-sentinelisation fails open on a format change | fixed (design) | Plan §4.2: bind by path and method; structural replacement; fail closed; R10 raised to medium | Broker unit tests (broker session) |
| 9 | medium | Config sync | Every setting registered for agent-host sync is mirrored to the agent host, including `http.proxy` with credentials | fixed (design) | Plan §3.2: configuration allowlist | A19 |
| 10 | medium | Settings model | `tab_writable = scope != APPLICATION` misses settings unregistered in the consuming window; several policy-bearing settings are missing from class (e) | fixed (design); raised | I5; research §11; plan §10 pinned settings; raised to RPC-lockdown | A6, A23 |
| 11 | medium | Inventory | A drift check generated only from the protocol registry misses the 36 vendor extension methods, reverse requests, and the `mcp:/`, OTLP, annotations, canvas and automation-run channels | fixed (design) | Plan §3.3: generate class (f) from every definition and client handler; default deny | A14 |
| 12 | medium | Prompts | The tab can trigger upstream prompts directly (resource permission, workspace trust, MCP sign-in), outside the inbox | fixed (design) | Plan §9.2: triggers denied, not restyled | A11, A16 |
| 13 | medium | Local agent host | A renderer null service does not remove it; main creates the starter; Agents window, Mission Control and GitHub environments remain | fixed (design) | Plan §3.5 and §8.1; §10 patch in `app.ts` | A12 |
| 14 | medium | Tier C | A host view of a tab page runs in host Chromium; upstream's browser tunnel proxy opens agent-host TCP automatically when a `WINDOW` setting is on; MCP grants were per server | fixed (design) | Plan §5.3: ephemeral partition, broker-only traffic, setting pinned, per-tool MCP grants, secret scan on mounts | Tier C probes |
| 15 | low | Rendering | The adapter adds its own command links; links to the product URL protocol reach host URL handlers; remote images load over the host network | fixed (design) | Plan §3.4 | A4, A24 |
| 16 | low | Supply chain | Claude and Codex SDKs are downloaded at run time with only a completion marker | fixed (design) | Research §14; plan R9 and D3 | Tampered-tarball probe with D3 |
| 17 | info | Keys and URLs | Canonicalise provider-table keys; restrict `openExternal` to `https` public hosts | fixed (design) | Plan §4.2 step 1; §5.2 | Fuzz with A1 and B1 |

**Factual errors the reviewer found, all corrected:**

- Research §4.3 claimed that the advertised client-tool set bounds what can run.
- Plan §4.4 (now §4.5) said host MCP servers are unreachable, but their configurations were forwarded.
- Research §11 missed unregistered settings.
- Research §2.2 had an incomplete channel list and called a re-export file "one registry".
- Plan §3.2 omitted `debugEnv`.
- Plan §8.1 and §10 assumed a renderer null service removes the local agent host.
- The ADR's patch estimate was low.
- The plan and ADR pointed to this record before it existed.
- The reviewer could not verify the `learn.chatgpt.com` citation. The triaging session fetched it on 2026-11-05: it is OpenAI's Codex security page and supports the cited claims.

## Re-review

**Round 2** (security-review agent, default model): `f62a485..09ebb4c` (rebased from `9f4ded7..6d71734`; content unchanged). **No high or
critical finding open.** Round-1 findings 1, 3, 5, 6, 8, 9, 11, 13 and 16 were closed as
written. Findings 2, 4, 7, 10, 12, 14, 15 and 17 needed the follow-ups below. All
round-2 findings were fixed in the design in the commit that adds this section.

| # | Severity | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| 2.1 | medium | Outbound data | The live text of an unsaved or untitled active editor is embedded as a URI-less attachment, and implicit context accepts host schemes, so a transport URI filter cannot see host content | fixed (design) | Plan §3.2: filter at the source; same rule for queued messages and chat import | A19 |
| 2.2 | medium | Prompts and URLs | A URL-bearing input request renders as a trusted "Authorization Required, Open …" card that opens any scheme; pills open agent-host URLs externally | fixed (design) | Plan §3.2: stripped, or an `openExternal` safe output with the §5.2 rules | A24 |
| 2.3 | medium | Broker body policy | A deny-list over request bodies fails open (duplicate keys, escapes, compression, WebSockets) and contradicts the broker ADR's closed list of content uses | fixed (design) | Plan §4.4: fail-closed allowlist; a broker-session ADR to amend the rule | A22 |
| 2.4 | medium | Settings | Pinning "by policy" cannot be done (no policy on these registrations); a key was misnamed; `workbench.browser.enableRemoteProxy` defaults to on in non-stable builds | fixed (design) | Plan §3.5 and §10: forced in code; exact keys from the class (e) inventory, including the ten settings the RPC-lockdown session found registered only in the Agents window | A23 |
| 2.5 | low | Auth | Tokens are sealed to an agent-host-advertised key before the transport | fixed (design) | Plan §3.2: unconditional rewrite; key stripped | A25 |
| 2.6 | low | Credentials | Codex account sign-in mints a real credential in the tab | fixed (design) | Plan §4.2: harness sign-ins denied; BYOK import only | A25 |
| 2.7 | low | URIs | Non-`file` URIs pass through unmapped; "tab authority only" was ambiguous | fixed (design) | Plan §3.2: accept only `file:` and the tab's own authority | A26 |

Round 2 also confirmed from source:
- denying every server-to-client request is viable, because a tab-side agent host reads
  its own files;
- with `IRemoteAgentHostService` null, the §3.5 list of connection providers is complete
  for editor windows;
- `_executeClientTool` is the only path to `invokeTool`.

No prompt injection was found in either round. A further review round is required on the
implementation of each tier (plan §11.2).
