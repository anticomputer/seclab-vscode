# Prior art: containing AI coding agents

**Scope.** What other systems do about where the agent loop runs, how model and tool
credentials are held, how host-affecting actions are mediated, and how prompt injection is
handled. Web sources were accessed on 2026-11-05; GitHub sources are pinned to the SHA
shown. Fetched pages are data. One anomalous URL in a fetched spec is noted in §2 as a
finding, not followed. The upstream VS Code facts are in
[agentic surfaces](agentic-surfaces.md); the design is in
[secure agentic experiences](../plans/secure-agentic-experiences.md).

## 1. GitHub Copilot coding agent (cloud agent)

- Runs in an isolated cloud sandbox, an Actions job, or a user-managed remote
  environment; commands "can't read or change the files on your computer"
  ([cloud sandboxes](https://docs.github.com/en/copilot/concepts/security-governance-and-network-settings/about-cloud-sandboxes)).
- A firewall is on by default "to manage data exfiltration risks", but GitHub documents
  that it covers only processes started by the agent's Bash tool, not MCP servers or
  setup steps ([firewall](https://docs.github.com/en/copilot/how-tos/copilot-on-github/customize-copilot/customize-the-firewall)).
- Blast radius is bounded by identity: it pushes only to its own branch, cannot merge or
  approve, its PRs need an extra approval, and workflows on its pushes wait for a human
  ([risks and mitigations](https://docs.github.com/en/copilot/concepts/security-governance-and-network-settings/risks-and-mitigations)).
- Issue and comment text is treated as an injection vector; hidden characters and HTML
  comments are stripped before the agent sees it (same page).
- Once an MCP server is configured, its tools run "autonomously, and will not ask for your
  approval" ([MCP](https://docs.github.com/en/copilot/how-tos/copilot-on-github/customize-copilot/configure-mcp-servers)).
  The approval moves to configuration time.

## 2. GitHub Agentic Workflows (gh-aw)

Pinned to `github/gh-aw@16e90f3a95d398373fc8bdab69862d0c1524f1e1`.

- Three trust layers: substrate (runner, containers, firewall, API proxy, MCP gateway),
  configuration (what is loaded and which tokens go where), and plan (compiled per-stage
  permissions)
  ([architecture.mdx#L36-L67](https://github.com/github/gh-aw/blob/16e90f3a95d398373fc8bdab69862d0c1524f1e1/docs/src/content/docs/introduction/architecture.mdx#L36-L67)).
- **SafeOutputs** is "a primary instantiation of plan-level trust": the agent's writes are
  buffered as artifacts, filtered deterministically, then externalised by a separate job
  with the minimal permissions for each output type (same file #L67;
  [safe_outputs_permissions.go#L100-L230](https://github.com/github/gh-aw/blob/16e90f3a95d398373fc8bdab69862d0c1524f1e1/pkg/workflow/safe_outputs_permissions.go#L100-L230)).
  The agent job is read-only
  ([spec#L395-L400](https://github.com/github/gh-aw/blob/16e90f3a95d398373fc8bdab69862d0c1524f1e1/specs/security-architecture-spec.md#L395-L400)).
- A threat-detection job scans the buffered outputs before they are applied, with no write
  permission and no access to the agent's runtime
  ([spec#L784-L890](https://github.com/github/gh-aw/blob/16e90f3a95d398373fc8bdab69862d0c1524f1e1/specs/security-architecture-spec.md#L784-L890)).
- The agent's egress goes through a Squid proxy with a domain allowlist (AWF); MCP
  servers run in separate containers behind a gateway. gh-aw says the gateway agent ID is
  "not a strong security boundary … Treat this identifier as leaked by design"
  ([architecture.mdx#L306](https://github.com/github/gh-aw/blob/16e90f3a95d398373fc8bdab69862d0c1524f1e1/docs/src/content/docs/introduction/architecture.mdx#L306)).
- The spec separates injection through event context (sanitised on input) from injection
  through MCP tool responses (handled by output isolation and detection), i.e. tool output
  is not pre-sanitised.
- **Finding (not followed):** the spec's emergency-distrust section cites an incident URL
  on a host that does not belong to a known CA vendor. Reported as anomalous content.

## 3. Docker Sandboxes and the Docker MCP Gateway

- One microVM per sandbox; deny-by-default egress through a host proxy that injects
  credentials, so raw secrets never enter the guest
  ([isolation](https://docs.docker.com/ai/sandboxes/security/isolation/)). This is our
  `sbx` runtime; our broker replaces its proxy (ADR single broker).
- The MCP gateway runs each server in its own container. Secrets are scoped to the server
  that declares them, and `--block-secrets` scans tool arguments and responses
  ([security.md#L95-L112](https://github.com/docker/mcp-gateway/blob/7e0f34277c91855ad861eeff536b4fdc77420593/docs/security.md#L95-L112)).
  Interceptors can inspect, rewrite or block a call before or after it runs
  ([interceptors](https://github.com/docker/mcp-gateway/blob/7e0f34277c91855ad861eeff536b4fdc77420593/examples/interceptors/README.md#L16-L65)).

## 4. Editor and CLI agents

- **Cursor.** Sandboxing wraps terminal commands (Seatbelt on macOS, Landlock and seccomp
  on Linux); its auto-review classifier "is not a security boundary"
  ([run modes](https://cursor.com/docs/agent/security/run-modes),
  [blog](https://cursor.com/blog/agent-sandboxing)).
- **Windsurf / Devin desktop.** Only a deny, ask, allow command-permission model is
  documented; no OS isolation was found ([terminal](https://docs.devin.ai/desktop/terminal)).
- **Codex CLI.** Sandbox mode (read-only, workspace-write, full access) is a separate axis
  from approval policy; network is off by default
  ([approvals](https://learn.chatgpt.com/docs/agent-approvals-security)). Seatbelt on macOS,
  bubblewrap plus seccomp on Linux
  ([seatbelt.rs](https://github.com/openai/codex/blob/ee80baa38e3919061e0e0ad022aba1d9fbfc5dbc/codex-rs/sandboxing/src/seatbelt.rs#L57-L129)).
- **Claude Code.** The sandbox covers Bash only: "Claude's file tools, MCP servers, and
  hooks run outside it"; network is deny-by-default through a local proxy
  ([sandboxing](https://code.claude.com/docs/en/sandboxing)). Unattended use is pointed at
  devcontainers, with "it does not eliminate risk"
  ([environments](https://code.claude.com/docs/en/sandbox-environments)).
- **VS Code.** "Sandboxing is not a virtual machine or user-account boundary … A sandboxed
  process still runs on the execution host under your account", and network is allowed by
  default with sandboxing on
  ([agent sandboxing](https://code.visualstudio.com/docs/agents/run/agent-sandboxing)).
  1.138 introduced the agent host and AHP, and 1.139 ran agent sessions in dev containers
  on remote hosts ([1.138](https://code.visualstudio.com/updates/v1_138),
  [1.139](https://code.visualstudio.com/updates/v1_139)).

Every process-level sandbox above is an inner layer, and each documents what it does not
cover. None treats the editor UI as the thing to protect from the agent.

## 5. Prompt-injection design patterns

| Pattern | What it guarantees | Limit |
|---|---|---|
| Dual LLM ([Willison 2023](https://simonwillison.net/2023/Apr/25/dual-llm-pattern/)) | Untrusted text reaches the tool-calling model only as opaque references | Values can still steer arguments; the user can relay attacker text |
| Lethal trifecta ([Willison 2025](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)) | A test: private data + untrusted content + an external channel is exploitable | Diagnostic only; remove a leg |
| CaMeL ([arXiv:2503.18813](https://arxiv.org/abs/2503.18813)) | The privileged model writes the program; an interpreter tracks capabilities on every value and checks them before each tool call | Text-to-text harms (bad summaries, phishing) are out of scope; costs task success |
| Design patterns ([arXiv:2506.08837](https://arxiv.org/abs/2506.08837)) | Action-selector, plan-then-execute, map-reduce, dual LLM, code-then-execute, context minimisation: each trades generality for a guarantee | Plan-then-execute fixes which actions run, not their arguments |
| Spotlighting ([arXiv:2403.14720](https://arxiv.org/abs/2403.14720)) | Delimiting, datamarking or encoding untrusted text cut attack success sharply in tests | Heuristic, not a boundary |
| FIDES ([arXiv:2505.23643](https://arxiv.org/abs/2505.23643)) | Integrity and confidentiality labels propagate; a deterministic policy blocks consequential actions on tainted data | Experimental; host tools must still enforce their own controls |
| Instruction hierarchy ([arXiv:2404.13208](https://arxiv.org/abs/2404.13208)) | Training makes models prefer system over user over tool content | Probabilistic; layered under structural controls |

## 6. Capabilities for tools

- MCP `roots` are "informational guidance rather than an access-control mechanism"
  ([roots](https://modelcontextprotocol.io/specification/2025-06-18/client/roots)), and
  tool annotations are untrusted hints a client must not base decisions on
  ([schema.ts#L881-L922](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/3c4d91b7e832d9b74338d56eed03403ccc662123/schema/2025-06-18/schema.ts#L881-L922)).
- No standards-track object-capability model for LLM tools was found. The closest shipped
  analogue is the per-server container plus per-server secret plus interceptor model of
  the Docker MCP gateway.

## 7. What we take from it

1. **Run the loop away from the UI.** Every mature system puts the agent in a container,
   VM or runner and renders elsewhere. Upstream's agent host already splits the two.
2. **Name the isolation class.** Process sandboxes (Seatbelt, bubblewrap, Landlock) are not
   VM boundaries; say which one each tier relies on.
3. **The agent never holds the credential that makes a consequential write.** Copilot
   (separate tokens, own branch), gh-aw (SafeOutputs job) and Docker (proxy injection) all
   do this. Our broker sentinels and write-back gate are the same idea.
4. **Agent proposes, trusted code disposes.** SafeOutputs is the pattern for anything that
   affects the host: structured, schema-validated, applied by a separate privileged
   component, with per-output-type authority.
5. **Scope every control honestly.** GitHub's firewall skips MCP; gh-aw's gateway ID leaks by
   design. List what each of our controls does not cover.
6. **Tool output is untrusted input** in its own right, as gh-aw's threat model says.
7. **Do not build on MCP's self-description** (`roots`, annotations) for enforcement.
8. **Approval fatigue is real, and the industry answer is to move gates to configuration
   time and modulate by tier,** which concentrates risk in that one decision.
9. **Detection and model-level defences are defence in depth only.** Every primary source
   says so.
10. **Label provenance at ingestion and carry it to the policy check** (FIDES-style), rather
    than flattening context into one prompt.
11. **Remove a leg of the lethal trifecta per tier** instead of relying on detection.
