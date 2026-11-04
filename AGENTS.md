# AGENTS.md: seclab-vscode

Instructions for an agent picking this repo up cold. Keep this file current as
commands land. Every command here has actually been run; anything not built yet
is marked **TODO**. Don't invent commands.

## 1. Purpose
Browser-style containment for the VS Code editor: every workspace window is a
"tab" whose extensions, terminals, tasks, LSPs, git and MCP servers run in that
tab's own sandbox, so a rogue extension or malicious workspace is contained to
the tab. The UI is unchanged. Origin: [raw-idea.md](raw-idea.md). Current
design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Why it is shaped that
way: [docs/adr/](docs/adr/README.md).

## 2. Map
| Path | What |
|---|---|
| `upstream.lock` | **TODO (M0)**: pinned Code-OSS tag and SHA |
| `build/` | **TODO (M0)**: fetch, jq product.json, apply patches, Linux container build |
| `patches/` | **TODO (M0)**: ordered core patch queue (`NNNN-*.patch`); empty for M0/M1 |
| `.github/workflows/` | **TODO (M0)**: macOS arm64 unsigned app build; Linux CI |
| `extensions/seclab-tab-manager/` | **TODO (M1)**: built-in UI-side extension: `seclab+` resolver, routing, `SandboxProvider` (sbx primary, OCI second) |
| `broker/` | mitmproxy broker; owned by the broker session; see `broker/AGENTS.md` once it lands |
| `test/containment/` | **TODO (M1)**: rogue extension, malicious-workspace fixtures, assertions |
| `docs/adr/`, `docs/edr/` | Architecture and engineering decision records ([ADR README](docs/adr/README.md), [EDR README](docs/edr/README.md)) |
| `docs/security-reviews/` | Security review rounds and process ([README](docs/security-reviews/README.md)) |
| `docs/research/` | Cited research behind the design (pinned permalinks) |
| `.work/` | Gitignored scratch (spikes). Durable, unlike `/tmp` |

Nested AGENTS.md files (owned by their sessions): `broker/AGENTS.md`
(broker), plus any the RPC-lockdown session adds. Keep them consistent with
this file.

**Trust boundaries:**
1. **Trusted host editor**: Electron main, workbench, and the local extension
   host (first-party only: Tab Manager, auth providers). Native macOS app.
2. **Tab sandbox**: an sbx microVM per tab (OCI pod in CI/Linux) running the
   REH and all workspace-kind extensions. Only the workspace is mounted.
3. **Broker**: our mitmproxy per tab. The only egress; it swaps sentinels for
   real credentials and raises prompts.
4. **sbx fence**: per-tab sbx policy allowing only that tab's broker
   `localhost:P`; mirrors and verifies denies for every global allow, and
   fails closed.
5. **RPC filter**: default-deny filter on REH→UI `MainThread*` calls (M4,
   proposed).

## 3. Hard rules (non-negotiable)
- **Never install tooling on the macOS host.** docker, gh and sbx are allowed;
  anything else needs the user's approval. Why: host hygiene is the user's
  explicit constraint. Builds run in containers or on Actions.
- **Never use `/tmp` for anything that matters; commit early.** Why: sessions
  are long-lived and `/tmp` is pruned mid-session. Use `.work/` or named
  volumes.
- **Stage only the files that belong to the commit.** Never `git add -A` or
  `git add .`. Why: several branches and worktrees are worked in parallel.
- **No real credentials in the repo, logs or fixtures.** Why: the repo is on
  GitHub, and fixtures are read by rogue-extension tests. Use sentinels.
- **Probes and escape tests run only against our own local builds and
  sandboxes.** Why: no testing against third-party systems.
- **Base claims on code, with permalinks pinned to a SHA.** Why: upstream
  moves; unpinned claims rot.
- **Keep core patches minimal: one concern per patch, under about 50 lines.**
  Why: the cost of upstream bumps is the project's lifeline.
- **Don't use Microsoft's proprietary VS Code Server or Remote extensions.**
  Why: their licence is restricted to Microsoft builds. Build the REH from
  pinned Code-OSS.
- **Stop and ask when a constraint leads to bad design**, rather than
  working around it. Why: the user prefers to revise constraints (see the
  native-editor ADR).
- **Never change sbx's global policy** without the user's consent. Why: it is
  shared with their other sandboxes.

## 4. Common tasks
Verified commands:
```sh
# sbx: version, daemon, sandboxes, effective policy (JSON), denial log
sbx version
sbx daemon status
sbx ls
sbx policy ls --wide --json
sbx policy log <sandbox>

# per-tab fence primitives (the resource must be localhost:P, not host.docker.internal:P)
sbx policy allow network --sandbox <tab> localhost:<port>
sbx policy deny  network --sandbox <tab> <resource>
sbx policy rm    network --force --sandbox <tab> --resource <resource>

# exec stdio (the REH transport primitive); binary-safe
sbx exec -i <tab> cat < file > copy
```
**TODO**, not built yet:
- Build Linux (editor + REH) in containers.
- Trigger the macOS build on Actions and fetch it with `gh run download`, then
  clear quarantine (needs user approval).
- Run the editor.
- Run the containment suite (sbx locally; OCI in CI).
- Run the broker tests (see `broker/AGENTS.md`).
- Regenerate the RPC inventory and drift check (RPC-lockdown session).
- Bump upstream: update `upstream.lock` → re-run jq → rebase `patches/` →
  drift check → containment suite → security review → write an EDR.

## 5. Process
- **ADR or EDR?** An ADR records the shape of the system (boundaries,
  components, runtimes, trust, protocols). An EDR records how we build it
  (tooling, CI, libraries, tests, spike results). Name files
  `YYYYMMDD-short-slug.md`. Records are append-only: supersede, don't edit,
  and link both ways. Any deviation from ARCHITECTURE.md needs an ADR.
- **Security review loop** ([process](docs/security-reviews/README.md)):
  required for new components or boundaries, `patches/` changes, product.json
  policy changes, provider, fence or transport changes, CI and workflow
  changes, and each milestone. Use the `security-review` agent; if it refuses,
  re-run it with `cvp-claude-opus-5`. Triage every finding, re-review until no
  high or critical issues remain, and add a regression test for each real
  finding.
- **Definition of done for a change:**
  - tests pass;
  - a review round is recorded (if required);
  - ADRs and EDRs are written or updated;
  - ARCHITECTURE.md is updated if the current state changed;
  - this file is updated if commands changed.

## 6. Gotchas learned so far
- **sbx policy layers:** a global `local-policy` (on this host "balanced",
  187 allows) applies to every sandbox. Per-sandbox rules stack on top, and
  **deny beats allow**, so you can't "deny `**` then allow the broker". Mirror
  global allows as per-tab denies instead
  ([EDR](docs/edr/20261104-sbx-fence-spike.md)).
- **sbx normalises `host.docker.internal:P` to `localhost:P`** in policy.
  Rules must name `localhost:P`.
- **sbx injects lowercase `http_proxy`/`https_proxy`**, and curl prefers
  lowercase. Override both cases.
- **`curl --noproxy "*"` also disables `-x` and `--socks5-hostname`.** Unset
  the env proxies instead.
- **sbx mounts host paths at the same absolute path** inside the sandbox, so
  folders opened in the editor must be real host paths.
- **sbx secrets bind to a host only** (0.39 and 0.51, `--host`). There is no
  method or path binding locally, hence our broker is the engine. 0.51 adds
  HTTP method and path network rules and `policy approval`; whether approval
  holds a flow is untested.
- **Inside the sbx `shell` kit** the user `agent` has sudo and an inner
  docker.sock (VM-local). The VM is the boundary.
- **`sbx policy profile` is remote-governance only**; you can't define one
  locally.
- **Hosted Actions runners have no nested virtualisation**, so the sbx suite
  runs locally and CI runs the OCI suite.
- **Workspace Trust is not a boundary** (ADR). Tests run with the workspace
  trusted, the worst case.
- **The `extensionKind` product.json map has no wildcard**, so overrides are
  per extension ID.

## 7. Where to look first when something breaks
- A tab won't connect: the Tab Manager output channel (TODO: name), then
  `sbx ls`, then `sbx policy log <tab>` (fence denials show the normalised
  resource and the reason).
- Egress fails inside a tab: `sbx policy log <tab>`, and `env | grep -i proxy`
  inside the tab (both cases must point at the broker).
- A record seems contradicted: check for a superseding ADR or EDR before
  trusting an older one.
