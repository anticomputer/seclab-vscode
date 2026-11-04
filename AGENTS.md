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
| `upstream.lock` | Pinned Code-OSS tag and SHA (1.145.0 @ a717861c) |
| `build/` | `fetch-upstream.sh` (verifies tag→SHA), `prepare.sh` (overlay, jq product.json, patches), `product/` (overrides.json, product.jq with invariants, remove-extensions.txt), `linux/` (builder image + build.sh), `build-darwin.sh` (Actions only) |
| `patches/` | Ordered core patch queue (`NNNN-*.patch`): 0001 build-only, 0002/0003 extension placement |
| `.github/workflows/` | `build-macos.yml` (unsigned darwin-arm64 app), `ci-linux.yml` (unit, REH, OCI e2e/containment/canary/secrets) |
| `extensions/seclab-tab-manager/` | Built-in UI-side extension: `seclab+` resolver, routing, UI. `tabd-src` symlinks `tabd/src` and is bundled in |
| `tabd/` | `seclab-tabd` supervisor: protocol, validation, sbx and OCI drivers, fence. Tests in `tabd/test/`. Spec: `docs/tabd/PROTOCOL.md` |
| `sandbox/` | In-tab scripts (`rootfs/opt/seclab/bin`), the sbx template builder, OCI images |
| `broker/` | mitmproxy broker; owned by the broker session; see `broker/AGENTS.md` once it lands |
| `test/containment/` | Malicious-workspace fixtures, the rogue extension, level A runner and level B (editor) evidence check |
| `test/canary/` | Shared canary harness (headline acceptance test); other sessions plug in stores and observation sources |
| `docs/adr/`, `docs/edr/` | Architecture and engineering decision records ([ADR README](docs/adr/README.md), [EDR README](docs/edr/README.md)) |
| `docs/security-reviews/` | Security review rounds and process ([README](docs/security-reviews/README.md)) |
| `docs/research/` | Cited research behind the design (pinned permalinks) |
| `.work/` | Gitignored scratch and build outputs (`.work/out`). Durable, unlike `/tmp` |

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
- **Push to origin on every major iteration:** a milestone or sub-milestone
  working end to end, a new component or protocol, a patch-queue change, or a
  fixed review round. Each push needs its review recorded, the relevant tests
  passing, and the records updated. Fast-forward reviewed, coherent increments
  to `main`; `main` always builds and passes. Never force-push `main`. Why:
  the user asked for it, and other sessions build on `main`.
- **Fixture canaries must be obviously fake** (`seclabcanary_…`, no real token
  prefixes), and staged changes are checked with gitleaks before a push. Why:
  GitHub push protection, and no real-looking secrets in history.

## 4. Common tasks
Verified commands (one entry point: `./seclab help`):
```sh
./seclab build linux            # REH (linux-<arch>) in the trixie builder container -> .work/out/  (~10 min warm)
./seclab template sbx           # sbx tab template seclab-tab:local (shell kit + REH + /opt/seclab), ~20 s
./seclab image oci              # OCI images seclab-tab-oci:local + seclab-broker-placeholder:local
./seclab test unit              # tabd unit + supervisor tests (node container)
./seclab test e2e sbx           # tabd end to end: claim -> fence -> REH 101 handshake over exec stdio (also: oci)
./seclab test containment sbx   # malicious-workspace vectors in real tabs (sbx 89/89, oci 86/86)
./seclab test canary sbx        # canary acceptance test, level A (also: oci)
./seclab test secrets sbx       # pre-mount gitleaks gate: block, move-to-vault + sentinel, restore, accept (also: oci)
./seclab test evidence prepare .work/editor-test/user-data sbx   # level B setup (then open the printed --folder-uri)

# sbx inspection
sbx ls; sbx policy ls --wide --json; sbx policy log <sandbox>; sbx secret ls --json
sbx policy check network --sandbox <tab> --json <host:port>    # exits 1 when denied; JSON on stdout
```
Tests run on the host use the already-present `node` (or set `SECLAB_NODE` to the editor's
Electron with `ELECTRON_RUN_AS_NODE=1`); nothing is installed.

**TODO** (written but not yet run end to end):
- `./seclab build linux editor` needs at least 12 GB of Docker memory (esbuild is OOM-killed at 8 GB).
- macOS app: `gh workflow run build-macos.yml --ref <branch>`, then
  `SECLAB_ALLOW_UNREVIEWED_BUILD=1 ./seclab fetch macos` for branch builds
  (main/push builds need no override). Then clear quarantine, with the user's
  approval.
- `./seclab test evidence check .work/editor-test/user-data`, after the editor ran the prepared tab.
- Broker tests (see `broker/AGENTS.md`), and the RPC inventory and drift check (RPC-lockdown session).
- **Bump upstream:**
  1. Edit `upstream.lock` (tag + SHA from `git ls-remote`).
  2. `./seclab build linux`, which re-runs fetch, jq and patches; fix any patch that fails to apply.
  3. Drift check.
  4. `./seclab template sbx && ./seclab image oci`.
  5. Containment + canary suites (sbx and oci).
  6. Security review.
  7. Write an EDR.

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
  re-run it with an Opus-class model. Triage every finding, re-review until no
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
- **The `extensionKind` product.json map has no wildcard upstream**; patch 0002
  adds `*` (built-in-only explicit entries). Patch 0003 stops local windows
  running anything but `ui` built-ins. Upstream runs `workspace`-kind
  extensions locally when there is no remote.
- **Local windows**: the Tab Manager closes any local folder window *before*
  asking anything. Never open a hostile fixture by local path; use
  `--folder-uri vscode-remote://seclab+<tabId><path>`.
- **sbx `browser.enabled` defaults true** (a sandbox can open URLs in the host
  browser). It is a global setting; we haven't changed it (it needs the
  user's consent).
- **Docker Desktop VM has 8 GB.** The Linux *editor* bundle OOMs; the REH is fine.
- **1.145.0 local builds fail in the Copilot shim**; we remove the built-in
  Copilot extension (patch 0001, EDR).
- **The Electron 43 headers need gcc ≥ 13**, so the builder is trixie, not bookworm.
- **sbx sandboxes stop when the supervisor exits** (by design, fail closed),
  and the REH must be restarted via `ensureRunning`.
- **`sbx policy check` exits 1 on deny**, so parse stdout, not the exit code.
- **Node type stripping**: no parameter properties or enums in `tabd/`
  (`node --test` runs the `.ts` directly).
- **Docker Desktop (macOS) bind mounts:**
  - files appear owned by the accessing uid;
  - `access(2)` can report a path as readable while `open`/`stat` fail with
    ENOENT;
  - inode numbers aren't stable;
  - the mount is case-insensitive.
  
  So test real reads, and keep (dev, ino)-checked scratch on named volumes.
  A native Linux engine is different: the tab and scanner run as the
  workspace owner ([EDR](docs/edr/20261104-oci-tab-user-on-linux.md)).
- **gitleaks always loads `<source>/.gitleaksignore`** and skips the file at
  its config path. Its default allowlist applies to *resolved* symlink paths,
  can't be removed via `[extend]` (allowlists append), and `--log-level
  error` hides permission skips. It silently skips files (and `stdin`
  streams) whose first chunk has an `application/*` magic, and it colours
  its logs even off a TTY (use `--no-color`). Hence the framed scanner script
  in `tabd/src/scan.ts`
  ([ADR](docs/adr/20261104-pre-mount-secret-scan.md)).
- **Secret-finding ids must be deterministic** across rescans, because
  `acceptFindings` must match on the re-gate. gitleaks reports concurrently,
  so sort.

## 7. Where to look first when something breaks
- A tab won't connect: the "seclab Tab Manager" output channel, then
  `<state>/audit.log`, where state is
  `<userData>/User/globalStorage/seclab.tab-manager/tabd`. Then `sbx ls`, then
  `sbx policy log <tab>` (fence denials show the normalised resource and the
  reason). Inside the tab, the REH log is `/run/user/1000/seclab/reh.log`.
- Egress fails inside a tab: `sbx policy log <tab>`, and `env | grep -i proxy`
  inside the tab (both cases must point at the broker).
- A record seems contradicted: check for a superseding ADR or EDR before
  trusting an older one.
