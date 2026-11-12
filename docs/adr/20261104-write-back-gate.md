# Write-back gate: tab writes reach the host checkout only through tabd, code-running files only with approval

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** Project owner (2026-11-04): watch and warn; the supervisor flags any change a tab makes to files that run code (git hooks and config, `.vscode/*`, `.envrc`, `package.json` scripts, Makefile and similar), shows the diff, and requires approval before that file goes live in the real checkout. Go-ahead on the fuse-overlayfs design, with the coordinator's hard requirements (below).
- **Related:** [EDR write-back gate spike](../edr/20261104-write-back-gate-spike.md), [threat model, worked example step 8](20261104-threat-model-rogue-extension.md), [ADR defeat folder-open loaders](20261104-defeat-folder-open-loaders.md)
- **Editorial redaction (2026-11-12):** quotations of project conversations replaced with neutral statements; decisions unchanged.

## Context
The tab mounts the workspace read-write. Code in the tab can therefore plant
host-executed code in the user's real checkout: git hooks or `core.fsmonitor`,
`.envrc`, `package.json` scripts, `Makefile`, `.vscode/tasks.json`. That code runs
the next time the user uses git, direnv, npm or make **on the host**. Planting it is
also how the Contagious-Interview campaign spreads. Unapproved content must
**never** be live in the host checkout, not even briefly; detect-and-revert is only
a documented fallback.

## Decision
### 1. The tab never writes the host checkout directly
- **sbx:** as root, before the REH starts, a `fuse-overlayfs` mount is laid over
  the workspace's absolute path inside the VM:
  - lower: the host workspace, mounted read-only (a second sbx workspace with
    `:ro`);
  - upper: VM-private disk;
  - `uidmapping`/`gidmapping` map uid 0 to the tab user. virtiofs presents host
    files as uid 0, and kernel overlay and idmapped mounts don't work there (spike).
  
  The sbx primary workspace, which must be read-write, is an empty per-tab
  scratch directory that nothing on the host reads. The mount happens in the same
  pre-REH root slot as the observability collector, in a fixed order: mount, then
  collector, then REH.
- **OCI (native Linux):** a Docker `local` volume of type overlay (lower = the
  host workspace, upper and work = a per-tab volume) mounted at the workspace path.
- **OCI on Docker Desktop:** no gate (ownership, per the spike). The driver
  capability descriptor says `writeBack: "ungated"`, and the editor shows
  "write-back not gated" for such tabs.

> **As built (increment 2a, 2026-11-05;** [spike addendum](../edr/20261104-write-back-gate-spike.md)**):**
> the overlay sits over the primary (read-write) workspace path itself, with that
> same path as its lower layer. No second `:ro` mount or scratch primary is needed:
> fuse-overlayfs opens the lower layer before mounting over it, and the tab can no
> longer reach the path underneath. Ownership uses `squash_to_uid`/`squash_to_gid`
> (the tab user), and `timeout=0` makes host-side changes show through. The root-only
> helper `/opt/seclab/bin/seclab-wb-mount` mounts it; `seclab-obs-collect` calls it
> before it starts the REH, and fails closed. The helper refuses if any non-root
> process already has its cwd or root inside the workspace. Only `fuse-overlayfs`
> and `libfuse3-4` are installed: no `fuse3`, so there is no setuid `fusermount3`.
> Never change the upper layer's directory structure while it is mounted; that is
> unsafe (spike).

### 2. tabd's write-back engine is the only writer of tab changes to the host
It reads the tab's upper layer (through the driver, as root in the tab) and
classifies each change:
- **auto:** copied back promptly; ordinary source files.
- **held:** listed for approval, never copied until approved.
- **tab-local:** never copied back and never offered for approval. These are
  generated or installed artifacts the host regenerates from held sources:
  `**/__pycache__/**`, `*.pyc`/`*.pyo` and `**/node_modules/**`. Bytecode runs with
  no visible source change, and installed trees are gitignored, so no review would
  see an edit (review Y-2/Y-3). More generally, any new or changed file that the
  **host's** git ignores is tab-local, unless the policy holds it (then the prompt
  shows it): ignored means invisible to `git status`, so nothing could review it
  (review Z-1). This is checked with a read-only, hardened `git check-ignore
  --no-index` on the host (`tabd/src/gitignore.ts`). A workspace that is a
  subfolder of a host repo is checked against the parent's rules; when the root
  has its own `.git`, git is pinned to it (no discovery), and a `HEAD` that isn't
  a ref or hash is held (review AA-1). If the check fails, the change is held.
  Refused paths are listed with their reason, so a dropped edit is visible.
  `.gitignore` itself is held, because it decides what review can see.
- **Native code modules** (`*.so*`, `*.dylib`, `*.bundle`, `*.node`, `*.pyd`,
  `*.dll`, `*.exe`) that aren't ignored are held, structurally. Python's import
  system finds `foo.cpython-312-darwin.so` before `foo.py`, and dlopen needs no
  exec bit.
- **Depth:** every held, tab-local and never-Always pattern matches at any
  directory depth. Agents, editors and build tools started in a monorepo
  subdirectory read that directory's `.github/hooks`, `.claude/`, `Makefile` and
  so on (review Z-2).

**Default-hold where code-running config lives:**
- **Under `.git/`:** only `objects/`, `refs/`, `packed-refs`, `index`, `HEAD`,
  `logs/`, `FETCH_HEAD` and `ORIG_HEAD` are auto. Everything else is held,
  including `config`, `hooks/`, `info/`, `modules/*/config` and `worktrees/`.
- **The reviewed list,** in `tabd/src/writeback-policy.ts` (data, not logic; a
  change needs a review round):
  - `.vscode/**`, `*.code-workspace`, `.devcontainer/**`;
  - `.envrc`, `.env*`, `.tool-versions`, `.npmrc`, `.yarnrc*`, `.pnpmfile.cjs`;
  - `package.json` (held when `scripts`, `bin` or other run keys change, or when
    any dependency is added or changed), npm-family lockfiles, `Makefile`,
    `justfile`, `*.sh`;
  - `pyproject.toml`, `setup.py`, `conftest.py`, `.pre-commit-config.yaml`,
    `.venv/**`, `site-packages/**`, `*.pth`;
  - `gradlew`, `mvnw`, `build.gradle*`, `Cargo.toml`, `build.rs`, and other
    build definitions (CMake, Bazel, MSBuild, Maven, CI configs);
  - vendored trees: `vendor/**`, `.bundle/**`, `.gradle/**`;
  - all of `.github/**` (workflows, actions, and Copilot hooks, skills,
    instructions and agents), `.gitattributes`, `.gitmodules`;
  - other coding agents' instructions and config (`AGENTS.md`, `CLAUDE.md`,
    `.claude/**`, `.mcp.json`, `.cursor/**`, `.agents/**` and similar) and IDE
    project config (`.idea/**`, `.zed/**` and similar);
  - hook managers: `.husky/**`, `lefthook.yml`, `.lefthook/**`, `.githooks/**`;
  - anything under the **host's** current `core.hooksPath`, and any workspace
    file the host's git config includes (followed recursively, bounded).
- **Held regardless of path:**
  - a newly set executable bit;
  - symlinks and hardlinks;
  - special files;
  - any path whose name equals a held path after case folding and Unicode NFC
    or NFD normalisation (`.Git/hooks`, `.VSCODE/`), because APFS is
    case-insensitive and normalising.
- **Deletions:** deleting a held file is a held change. Deleting an auto file is
  auto.

### 3. The engine is a trusted writer handling hostile input
- **Destination:** resolved relative to the workspace root that tabd pinned at
  claim (dev and inode re-checked). Every component is opened or `lstat`ed
  without following symlinks; a symlink or non-directory anywhere in the path is
  refused. `..`, absolute paths, NUL bytes, and anything resolving outside the
  root are rejected.
- **Writes:** atomic, via an exclusively created temp file in the same directory,
  `fsync`, then rename. Modes are limited to 0644/0755, and an exec bit is only
  ever set by approval.
- **Caps:** per-file size, per-sync file and byte count, and a rate limit. Going
  over a cap holds the rest, so nothing is dropped silently.
- **Content:** never executed and never parsed, except to compute the displayed
  diff and the `package.json` `scripts`/`bin` comparison. That comparison is done
  by a size-capped JSON parse; a parse failure means held. The display is escaped
  (`safeText`).
- **Why per-component `lstat` and `O_NOFOLLOW` are equivalent to `openat` here:**
  the attacker controls only the tab's upper-layer content, never the host
  directories, which only the user and this engine write. A pre-existing symlink
  in the host checkout is caught by the per-component check. A race on host
  directories would need a host-side attacker, who is out of scope.

### 4. Conflicts and deletes
The engine keeps, per path, the host file's identity and hash as the tab last saw
it, meaning when it was copied back or when the lower layer was read. If the
host file has changed since, the change is a **conflict**: held, shown with both
sides, never silently overwritten.

### 5. Fail closed
Held changes live only in the tab's upper layer and in tabd's state (a list of
paths and hashes). If the overlay, the engine or tabd crashes, nothing held
reaches the host. On restart, the pending list is rebuilt from the upper layer
and **shown again**, never auto-applied. If the overlay isn't mounted, the tab
doesn't start (sbx and native OCI).

### 6. Prompt
The trusted Tab Manager UI shows:
- "Tab *X* changed *N* file(s) that run code";
- per file: path, kind (new, modified, deleted, mode, link, conflict), and an
  escaped diff, capped;
- the choices **Approve**, **Reject (keep the original)** and **Always allow for
  this tab and path**.

Approve copies the file to the host. Reject restores the host version into the
tab's view by writing it through the merged mount, so the next sync sees no
difference. "Always" records a per-tab, per-path rule in tabd state, never in
the workspace. It is never offered for git metadata, hooks, host-executable
files, or agent and IDE config, and it never waives a manifest's script or
dependency holds, only plain content changes. Decisions are emitted to
observability as trusted events.

### 7. Fallback (documented, not default)
Drivers without the overlay (OCI on Docker Desktop) mount the workspace
read-write as today, and the UI says "write-back not gated". Detect-and-revert
(host file events on held paths, restored from a shadow copy) has a race window
and is not implemented as protection.

## Consequences
- Ordinary edits reach the host after a short sync delay, not instantly. Host
  tools see a tab's edits once they are synced.
- Host-side changes may not raise file events inside the tab. This needs
  measuring with fuse-overlayfs; the fallback is polling.
- The engine is new code on the trust boundary, so it gets a security-review round
  per increment and is covered by the Contagious-Interview test: planted
  `.git/hooks/pre-commit` and `.envrc` must never appear in the host checkout.
- Increments:
  1. engine and policy (unit-tested against a hostile upper layer);
  2. sbx overlay (2a, built: tab writes stay in the VM) and sync (2b, built);
  3. Tab Manager prompt (built);
  4. OCI on native Linux.

> **As built (increment 3):** when tabd holds changes, the Tab Manager warns once
> ("This tab changed N file(s) that can run code on your machine…") and shows a status
> bar count. "seclab: Review Held Changes…" lists them as plain text: escaped paths and
> reasons, with codicon syntax neutralised. For the selected change it opens a read-only
> diff (your machine ↔ tab) in virtual documents, never a webview, then a modal with
> **Approve**, **Reject (keep the original)** and **Always allow for this tab and path**.
> - The decision carries the signature of what was shown, and tabd re-reads the tab's
>   entry and refuses if it changed.
> - Reject restores the host's version into the tab when the host has the file; otherwise
>   the tab keeps its own copy, marked decided.
> - "seclab: Confirm Held Deletions…" releases the sticky mass-deletion hold.
> - Tabs whose runtime can't gate writes show "Write-back not gated" in the status bar.

> **As built (increment 2b):** tabd syncs each running gated tab every 3 s, and again
> before it stops. A root helper in the VM, `seclab-wb-feed`, reads the upper layer
> directly and never through the overlay: it lists entries with their sha256, fetches
> the content of changed files, and mirrors host edits in place (compare-and-swap).
> - Directories aren't synced on their own; files carry their parents.
> - `.wh.<name>` is a deletion. An opaque directory expands, against the host, into
>   per-file deletions, which are subject to the engine's limits.
> - The engine remembers each entry's signature once it has been applied or decided, so
>   applied files are not re-applied.
> - A host edit to a synced file that the tab hasn't touched is mirrored into the upper
>   copy. A host deletion of such a file isn't reflected until the next tab start.
> - The root `.git` auto set applies only into an existing host repository. A tab can't
>   turn a plain host folder into a repo.
> - A workspace that an enclosing repo ignores is treated as outside that repo.
> - Protocol: `tab.writeback.status` and `tab.writeback.sync`. Decisions on held changes
>   come with increment 3.
> - The mass-deletion brake guards against accidents (an `rm -rf`, a bad script), not
>   against deliberate destruction. A hostile tab can already overwrite every ordinary
>   file it may modify, and the brake can't stop that. What protects the user from such
>   a tab is everything else here: code-running files are held, and nothing the tab
>   writes runs on the host unasked. Git history protects tracked content.
