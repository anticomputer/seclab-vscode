# Security review: write-back gate, increment 1 (engine and policy)

- **Date:** 2026-11-04
- **Scope:**
  - `tabd/src/writeback.ts`: the engine (classification, trusted host writer, conflicts, fail-closed state);
  - `tabd/src/writeback-policy.ts`: the reviewed policy data;
  - `tabd/src/gitignore.ts`: the host ignore probe;
  - `tabd/test/writeback.test.ts`: the regression tests.
- **Threat:** a hostile tab controls every name, mode, link target and byte in its overlay upper layer. It wants a file on the host checkout that runs code when the user next uses git, an editor, an agent or a build tool there, without the user seeing it.
- **Decision records:** [ADR write-back-gate](../adr/20261104-write-back-gate.md), [EDR write-back-gate-spike](../edr/20261104-write-back-gate-spike.md).
- **Reviewer:** `security-review` agent.
- **Not yet in scope:** the sbx overlay mount and change feed, the Tab Manager prompt, and OCI wiring (increments 2–4, each with its own round).

## Round 1
| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| W-1 | **High** | Git metadata | A nested `.git`, a gitfile, a gitdir under another name, or a gitlink index entry got past the root-only `.git` rules. | Fixed | Any folded `.git` segment is held except the exact root auto set; disguised gitdirs (`HEAD`, `commondir`, `config` beside a `HEAD`, `gitdir:` content) are held; `.git/index` is auto only if it parses as v2/v3 with no gitlink. |
| W-2 | **High** | Code that runs unasked | Content of host-executable files, virtualenvs, `*.pth`, config-as-code (`*.config.js` and similar), and includes of the host's git config were auto. | Fixed | A host exec bit holds content changes; held list extended; files the host's git config includes are held. |
| W-3 | **High** | Approval binding | Approval was bound to content only, so the tab could swap mode or link target after the prompt. | Fixed | `sig` binds kind, mode, link target, content and link count; approval re-checks it and refuses new structural reasons. |
| W-4 | Medium | Conflicts and case | A host edit after the tab started could be overwritten; names that collide on APFS were applied. | Fixed | A baseline seeded by a stat walk, keyed by folded path; colliding names are held. |
| W-5 | Medium | "Always" | Could be granted for git metadata, hooks and host-executable files. | Fixed | Refused for those. |
| W-6 | Medium | Mass delete | No limit on deletes per sync. | Fixed | Over 100 deletes in a sync are held. |
| W-7 | Low | Git deletes, invisible names | Git metadata deletes were auto; default-ignorable code points in names. | Fixed | Held. |
| W-8 | Low | Root git set | `objects/info/alternates` matched the auto set. | Fixed | Exact names; object files must match the loose or pack name pattern. |
| W-9 | Low | Worktrees | A gitfile checkout skipped the host config checks. | Fixed | The real gitdir's and commondir's configs are read. |
| W-10 | Low | Writer race | A host tool swapping a directory for a link mid-write. | Accepted | Out of scope (host-side attacker); narrowed by re-verifying the temp file's directory. |
| W-11 | Low | Manifests | Duplicate keys in `package.json` (`JSON.parse` takes the last one; others may take the first). | Fixed | Held. |

## Round 2
W-1 to W-11 verified.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| X-1 | **High** | Agent config | Instructions, settings hooks and MCP config for host-side coding agents were auto. | Fixed | Held; "Always" never offered. |
| X-2 | Medium | Dependencies | A new or changed dependency, or a lockfile `resolved` URL, runs install scripts on the host's next install. | Fixed | Held; the prompt names the packages. |
| X-3 | Medium | Build and IDE files | Maven, CMake, Bazel, MSBuild, CI and IDE project files were auto. | Fixed | Held. |
| X-4 | Low | Git includes | Relative includes, and includes from a gitfile checkout's real gitdir, were missed. | Fixed | Resolved against the config's directory. |
| X-5 | Low | Mass delete | The per-sync limit could be split across syncs. | Fixed | A rolling window of 200 per 10 minutes (in memory). |

## Round 3
X-1 partly fixed; X-2 to X-5 fixed.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| Y-1 | **High** | Copilot hooks and skills | `.github/hooks/*.json` and `.github/skills/**` run commands in Copilot sessions on the host. | Fixed | All of `.github/**` held, plus other agents' files; one list feeds both `held` and `neverAlways`. |
| Y-2 | **High** | Bytecode | A forged `__pycache__/*.pyc` runs on the next import, with no visible source change. | Fixed | New tab-local category: never written back. |
| Y-3 | Medium | Installed trees | `node_modules`, `vendor`, `.bundle` and `.gradle` were auto and gitignored. | Fixed | `node_modules` tab-local; the rest held. |
| Y-4 | Low | Dependencies | A non-object dependency section wasn't held. | Fixed | Held. |
| Y-5 | Low | Git config parser | Same-line keys, continuations, case-sensitive root, non-recursive includes. | Fixed | `parseGitConfig`; bounded recursive includes; folded prefix compare. |
| Y-6 | Low | "Always" | Lists drifted; "Always" on a manifest waived the scripts and dependency holds. | Fixed | Derived list; "Always" waives only the plain path reason. |

## Round 4
Y-1 to Y-6 verified; no engine regressions.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| Z-1 | **High** | Native modules, ignored output | `foo.cpython-312-darwin.so` loads before `foo.py`; any gitignored output is invisible to review. | Fixed | Native modules held (structural). Files the host's git ignores are tab-local, via a hardened read-only `git check-ignore`; unknown means held; `.gitignore` held. |
| Z-2 | Medium | Depth | Patterns were root-only; agents and tools start in monorepo subdirectories. | Fixed | Every pattern matches at any depth. |
| Z-3 | Low | Git config parser | Comment continuation, backslash parity, escapes, malformed headers. | Fixed | Fixed in the parser. |

## Round 5
Z-1 to Z-3 verified; the probe can't inject (fixed argv, no shell, `./` prefix, scrubbed env).

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| AA-1 | Medium | Ignore probe | A workspace inside a host repo short-circuited to "nothing ignored". | Fixed | Upward discovery; "not a repository" means empty only without a root `.git`; with one, `GIT_DIR` is pinned and errors hold; a `HEAD` that isn't a ref or hash is held. |
| AA-2 | Low | Ignore probe | Results were matched by string, so git's spelling could differ (macOS precompose). | Fixed | `--verbose --non-matching`, matched by position. |
| AA-3 | Low | Git config parser | An inline comment ending in `\` continued. | Fixed | Comments are stripped before the continuation check. |
| note | Info | Ignore probe | Force-added tracked files that match an ignore pattern are tab-local. | Accepted | Fails safe; refused paths carry a reason for the prompt (increment 3). |

## Round 6
AA-1 to AA-3 and the workflow change's B-1 verified. **Nothing medium or higher remains.**

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| BB-1 | Low | Git config | For a subfolder workspace, the enclosing repo's `hooksPath` and includes pointing into it weren't read. | Fixed | `hostConfigs()` walks up to the nearest enclosing checkout (read-only); a relative `hooksPath` resolves against that checkout's root. |
| BB-2 | Low | Ignore probe | A localised git's "not a git repository" didn't match, so non-git folders held everything. | Fixed | `LC_ALL=C`, `LANGUAGE=` for the probe. |
| BB-3 | Low | Git config parser | Quote state isn't carried across continuation lines. | Accepted | Needs host-owned config written that way; the failure mode is a missed include, which the exec-bit and held lists still bound. |

## Workflow change: RPC filter CI jobs (commit 4306096)
Reviewed under the workflow-review rule. Permissions are `contents: read` with `persist-credentials: false`; no `${{ }}` in `run:`; every tool container runs with `--network none`; pins are unchanged digests. B-1 (low: `git diff` misses untracked inventory files) is fixed with a `git status --porcelain` check. No medium or higher.

## Increment 2a: sbx overlay (b9ba0e2 and fixes)
Threat: tab code (agent uid in the VM, owns /dev/fuse) writes the host checkout around the overlay,
or gains root in the VM (a gate bypass since 2a).

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| JJ-1 | **Critical** | Process cwd | `sbx exec` starts the collector with cwd = the workspace path, before the mount; the REH, extension host and ptyHost inherited it, so relative writes and `/proc/<pid>/cwd/…` reached the host checkout. Reproduced by the new regression (negative control on the 2a template). | Fixed | Collector launched with `-w /` and `chdir("/")`; REH spawned with cwd = the workspace resolved after the mount; `seclab-wb-mount` checks after mounting (and on every call) that no process but the overlay holds a cwd, root, fd, mapping or per-thread cwd/root on the host share's device, and fails closed. Containment regression writes through every agent process's cwd. |
| JJ-2 | **Medium** | Namespaces | Tab code could create user and mount namespaces (the way into kernel LPEs; root in the VM now bypasses the gate). | Fixed | seclab-obs-guard: `unshare`/`clone` with `CLONE_NEWUSER`/`CLONE_NEWNS` → EPERM. Regression (with a control). |
| JJ-3 | Low | Pre-mount scan | Non-dumpable processes, fds, per-thread cwds, TOCTOU. | Fixed | Replaced by JJ-1's post-mount device check. |
| JJ-4 | Low | Fail-open | A missing helper skipped the mount; `writeBack` is static. | Fixed (helper); accepted (static capability) | Missing helper now fails closed, so a pre-2a template never starts a REH. |
| JJ-5 | Low | dpkg | `--ignore-depends=fuse3` invites apt to pull setuid `fusermount3` later. | Fixed | `apt-mark hold`; runtime refusal if any setuid fusermount exists. |

Note for 2b (from this round): read the upper layer directly (`/var/lib/seclab/wb/upper`, init mount
namespace), never through the overlay or `/proc/<pid>/root`.

### Increment 2a, re-review (6e5886e)
JJ-1, JJ-4 and JJ-5 verified closed; JJ-2's filter verified, with one bypass:

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| KK-1 | **Medium** | Unguarded same-uid processes | sbx's own agent-uid boot processes (PID 1 `sh`, `sleep`, clipboard-bridge) carry no filter; with no Yama, tab code could write their memory (`/proc/<pid>/mem`) and run `unshare` there, undoing JJ-2. | Fixed | seclab-obs-guard puts the tab in a Landlock domain (ABI ≥ 6, fail closed): ptrace access, signals and abstract unix sockets are scoped to the domain; file and network access unchanged. Regression with an unguarded control. |
| KK-2 | Low | Post-mount check | fd in flight, fork during the scan, a second mount of the share. | Fixed (in part) | Rescan until the pid set is stable; refuse a second mount of the lower device. In-flight `SCM_RIGHTS` remains theoretical (no tab code runs before the mount). |
| KK-3 | Info | Exemption | Exempt fuse-overlayfs by owner of /proc/<pid>. | Fixed | All four uids 0 from `status`. |
