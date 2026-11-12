# Security review: seclab-tabd design (protocol and process model)

- **Date:** 2026-11-04
- **Scope:** design docs at f36f759 plus the uncommitted drafts of `docs/adr/20261104-tab-supervisor.md`,
  `docs/tabd/PROTOCOL.md` and `docs/edr/20261104-tabd-implementation-language.md`, reviewed before any
  tabd code existed, against the threat model in ARCHITECTURE.md §2.
- **Reviewer:** security-review agent (default model); triage by the fork-build session.
- **Related:** [ADR tab supervisor](../adr/20261104-tab-supervisor.md), [EDR sbx fence](../edr/20261104-sbx-fence-spike.md)

## Findings
| # | Sev | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| 1 | **Critical** | RPC boundary | The REH *server* runs in the tab and is hostile. Server→client IPC bypasses a `MainThread*`-only filter: the `download` channel copies or fetches with server-chosen URIs (host file read/write, broker bypass), and pty `onExecuteCommand` allows `_remoteCLI.windowOpen/openExternal`. | **Open; owned by M4 (RPC-lockdown session)** | Forwarded to the RPC-lockdown session: filter scope must cover every server→client channel and event. M1 can't fix it without core patches. Tracked as an open critical in ARCHITECTURE.md §7. | TODO: rogue-REH fixture (M4) |
| 2 | High | `tab.claim` inputs | Tab-influenced inputs (commands, `windowOpen`, `.code-workspace`, links) reach claim; validation was only a root denylist. | Fixed (supervisor); Tab Manager part TODO in M1 | `canonicalWorkspacePath`: rejects `, : =` and control chars, symlinked components, sensitive dirs and their **ancestors**, editor data/extension dirs, the state dir and extra `--sensitive` paths; optional `--allowed-root` allowlist; case-folded, NFC-normalised comparisons. The Tab Manager must call claim only from user gestures with the canonical path shown. | `unit.test.ts` "validate: workspace paths" |
| 3 | High | Overlapping mounts | A parent tab can write a nested tab's `.vscode`/`.git`. The path can be swapped (symlink) between claim and mount. Case aliases. | Fixed | No nested or overlapping tabs (case-folded). `(dev, ino)` stored at claim and re-checked, with re-canonicalisation, before every `ensureRunning`. | `unit.test.ts` "state: … rejects overlaps" |
| 4 | Medium | Tab IDs | IDs are public, not secrets. A crafted authority could apply A-authored config in B. | Accepted for the supervisor; Tab Manager TODO | IDs are documented as public. The Tab Manager's resolver must refuse when the window's folders or workspace file are not inside the tab's `hostPath`. | TODO (M1 Tab Manager) |
| 5 | Medium | Fence fail-closed | A mismatch only disconnected the UI; the drift window was unbounded without a supervisor; remove order; non-network rule kinds. | Fixed | On mismatch or drift: close channels, **re-mirror denies and `sbx stop`** (`quarantine`). Mirror at every start. On stdin EOF or SIGTERM, stop the tabs this supervisor connected. Remove fence rules only after `sbx ls` confirms the sandbox is gone. Unknown resource types, decisions, actions or statuses fail closed. Broker-port findings → broker session. | `unit.test.ts` "fence: …" |
| 6 | Medium | Argument injection | Docker `--mount` CSV injection (`x,source=$HOME`), `:` specs, bare `-e NAME`, option-like values. | Fixed | Paths reject `, : =`. `--` before positionals in docker and sbx create. No `-e` is used at all. Policy resources use a strict grammar (no leading `-`). | `unit.test.ts` (paths, resources) |
| 7 | Medium | Inherited env | Editor env (tokens, `ELECTRON_RUN_AS_NODE`, `SSH_AUTH_SOCK`) reaches the supervisor and CLIs; binary planting via PATH or cwd. | Fixed | The supervisor wipes `process.env` at startup. Children get a fixed `PATH` plus an allowlist (`HOME`, `USER`, `LANG`, `TMPDIR`, `DOCKER_*`). Binaries resolve only from fixed system dirs. `cwd` = the state dir. | TODO: in-tab environ scan (containment suite) |
| 8 | Medium | Framing | Stray stdout writes could forge frames; channel races are fatal; oversize; reuse. | Fixed | `process.stdout.write` and `console.*` are redirected to stderr; only the framer writes stdout. Children use piped stdio. Data is split at 1 MiB. Channel IDs are monotonic and never reused; data for recently closed channels is dropped and only never-opened channels are fatal. | `unit.test.ts` "frames: …" |
| 9 | Medium | Broker SSRF | The broker can reach host loopback and other brokers. | Forwarded (broker session) | IP-level deny, a network per broker, digest pinning, per-tab proxy auth. | Broker session |
| 10 | Low | Concurrent supervisors | Shared state without locking. | Mitigated | Per-tab files plus an `O_EXCL` path claim (lock-free). Residual: the overlap check vs. a concurrent claim of a nested path is racy (TOCTOU between `list()` and the claim). Accepted for v0. | — |
| 11 | Low | Secrets in argv/audit | Tokens in `ps` or the audit log. | Fixed | The token is passed only over stdin. Audit args are redacted (`redactArgs`). The audit log is `0600`. | — |

## Re-review
Pending: round 2 reviews the implementation (`tabd/`, `build/`, `.github/workflows/`, `sandbox/`).
Finding 1 remains **open critical** and is owned by M4. It is explicitly called out as an M1 limitation.
