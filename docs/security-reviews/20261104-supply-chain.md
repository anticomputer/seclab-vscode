# Security review: supply-chain provenance and CI credential sweep

- **Date:** 2026-11-04
- **Scope:**
  - the dependency register (`deps/registry.json`, `build/deps.ts`, `docs/DEPENDENCIES.md`);
  - publisher-signature verification (`build/verify-image.ts`, `build/registry.ts`, `seclab` `verify_signed_image`);
  - the weekly update report (`build/deps-outdated.ts`, `.github/workflows/deps-updates.yml`);
  - the Node/.nvmrc guard and the Dependabot ignore;
  - credentials into third-party containers (lychee, zizmor);
  - the RPC inventory CI jobs, including the RPC session's determinism and source-provenance fixes.
- **Threat:** a compromised publisher account, registry or bot PR puts bytes we didn't intend into the build, the tools or the app; or a third-party tool image exfiltrates a credential or the private repo.
- **Decision records:** [ADR supply-chain provenance](../adr/20261104-supply-chain-provenance.md), [EDR ci-hardening](../edr/20261104-ci-hardening.md), [EDR prompt-injection hygiene](../edr/20261104-prompt-injection-hygiene.md).
- **Reviewer:** `security-review` agent; every prompt carried the prompt-injection warning. No injection text was found.

## Round 1: RPC CI jobs and the credential sweep
| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| B-1 | Low | rpc-inventory | `git diff` misses untracked inventory files. | Fixed | `git status --porcelain` check added. |
| CC-1 | **Medium** | zizmor | A third-party image still received `GH_TOKEN` (local PATs included). | Fixed | zizmor runs `--offline --network none` with no token everywhere. |
| CC-2 | Low | RPC inventory | Nothing required tied the inventory and policy to `upstream.lock`. | Fixed | `lint deps` requires `upstream_sha` == `upstream.lock`. |

## Round 2: register and verification
| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| DD-1 | **Medium** | verify-image | Index entries without a platform were never verified, but containerd selects them. | Fixed | Every non-attestation entry needs a concrete platform and a binding. |
| DD-2 | **Medium** | deps.ts | `docker://` steps and `$VAR/…@sha256` references escaped the register. | Fixed | Captured, or reported as an unrecognised pin. |
| DD-3 | **Medium** | register | mitmproxy claimed signed-verified with no verifier in the tree. | Fixed | `verifiedBy` must exist in the tree; mitmproxy demoted with a gap. |
| DD-4 | Low | verifier | The networked verifier container saw the whole repo. | Fixed | Only its two scripts are mounted. |
| DD-5 | Low | cache | The marker was keyed by digest only, and could be planted or committed. | Fixed | Keyed by digest + identity; CI always re-verifies; tracked `.work/` fails. |
| DD-6 | Low | rpc-filter | `fetch-upstream.sh` trusted a codeload tarball. | Fixed (RPC session) | git clone, checkout by SHA, verify HEAD. |
| DD-7 | Low | deps.ts | `ci: run` blocks, patch additions and lock files weren't scanned. | Fixed | Scanned. |
| DD-8 | Low | register | Host tools and unverified signers claimed official-pinned. | Fixed | `host-installed` bar with a required gap; gaps listed. |

## Round 3: re-review
DD-1 to DD-8 verified closed. **No medium or higher remains.**

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| EE-1 | Low | deps-updates | Lookup errors could print "Nothing outdated." and silence the report. | Fixed | That line only when every lookup succeeded. |
| EE-2 | Low | deps outdated | Networked container saw the whole repo. | Fixed | Only its three files are mounted. |
| EE-3 | Low | deps-updates | Registry/API strings could @-mention or autolink in the issue. | Fixed | No `@`; external strings in code spans. |
| EE-4 | Low | register | `verifiedBy` matched a comment; strace hashes weren't pins. | Fixed | Comment lines ignored; `deb:` pins from lock files. |
| info | — | rpc-filter/tools/test.sh | `--platform linux/arm64` on x86 runners. | Fixed | Removed (multi-arch digest). |
| — | Residual | rpc-filter | A local `.work/upstream` tree could be modified by containers that mount the repo read-write. | Accepted | Local only; CI clones fresh. |

## Round 4: observability suite in ci-linux (c0fb442)
Nothing medium or higher. The privileged Falco container runs `--network none`, with no secrets
or `docker.sock` and read-only host mounts, from the cosign-verified digest. On a hosted runner
every step is already root, and the job holds only a read-only, job-lifetime token.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| FF-1 | Info | register | `act-cache.used` listed ci-linux, which has no cache step. | Fixed | Dropped. |

## Round 5: uri-constraint step, check-pins skip, docs-check token (5a6ca41, a2087a6, 02a9f31)
Nothing medium or higher.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| GG-1 | Low | check-pins | Skipping all of `broker/tools/supplychain.py` would hide a future unpinned image it runs. | Fixed | Any process-execution or dynamic-import construct in it un-skips it. |
| HH-1 | Low | docs-check | The read-only job token reaches every `ci: run` command (and anything with the docker socket), though only `gh` needs it. | Open (broker session) | Split: a token-only step downloads the attestation bundle; `verify-images.sh` verifies offline with `--bundle`; the docs gate runs tokenless. |
| HH-2 | Low | docs-check | PR runs have no token, so `broker/build.sh` fails closed and `docs` is red on PRs. | Accepted | Changes land by branch push and fast-forward (AGENTS push flow); the `docs` check is push-only in practice until HH-1. |

## Round 6: attestation download split (broker 21979ca, 45be740)
HH-1 verified closed: only `gh` gets the token, in a download-only step on pushes; the docs gate is
tokenless. A planted or replaced bundle can't weaken the check (digest-named, subject-checked,
Sigstore-rooted, identity-pinned); deleting it forces a tokenless online check that fails closed.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| II-1 | Low | verify-images | Locally, a cached bundle never re-checks revocation. | Open (broker session) | Re-download outside CI when older than N days, or use `--bundle` only in CI. |

## Round TT (2026-11-05): pinned tools, sbx fence kit allows, broker.hello gate
Scope: `ca20ca0..3f97fb8` (EDR [pinned tools](../edr/20261105-pinned-tools.md)). No prompt
injection found. The fence change, the broker gate and the download/verify/build flow (the
in-build sha256 recheck closes TOCTOU) hold.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| TT-1 | **Medium** | CI | The `tools` job held `id-token`/`attestations: write` while running branch code (any push, same-repo PR), so a branch could mint a provenance attestation from this repo for any binary. | Fixed | `tools` builds and checks with `contents: read` and uploads the binaries; `attest-tools` (needs it; push to main only) holds the permissions, checks out nothing and runs no repository code. |
| TT-2 | Low | tabd scan | tabd trusted the scanner image by name; a cache hit didn't retag; the shipped binary wasn't rechecked. | Fixed | The image build rechecks the pinned binary sha256. `tool.sh` retags the stable name on cache hits. tabd checks `/usr/bin/gitleaks` against the pinned hashes before its first scan and refuses on a mismatch. Unit tests (constants equal tools.json; refusal; re-check). |
| TT-3 | Low | tabd scan | GNU find quotes paths C-style; the decoder assumed shell quoting. | Fixed | `unquoteFindPath` decodes C escapes and octal bytes; test vectors captured from the image's own find. |
| TT-4 | Low | CI | `GH_TOKEN` reached PR code in workflow-lint (for actionlint's `gh attestation verify`). | Fixed | actionlint is verified by sigstore-python against a committed attestation bundle: no API, no token anywhere (also fixes the tokenless docs gate). |
| TT-5 | Low | tool.sh | The cache key didn't cover the verifier. | Fixed | `tool.sh`, the verifier's lockfile and any committed bundle are in the key. |
| TT-6 | Low | npm | Off-registry packages are skipped silently by `npm audit signatures`; an old stamp skipped the audit; it runs after install scripts. | Fixed / accepted | Off-registry `resolved` entries fail; the stamp is versioned (`sig1-`). Running after install scripts is accepted (upstream's postinstall needs them) and stated in the EDR. |

## Round VV (2026-11-05): ripgrep seeding, patch-build gate, mechanical secret scan
Scope: `0ae1eeb..ba65194` (EDRs [patch-build gate](../edr/20261105-patch-build-gate.md),
[mechanical secret scan](../edr/20261105-mechanical-secret-scan.md)). No prompt injection found.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| VV-1 | **Medium** | lint secrets | `git diff BASE..TIP` scans the snapshot, so a secret added in one commit and removed in a later one (still in history, still pushed) passes. | Fixed | `git log -p -m --text --no-ext-diff --no-textconv` over the range: every commit, merges included. Reproduced with a generated token: old form exit 0, new form exit 1. |
| VV-2 | **Medium** | CI | Scanning only from the push's previous head lets a secret pushed earlier on a branch (hook bypassed) reach `main` in a later clean push. | Fixed | Pushes to `main` scan from the previous head; every other push and PR scans every commit since the merge base with `main`. |
| VV-3 | **Medium** | lint secrets | A `binary` or `-diff` attribute makes git print "Binary files differ", hiding the content. | Fixed | `--text` (covered by the VV-1 reproduction, `*.bin -diff`). |
| VV-4 | Low | hook | `core.hooksPath=build/hooks` resolves per worktree, so a branch could edit or delete its own hook. | Fixed / accepted | The hook is copied to the clone's common git dir and `core.hooksPath` is absolute. It still runs the pushing checkout's `./seclab` (refusing if it has none); a branch that weakens `lint_secrets` is caught by the required CI step and by review, since main only fast-forwards. |
| VV-5 | Low | ripgrep | The seed verified the archive but not the installed binary; the postinstall could take another path; the cache was in shared `/tmp`. | Fixed | `ripgrep.lock` pins each `rg` binary; `--verify-installed` runs after `npm ci` (and on every Linux build); seed and install use a fresh private `TMPDIR`. Negative control: a substituted `rg` fails. |
| VV-6 | Low | patch-build | The reach graph counted commented-out and type-only imports as edges, and a `reach.json` patch touching no `.ts` file passed with nothing checked. | Fixed | Comments stripped, type-only imports/exports skipped (`build/patch-reach-imports.ts`, unit tests), and a `reach.json` patch with zero checked files fails. Patch 0012 still reaches desktop; `workbench.web.main.ts` still reaches only web. |
