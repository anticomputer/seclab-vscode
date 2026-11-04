# Scan a folder for secrets before it is mounted into a tab

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** anticomputer (user: "Scan before mounting: run gitleaks in a container when a folder opens; if secrets are found, block and offer to move them into the broker (the file then holds a sentinel), open anyway with a recorded exception, or cancel"); fork-build session
- **Related:** [ADR no real secret in a tab](20261104-no-real-secret-in-a-tab.md); security review round 5 in [20261104-m0-tabd-code](../security-reviews/20261104-m0-tabd-code.md)

## Context
"No real secret ever enters a tab" is broken by the user's own folder if it
already contains credentials (`.env`, config files, remote URLs with tokens,
secrets in git history). The tab mounts the folder, so a rogue extension would
read them.

## Decision
`seclab-tabd` scans **before every mount** (each `tab.ensureRunning`, i.e. every open and reopen):
- **Scanner:** gitleaks v8.30.1, pinned by digest
  (`ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0…`). It runs in a throwaway
  container with:
  - `--network none --read-only --cap-drop ALL --security-opt no-new-privileges`;
  - uid 65534, 256 pids, 1 GB memory;
  - the workspace mounted **read-only**;
  - git hardened (no system/global config, `--no-textconv --no-ext-diff`),
    because the repo is hostile.
- **Coverage:** three passes:
  1. the working tree;
  2. `.git/config` (remote URLs with embedded credentials);
  3. **git history** (`--all`).
  
  History is included because `.git` is mounted, so the tab can read every
  past blob. Findings in history can't be rewritten, so the user can only
  accept them with a recorded exception, or cancel and clean the history
  themselves.
- **On findings, the open is blocked** (`-32020`, redacted findings: file, line,
  rule, source). Secret values stay only in supervisor memory. The Tab
  Manager's modal offers:
  1. **Move to broker:** the user binds each credential to a host (prefilled
     from the gitleaks rule) and confirms. tabd rewrites the value in the
     working copy to a sentinel. The write is atomic, refuses symlinks or files
     outside the workspace, and requires the tab to be stopped. tabd never
     commits. It records `{file, line, sentinel, secret, bind}` in a host-side
     **vault** (`<state>/tabs/<id>.vault.json`, 0600, outside every tab) until
     the broker imports it. `tab.restoreSecrets` reverses the rewrite.
  2. **Open anyway:** records an exception (tab, files, rules, timestamp) in
     `<state>/tabs/<id>.exceptions.json` and the audit log.
  3. **Cancel.**
- **Scan failure fails closed** (`-32021`). The user may open anyway, which
  records a `scan-incomplete` exception.

## Residuals (accepted)
- **Secrets the user types or pastes into a file while the tab is running**
  are visible to the tab until the next reopen. A rogue extension can't plant
  a real secret, since it never has one.
- **History findings opened anyway.**
- **Rules miss custom formats.** gitleaks' rules are heuristic. The canary
  rule (`seclab-canary`) proves the pipeline end to end.
- **Broker import is pending.** Until the broker session's import API exists,
  moved credentials live in the vault, and egress injection for them waits for
  the broker (M2/M3).

## Alternatives considered
- **trufflehog**: larger image and verification calls to the internet
  (unwanted); gitleaks was the user's choice.
- **Scan inside the tab**: rejected; it is too late, because the tab can
  already read the secret.
- **Working tree only**: rejected; the tab can read history from `.git`.

## Evidence
`node test/secrets/run.ts oci|sbx`: blocked with worktree, .git/config and history findings; the moves rewrite to sentinels; history needs an exception; the audit log has no secret values; the moved values aren't visible in the tab; restore works. Supervisor unit tests cover block, accept, move, restore and the no-scanner fail-closed path.

## Addendum (2026-11-04, security review round 5)
The decision stands. The review showed that a tab could blind later scans by
leaving files in its workspace, so the scanner was hardened:
- **Coverage now includes:**
  - every git dir under the workspace (nested repositories, submodules
    under `.git/modules`, bare repos), with each one's config and history;
  - history with `--all --reflog`;
  - an **object-store pass** over every blob, commit and tag object
    (`git cat-file --batch-all-objects`), which covers the index, stash,
    reflog-only and dangling objects. It backstops any history rewriting.
- **Workspace suppression inputs are ignored:**
  - gitleaks config and ignore files come from our tmpfs;
  - no pass uses the workspace itself as gitleaks' source, because gitleaks
    always loads `<source>/.gitleaksignore`;
  - `--ignore-gitleaks-allow` is set;
  - git uses `--text` plus `GIT_CONFIG_*` overrides (colour, prefixes,
    `bigFileThreshold`, `format.pretty`, `log.showRoot`, attributes, …) and
    `GIT_NO_REPLACE_OBJECTS`.
- **Partial results always block:** each pass is framed separately, so a
  failed or oversized pass can't discard another pass's findings. A report
  over 64 MiB, or more than 64 git dirs, is an *overflow*. It gets its own
  warning that decoys may be hiding real secrets.
- **Moving and restoring a value** is a byte-exact splice, verified by
  reading the file back. The vault entry is written before the file and
  removed only after a verified restore.
- **Displayed file names are escaped** (control, bidi and line-separator
  characters), and files with such names are never movable.

Residuals added:
- **Paths in gitleaks' default global allowlist are not scanned in the working
  tree.** This covers lockfiles, `node_modules/`, some `vendor/` trees, images
  and any path containing `gitleaks.toml`. Committed copies are still caught by
  the object-store pass.
- **The scanner needs Docker.** Docker Desktop is already required for the
  per-tab broker. Without it, every open shows the scan-incomplete prompt.
- **A git dir whose `.git` file points outside the workspace** (for example a
  worktree or submodule checkout) isn't mounted, so the tab can't read it
  either.

Regressions: `test/secrets/run.ts` adds:
- `.gitleaksignore` and `gitleaks:allow`;
- `-diff`/`binary` attributes, `core.bigFileThreshold=1`,
  `diff.noprefix`, `color.diff=always` and `log.showRoot=false`;
- a reflog-only commit, a staged-only blob, and a nested repo's config.

Unit tests cover frame parsing (partial results, overflow, malformed output),
name escaping, and byte-exact rewrites containing `$&` and non-UTF-8 bytes.
Evidence in gitleaks at
[83d9cd6](https://github.com/gitleaks/gitleaks/blob/83d9cd684c87d95d656c1458ef04895a7f1cbd8e/cmd/root.go#L317)
(the source `.gitleaksignore` is always loaded) and
[detect.go#L296](https://github.com/gitleaks/gitleaks/blob/83d9cd684c87d95d656c1458ef04895a7f1cbd8e/detect/detect.go#L296)
(the file at the config path is skipped).
