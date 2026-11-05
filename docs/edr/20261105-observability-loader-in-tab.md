# Observability demo loader is assembled inside the tab

- **Status:** accepted
- **Date:** 2026-11-05
- **Deciders:** anticomputer; coordinator; tab-observability session
- **Related:** [EDR fixture safety, addendum](20261104-fixture-safety.md), [EDR observability sensor spike](20261104-tab-observability-sensor-spike.md), [ADR write-back gate](../adr/20261104-write-back-gate.md), [security review](../security-reviews/20261104-tab-observability.md)

## Context
The observability e2e and README demo ran an inert folder-open loader from
`test/observability/fixtures/loader-workspace/`. That directory held two files:
- `.vscode/tasks.json`: a hidden folder-open task running `sh .seclab/loader.sh`;
- `.seclab/loader.sh`: detach, a fetch tool, inline interpreter eval, and reads of
  browser and wallet paths.

Each file alone passed the single-file `av-loader` lint. Together they reproduced the
campaign's shape on the host's disk, in every checkout of `main` and in every run's
copy under `.work/observability/` and `.work/obs-demo/`. That breaks the fixture-safety
rule that no host file may match an AV signature.

## Decision
1. **The host holds only parts.** The fixture is now `.seclab/loader.parts.json` (split
   tokens: fetch tool, interpreter, inline code, honeypot paths, beacon host) and a
   README. No host file holds a loader, a hidden folder-open task, or a browser or wallet
   path.
2. **Assembly happens in memory, and the result is written inside the tab.**
   `test/observability/loader.ts` checks the parts (charset, RFC 5737 beacon only, bounded
   counts), builds the script, and pipes it over `sbx exec -i` / `docker exec -i` to
   `$HOME/.cache/seclab-obs/loader.sh` in the tab. The tab's home is tab-private under
   both drivers.
3. **The e2e runs the task's command directly** (`TASK_COMMAND`). It needs no
   `tasks.json`. It asserts that no loader exists in the host workspace.
4. **The demo (sbx only) also writes the hidden `.vscode/tasks.json` inside the tab.**
   The write-back gate holds `.vscode/**` in the VM-private upper layer, so the editor
   sees it but the host never does. The guard is `tab.ensureRunning`: it fails unless the
   collector has mounted the overlay (`seclab-obs-collect` refuses to start the REH
   without it). After writing, `demo.ts` also fails the run if `.vscode` appears in the
   host checkout. OCI is refused, because an OCI tab's workspace writes reach host disk.
5. **Generated copies were removed** from every worktree's `.work/`. The tracked files
   leave each checkout as branches rebase onto `main`.

## Alternatives considered
- **Keep the files and add an AV exclusion:** this is the user's own machine, and
  an exclusion would also hide real detections.
- **Encode the whole script (base64):** this is still a decodable loader on disk.
  Parts plus a strict charset check is what the contagious-interview fixture already does.
- **Write the loader into the workspace inside the tab:** OCI on Docker Desktop has no
  write-back gate, so the file would land on the host. The tab's home avoids that under
  both drivers.

## Consequences
- The demo needs a running sbx tab at prepare time. It starts the tab, writes the
  files, then stops it; the upper layer persists on the VM disk.
- Detection rules and the collector's honeypot list still name credential paths. They
  are sensors, not payloads, and carry no loader shape.
- A run's event log (`<state>/events/<tab>/*.jsonl`, 0600, under `.work/` or the test
  profile) records what the loader did, by design: its argv (the detached shell with the
  fetch tool and `-e`) and the honeypot paths, JSON-escaped one event per line. It holds
  no task file and no fetch piped into an interpreter. No detection was raised with these
  logs present. Teardown removes the profile; delete a run's `.work/` state if a
  detection ever names one.

## Evidence
- The endpoint protection's threat list before and after: the same entries
  (2026-11-04 17:43:04 and 17:44:00, quarantined, from the earlier contagious-interview
  fixture). No new detection.
- `./seclab lint fixtures`: clean, including `--av` over tracked files.
- `./seclab test obs oci`: OBSERVABILITY OK. This includes the check "loader written
  inside the tab (never a host file)". Afterwards the host workspace holds only
  `.seclab/targets` and the `.envrc` marker.
