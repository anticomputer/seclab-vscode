# loader-workspace (observability demo fixture)

An inert stand-in for a folder-open task loader, so the tab's event stream has
something to show. On the host this directory holds only `.seclab/loader.parts.json`:
split tokens, with no loader, no task and no credential-store paths spelled out.

`test/observability/loader.ts` assembles the loader in memory and writes it into the
tab's own home, inside the tab. The demo also writes the hidden folder-open
`.vscode/tasks.json` inside the tab, where the write-back gate holds it in the overlay.
Neither ever exists as a host file: endpoint AV quarantines faithful loader-shaped
files (EDR fixture-safety, addendum).

Fixture safety: the loader is inert unless armed by a harness run (`.seclab/targets`
with a per-run nonce, the workspace inside that run's directory, unexpired). It
contacts only 192.0.2.10 (RFC 5737), reads only the tab's honeypots and writes one
marker (`.envrc`) in the workspace.
