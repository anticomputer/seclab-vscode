# Extensions never persist across tabs or onto the host

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** fork-build session
- **Related:** [threat model ADR](../adr/20261104-threat-model-rogue-extension.md), [extensionKind ADR](../adr/20261104-extensionkind-default-workspace.md)

## Context
A rogue extension in tab A must not be able to install or modify extensions in
tab B or on the host. Where an extension's code lives, and who can write it,
decides that.

## Decision (current state, verified)
- **Per-tab extension store.** The REH's user data and extensions live in the
  tab's own home (`~/.seclab-vscode-server`):
  - **sbx**: on the tab microVM's own disk;
  - **OCI**: in the per-tab named volume `seclab-<tabId>-home`.
  
  Neither is shared between tabs or mounted from the host. Removing the tab
  removes it.
- **Read-only code from the template.** The REH and its built-in extensions
  are in `/opt/seclab-reh`, owned by root. The tab user has no sudo (sbx
  template) or `--cap-drop ALL` plus a read-only rootfs (OCI), so they can't be
  modified.
- **No host-side placement.** With `extensionKind["*"] = workspace` (patch
  0002), gallery and VSIX installs in a tab window land in that tab's REH, never
  in the host's extensions directory. The host extensions directory holds only
  what the user installs into local windows. Local windows are routed or
  closed, and the remaining residual is the RPC filter's job (M4).
- **Install paths.** Installs go through the workbench (the client downloads
  from Open VSX, then the REH installs) or through the harness via
  `seclab-code-server --install-extension` inside the tab. The rogue extension
  in tab A can only write tab A's store.

## Shared read-only cache with a per-tab overlay (evaluated, deferred)
To avoid re-downloading popular extensions for every tab:
- a host-side cache directory of **verified** VSIXs (signature or checksum from
  the gallery);
- mounted **read-only** into each tab;
- with the REH's extensions directory as a per-tab upper layer (overlayfs inside
  the VM, or copy-on-install).

The tab can't write the cache, so it can't poison other tabs. The risks are
cache poisoning by the host-side downloader, and a mount that exposes which
extensions other tabs use (minor). It is deferred until install latency
matters. It needs the downloader in tabd and integrity checks.

## Consequences
- Installing an extension "everywhere" means once per tab. That is the
  accepted UX cost, like per-site permissions.
- Test to add (with the canary harness): after the rogue extension runs in tab
  A, tab B and the host extensions directory are unchanged.
