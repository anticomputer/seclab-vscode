# A tab's server says where the tab's files are; the window checks it

- **Date:** 2026-11-18
- **Status:** proposed: the read-only host extension management, and the tab limitation it adds, await the coordinator's confirmation. Runtime proof: see below.
- **Owner:** the RPC follow-ups session (register owner `rpc`).
- **Related:** [configuration snapshot](20261112-tab-configuration-snapshot.md) (0036),
  the tab terminal settings change (0053-0058, which rests on this),
  [review record](../security-reviews/20261118-tab-server-environment.md),
  [RPC lockdown](../RPC-LOCKDOWN.md).

## Context
When a window connects, its server answers `getEnvironmentData` with where the window keeps that
connection's files: the remote settings file, MCP config, logs, global and workspace storage, local
history, the user home and the profiles. Upstream revives those URIs and uses them as given. A
genuine server runs the reply through its URI transformer, so every URI is `vscode-remote` on the
window's own authority. A tab's server is hostile under the threat model, and nothing checked it.

A review of the tab terminal settings change found the consequence (R5-17): a server naming the host
user's `settings.json` as `settingsPath` makes the window read that file as the tab's settings layer
(patch 0036 passes the layer to the tab, and 0053 takes terminal settings from it), and write the
tab's settings into it (0057 routes tab-window profile choices there). Both rest on this premise, so
this change lands first (coordinator, 2026-11-18).

## Decision
Patch 0059, in a `seclab+` window. Two controls.

**1. Every location a tab's server names is on the tab.** One check, `seclabTabUris` in the RPC
filter module, applies to everything a tab's server says about where the tab's files are:
- every URI must be `vscode-remote` with exactly the window's authority;
- every URI is rebuilt from its components, so a server can't slip a host string into the
  `external` or `fsPath` a revived URI would report;
- any plain object with a URI key (`$mid`, `scheme`, `authority`, `path`, `external`, `fsPath`,
  `_sep`) is a URI to check, since `URI.revive` ignores `$mid` and builds a URI from any object; it
  must be marked `$mid: 1` and carry nothing but URI keys, so URI fields on a container can't make
  the walk skip it;
- plain objects and arrays are walked whole, to a bounded depth; manifests are passed over only
  where upstream leaves them unrevived, and MCP `config.env` and `config.headers` are checked as
  records of strings, numbers and nulls;
- the environment must carry every location a genuine server sends (settings, logs, storage,
  local history, user home, profiles home and the rest), each an object: a missing or null one
  would make its consumers fall back to the host's own, and local history doesn't fall back to
  the host's directory when the environment is refused (PR review on #66).

It applies to the `getEnvironmentData` reply (a foreign location refuses the environment, which
stays a failure rather than reading as "no remote"), the `userDataProfiles`, `logger`, `extensions`
and `mcpManagement` channels' replies (refused) and events (dropped), MCP discovery, file change
events and scanned extensions. Where a location is kept, the rebuilt value is used. Install events
from the tab lose any gallery entry; MCP servers from the tab lose their icon and links, which the
renderer would load as given.

**2. A tab window doesn't change the host's extensions.** In a tab window which extensions an
action reaches, and their manifests, are the tab's server's to say. Review rounds 4 to 8 each found
another workbench route by which that made the host install, update or uninstall something, so the
control is central rather than per route:
- the window's channel to the host's own extension management takes reads only (and `download`,
  which fills the download cache to install in the tab); every change is refused;
- the host's global enablement, kept by id in storage the host's windows share, is read-only; a
  tab window enables and disables for its workspace;
- the host-shared settings a tab window could reach by id are left alone: auto-update lists,
  publisher trust, the synced extension ignore list, the "AI features" setting through a tab
  extension claiming the chat extension's id, Extension Bisect, one-time migrations, profiles made
  from a template, the display-language prompt on the tab's events;
- the tab's server gets no marketplace access token.
The per-route guards from earlier rounds stay, as defence in depth.

Each refusal logs `data:server-locations` with its site (`environment`, `profiles`, `loggers`,
`watcher`, `extensions`, `extension-management`, `mcp-discovery`, `mcp-management`,
`host-install`, `host-enablement`), never the value.

The check can't break a genuine tab: the server transforms every URI it sends with the authority
the window itself asked for, and builds each one fresh. Control 2 costs the user host extension
management from tab windows; ARCHITECTURE §4.8 lists what changes.

## Proof
- **Unit:** `test/containment/reh-environment.test.ts` (`./seclab test reh-environment`, in
  `./seclab test rpc-filter`) runs upstream's own methods from the pinned files, with whichever
  version of 0059 a tree has. On main it takes every lie; on each version a review round read it
  fails on that round's findings; on the final version it refuses and logs each, a genuine server
  passes unchanged, and a window that isn't a tab is unchanged. Each mutant lets its own lie
  through, and every file the patch touches must be one the suite lists.
- **Runtime:** `test/containment/reh-environment.ts` in a real OCI tab of the containment build. A
  terminal first runs a command in the tab (the genuine environment is accepted). The rogue REH then
  points `settingsPath` at a host file the run wrote, holding only a terminal env canary, and the
  window reloads and opens a terminal. The rogue-REH hook arms a run staged before a server starts
  as that server starts, since each window load starts a new server and asks for its environment
  at once. The host-install routes are proven by the unit suite only: on main the product's
  extension kinds already send a tab's VSIX to the tab, and the routes that reach the host query
  the marketplace first, which a probe may not.
  - Baseline: Actions run 44407175619, branch `anticomputer-rpc-reh-environment-base` (main plus
    only the test hook change). The REH served the lie once; the window read the host file as the
    tab's settings and the terminal's `createProcess` carried its canary back to the REH. The
    control terminal ran first; teardown clean.
  - Patched: Actions run 44407171110, this branch. The REH served the lie once; the window refused
    the environment and logged `data:server-locations` twice; no canary reached the REH, and the
    terminal after the reload never started, since the window had no environment. The control
    terminal ran first; teardown clean.
  - The hook's arming regression (`node test/builds/rogue-reh-arming.ts`) passed on the patched
    build's image, its startup cases included.

## Consequences
- A tab whose server lies about any location fails to connect, rather than running with host files.
- 0053 and 0057 can treat the remote user settings layer as the tab's own.
- Host extensions are managed from a window that isn't a tab (ARCHITECTURE §4.8).
- 0059 is large (about 345 added lines over 25 upstream files) for one concern, a tab's server
  steering the host through what it names; the range for RPC follow-ons is full, and splitting it
  would leave each part's guarantee depending on the others.
