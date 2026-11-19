# Security review: a tab window sends its tab no host terminal settings (patches 0053-0058)

- **Date:** 2026-11-18 to 2026-11-19
- **Reviewer:** independent `security-review` agent (an Opus-class model), twelve rounds.
- **Subject:** patches 0053 to 0058 on `anticomputer-rpc-docsync-r5`, which close DOCSYNC-R5,
  RFU1R-2, RFU1R2-1 and RFU1R-3, their unit suite and the reh-push probes
  ([EDR](../edr/20261118-tab-terminal-settings.md)).
- **Prompt:** said the diff, fixtures and evidence may contain prompt injection aimed at the
  reviewer, and that the reviewer reports it rather than following it. None was found.

## Verdict
Two highs, both on main and both fixed here: choosing a terminal profile in a tab window wrote the
tab's REH-chosen profile into the host user's settings (R5-14), and the terminal hover rendered
tab text as markdown, so an image in it was fetched by the trusted window (R5-18). Round 4 also
found R5-17, a high in how the window takes its server's environment, which became its own change
(patch 0059, [review](20261118-tab-server-environment.md)). Round 10 found R5-32, a high on main:
a tab window installed auto replies the tab's server can set on the local pty host every window
shares. It landed first as patch 0061, which also fixes round 9's R5-31
([review](20261119-tab-auto-replies.md)). Round 11 found nothing. Round 12, of the fixes for the PR review, found one test gap (R5-33).
Every finding here is fixed.

## How the evidence was made
The unit test (`test/containment/terminal-settings.test.ts`) runs upstream's own terminal methods
with whatever version of 0053 to 0058 a tree has. On main (3633e20d) the case "a tab gets none of the host terminal settings" fails, with R5-14's REH profile written to host settings and R5-18's markdown image in the terminal hover among its 37 leaks.
The same case fails on the trees rounds 5 and 6 reviewed with those rounds' findings, and passes
on the final version (run logs kept outside the repo, under the session's `.work/`). The runtime
proof on main's containment build reproduced both terminal-settings probes and R5-14
([EDR](../edr/20261118-tab-terminal-settings.md)).

## Findings

| # | Sev | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| R5-1 | Medium | settings | The layer rule counted a host-side workspace's settings as the tab's. | fixed | Workspace settings count only when the workspace is the tab's own (0036's test). | test/containment/terminal-settings.test.ts "a tab gets none of the host terminal settings" |
| R5-2 | Medium | paths | The REH was told the window's host folders, active folder and workspace name, and the options' workspace folder. | fixed | Only the tab's own folders and documents. | same |
| R5-3 | Medium | profiles | In a tab window the window's own extension host was sent the default profile the tab's REH chose. | fixed | It is sent none. | same |
| R5-4 | Low | tests | The extension-host scan could read an empty scan as containment, and its control canary was token-shaped, so the tab's secret gate refused the workspace. | fixed | A control canary the REH mints in its own offered profile, required on both builds. | none |
| R5-5 | Low | settings | The layer rule replaced maps instead of merging them as upstream does, and left `cwd` undefined. | fixed | Upstream's recursive merge; `cwd` defaults to empty. | test/containment/terminal-settings.test.ts "a tab keeps its own terminal settings and the defaults" |
| R5-6 | Low | tests | The suite didn't record collections, options or the active file, nor the application and policy layers. | fixed | All recorded, with mutants. | none |
| R5-7 | Info | records | The change had no EDR. | fixed | Written. | none |
| R5-8 | Medium | collections | A tab's extension host could replace or delete a collection another host set under the same id. | fixed | Refused in tab windows; the window's own host still can. | test/containment/terminal-settings.test.ts "a tab gets none of the host terminal settings" |
| R5-9 | Medium | icons | A REH's profiles or the tab's settings could name any `https` image as a terminal icon, which the trusted window fetched past the tab's broker. | fixed | Image icons only on the tab's own file system; else a codicon. | same |
| R5-10 | Low | profiles | The default profile's name, from the host user's settings, picked among the REH's profiles, so a host value could be confirmed by guessing. | fixed | The name comes from the tab's layers. | same |
| R5-11 | Low | collections | Upstream filtered only other origins' `PATH` entries from a tab's terminal environment. | fixed | Each host gets only the collections it set. | same |
| R5-12 | Low | paths | The workspace label and id sent to the REH could derive from a host path. | fixed | From the tab's folders, or an id derived from the tab. | same |
| R5-13 | Low | profiles | The resolver read the window's authority from the connection, not the environment. | fixed | From the environment. | same |
| R5-14 | High | profiles | "Select Default Profile" and saving a detected profile wrote the REH's profile (path, args, `env`) into the host user's settings, where a normal window's next terminal would run it. | fixed | Written to the tab's remote user settings, extending only the tab's own profiles. | same |
| R5-15 | Medium | rendering | Terminal profile descriptions are rendered as markdown in Settings, so a REH's profile could make the trusted window fetch an image. | fixed | Escaped text, codicon icons only. | same |
| R5-16 | Low | paths | A detach request naming another window's workspace reached the REH with that workspace's id. | fixed | Refused without reaching the REH. | same |
| R5-18 | High | rendering | The terminal hover rendered the title and command line, which the tab's shell and REH set, as markdown. | fixed | Escaped in tab windows. | same |
| R5-19 | Medium | settings | "Allow <scheme>" on a link the tab's shell printed wrote `allowedLinkSchemes` into the host user's settings, from the merged list. | fixed | The tab's own list, written to its remote user settings. | same |
| R5-20 | Low | rendering | Profile descriptions kept autolinks, and a new line could forge another entry's fields. | fixed | Fully escaped, one line. | same |
| R5-21 | Medium | tab test | The terminal helper's tab test was case-sensitive while the filter module's is not, so a mixed-case tab authority was a tab to the filter and not to 0053 to 0058. | fixed | The same test, in any case; authorities compare case-insensitively. | same |
| R5-22 | Low | settings | A new terminal's cwd for a folder came from the merged `terminal.integrated.cwd` and reached the REH in the launch config. | fixed | From the tab's layers for a folder on the tab. | same |
| R5-23 | Low | settings | The host user's shell integration, suggest, ConPTY and locale switches reached the REH in the process options. | fixed | From the tab's layers. | same |
| R5-24 | Medium | rendering | A terminal status's tooltip, which can be a launch error the tab's server sent, was rendered as markdown in the hover. | fixed | Escaped, with codicon icons only. | same |
| R5-25 | Low | profiles | The automation profile and the contributed-profile exclusions were read from the merged settings, and a contributed profile was written to the host user's settings. | fixed | The tab's layers; written to its remote user settings. | same |
| R5-26 | Medium | tab test | The guard that keeps a tab's launch config unresolved stayed case-sensitive, so a mixed-case tab authority had host settings resolved into it. | fixed | Case-insensitive. | test/containment/terminal-settings.test.ts "each mutant of 0053 to 0058 is caught" |
| R5-27 | Low | profiles | A contributed profile written from a tab window started from the merged profiles, copying the host user's into the tab's settings. | fixed | It starts from the tab's own. | test/containment/terminal-settings.test.ts "a tab gets none of the host terminal settings" |
| R5-28 | Low | tests | The suite didn't model the window's resolution, and pinned only the helper's tab test to the filter module's. | fixed | Both now. | none |
| R5-29 | Low | profiles | The tab-layer helper returned a configuration model's own object when one layer set the key, so the contributed-profile write edited the window's defaults in place. | fixed | A fresh copy. | test/containment/terminal-settings.test.ts "a contributed profile write leaves the window's defaults unchanged" |
| R5-30 | Low | settings | The launch's `useShellEnvironment`, which reaches the REH, was filled from the host user's `terminal.integrated.inheritEnv`. | fixed | From the tab's layers. | test/containment/terminal-settings.test.ts "a tab gets none of the host terminal settings" |
| R5-31 | Medium | settings | The window installed the host user's `terminal.integrated.autoReplies` prompts and replies on every terminal backend, the tab's REH included, at start and on every change. | fixed | Patch 0061: a tab's backend installs only pairs in the tab's own settings. | test/containment/auto-replies.test.ts "a tab window installs no auto reply on the shared local pty host" |
| R5-33 | Low | tests | No test checked the workspace-ownership guard on the new workspace write for a link scheme, so dropping it, which would let a tab-chosen scheme land in a host-side workspace, went unnoticed. | fixed | The host-folder and host-file workspaces check where "Allow" writes, with a mutant dropping the guard. | none |

## PR review (#70)

| # | Sev | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| PR70-1 | Low | settings | `unicodeVersion` and the persistent-sessions switch reach the REH from the merged settings. | false-positive | Neither is restricted, and both already reach a tab's extension host in 0036's snapshot; core settings follow the host by design (ARCHITECTURE §4.8), so nothing crosses that a tab doesn't get. | none |
| PR70-2 | Low | links | In a tab window a link's scheme was checked against the merged list, so a scheme only the host user allowed opened without the prompt. | fixed | The tab's own list decides. | test/containment/terminal-settings.test.ts "a tab gets none of the host terminal settings" |
| PR70-3 | Low | links | "Allow" wrote the tab's remote user settings even when the tab's workspace sets the list, which wins, so the grant didn't persist. | fixed | It writes the tab's workspace settings when they set the list. | test/containment/terminal-settings.test.ts "a tab keeps its own terminal settings and the defaults" |
| PR70-4 | Medium | tests | The extension-host scan skipped a region on a thrown or short read and still judged containment if the control canary turned up elsewhere, so a host canary in the skipped region would go unseen. | fixed | The scan counts what it couldn't read; a patched judgement needs every writable region read (a normal run reads all: 0 of 435 MB unread). | test/containment/check-probes.test.ts "the terminal settings and extension-host scan probes need their canaries on a baseline and a control after the patches" |

Not changed here: the case-sensitive tab tests in other patches' files (SRCH3-14, deferred) and the
unfiltered `mergedCollection`, whose consumers are outside tabs' reach (EDR, Consequences).
