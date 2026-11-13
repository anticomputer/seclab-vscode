# A tab receives only its own settings: the configuration snapshot filter (patch 0036)

- **Status:** proposed
- **Date:** 2026-11-12
- **Deciders:** coordinator, 2026-11-09 (scope; drop rather than sentinel for now; policy filtered like user settings; core keys allowed by scope with `restricted` and credential-named keys excluded, no editor allowlist; each withheld key reported by name for the user to move to the broker). Tab observability session, 2026-11-09 (the report's shape and its verification on the Tab Manager side). Project owner, 2026-11-13 (extension-declared keys never receive host user, policy or local-workspace values; a per-extension opt-in is a follow-up). Document-sync session: implementation.
- **Related:** [document sync provenance](20261109-document-sync-provenance.md) (0035); [settings withheld notice](20261109-settings-withheld-notice.md); [RPC lockdown](../RPC-LOCKDOWN.md) §7; [no real secret in a tab](../adr/20261104-no-real-secret-in-a-tab.md); [pre-mount secret scan](../adr/20261104-pre-mount-secret-scan.md)

## Context
`MainThreadConfiguration` sends every extension host `configurationService.getConfigurationData()`
whole, at start and on every change
([mainThreadConfiguration.ts#L28-L42](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/workbench/api/browser/mainThreadConfiguration.ts#L28-L42)).
That includes the host user `settings.json` (`userLocal`), `application`, `policy` and every
undeclared key, and `inspect()` exposes each layer. Setting values can be credentials: proxy
authorization, extension API keys, environment maps. The 0035 probe showed an undeclared user
setting's value reaching a tab on main.

Registration isn't stable either. Upstream deregisters and re-registers the proxy settings at run
time, as `APPLICATION` or `MACHINE` depending on `http.useLocalProxyConfiguration`
([request.ts#L292-L340](https://github.com/microsoft/vscode/blob/a717861c07586a53d83b80d742cd3f59b20a6273/src/vs/platform/request/common/request.ts#L292-L340)).
A Level B run on main once saw the `http.proxyAuthorization` canary in a tab's configuration dump
(reported by the coordinator, 2026-11-09), so a rule that trusts the registry's scope at snapshot time races.

## Decision
Patch `0036-seclab-tab-configuration-snapshot`, for a non-`LocalProcess` host in a `seclab+` window
only (0035's predicate). The local host and other windows get the snapshot as upstream.

1. **Credentials first, registry-independent.** `withholdReason(key, value)` withholds a key if its
   name, or any key name inside its value, matches a credential pattern (`token`, `passw`, `pwd`,
   `secret`, `auth`, `api key`, `credential`, `private key`, and `env` maps), or if any string in it
   is a secret by gitleaks' default rules. This runs before any registry lookup, in every layer that
   is filtered, `[lang]` sections included. Names catch low-entropy passwords that scanners miss.
2. **Then declaration.** `policy`, `userLocal` and local workspace or folder settings (values the
   host user, policy or a local workspace set) keep only keys registered by core with a scope other
   than `APPLICATION`, `MACHINE`, `APPLICATION_MACHINE` or `MACHINE_OVERRIDABLE` and not
   `restricted`. A key an extension declares never receives a host value there (review round 1,
   A1): the tab chooses which keys its extensions declare, so any credential denylist would have
   gaps (a URL with userinfo inside an env map, a passphrase, a cookie, a numeric PIN). Extensions
   in a tab read their settings from the tab's own remote and workspace settings. `defaults`
   (registry defaults, not user values) also keeps the keys of extensions installed in this tab.
   A core value that is an object or array crosses from those layers only if it holds no strings
   (review round 2, CFG-8): free-form settings such as `launch` carry `args` and connection strings
   the classifier can't recognise. Scalar strings are still scanned. Undeclared keys never cross,
   and neither do keys with a `__proto__`, `constructor` or `prototype` segment.
3. **Layers.** `application` is dropped. `userRemote` (the REH's own) and workspace or folder
   settings on the tab's own authority pass unchanged: the tab already controls them.
4. **Changes.** Every `$acceptConfigurationChanged` rebuilds and refilters the snapshot. The change's
   key list names a key only if it crossed from a host layer before or now and isn't withheld now,
   or if its value in a layer the tab owns changed. The event's source isn't trusted: upstream tags
   multi-layer reloads as a workspace change (review round 2, CFG-9).
5. **Report.** Keys withheld from the top level of `userLocal` are reported by name and reason,
   never value, at most 64 per call and 256 characters per key, once per window, with the marker
   `seclabSettingsWithheld:v1` and the window's own authority. The report goes directly to the
   window's `LocalProcess` extension host (`$executeContributedCommand` on its `ExtHostCommands`
   proxy), never through the global command service, where a tab could register the same command
   id and intercept or suppress it. The Tab Manager re-runs the same classifier on the host's own
   value before raising a notice.

**The scanner.** `build/secret-rules/generate.ts` turns gitleaks' own `config/gitleaks.toml`, at
the commit pinned in `build/tools/tools.json`, into a V8 rule table: inline `(?i)` becomes the `i`
flag, `(?P<` becomes `(?<`, POSIX classes become ranges. Rules bound to a file path are skipped,
and example tokens in allowlists are left out. `seclabSecretScan.ts` ports gitleaks' per-rule
decision (keywords, secret group, entropy, allowlists, stopwords). The table is stored base64,
because a readable list of scanner keywords trips secret scanners, our pre-push one included.
`generate.ts --decode` prints it.

**One source, two consumers.** `build/secret-rules/src` holds the classifier, scanner and table.
The patch carries them as new files, kept identical by `sync-patch.ts --check` (a unit test), and
the Tab Manager imports the same directory.

## Alternatives considered
- **Trust the registry's scope:** rejected because of the run-time re-registration race above.
- **An explicit editor-settings allowlist:** rejected by the coordinator for the upkeep on every
  upstream bump. Scope plus scanning, with `restricted` and credential names excluded, is the
  rule, and the measured list of core keys that cross is recorded so drift shows in review.
- **A sentinel instead of dropping:** deferred. The broker has no import path for setting values
  yet. Dropping, plus a notice naming the key, is the first step.
- **Let tab-declared keys receive host values, behind the credential rule** (the first design):
  rejected after review round 1. The tab picks the keys, and the rule can't recognise every
  credential shape.
- **Run gitleaks itself:** a native binary in the renderer is not an option. The port is checked
  against the pinned binary instead.

## Consequences
- A tab never receives an extension setting from the host user settings, policy or a local
  workspace file, or anything that looks like a credential. **User-visible:** an extension in a
  tab only sees what the tab's own remote or workspace settings say; settings for it in the host
  `settings.json` don't follow it into tabs (ARCHITECTURE §4.8). Core editor settings still do,
  except object or array settings that contain text (for example global `launch` configurations or
  `editor.quickSuggestions`), which must be set in the tab.
- An extension that needs a credential gets nothing until the user moves it to the broker, and the
  Tab Manager names the withheld key.
- **Follow-up:** a per-extension opt-in to receive host values, as its own reviewed change.
- Core settings the tab does receive are listed in the evidence below, for review on upstream bumps.
- **Residuals:**
  - the scanner doesn't decode base64, hex or percent-encoded segments as gitleaks can;
  - withholdings from policy, defaults, local workspace settings and `[lang]` sections are silent;
  - the tab's own `userRemote` and tab-authority workspace settings are not filtered;
  - object keys inside a structured core value (glob patterns in `files.exclude`) still cross,
    unless they contain a scheme or `@`; otherwise only the name rule checks them;
  - a change confined to a `[lang]` section of a tab-owned layer isn't named in the change event.

## Evidence
**Port vs pinned gitleaks.** `node build/secret-rules/differential.ts build/secret-rules/src`
generates settings-shaped lines from every rule's own pattern, plus negatives, and compares
verdicts with the pinned gitleaks binary (decoding off). Three runs of about 500 lines each: 0
disagreements.

**Unit tests.** `node --test build/secret-rules/secret-rules.test.ts` (in `./seclab test unit`):
credential names withheld whatever the value, `http.proxyAuthorization` by name alone,
secret-shaped strings under neutral names, ordinary settings crossing, the marker, and the patch
in sync with its source.

**Runtime proof** (2026-11-12; sbx tab; background launch through `test/window.ts`; attested
builds: main `607873da`, run 43264609543, and this branch at `af36452`, run 43273392338).
- **`fixture:test/configsync/probe-extension`:** `test/configsync/probe.ts`, 10 runs on each
  build, first version of the harness (five canaries: undeclared, proxyAuth, password,
  secretValue, changed).
  - Main: 10 of 10 runs fail as designed. Four canaries reach the tab every run: undeclared,
    `http.proxyAuthorization`, the low-entropy password and the secret-shaped value, in the
    initial snapshot and again after the host change.
  - Patched: 10 of 10 pass. No canary reaches the tab, and the controls hold: `editor.tabSize`, a
    tab extension's own setting, and the change itself all arrive. No focus steal; the teardown
    gate passed every run.

Review round 1 then hardened the harness. It now activates on `*` and scans from the first
moment, a canary in the tab's own workspace settings must be seen (proving detection works on the
build under test), and canaries cover an env-style map and nested-form settings under a
tab-declared key. Results for the hardened harness: to be added.
