# A tab receives only its own settings: the configuration snapshot filter (patch 0036)

- **Status:** proposed
- **Date:** 2026-11-12
- **Deciders:** coordinator, 2026-11-09 (scope; drop rather than sentinel for now; policy filtered like user settings; core keys allowed by scope with `restricted` and credential-named keys excluded, no editor allowlist; each withheld key reported by name for the user to move to the broker). Tab observability session, 2026-11-09 (the report's shape and its verification on the Tab Manager side). Document-sync session: implementation.
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
2. **Then declaration.** `defaults`, `policy`, `userLocal` and local workspace or folder settings
   keep only keys registered by core with a scope other than `APPLICATION`, `MACHINE`,
   `APPLICATION_MACHINE` or `MACHINE_OVERRIDABLE` and not `restricted`, or declared by an extension
   installed in this tab. Undeclared keys never cross.
3. **Layers.** `application` is dropped. `userRemote` (the REH's own) and workspace or folder
   settings on the tab's own authority pass unchanged: the tab already controls them.
4. **Changes.** Every `$acceptConfigurationChanged` rebuilds and refilters the snapshot, and the
   change's key list names only keys the tab knew before or knows now.
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
- **Run gitleaks itself:** a native binary in the renderer is not an option. The port is checked
  against the pinned binary instead.

## Consequences
- A tab never receives host user settings it has no declared use for, or anything that looks like
  a credential. An extension that needs a credential setting gets nothing until the user moves the
  credential to the broker, and the Tab Manager tells them which key.
- Core settings the tab does receive are listed in the evidence below, for review on upstream bumps.
- **Residuals:**
  - the scanner doesn't decode base64, hex or percent-encoded segments as gitleaks can;
  - withholdings from policy, defaults, local workspace settings and `[lang]` sections are silent;
  - a tab extension can declare a setting key another extension owns (the registry keeps the
    first), and then receives that key's non-credential value;
  - the tab's own `userRemote` and tab-authority workspace settings are not filtered.

## Evidence
**Port vs pinned gitleaks.** `node build/secret-rules/differential.ts build/secret-rules/src`
generates settings-shaped lines from every rule's own pattern, plus negatives, and compares
verdicts with the pinned gitleaks binary (decoding off). Three runs of about 500 lines each: 0
disagreements.

**Unit tests.** `node --test build/secret-rules/secret-rules.test.ts` (in `./seclab test unit`):
credential names withheld whatever the value, `http.proxyAuthorization` by name alone,
secret-shaped strings under neutral names, ordinary settings crossing, the marker, and the patch
in sync with its source.

**Runtime proof.** To be added: `test/configsync/probe.ts` on a main build and on this branch's
build, at least 10 runs each.
