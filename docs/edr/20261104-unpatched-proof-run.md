# Unpatched proof run: which escapes are real

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** RPC-lockdown session
- **Build:** unpatched `seclab-vscode`, Actions run 41893270973, upstream `a717861c07586a53d83b80d742cd3f59b20a6273`
- **Evidence:** [`rpc-filter/probes/runs/20261104-unpatched-a717861.json`](../../rpc-filter/probes/runs/20261104-unpatched-a717861.json)
- **Related:** [EDR: escape probes](20261104-rpc-escape-probes.md), [EDR: probe safety](20261104-probe-safety.md)

## Why this run matters

A probe that has never succeeded proves nothing when it later fails: it may
simply be broken. This is the run that makes the probe set trustworthy, and it
is also the run where the probes really execute on the developer's Mac, so it
happened only after the probe-safety review closed.

The tab (`t-lwhsbwfdukbbcjhizfmkwmedg4`) ran the rogue extension with
`remoteName: seclab`, hostname `seclab-t-…`, `linux`, uid 1000 — i.e. the
extension was forced into the sandbox, and everything below is an escape *from*
there.

## Result: 9 of 17 probes proved a real escape

| Probe | Evidence |
|---|---|
| `host-terminal-newlocal` + `host-terminal-sendsequence` | **A `PWNED` file appeared on the host**, outside the tab's mount. Host code execution, start to finish. |
| `clipboard-read` | Returned the developer's **real clipboard contents**. |
| `command-enumeration` | 3105 commands visible, including `workbench.action.terminal.newLocal`. |
| `launder-direct` | `_remoteCLI.windowOpen` ran. **Verdict laundering confirmed empirically**, not just inferred from source. |
| `launder-manage-extensions` | Extension management reachable from a tab. |
| `secret-write-own`, `secret-read-cross-tab` | SecretStorage reachable and shared. |
| `host-fs-write-file-scheme` | Returned success — but see below. |

## A probe that "succeeded" and proved nothing

`host-fs-write-file-scheme` reported success and returned a `file://` URI, but
**`PWNED.rpcwrite` was never created on the host**. In a remote window
`workspace.fs.writeFile` with a `file:` URI is served by the REH's own file
system provider, inside the tab. The call succeeded; the escape did not happen.

This is exactly the failure the probe-safety review predicted — "probes whose
success does not actually demonstrate the claimed escape" — and it is why
`expectations.json` carries a `hostEffect` field. **`check-probes.ts` does not
yet verify `hostEffect`**, so this probe would have been recorded as a genuine
escape and then "fixed" by a patch that changed nothing. Verifying `hostEffect`
is the highest-priority follow-up.

The same doubt applies to `launder-direct` and the terminal pair: the terminal
pair is corroborated by the marker file, `launder-direct` is not corroborated by
anything yet.

## The eight errors, all explained

None of these is containment; every one is a harness or fixture gap.

| Probe | Cause | Fix |
|---|---|---|
| `host-fs-read-file-scheme` | `canary.txt` is not where the guard derives it (`prepare` writes `canary/secret.txt`) | align the fixture with `probe-safety.js` |
| `host-fs-read-userdata` | the fresh test profile has no `User/settings.json` yet | seed it in `prepare` |
| `auth-get-session` | no `seclab-fake-auth` provider is registered | ship a fixture auth provider |
| `launder-open-external` | **the safety guard refused `null/remotecli`** because the beacon port never reached the tab | plumb `beaconPort` from the arming file |
| `open-external-silent`, `as-external-uri`, `webview-egress` | skipped entirely for the same reason | same |
| `launder-await/timer/event/captured-service` | `_seclabTest.launder` does not exist | lands with the taint patch |

The `launder-open-external` refusal is the guard working as designed: a
mis-targeted probe became an `ERROR`, never a denial.

## Arming had to change, and why

The tab gets `env -i` (`sandbox/rootfs/opt/seclab/bin/seclab-tab-env`), so **no
host environment variable reaches an extension**. The first armed run therefore
reported `not armed` and ran nothing. Arming for the in-tab payload now travels
in a workspace file that `prepare` writes.

That is weaker, and is recorded as such in `probe-safety.js`: the workspace is
attacker-writable, so a hostile workspace could self-arm. Accepted, because
arming exists to stop the extension doing anything when installed outside a
harness run — it was never a containment boundary. The real boundary is
host-side: the teardown tripwire and the beacon.

For the same reason, in-tab path containment is **lexical only**: the run
directory is a host path the tab cannot stat. `probe-safety.js` marks this
`lexicalOnly` and `advisory` rather than silently weakening the check.

## Host integrity

`teardown.ts verify` after the run: the run-scoped keychain key is absent,
`$HOME`, `~/Library/LaunchAgents`, `~/.ssh`, `~/.aws` and `~/.config` are
unchanged, no sandbox left running, and the clipboard was restored. The only
host residue was the intended `PWNED` marker inside the run directory.

## Consequences

- Nine probes are now **known-valid** and can be used to judge the filter.
- Eight are not yet trustworthy and must not be counted as containment when
  they fail after patching.
- `check-probes.ts` must verify `hostEffect` before the patched run, or the
  `host-fs-write` class of false assurance survives into the result.
