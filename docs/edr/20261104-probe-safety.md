# Probe payloads must be inert against the host

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** user; RPC-lockdown session
- **Related:** [EDR: escape probes](20261104-rpc-escape-probes.md), [review](../security-reviews/20261104-rpc-probes-increment.md)

## Context

The probe set is validated by running it against the **unpatched** build, where
every probe is supposed to succeed. That is the only way to know a probe works
(see the escape-probes EDR). It also means the probe set is, by design, a
working exploit chain that executes on the user's own Mac: host terminal
creation, host file read and write, credential access, and egress.

The user's requirement, verbatim: *"of course make sure our vuln examples are
not actively malicious against our host."*

The first draft was not. `host-terminal-sendsequence` built a shell string by
interpolation; the rogue-REH MCP probe sent an arbitrary `command` argument to a
host-side tool; `auth-get-session` asked for the user's **real** `github`
session; and nothing stopped a probe naming any path on the machine.

## Decision

Payloads demonstrate **reach** and nothing else, enforced in three independent
places so that no single mistake is sufficient:

| Layer | What it enforces | Where |
|---|---|---|
| Runtime | targets, arming, the one permitted command | `probe-safety.js` |
| Review | payload *shape*: no spawn, no destructive FS, no external host, no persistence | `rpc-filter/tools/lint_probes.py` |
| Tests | the guards themselves | `test/containment/probe-safety.test.ts` |

The seven rules are in `rpc-filter/AGENTS.md` §8. The load-bearing ones:

- **Arming needs two halves**: `SECLAB_PROBE_NONCE` *and* a matching
  `.seclab-probe-nonce` file in the run directory. Environment alone does not
  arm, so the extension installed outside the harness does nothing.
- **Every path goes through `safePath()`**, which rejects known real-user
  locations by pattern and then requires the **symlink-resolved** location to
  be inside the run directory.
- **Every URL goes through `safeUrl()`**: literal `127.0.0.1` on the beacon
  port only.
- **One permitted command**: `markerCommand()` emits `touch '<marker>'` with a
  path already proven inside the run directory.
- **A safety refusal is never a denial.** `SafetyError` is tagged, and
  `classify()` records it as `ERROR`. Otherwise a mis-targeted probe would
  score as containment — the exact false assurance the previous review round
  was about.

## Alternatives considered

- **Trust the probe authors.** Rejected: the first draft was written carefully
  and still had four violations.
- **Runtime guards only.** Rejected: a future probe can simply not call them.
  The lint enforces shape independently, and fails if a payload does not call
  `safety.context()` at all.
- **Lint only.** Rejected: pattern matching cannot see a path assembled at
  runtime.
- **Drop the unpatched run.** Rejected: it is the only thing that makes the
  probe set trustworthy.

## Consequences

- Probes are less faithful to a real attacker, deliberately. A real rogue
  extension would not stop at a marker file. We measure reach and accept that
  gap.
- `auth-get-session` now targets a harness-seeded fake provider, so it no longer
  exercises the real GitHub flow. Sentinel behaviour against a real provider
  needs separate, explicitly consented testing.
- The lint is blunt and will produce occasional false positives. That is the
  right trade: a probe needs almost none of the API surface it rejects.

## Verification

`test/containment/probe-safety.test.ts`, 20 assertions, all passing:

- unarmed with no nonce, with env only, and on mismatch; armed only when both
  halves agree;
- refuses `~/.ssh`, `~/.aws`, `/etc/passwd`, `Library/Keychains`;
- refuses a path outside the run directory, a `..` traversal, and a symlink
  pointing out of it;
- accepts the beacon; refuses `https://example.com`, `localhost` by name, the
  wrong port, and the `127.0.0.1:18099.evil.com` prefix trick;
- `markerCommand` emits only a `touch` with no shell metacharacters, and
  refuses a suffix that escapes;
- `SafetyError` is tagged so it cannot be scored as a denial.

The symlink test **failed on first run** and found a real bug: `safePath` had an
`|| inside(resolved)` fallback that accepted the lexical path, which defeated
the symlink check entirely. A symlink inside the run directory pointing at
`/usr/local` was accepted. Fixed to require the resolved location.

`lint_probes.py` reports the two payloads clean against 8 rules, and was
verified to catch an injected real-user path, external host, and chained shell
command.

## Review outcome

A dedicated safety review ([round 3](../security-reviews/20261104-probe-safety.md))
returned **NO-GO** on the first version and found nine issues, including a
working command injection into a real host shell: the marker came from the
hostile workspace and `safePath()` did not reject quotes, so
`markerCommand()` emitted an attacker-chosen command that was typed into a host
terminal. Also a dangling-symlink bypass that turned the one permitted write
into arbitrary host file creation, and an arming gate the tab could satisfy by
itself because the nonce leaked in an environment dump.

The guard and payload findings are fixed; harness-side ones (teardown, the
`core.fsmonitor` disarm, the clipboard) remain open and the run stays no-go
until they close.

## Outstanding

- Teardown and the post-run "nothing outside the run directory changed" check
  are specified in AGENTS.md §8.7 but **not yet implemented**; they belong with
  the harness changes the fork-build session is making for concurrency safety.
- The harness must write `.seclab-probe-nonce` and export `SECLAB_PROBE_NONCE`
  during `prepare`; until it does, the probes are inert, which is the correct
  default.
