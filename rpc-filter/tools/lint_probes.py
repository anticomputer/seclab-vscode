#!/usr/bin/env python3
"""Lint the probe payloads for anything that could harm the host.

The safety module enforces targets at runtime. This lint enforces *shape* at
review time, so a dangerous payload cannot be introduced and then quietly
bypass the guards by not calling them.

It is deliberately blunt. A probe exists to demonstrate reach, so it needs
almost none of the API surface this rejects, and a false positive is cheap
next to shipping a working exploit chain that runs on the user's Mac.

Usage:
    python3 lint_probes.py          # exit 1 on any violation
"""

from __future__ import annotations

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", ".."))

# Files that are probe payloads: they run inside the tab against a real host.
# Everything under test/containment that runs inside or against a tab. Scanned
# as a tree, not a hard-coded pair: the first version listed only the two probe
# files, so extension.js (which dumped the real environment and real auth
# sessions) and probe.sh (which egresses externally) were never linted.
PAYLOAD_ROOT = "test/containment"
PAYLOAD_SUFFIXES = (".js", ".sh")
# The guards legitimately name forbidden paths, in order to refuse them.
# The guards legitimately name forbidden paths in order to refuse them. The
# build-time copies are exempt too, but only because the guard-divergence check
# below proves they are byte-identical to the source.
EXEMPT = (
    "test/containment/probe-safety.js",
    "test/containment/rogue-extension/probe-safety.js",
    "test/containment/rogue-reh/probe-safety.js",
)


def payload_files(repo):
    out = []
    root = os.path.join(repo, PAYLOAD_ROOT)
    for dirpath, dirnames, filenames in os.walk(root):
        # Sorted in place: os.walk reads this list back to pick its descent
        # order, so without it the lint reports findings in filesystem order.
        dirnames[:] = sorted(d for d in dirnames if d not in ("node_modules", "fixtures"))
        for name in sorted(filenames):
            if not name.endswith(PAYLOAD_SUFFIXES):
                continue
            rel = os.path.relpath(os.path.join(dirpath, name), repo)
            if rel in EXEMPT:
                continue
            out.append(rel)
    return out

RULES = (
    # (id, regex, why)
    ("real-user-path",
     re.compile(r"""['"`][^'"`\n]*(?:\.ssh|\.aws|\.gnupg|\.kube|\.netrc|"""
                r"""\.git-credentials|Library/Keychains|/etc/passwd|/etc/shadow)"""),
     "names real user data; probes read only harness-seeded canaries"),
    ("external-host",
     re.compile(r"""['"`]https?://(?!127\.0\.0\.1[:/])[^'"`\s]+"""),
     "names a non-loopback URL; the local beacon is the only allowed destination"),
    ("process-spawn",
     re.compile(r"\b(?:child_process|execFile|execSync|spawnSync|spawn|exec)\s*\("),
     "spawns a process; a probe demonstrates reach, it does not run payloads"),
    ("destructive-fs",
     re.compile(r"\bfs\.(?:rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync|chmod|chmodSync|"
                r"chown|chownSync|rename|renameSync|truncate|truncateSync)\s*\("),
     "destructive or permission-changing filesystem call"),
    ("persistence",
     re.compile(r"LaunchAgents|LaunchDaemons|crontab|\.bashrc|\.zshrc|\.profile|launchctl"),
     "touches a persistence mechanism"),
    ("process-control",
     re.compile(r"\bprocess\.kill\s*\(|\bprocess\.exit\s*\(|\bkillall\b"),
     "kills processes"),
    ("shell-chaining",
     # Only flag a quoted string that actually looks like a command line: a
     # shell verb AND a chaining operator inside the same literal. Matching a
     # bare ` && ` spans ordinary JS (`String(err && err.stack)`).
     re.compile(r"""['"`][^'"`\n]*\b(?:rm|curl|wget|bash|sh|nc|osascript|open|chmod)\b"""
                r"""[^'"`\n]*(?:&&|\|\||;|\|)[^'"`\n]*['"`]"""),
     "chains shell commands; the only permitted command is the marker touch"),
    ("network-client",
     re.compile(r"\brequire\(['\"](?:https?|net|dgram|tls)['\"]\)"),
     "opens its own network client; egress goes to the beacon through the API under test"),
)

# Files that must go through the arming gate. Other scanned files (fixtures
# invoked only inside a tab) still get the content rules.
MUST_ARM = (
    "test/containment/rogue-extension/rpc-probes.js",
    "test/containment/rogue-reh/probes.js",
    "test/containment/rogue-extension/extension.js",
)
# An arming gate must not merely be MENTIONED: the call has to be followed
# closely by a bail-out, so a future edit cannot keep the call while gutting the
# check. Matches `const x = armed(root)` / `safety.context(...)` followed within
# a few lines by continue/return/if (!...).
ARMING_CALL = re.compile(r"(?:safety\.context\(|\barmed\s*\(\s*root\s*\))")
ARMING_BAIL = re.compile(r"\b(?:continue|return)\b|\bif\s*\(\s*!")
# Exemptions are LINE-scoped, never file-scoped. A file-wide exemption covered
# every future base64 use in a 110-line payload that writes its output where the
# attacker reads it; the justification only ever applied to one expression.
# Opt out on the exact line with a pragma:
#     const decoded = Buffer.from(t, 'base64');  // lint-allow: base64-canary-compare
PRAGMA = re.compile(r"//\s*lint-allow:\s*(?P<id>[\w-]+)")
ALLOWED_PRAGMAS = {"base64-canary-compare"}

# Real user sources a probe may read only where the harness seeded a canary first: the
# source expression must be preceded, within a few code lines, by a check of the seeding
# fact that BAILS (throw/return) when it is absent. On 2026-11-09 clipboard-read read the
# user's real clipboard on an unfiltered build because nothing tied the read to the run's
# opt-in; this makes that tie structural rather than a convention.
#   (id, source, guard, why)
GUARDED_SOURCES = (
    ("unseeded-clipboard",
     re.compile(r"\bclipboard\.readText\s*\("),
     re.compile(r"\b(?:targets|arm)\.clipboard\b"),
     "reads the clipboard; only after checking the run seeded it (targets.clipboard / arm.clipboard) and bailing if not"),
    ("unseeded-profile",
     re.compile(r"""scheme:\s*['"]vscode-userdata['"]|['"`]vscode-userdata:"""),
     re.compile(r"\.seclab-test"),
     "names a host profile resource; only the isolated ~/.seclab-test profile the harness launched, checked before use"),
    ("real-keychain",
     re.compile(r"\bkeytar\b|SecKeychain|find-(?:generic|internet)-password|Keychains/"),
     re.compile(r"(?!)"),
     "reads the keychain; no harness seeds it, so no probe may read it"),
)
GUARD_LOOKBACK = 10
GUARD_BAIL = re.compile(r"\bthrow\b|\breturn\b")


def guarded_source_violations(rel: str, code: list) -> list:
    out = []
    for i, (n, line) in enumerate(code):
        for rid, source, guard, why in GUARDED_SOURCES:
            if not source.search(line):
                continue
            window = [l for _, l in code[max(0, i - GUARD_LOOKBACK):i + 1]]
            guarded = any(guard.search(l) for l in window) and any(GUARD_BAIL.search(l) for l in window)
            if not guarded:
                out.append((rel, n, rid, f"{why}\n      {line.strip()[:120]}"))
    return out


def main(argv: list | None = None) -> int:
    # An optional root lints another copy of the tree (how a fixed rule is shown to
    # catch the version it was written against).
    args = sys.argv[1:] if argv is None else argv
    root = os.path.abspath(args[0]) if args else REPO
    violations = []
    payloads = payload_files(root)
    if not payloads:
        # A lint over nothing reports clean; that is a lint that cannot fail.
        violations.append((root, 0, "no-payloads", "found no probe payloads to lint under this root"))
    for rel in payloads:
        path = os.path.join(root, rel)
        if not os.path.isfile(path):
            violations.append((rel, 0, "missing", "payload file not found"))
            continue
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        code = []
        for n, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("#"):
                continue
            code.append((n, line))
            for rid, pattern, why in RULES:
                if pattern.search(line):
                    violations.append((rel, n, rid, f"{why}\n      {stripped[:120]}"))
        # Also match across lines, so a construct split over two lines or built
        # by concatenation does not slip past a line-by-line scan.
        joined = "\n".join(l for _, l in code)
        flat = re.sub(r"['\"]\s*\+\s*['\"]", "", joined)
        for rid, pattern, why in RULES:
            if pattern.search(flat) and not any(v[0] == rel and v[2] == rid for v in violations):
                violations.append((rel, 0, rid, f"{why} (matched after joining lines)"))
        violations.extend(guarded_source_violations(rel, code))
        for n, line in code:
            if "fromCharCode" in line or "'base64'" in line:
                m = PRAGMA.search(line)
                if not m or m.group("id") not in ALLOWED_PRAGMAS:
                    violations.append((rel, n, "obfuscation",
                                       "builds strings via character codes or base64; "
                                       "add `// lint-allow: base64-canary-compare` on this "
                                       "line if it only decodes to compare against a canary"))
        if rel in MUST_ARM:
            gated = False
            for i, (n, line) in enumerate(code):
                if not ARMING_CALL.search(line):
                    continue
                window = "\n".join(l for _, l in code[i:i + 4])
                if ARMING_BAIL.search(window):
                    gated = True
                    break
            if not gated:
                violations.append((rel, 0, "no-arming",
                                   "no arming gate: a safety.context()/armed(root) call must be "
                                   "followed within a few lines by a bail-out"))
        # Any shell command must come from the guard, in this file.
        for n, line in code:
            if "touch '" in line and "markerCommand" not in line:
                violations.append((rel, n, "raw-shell-command",
                                   "builds a shell command without safety.markerCommand()"))

    # Build-time copies of the guard must match the single source exactly.
    src = os.path.join(root, "test/containment/probe-safety.js")
    if os.path.isfile(src):
        with open(src, "rb") as fh:
            want = fh.read()
        for d in ("rogue-extension", "rogue-reh"):
            copy = os.path.join(root, "test/containment", d, "probe-safety.js")
            if os.path.isfile(copy):
                with open(copy, "rb") as fh:
                    if fh.read() != want:
                        violations.append((f"test/containment/{d}/probe-safety.js", 0,
                                           "guard-divergence",
                                           "differs from test/containment/probe-safety.js"))

    if not violations:
        print("probe payloads clean: %d files, %d rules" % (len(payloads), len(RULES)))
        return 0

    for rel, n, rid, why in violations:
        where = f"{rel}:{n}" if n else rel
        print(f"FAIL [{rid}] {where}\n      {why}", file=sys.stderr)
    print(f"\n{len(violations)} violation(s). Probes demonstrate reach; they are "
          f"never payloads. See rpc-filter/AGENTS.md section 8.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
