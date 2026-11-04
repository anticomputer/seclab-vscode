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
PAYLOADS = (
    "test/containment/rogue-extension/rpc-probes.js",
    "test/containment/rogue-reh/probes.js",
)
# The guards themselves legitimately name forbidden paths, to refuse them.
EXEMPT = (
    "test/containment/rogue-extension/probe-safety.js",
    "test/containment/rogue-reh/probe-safety.js",
)

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

# The one shell command a probe may build. Anything else that looks like a
# command string must come from safety.markerCommand().
MARKER_OK = re.compile(r"safety\.markerCommand\(")


def main() -> int:
    violations = []
    for rel in PAYLOADS:
        path = os.path.join(REPO, rel)
        if not os.path.isfile(path):
            violations.append((rel, 0, "missing", "payload file not found"))
            continue
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        for n, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue
            for rid, pattern, why in RULES:
                if pattern.search(line):
                    violations.append((rel, n, rid, f"{why}\n      {stripped[:120]}"))
        # Every payload must go through the arming gate.
        body = "\n".join(lines)
        if "safety.context(" not in body:
            violations.append((rel, 0, "no-arming",
                               "payload does not call safety.context(); it would run unarmed"))
        if "touch '" in body and not MARKER_OK.search(body):
            violations.append((rel, 0, "raw-shell-command",
                               "builds a shell command without safety.markerCommand()"))

    if not violations:
        print("probe payloads clean: %d files, %d rules" % (len(PAYLOADS), len(RULES)))
        return 0

    for rel, n, rid, why in violations:
        where = f"{rel}:{n}" if n else rel
        print(f"FAIL [{rid}] {where}\n      {why}", file=sys.stderr)
    print(f"\n{len(violations)} violation(s). Probes demonstrate reach; they are "
          f"never payloads. See rpc-filter/AGENTS.md section 8.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
