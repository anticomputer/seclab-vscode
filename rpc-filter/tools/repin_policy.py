#!/usr/bin/env python3
"""Re-pin the RPC policy to a new upstream commit on an upstream bump.

    python3 rpc-filter/tools/repin_policy.py OLD_SHA NEW_SHA CHANGED_FILES

`policy.json` carries the upstream SHA it was reviewed against and a permalink per evidence
entry. On a bump, the drift check refuses an inventory at the new SHA while the policy claims the
old one. This moves both, and only when it is safe to. Every file a permalink cites must:
  - exist in the fetched upstream tree (.work/upstream/vscode, which must be at NEW_SHA); and
  - be absent from CHANGED_FILES (one path per line, every file the bump changes upstream, e.g.
    from the GitHub compare API), so the cited lines are byte-identical at NEW_SHA.
A cited file the bump changed is listed and nothing is written: re-check those entries by hand.
Run check.sh afterwards, read the diff, then check.sh --accept.
"""

import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
POLICY = os.path.join(ROOT, "rpc-filter", "policy", "policy.json")
UPSTREAM = os.path.join(ROOT, ".work", "upstream", "vscode")
SHA = re.compile(r"^[0-9a-f]{40}$")


def main(argv):
    if len(argv) != 3 or not SHA.match(argv[0]) or not SHA.match(argv[1]):
        print("usage: repin_policy.py OLD_SHA NEW_SHA CHANGED_FILES", file=sys.stderr)
        return 2
    old, new, changed_path = argv
    head = subprocess.run(["git", "-C", UPSTREAM, "rev-parse", "HEAD"], capture_output=True, text=True)
    if head.returncode != 0 or head.stdout.strip() != new:
        print("repin: %s is not at %s (rpc-filter/tools/fetch-upstream.sh)" % (UPSTREAM, new[:12]), file=sys.stderr)
        return 1
    with open(changed_path, encoding="utf-8") as f:
        changed = {line.strip() for line in f if line.strip()}
    if not changed:
        print("repin: the changed-files list is empty; refusing to assume nothing changed", file=sys.stderr)
        return 1
    with open(POLICY, encoding="utf-8") as f:
        text = f.read()
    if json.loads(text).get("upstream_sha") != old:
        print("repin: policy.json is not at %s" % old[:12], file=sys.stderr)
        return 1
    cited = sorted(set(re.findall(r"microsoft/vscode/blob/%s/([^#\s\")\]]+)" % old, text)))
    missing = [p for p in cited if not os.path.isfile(os.path.join(UPSTREAM, p))]
    moved = [p for p in cited if p in changed]
    for p in missing:
        print("repin: cited file gone at %s: %s" % (new[:12], p), file=sys.stderr)
    for p in moved:
        print("repin: cited file changed by the bump (re-check its entries by hand): %s" % p, file=sys.stderr)
    if missing or moved:
        return 1
    out = text.replace(old, new)
    with open(POLICY, "w", encoding="utf-8") as f:
        f.write(out)
    print("repin: policy.json %s -> %s (%d cited files, none changed by the bump; %d SHA occurrences)"
          % (old[:12], new[:12], len(cited), text.count(old)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
