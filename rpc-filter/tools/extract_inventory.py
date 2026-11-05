#!/usr/bin/env python3
"""Generate the RPC attack-surface inventory from pinned upstream source.

Usage:
    python3 extract_inventory.py --source <vscode-checkout> [--out <dir>]

The upstream SHA is taken from ``upstream.lock`` when it exists, so the
inventory always matches the build. Output is deterministic: run it twice on
the same source and the files are byte-identical, which is what makes the
drift check meaningful.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from seclab_inventory import ai, channels, commands, rpc, tabdata  # noqa: E402
from seclab_inventory.render import render_markdown  # noqa: E402
from seclab_inventory.sources import SourceTree, read_pinned_sha  # noqa: E402

# Used only when upstream.lock is absent. Keep in step with ARCHITECTURE.md.
FALLBACK_SHA = "a717861c07586a53d83b80d742cd3f59b20a6273"

REPO_ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True,
                        help="path to a checkout of microsoft/vscode at the pinned SHA")
    parser.add_argument("--out", default=os.path.join(REPO_ROOT, "rpc-filter", "inventory"),
                        help="output directory")
    parser.add_argument("--sha", default=None,
                        help="override the upstream SHA used for permalinks")
    args = parser.parse_args(argv)

    source = os.path.abspath(args.source)
    if not os.path.isdir(os.path.join(source, "src", "vs")):
        print("error: %s does not look like a vscode checkout" % source, file=sys.stderr)
        return 2

    sha, sha_origin = read_pinned_sha(REPO_ROOT, FALLBACK_SHA)
    if args.sha:
        sha, sha_origin = args.sha, "--sha flag"

    tree = SourceTree(root=source, sha=sha)

    inventory = {
        "schema": 1,
        "upstream_sha": sha,
        "upstream_sha_origin": sha_origin,
        "surfaces": {
            "a_mainthread_rpc": rpc.build(tree),
            "b_command_registry": commands.build(tree),
            "c_client_served_channels": channels.build(tree),
            "d_tab_supplied_data": tabdata.build(tree, REPO_ROOT),
            "e_trusted_ai_surfaces": ai.build(tree),
        },
    }

    os.makedirs(args.out, exist_ok=True)
    json_path = os.path.join(args.out, "inventory.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(inventory, fh, indent=2, sort_keys=True)
        fh.write("\n")

    md_path = os.path.join(args.out, "INVENTORY.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(render_markdown(inventory))

    a = inventory["surfaces"]["a_mainthread_rpc"]
    b = inventory["surfaces"]["b_command_registry"]
    c = inventory["surfaces"]["c_client_served_channels"]
    d = inventory["surfaces"]["d_tab_supplied_data"]
    e = inventory["surfaces"]["e_trusted_ai_surfaces"]
    print("upstream %s (from %s)" % (sha[:12], sha_origin))
    print("  (a) %d MainThread services, %d methods, %d undeclared-but-callable"
          % (a["service_count"], a["method_count"],
             sum(len(s["undeclared_methods"]) for s in a["services"])))
    print("  (b) %d commands, %d unresolved id expressions"
          % (b["command_count"], b["unresolved_count"]))
    print("  (c) %d client-served channels, %d server-initiated callbacks"
          % (c["client_served_channel_count"], c["server_initiated_callback_count"]))
    print("  (d) %d tab-data sink classes over %d sites"
          % (d["upstream_sink_count"], d["upstream_site_count"]))
    print("  (e) %d AI tools (%d may reach the host, %d of those undeclared), "
          "%d agent settings (%d tab-writable)"
          % (e["tool_count"], e["may_reach_host_count"],
             e["may_reach_host_undeclared_count"], e["setting_count"],
             e["tab_writable_setting_count"]))
    print("wrote %s and %s" % (json_path, md_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
