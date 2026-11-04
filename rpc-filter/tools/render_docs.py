#!/usr/bin/env python3
"""Render the generated regions of the RPC-lockdown docs, and check for drift.

Prose is written by hand; every number, table and list that restates the
inventory, the policy table or the probe registry is generated from them. A doc
that restates data by hand is a doc that will disagree with the data, usually
right after an upstream bump, and usually without anyone noticing.

Regions are delimited in Markdown by HTML comments, so they render invisibly:

    <!-- seclab:begin surface-counts -->
    ...generated...
    <!-- seclab:end surface-counts -->

Usage:
    python3 render_docs.py --check    # exit 1 and show what differs
    python3 render_docs.py --write    # update the files in place

``--check`` is the CI gate. ``--write`` is what you run after regenerating the
inventory, in the same commit as the change that moved the numbers.
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", ".."))

INVENTORY = os.path.join(REPO, "rpc-filter", "inventory", "inventory.json")
POLICY = os.path.join(REPO, "rpc-filter", "policy", "policy.json")
COVERAGE = os.path.join(REPO, "rpc-filter", "policy", "coverage.json")
EXPECTATIONS = os.path.join(REPO, "rpc-filter", "probes", "expectations.json")

TARGETS = (
    os.path.join(REPO, "docs", "RPC-LOCKDOWN.md"),
    os.path.join(REPO, "rpc-filter", "AGENTS.md"),
)

BEGIN = re.compile(r"^(?P<indent>[ \t]*)<!-- seclab:begin (?P<name>[\w-]+) -->$", re.M)


def _load(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _verdict(value: str) -> str:
    """coverage.json pins reachable entries as 'verdict#hash'."""
    return value.split("#", 1)[0]


# --------------------------------------------------------------------- blocks

def block_surface_counts(ctx) -> list:
    inv = ctx["inventory"]
    a = inv["surfaces"]["a_mainthread_rpc"]
    b = inv["surfaces"]["b_command_registry"]
    c = inv["surfaces"]["c_client_served_channels"]
    d = inv["surfaces"]["d_tab_supplied_data"]
    return [
        "| | Surface | Size at this pin |",
        "|---|---|---|",
        "| (a) | `MainThread*` RPC the extension host calls | %d services, %d methods |"
        % (a["service_count"], a["method_count"]),
        "| (b) | The command registry reachable via `$executeCommand` | %d ids |"
        % b["command_count"],
        "| (c) | Channels the client serves to the server, and server-initiated callbacks | %d channels, %d callback sites |"
        % (c["client_served_channel_count"], c["server_initiated_callback_count"]),
        "| (d) | Tab-supplied data the trusted side interprets with authority | %d sink classes over %d sites |"
        % (d["upstream_sink_count"], d["upstream_site_count"]),
    ]


def block_baseline(ctx) -> list:
    mapping = ctx["coverage"]["mapping"]
    reachable = {k: _verdict(v) for k, v in mapping.items() if _verdict(v) != "deny"}
    counts = {}
    for v in reachable.values():
        counts[v] = counts.get(v, 0) + 1
    summary = ", ".join("%d %s" % (n, v) for v, n in sorted(counts.items()))
    return [
        "Current baseline at `%s`: **%d surfaces, %d denied, %d not denied** (%s)."
        % (ctx["inventory"]["upstream_sha"][:12], len(mapping),
           len(mapping) - len(reachable), len(reachable), summary),
    ]


def block_reachable(ctx) -> list:
    mapping = ctx["coverage"]["mapping"]
    rows = sorted((k, _verdict(v)) for k, v in mapping.items() if _verdict(v) != "deny")
    out = [
        "Every surface below is reachable from a tab. Each one has an entry in",
        "`policy/policy.json` with an impact assessment; the drift check fails if",
        "any becomes reachable without one.",
        "",
        "| Surface | Verdict |",
        "|---|---|",
    ]
    out += ["| `%s` | %s |" % (k, v) for k, v in rows]
    return out


def block_probes(ctx) -> list:
    exp = ctx["expectations"]
    out = [
        "| Probe | Fixture | Policy entry | Patched expectation |",
        "|---|---|---|---|",
    ]
    for fixture, key in (("rogue extension", "probes"), ("rogue REH", "rehProbes")):
        for pid, spec in sorted(exp[key].items()):
            if not isinstance(spec, dict):
                continue
            out.append("| `%s` | %s | `%s` | %s |" % (
                pid, fixture, spec.get("policyRef", "?"),
                spec.get("patchedOutcome", "denied")))
    return out


def block_invariants(ctx) -> list:
    out = []
    for inv in ctx["policy"]["invariants"]:
        out.append("%d. **%s** — %s" % (
            len(out) + 1, inv["id"], inv["statement"]))
    return out


BLOCKS = {
    "surface-counts": block_surface_counts,
    "baseline": block_baseline,
    "reachable": block_reachable,
    "probes": block_probes,
    "invariants": block_invariants,
}


# --------------------------------------------------------------------- render

def render(text: str, ctx) -> str:
    """Replace the body of every generated region.

    Each region is located afresh in the string being built, not in the
    original. Iterating matches from the original while mutating a copy makes
    the offsets drift as soon as a replacement changes length, which silently
    eats the next marker.
    """
    out = text
    pos = 0
    while True:
        m = BEGIN.search(out, pos)
        if not m:
            return out
        name = m.group("name")
        if name not in BLOCKS:
            raise SystemExit("unknown generated block: %s" % name)
        end_marker = "<!-- seclab:end %s -->" % name
        end_idx = out.find(end_marker, m.end())
        if end_idx < 0:
            raise SystemExit("unterminated block: %s" % name)
        body = "\n" + "\n".join(BLOCKS[name](ctx)) + "\n"
        out = out[:m.end()] + body + out[end_idx:]
        pos = m.end() + len(body) + len(end_marker)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true")
    group.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)

    for path in (INVENTORY, POLICY, COVERAGE, EXPECTATIONS):
        if not os.path.isfile(path):
            print("error: %s missing; regenerate the inventory first" % path,
                  file=sys.stderr)
            return 2

    ctx = {
        "inventory": _load(INVENTORY),
        "policy": _load(POLICY),
        "coverage": _load(COVERAGE),
        "expectations": _load(EXPECTATIONS),
    }
    if ctx["inventory"]["upstream_sha"] != ctx["policy"]["upstream_sha"]:
        print("error: inventory and policy disagree on the upstream SHA",
              file=sys.stderr)
        return 2

    drifted = []
    for path in TARGETS:
        if not os.path.isfile(path):
            continue
        with open(path, "r", encoding="utf-8") as fh:
            original = fh.read()
        updated = render(original, ctx)
        if original == updated:
            continue
        if args.write:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(updated)
            print("updated %s" % os.path.relpath(path, REPO))
        else:
            drifted.append((path, original, updated))

    if args.write:
        return 0

    if not drifted:
        print("docs are in sync with the inventory, policy and probe registry")
        return 0

    for path, original, updated in drifted:
        rel = os.path.relpath(path, REPO)
        print("FAIL %s is out of date" % rel, file=sys.stderr)
        for line in difflib.unified_diff(
                original.splitlines(), updated.splitlines(),
                fromfile="%s (committed)" % rel, tofile="%s (generated)" % rel,
                lineterm="", n=1):
            print("  %s" % line, file=sys.stderr)
    print("\nRun rpc-filter/tools/docs.sh --write, in the same commit as the "
          "change that moved the numbers.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
