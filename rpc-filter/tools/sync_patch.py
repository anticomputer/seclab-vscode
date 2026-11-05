#!/usr/bin/env python3
"""Keep the patch queue's embedded sources in sync with rpc-filter/patch-src.

The filter's TypeScript lives twice: as editable source under
``rpc-filter/patch-src/`` and as a new-file hunk inside the patch that ships it.
Nothing connected the two, so editing the source -- or regenerating
``seclabPolicyData.ts`` after a policy change -- left the patch shipping the
previous content. ``build/apply-patches.sh --check`` does not catch that: it
verifies the patch *applies*, not that it carries what we think it carries.

That is the project's recurring failure mode, a gate that passes because it
never asked the question, so this adds the question:

    rpc-filter/tools/sync_patch.py --check   # fail when the patch is stale
    rpc-filter/tools/sync_patch.py --write   # regenerate from patch-src

Only whole-new-file sections are handled. A section that patches an existing
upstream file has no single source of truth here and is left alone.
"""

from __future__ import annotations

import argparse
import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

# Target path inside the patch -> editable source in the repo.
MAPPING = {
    "src/vs/workbench/services/extensions/common/seclabPolicyData.ts":
        "rpc-filter/patch-src/seclabPolicyData.ts",
    "src/vs/workbench/services/extensions/common/seclabRpcFilter.ts":
        "rpc-filter/patch-src/seclabRpcFilter.ts",
}

PATCH_DIR = os.path.join(REPO, "patches")
NEW_FILE_MARK = "1969-12-31"


def _split_sections(lines: list) -> list:
    """Split a patch into (header_index, lines) sections on ``diff -ruN``."""
    out, cur = [], []
    for line in lines:
        if line.startswith("diff -ruN ") and cur:
            out.append(cur)
            cur = [line]
        else:
            cur.append(line)
    if cur:
        out.append(cur)
    return out


def _target_of(section: list) -> str | None:
    for line in section[:4]:
        if line.startswith("+++ b/"):
            return line[6:].split("\t")[0].strip()
    return None


def _is_new_file(section: list) -> bool:
    return any(line.startswith("--- a/") and NEW_FILE_MARK in line
               for line in section[:4])


def _rebuild(section: list, source_rel: str) -> list:
    """Rebuild a new-file section's hunk from the current source file."""
    with open(os.path.join(REPO, source_rel), "r", encoding="utf-8") as fh:
        body = fh.read().split("\n")
    if body and body[-1] == "":
        body.pop()  # trailing newline is implicit in the diff body

    head = []
    for line in section:
        head.append(line)
        if line.startswith("+++ b/"):
            break

    hunk = ["@@ -0,0 +1,%d @@" % len(body)] + ["+" + line for line in body]
    return head + hunk


def process(write: bool) -> int:
    problems = []
    for name in sorted(os.listdir(PATCH_DIR)):
        if not name.endswith(".patch"):
            continue
        path = os.path.join(PATCH_DIR, name)
        with open(path, "r", encoding="utf-8") as fh:
            original = fh.read()
        lines = original.split("\n")
        trailing_nl = original.endswith("\n")
        if trailing_nl:
            lines.pop()

        changed = False
        rebuilt_sections = []
        for section in _split_sections(lines):
            target = _target_of(section)
            source = MAPPING.get(target) if target else None
            if source and _is_new_file(section):
                fresh = _rebuild(section, source)
                if fresh != section:
                    changed = True
                    problems.append((name, target, source))
                section = fresh
            rebuilt_sections.append(section)

        if changed and write:
            body = "\n".join(line for sec in rebuilt_sections for line in sec)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(body + ("\n" if trailing_nl else ""))

    if not problems:
        print("patch sources in sync with rpc-filter/patch-src")
        return 0

    if write:
        for name, target, source in problems:
            print("regenerated %s from %s (in %s)" % (target, source, name))
        return 0

    print("FAIL: the patch queue is stale with respect to rpc-filter/patch-src.")
    for name, target, source in problems:
        print("  %s ships an outdated %s; source is %s" % (name, target, source))
    print("Run rpc-filter/tools/sync_patch.py --write (or emit.sh, which calls it).")
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--write", action="store_true")
    args = ap.parse_args()
    return process(write=args.write)


if __name__ == "__main__":
    sys.exit(main())
