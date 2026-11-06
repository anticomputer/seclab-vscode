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
import re
import re
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


def _exported_symbols(rel: str) -> list:
    """Exported `seclab*` function names declared in a patch-src file."""
    with open(os.path.join(REPO, rel), "r", encoding="utf-8") as fh:
        text = fh.read()
    return re.findall(r"^export function (seclab\w+)", text, re.M)


def _patch_added_text() -> str:
    """Lines the patch queue adds to *upstream* files.

    Sections that ship our own `patch-src` files are skipped. Including them
    would make this check vacuous: patch 0005 carries the whole filter module
    as a new-file hunk, so every exported symbol would find its own
    declaration in the added text and appear to have a caller. The first
    version of this check did exactly that and passed with the caller removed
    -- which is the same failure it was written to catch, one level up.
    """
    chunks = []
    for name in sorted(os.listdir(PATCH_DIR)):
        if not name.endswith(".patch"):
            continue
        path = os.path.join(PATCH_DIR, name)
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.read().split("\n")
        for section in _split_sections(lines):
            target = _target_of(section)
            if target and target in MAPPING:
                continue
            for line in section:
                if line.startswith("+") and not line.startswith("+++"):
                    chunks.append(line[1:] + "\n")
    return "".join(chunks)


# Entry points with no in-tree caller by design.
#
# Each entry declares a `consumer`: a repo-relative file that must exist and
# must mention the symbol, or None for "nothing consumes this yet", with the
# reason why that is the intended state.
#
# It used to be a bare string of prose. `seclabOnDecision` carried "consumed by
# the Tab Manager, outside the patched tree", and no Tab Manager file referenced
# it -- the whole decision stream had no consumer, so no filter denial was
# observable anywhere, and this exemption is what stopped the gate asking. An
# exemption is a claim that something is fine; an unverified claim in an
# exemption is strictly worse than no check, because it reads as having been
# checked.
CALLER_EXEMPT = {
    "seclabOnDecision": {
        "consumer": None,
        "reason": "NOTHING consumes this yet. The previous entry claimed the "
                  "Tab Manager did; no file referenced the symbol. Until the "
                  "denial log registers a listener in the patched tree, filter "
                  "denials are recorded in memory and observed by nobody.",
    },
    "seclabTaintEscapes": {
        "consumer": None,
        "reason": "NOTHING reads this yet. The previous entry claimed the probe "
                  "suite did; no test references the symbol. So a laundering "
                  "attempt caught by the backstop is recorded in an array and "
                  "seen by nobody -- the same gap as seclabOnDecision, found by "
                  "this gate on its first run. The denial log is the intended "
                  "consumer for both.",
    },
    "seclabRegisterRewrite": {
        "consumer": None,
        "reason": "called by a rewrite implementation; none ships yet, and the "
                  "absence is what makes rewrites deny",
    },
}


def _check_exemptions() -> list:
    """An exemption naming a consumer must name one that exists and refers to it.

    Verifying the claim is the whole point: the gate it suppresses is the one
    that catches code which ships, type-checks and never runs.
    """
    errors = []
    for symbol, entry in CALLER_EXEMPT.items():
        if not isinstance(entry, dict) or "consumer" not in entry \
                or not entry.get("reason"):
            errors.append(
                "CALLER_EXEMPT[%s] must be a dict with 'consumer' (a path or "
                "None) and 'reason'." % symbol)
            continue
        consumer = entry["consumer"]
        if consumer is None:
            continue
        path = os.path.join(REPO, consumer)
        if not os.path.exists(path):
            errors.append(
                "CALLER_EXEMPT[%s] names consumer %s, which does not exist. "
                "Point it at a real file, or set consumer=None and say so."
                % (symbol, consumer))
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            if symbol not in fh.read():
                errors.append(
                    "CALLER_EXEMPT[%s] names consumer %s, which never mentions "
                    "it. The exemption asserts something that is not true."
                    % (symbol, consumer))
    return errors


_IMPORT_BLOCK = re.compile(r"^\s*import\s[\s\S]*?from\s*['\"][^'\"]+['\"]\s*;?\s*$", re.M)


def _without_imports(text: str) -> str:
    """Drop import statements.

    An import names a symbol without using it, and an entry point that is
    imported but never invoked is precisely the dead mechanism this check is
    looking for.
    """
    return _IMPORT_BLOCK.sub("", text)


def check_callers() -> list:
    """Every exported `seclab*` entry point must have a caller, or an exemption.

    This project's recurring failure is a mechanism that type-checks, reviews
    well and is never invoked: `seclabRegisterTab` left `seclabFilterFor`
    throwing for every tab, and the whole command taint was dead because
    nothing routed `$executeCommand` into it. Both passed every gate, because
    no gate asked whether anything called them.

    A symbol counts as called if it is referenced outside the file that
    declares it -- in another patch-src file, or in a line the patch queue adds
    to an upstream file. An entry point that genuinely has no in-tree caller
    belongs in CALLER_EXEMPT with the reason, so the claim is visible rather
    than assumed.
    """
    errors = []
    errors.extend(_check_exemptions())

    added = _patch_added_text()
    sources = sorted(set(MAPPING.values()))
    texts = {}
    for rel in sources:
        with open(os.path.join(REPO, rel), "r", encoding="utf-8") as fh:
            texts[rel] = fh.read()

    for rel in sources:
        for symbol in _exported_symbols(rel):
            if symbol in CALLER_EXEMPT:
                continue
            elsewhere = "".join(t for r, t in texts.items() if r != rel)
            haystack = _without_imports(elsewhere) + "\n" + _without_imports(added)
            # A bare word, not `symbol(`: passing an entry point as a value --
            # `seclabFilterFor(authority, seclabResolveTabId)` -- is a use, and
            # requiring a call shape missed exactly that.
            if re.search(r"\b%s\b" % re.escape(symbol), haystack):
                continue
            errors.append(
                "%s exports %s, but nothing calls it. An entry point with no "
                "caller is the failure this check exists for: it type-checks, "
                "reviews well and never runs. Wire it, delete it, or add it to "
                "CALLER_EXEMPT with the reason." % (rel, symbol))
    return errors


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

    caller_errors = [] if write else check_callers()

    if not problems and not caller_errors:
        print("patch sources in sync with rpc-filter/patch-src; "
              "every seclab entry point has a caller")
        return 0

    if caller_errors and not write:
        print("FAIL: dead entry points in the patch queue.")
        for e in caller_errors:
            print("  " + e)
        if not problems:
            return 1

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
