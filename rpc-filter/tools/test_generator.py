#!/usr/bin/env python3
"""Tests for the inventory generator's determinism and constant resolution.

Run via rpc-filter/tools/test.sh (containerised, standard library only).

Why this exists
---------------
The generator feeds the policy table, and the policy *category* of a command is
derived from its id. So anything that can change an id can silently change a
security classification. Two defects did exactly that:

* ``os.walk`` yields directories in filesystem order, which differs between
  APFS and ext4, so the inventory was not reproducible across machines;
* constants were indexed in a flat tree-wide namespace keyed by bare
  identifier, with first-definition-wins, so whichever file the walk reached
  first decided a command's identity. 451 names upstream have more than one
  distinct value, and a surface moved into ``secrets-and-auth`` purely because
  of directory iteration order.

Sorting alone would only have frozen an arbitrary choice. These tests pin the
property that matters: the output depends on the *source*, not on the order it
was read in, and the generator refuses to invent an identity it cannot
determine.

Each test that asserts "X is stable" is paired with a negative control showing
the test can actually fail, because a determinism check that would pass against
the buggy implementation proves nothing.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from seclab_inventory import commands as C
from seclab_inventory.sources import SourceTree


def _write(root: str, rel: str, text: str) -> None:
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


class _ReversedWalk:
    """Context manager making ``os.walk`` yield directories in reverse order.

    Stands in for a filesystem that enumerates differently from the one the
    inventory was committed on. ``SourceTree.walk`` sorts ``dirnames`` in
    place, so a correct generator is unaffected.
    """

    def __init__(self, module):
        self.module = module
        self.real = module.os.walk

    def __enter__(self):
        real = self.real

        def walk(top, *a, **kw):
            for dirpath, dirnames, filenames in real(top, *a, **kw):
                dirnames.sort(reverse=True)
                filenames = list(reversed(filenames))
                yield dirpath, dirnames, filenames

        self.module.os.walk = walk
        return self

    def __exit__(self, *exc):
        self.module.os.walk = self.real
        return False


class FixtureTree(unittest.TestCase):
    """A small synthetic tree exercising the ambiguity that broke upstream."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="seclab-gen-test-")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

        # Two unrelated modules each define a class named GotoAction with a
        # different ID, and each registers it. Upstream really does this.
        _write(self.root, "src/vs/aaa/first.ts", """
export class GotoAction {
\tstatic readonly ID = 'editor.action.first';
}
CommandsRegistry.registerCommand({ id: GotoAction.ID, handler: () => {} });
""")
        _write(self.root, "src/vs/zzz/second.ts", """
export class GotoAction {
\tstatic readonly ID = 'workbench.action.second';
}
CommandsRegistry.registerCommand({ id: GotoAction.ID, handler: () => {} });
""")
        # A third file imports one of them, so resolution must follow the
        # import rather than guess.
        _write(self.root, "src/vs/mmm/third.ts", """
import { GotoAction } from '../aaa/first.js';
CommandsRegistry.registerCommand({ id: GotoAction.ID, handler: () => {} });
""")
        # A genuinely undeterminable name: same file, two values.
        _write(self.root, "src/vs/mmm/murky.ts", """
function a() {
\tconst commandId = 'murky.one';
\tCommandsRegistry.registerCommand({ id: commandId, handler: () => {} });
}
function b() {
\tconst commandId = 'murky.two';
\tCommandsRegistry.registerCommand({ id: commandId, handler: () => {} });
}
""")
        os.makedirs(os.path.join(self.root, "extensions"), exist_ok=True)
        self.tree = SourceTree(root=self.root, sha="test")

    def build(self):
        return C.build(SourceTree(root=self.root, sha="test"))

    def ids(self, built):
        return sorted(c["id"] for c in built["commands"])

    # -- resolution correctness -------------------------------------------

    def test_same_name_in_two_files_resolves_to_both_values(self):
        """Per use site, not per name: each file means its own constant."""
        ids = self.ids(self.build())
        self.assertIn("editor.action.first", ids)
        self.assertIn("workbench.action.second", ids)

    def test_resolution_follows_imports(self):
        """third.ts imports from first.ts, so it must not pick second.ts."""
        built = self.build()
        entry = next(c for c in built["commands"] if c["id"] == "editor.action.first")
        self.assertIn("src/vs/mmm/third.ts", entry["files"])
        other = next(c for c in built["commands"] if c["id"] == "workbench.action.second")
        self.assertNotIn("src/vs/mmm/third.ts", other["files"])

    def test_refuses_to_guess_when_undeterminable(self):
        """Two values for one name in one file: report it, do not pick one."""
        built = self.build()
        ids = self.ids(built)
        self.assertNotIn("murky.one", ids)
        self.assertNotIn("murky.two", ids)
        self.assertTrue(
            built["unresolved_reasons"].get("commandId", "").startswith("ambiguous"),
            "an undeterminable id must be reported as ambiguous work, not "
            "silently resolved: %r" % built["unresolved_reasons"])

    # -- determinism -------------------------------------------------------

    def test_output_is_identical_under_reversed_filesystem_order(self):
        first = json.dumps(self.build(), sort_keys=True)
        with _ReversedWalk(C):
            second = json.dumps(self.build(), sort_keys=True)
        self.assertEqual(first, second,
                         "inventory changed when the filesystem enumerated "
                         "directories in a different order")

    def test_reversed_walk_control_detects_an_unsorted_generator(self):
        """Negative control: the harness must be able to see order leaking.

        Without this, ``test_output_is_identical...`` could pass simply because
        the reversal never reached the generator.
        """
        seen = []
        with _ReversedWalk(C):
            for rel in SourceTree(root=self.root, sha="t").walk("src/vs"):
                seen.append(rel)
        # walk() sorts, so order is ascending despite the reversal above.
        self.assertEqual(seen, sorted(seen))

        # And with the sort removed, the reversal is observable -- proving the
        # control is wired to something real.
        raw = []
        for dirpath, dirnames, filenames in C.os.walk(os.path.join(self.root, "src/vs")):
            for n in filenames:
                raw.append(os.path.join(dirpath, n))
        self.assertNotEqual(raw, sorted(raw),
                            "reversed walk produced sorted output; the control "
                            "is not exercising what it claims to")

    def test_flat_first_wins_index_would_have_been_order_dependent(self):
        """Pin the defect itself, so a regression to it is caught.

        Reproduces the old algorithm -- one flat ``name -> value`` map with
        ``setdefault`` -- and shows it yields different ids under different
        walk orders on this very fixture.
        """
        def flat_index(tree):
            out = {}
            for rel in tree.walk("src/vs"):
                text = tree.text(rel)
                for m in C.re.finditer(
                        r"(?P<name>[A-Za-z_$][\w$]*)\s*=\s*'(?P<val>[^'\n]*)'", text):
                    out.setdefault("GotoAction." + m.group("name"), m.group("val"))
            return out.get("GotoAction.ID")

        forward = flat_index(SourceTree(root=self.root, sha="t"))
        with _ReversedWalk(C):
            # Bypass walk()'s sort the way the old code was exposed to it.
            def unsorted_walk(self_, subdir, suffixes=(".ts",)):
                for dirpath, dirnames, filenames in C.os.walk(self_.path(subdir)):
                    for name in filenames:
                        if name.endswith(suffixes) and not name.endswith(".d.ts"):
                            yield os.path.relpath(
                                os.path.join(dirpath, name), self_.root)
            original = SourceTree.walk
            SourceTree.walk = unsorted_walk
            try:
                backward = flat_index(SourceTree(root=self.root, sha="t"))
            finally:
                SourceTree.walk = original

        self.assertNotEqual(
            forward, backward,
            "the fixture no longer reproduces the first-wins bug, so the "
            "determinism tests above are not constraining anything")


class RealTreeDeterminism(unittest.TestCase):
    """Double-run over the pinned upstream checkout, when one is present.

    Skipped when the source is absent so the fast tests still run anywhere;
    CI fetches upstream for the inventory job, so it runs there.
    """

    SRC = os.environ.get("SECLAB_UPSTREAM", "/src")

    def test_full_inventory_is_order_independent(self):
        if not os.path.isdir(os.path.join(self.SRC, "src/vs")):
            self.skipTest("no upstream checkout at %s" % self.SRC)
        tree = SourceTree(root=self.SRC, sha="x")
        first = json.dumps(C.build(tree), sort_keys=True)
        with _ReversedWalk(C):
            second = json.dumps(C.build(SourceTree(root=self.SRC, sha="x")),
                                sort_keys=True)
        self.assertEqual(first, second,
                         "the real inventory is not reproducible across "
                         "filesystem orderings")


if __name__ == "__main__":
    unittest.main(verbosity=2)
