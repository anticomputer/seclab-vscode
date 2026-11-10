"""The probe-safety lint's guarded-source rule must fail an unseeded read of a real user source.

Run: python3 -m unittest test_lint_probes  (from rpc-filter/tools)

On 2026-11-09 clipboard-read read the user's real clipboard on an unfiltered build: nothing
tied the read to the run's opt-in. These tests hold the rule that now does, in both
directions: the unguarded shape fails, the guarded shape passes.
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lint_probes as L  # noqa: E402


def code(*lines):
    return list(enumerate(lines, start=1))


class GuardedSourceTest(unittest.TestCase):
    def ids(self, *lines):
        return [v[2] for v in L.guarded_source_violations("x.js", code(*lines))]

    def test_an_unguarded_clipboard_read_fails(self):
        # The shape that read the user's clipboard.
        self.assertEqual(self.ids("() => vscode.env.clipboard.readText());"),
                         ["unseeded-clipboard"])

    def test_a_guard_that_does_not_bail_fails(self):
        self.assertEqual(self.ids("const seeded = targets.clipboard === '1';",
                                  "const v = await vscode.env.clipboard.readText();"),
                         ["unseeded-clipboard"])

    def test_a_seeded_and_bailing_clipboard_read_passes(self):
        self.assertEqual(self.ids("if (targets.clipboard !== '1') {",
                                  "  throw new safety.SafetyError('not seeded');",
                                  "}",
                                  "return await vscode.env.clipboard.readText();"), [])

    def test_a_profile_resource_outside_the_isolated_profile_fails(self):
        self.assertEqual(self.ids("Uri.parse('vscode-userdata:/User/settings.json')"),
                         ["unseeded-profile"])

    def test_a_profile_resource_anchored_to_the_isolated_profile_passes(self):
        self.assertEqual(self.ids("if (!/\\/\\.seclab-test\\//.test(targets.userdata)) {",
                                  "  throw new Error('no isolated profile');",
                                  "}",
                                  "return Uri.from({ scheme: 'vscode-userdata', path: p });"), [])

    def test_the_keychain_is_never_readable(self):
        self.assertEqual(self.ids("// .seclab-test", "return keytar.getPassword('a', 'b');"),
                         ["real-keychain"])

    def test_the_shipped_payloads_are_clean(self):
        self.assertEqual(L.main([]), 0)

    def test_a_root_with_no_payloads_fails_rather_than_passing_vacuously(self):
        # The first version of this test passed while linting 0 files (it read
        # unittest's own argv as the root).
        self.assertEqual(L.main([os.path.dirname(os.path.abspath(__file__))]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
