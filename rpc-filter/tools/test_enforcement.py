"""The enforcement gate must fail when a deny verdict has no code behind it.

Run: python3 -m unittest test_enforcement  (from rpc-filter/tools)

These tests exist because the project kept shipping gates that passed by never
asking the question. ``remoteTerminal.onExecuteCommand`` was denied in the
policy, skipped by a name-based exemption in ``check_drift.py``, and enforced
nowhere, while the increment claimed a tab could not execute host code.

So every test here injects the defect the gate claims to catch and requires a
non-zero result. A gate is only worth the line it occupies if it has been seen
to fail.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import check_drift as CD  # noqa: E402


class EnforcementGateTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="seclab-enf-test-")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        os.makedirs(os.path.join(self.root, "patches"))
        self._patch("0005-filter.patch", "function checkRpc(...) { }")
        self._series(["0005-filter.patch"])
        self.mapping = {"rpc:x.$y": "deny", "rpc:x.$z": "allow#abc123"}
        self.policy = {"enforcement": {
            "note": "...",
            "rpc:": {"mechanism": "the choke point",
                     "patch": "0005-filter.patch", "symbol": "checkRpc"}}}

    def _patch(self, name, body):
        with open(os.path.join(self.root, "patches", name), "w") as fh:
            fh.write(body)

    def _series(self, names):
        with open(os.path.join(self.root, "patches", "series"), "w") as fh:
            fh.write("\n".join(names) + "\n")

    def run_gate(self):
        return CD.check_enforcement(self.mapping, self.policy, self.root)

    def test_control_a_wired_up_policy_passes(self):
        # Without this, every test below could be passing for the wrong reason.
        self.assertEqual(self.run_gate(), [])

    def test_a_denied_surface_with_no_enforcement_entry_fails(self):
        self.mapping["push:ch:$onExecuteCommand"] = "deny"
        errors = self.run_gate()
        self.assertTrue(errors)
        self.assertIn("push:ch:$onExecuteCommand", errors[0])

    def test_a_symbol_missing_from_the_patch_fails(self):
        # The rename case: enforcement moved, the entry went stale, and the
        # verdict quietly stopped being enforced.
        self.policy["enforcement"]["rpc:"]["symbol"] = "checkRpcRenamedAway"
        errors = self.run_gate()
        self.assertTrue(errors)
        self.assertIn("checkRpcRenamedAway", errors[0])

    def test_a_patch_missing_from_the_series_fails(self):
        # The patch exists on disk but nothing applies it, so the code never
        # reaches the build. This is a real failure mode: 0011 sat unapplied.
        self._patch("0099-orphan.patch", "function checkRpc() { }")
        self.policy["enforcement"]["rpc:"]["patch"] = "0099-orphan.patch"
        errors = self.run_gate()
        self.assertTrue(errors)
        self.assertIn("not in patches/series", errors[0])

    def test_a_patch_that_does_not_exist_fails(self):
        self._series(["0005-filter.patch", "0098-ghost.patch"])
        self.policy["enforcement"]["rpc:"]["patch"] = "0098-ghost.patch"
        errors = self.run_gate()
        self.assertTrue(errors)
        self.assertIn("does not exist", errors[0])

    def test_an_entry_missing_patch_or_symbol_fails(self):
        self.policy["enforcement"]["rpc:"] = {"mechanism": "hand waving"}
        self.assertTrue(self.run_gate())

    def test_allow_verdicts_need_no_enforcement_point(self):
        # Only deny makes a claim that code must back up. An allow that is
        # simply not refused needs nothing, and demanding an entry for it would
        # push people to write fictional ones.
        self.mapping = {"push:ch:$onProcessData": "allow#deadbeef"}
        self.policy["enforcement"] = {"note": "..."}
        self.assertEqual(self.run_gate(), [])

    def test_the_longest_matching_prefix_wins(self):
        # 'ai-tool:' and 'ai-setting:' must not be satisfied by a shorter
        # prefix that happens to match first.
        self.mapping = {"ai-setting:chat.foo": "deny"}
        self.policy["enforcement"]["ai-"] = {
            "mechanism": "too broad", "patch": "0005-filter.patch",
            "symbol": "checkRpc"}
        self.policy["enforcement"]["ai-setting:"] = {
            "mechanism": "the real one", "patch": "0005-filter.patch",
            "symbol": "seclabAiDisabled"}
        errors = self.run_gate()
        self.assertTrue(errors, "the specific prefix's symbol is absent, so it "
                                "must fail rather than match the broad one")
        self.assertIn("seclabAiDisabled", errors[0])


class RealPolicyEnforcementTest(unittest.TestCase):
    """The shipped policy must satisfy its own gate."""

    def test_the_committed_policy_has_every_deny_enforced(self):
        import json
        root = CD.REPO_ROOT
        with open(os.path.join(root, "rpc-filter", "policy",
                               "policy.json"), encoding="utf-8") as fh:
            policy = json.load(fh)
        with open(os.path.join(root, "rpc-filter", "inventory",
                               "inventory.json"), encoding="utf-8") as fh:
            inv = json.load(fh)
        mapping = CD.build_mapping(inv, policy)
        self.assertEqual(CD.check_enforcement(mapping, policy, root), [])

    def test_server_initiated_pushes_are_in_the_digest(self):
        # The exemption that hid them was by name, so a test that only counts
        # entries would not have caught it. Name the key that was missing.
        import json
        root = CD.REPO_ROOT
        with open(os.path.join(root, "rpc-filter", "policy",
                               "policy.json"), encoding="utf-8") as fh:
            policy = json.load(fh)
        with open(os.path.join(root, "rpc-filter", "inventory",
                               "inventory.json"), encoding="utf-8") as fh:
            inv = json.load(fh)
        mapping = CD.build_mapping(inv, policy)
        self.assertEqual(mapping.get("push:remoteterminal:$onExecuteCommand"),
                         "deny")
        self.assertGreaterEqual(
            sum(1 for k in mapping if k.startswith("push:")), 20)


if __name__ == "__main__":
    unittest.main(verbosity=2)
