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
            "rpc:": {"mechanism": "the choke point", "whole_class": True,
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

    def test_a_prefix_without_whole_class_does_not_vouch_for_its_keys(self):
        self.policy["enforcement"]["rpc:"].pop("whole_class")
        errors = self.run_gate()
        self.assertTrue(errors, "a prefix entry must opt in to standing for "
                                "every key beneath it")

    def test_push_cannot_buy_the_whole_class_exemption(self):
        # The review's finding, injected back in: one `push:` entry naming the
        # patch that disables ONE subscription, vouching for all of them. When
        # this rule lived in a flag the injection simply set the flag and
        # passed, so the class list is now structural.
        self.mapping = {"push:a:$x": "deny", "push:b:$y": "deny"}
        self.policy["enforcement"]["push:"] = {
            "mechanism": "one entry for the class", "whole_class": True,
            "patch": "0005-filter.patch", "symbol": "checkRpc"}
        errors = self.run_gate()
        self.assertTrue(errors)
        self.assertTrue(any("whole_class" in e for e in errors), errors)

    def test_each_denied_push_needs_its_own_entry(self):
        self.mapping = {"push:a:$x": "deny"}
        self.policy["enforcement"]["push:"] = {
            "mechanism": "not a whole-class control", "whole_class": False}
        self.assertTrue(self.run_gate())
        self.policy["enforcement"]["push:a:$x"] = {
            "mechanism": "not registered", "patch": "0005-filter.patch",
            "symbol": "checkRpc"}
        self.assertEqual(self.run_gate(), [])

    def test_accepted_unenforced_is_recorded_not_silently_passed(self):
        # Explicit acceptance passes the gate, but only as an enumerated entry
        # the summary prints. The distinction being preserved is between a
        # known gap and a silent one.
        self.mapping = {"push:a:$x": "deny"}
        self.policy["enforcement"]["push:"] = {
            "mechanism": "per-key", "whole_class": False}
        self.policy["enforcement"]["push:a:$x"] = {
            "mechanism": "accepted, nothing refuses it",
            "unenforced_accepted": True}
        self.assertEqual(self.run_gate(), [])

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
            "symbol": "checkRpc", "whole_class": True}
        self.policy["enforcement"]["ai-setting:"] = {
            "mechanism": "the real one", "patch": "0005-filter.patch",
            "symbol": "seclabAiDisabled", "whole_class": True}
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


class ResidualGateTest(unittest.TestCase):
    """A residual's stated precondition must be checked, not just described.

    `deferred-laundering` is safe only while every command verdict is `deny`.
    Allowing a command is the obvious next compatibility fix, and nothing in
    review would connect that change to a paragraph in the residuals section.
    """

    def setUp(self):
        self.policy = {"residuals": {"deferred-laundering": {
            "statement": "...", "fixed": False}}}

    def test_control_all_commands_denied_passes(self):
        mapping = {"cmd:a": "deny", "cmd:b": "deny", "rpc:x.$y": "allow#abc"}
        self.assertEqual(CD.check_residuals(mapping, self.policy), [])

    def test_allowing_a_command_fails_while_the_residual_is_unfixed(self):
        mapping = {"cmd:a": "deny", "cmd:b": "allow#abc123"}
        errors = CD.check_residuals(mapping, self.policy)
        self.assertTrue(errors)
        self.assertIn("cmd:b", errors[0])
        self.assertIn("deferred-laundering", errors[0])

    def test_any_non_deny_verdict_counts_not_just_allow(self):
        # prompt and rewrite run the handler too.
        for verdict in ("prompt", "rewrite", "allow_with_constraint#abc"):
            with self.subTest(verdict=verdict):
                self.assertTrue(
                    CD.check_residuals({"cmd:a": verdict}, self.policy))

    def test_marking_the_residual_fixed_releases_the_constraint(self):
        # Otherwise the gate would make the residual impossible to retire.
        self.policy["residuals"]["deferred-laundering"]["fixed"] = True
        self.assertEqual(
            CD.check_residuals({"cmd:b": "allow#abc123"}, self.policy), [])

    def test_a_missing_residual_entry_does_not_silently_pass_commands(self):
        # If the entry is deleted the gate has nothing to hold, which is a
        # policy-authoring error rather than a safe state. It is caught by the
        # invariant's checked_by wiring, so assert the shipped policy keeps it.
        import json
        with open(os.path.join(CD.REPO_ROOT, "rpc-filter", "policy",
                               "policy.json"), encoding="utf-8") as fh:
            policy = json.load(fh)
        self.assertIn("deferred-laundering", policy.get("residuals", {}))
        self.assertFalse(policy["residuals"]["deferred-laundering"]["fixed"])
        self.assertTrue(any(
            i["id"] == "no-allowed-command-while-laundering-is-deferred"
            for i in policy["invariants"]))

    def test_the_shipped_policy_satisfies_the_residual_gate(self):
        import json
        root = CD.REPO_ROOT
        with open(os.path.join(root, "rpc-filter", "policy",
                               "policy.json"), encoding="utf-8") as fh:
            policy = json.load(fh)
        with open(os.path.join(root, "rpc-filter", "inventory",
                               "inventory.json"), encoding="utf-8") as fh:
            inv = json.load(fh)
        mapping = CD.build_mapping(inv, policy)
        self.assertEqual(CD.check_residuals(mapping, policy), [])


class LeafExceptionTest(unittest.TestCase):
    """While laundering is deferred, a reachable command must be a validated, evidenced leaf."""

    LEAF = {"verdict": "allow_with_constraint", "leaf": True, "validator": "setContextKey",
            "leaf_evidence": ["https://github.com/microsoft/vscode/blob/x/a.ts#L1-L2"]}

    def policy(self, entry=None, exceptions=("_setContext",)):
        return {"residuals": {"deferred-laundering": {
                    "fixed": False, "leaf_exceptions": list(exceptions)}},
                "commands": {"exact": {"_setContext": dict(entry or self.LEAF)}}}

    def test_control_a_complete_leaf_exception_passes(self):
        self.assertEqual(CD.check_residuals(
            {"cmd:_setContext": "allow_with_constraint#abc"}, self.policy()), [])

    def test_each_missing_leaf_field_fails(self):
        for field, value in (("leaf", False), ("leaf_evidence", []), ("validator", None),
                             ("verdict", "allow")):
            with self.subTest(field=field):
                entry = dict(self.LEAF)
                entry[field] = value
                errors = CD.check_residuals(
                    {"cmd:_setContext": "allow_with_constraint#abc"}, self.policy(entry))
                self.assertTrue(errors, field)
                self.assertIn("cmd:_setContext", errors[0])

    def test_a_complete_leaf_not_listed_as_an_exception_fails(self):
        errors = CD.check_residuals({"cmd:_setContext": "allow_with_constraint#abc"},
                                    self.policy(exceptions=()))
        self.assertTrue(errors)
        self.assertIn("leaf_exceptions", errors[0])

    def test_a_stale_exception_fails(self):
        errors = CD.check_residuals({"cmd:_setContext": "deny"}, self.policy())
        self.assertTrue(errors)
        self.assertIn("not reachable", errors[0])


class ValidatorGateTest(unittest.TestCase):
    SRC = ("export const SECLAB_VALIDATORS: ReadonlyMap<string, SeclabValidator> = new Map([\n"
           "\t['used', used],\n\t['other', other],\n]);\n")

    def policy(self, **entries):
        methods = {"$m": {"verdict": "allow_with_constraint", "validator": "used"},
                   "$n": {"verdict": "rewrite", "validator": "other"}}
        methods.update(entries)
        return {"rpc": {"S": {"methods": methods}}, "commands": {"exact": {}}}

    def test_control_every_validator_defined_and_used_passes(self):
        self.assertEqual(CD.check_validators(self.policy(), self.SRC), [])

    def test_an_undefined_validator_fails(self):
        errors = CD.check_validators(self.policy(**{"$x": {
            "verdict": "allow_with_constraint", "validator": "missing"}}), self.SRC)
        self.assertTrue(any("missing" in e for e in errors))

    def test_a_validator_nothing_names_fails(self):
        p = self.policy()
        del p["rpc"]["S"]["methods"]["$n"]
        self.assertTrue(any("'other'" in e for e in CD.check_validators(p, self.SRC)))

    def test_a_validator_on_a_verdict_that_never_runs_it_fails(self):
        errors = CD.check_validators(self.policy(**{"$n": {
            "verdict": "allow", "validator": "other"}}), self.SRC)
        self.assertTrue(any("never runs it" in e for e in errors))

    def test_a_constrained_command_without_a_validator_fails(self):
        p = self.policy()
        p["commands"]["exact"]["c"] = {"verdict": "allow_with_constraint"}
        self.assertTrue(any("cmd:c" in e for e in CD.check_validators(p, self.SRC)))

    def test_a_constrained_rpc_method_without_a_validator_fails(self):
        # Round 10 finding 3: only cmd: entries were checked, and the filter let a
        # positional URI argument discharge any named constraint.
        errors = CD.check_validators(self.policy(**{"$u": {
            "verdict": "allow_with_constraint", "constraint": "something"}}), self.SRC,
            {"S.$u": [0]})
        self.assertTrue(any("rpc:S.$u" in e for e in errors))

    def test_the_uri_rule_counts_only_when_declared_and_positioned(self):
        ok = {"verdict": "allow_with_constraint", "constraint": "uri", "constraint_is_uri_rule": True}
        self.assertEqual(CD.check_validators(self.policy(**{"$u": ok}), self.SRC, {"S.$u": [0]}), [])
        errors = CD.check_validators(self.policy(**{"$u": ok}), self.SRC, {})
        self.assertTrue(any("no URI positions" in e for e in errors))
        both = dict(ok, validator="used")
        self.assertTrue(any("pick one" in e for e in CD.check_validators(
            self.policy(**{"$u": both}), self.SRC, {"S.$u": [0]})))

    def test_the_command_dispatcher_is_the_one_listed_exception(self):
        p = self.policy()
        p["rpc"]["MainThreadCommands"] = {"methods": {"$executeCommand": {
            "verdict": "allow_with_constraint", "constraint": "commands table"}}}
        self.assertEqual(CD.check_validators(p, self.SRC, {}), [])

    def test_the_shipped_policy_satisfies_the_validator_gate(self):
        import json
        with open(CD.POLICY, encoding="utf-8") as fh:
            policy = json.load(fh)
        with open(CD.INVENTORY, encoding="utf-8") as fh:
            inv = json.load(fh)
        self.assertEqual(CD.check_validators(policy, CD._read(CD.VALIDATORS_SRC), CD._uri_positions(inv)), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
