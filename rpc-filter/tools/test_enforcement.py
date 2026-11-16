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


class LogTrustGateTest(unittest.TestCase):
    """The decision log's integrity checks must fail when they should.

    Round 14 of the observability review found this gate narrower than the
    claim it carried: it accepted any `allow_with_constraint` on `$writeFile`
    without checking that anything constrained it, and pinned neither
    `$delete` nor the other host-file writers. Nothing was exploitable, which
    is exactly why it could have stayed that way.

    Each case below was confirmed to pass *unnoticed* against the previous
    version of the gate before this one was written.
    """

    def setUp(self):
        import json
        root = CD.REPO_ROOT
        with open(os.path.join(root, "rpc-filter", "inventory",
                               "inventory.json"), encoding="utf-8") as fh:
            self.inv = json.load(fh)
        with open(os.path.join(root, "rpc-filter", "policy",
                               "policy.json"), encoding="utf-8") as fh:
            policy = json.load(fh)
        self.mapping = CD.build_mapping(self.inv, policy)

    def test_control_the_shipped_policy_passes(self):
        self.assertEqual(CD.check_log_trust(self.mapping, self.inv), [])

    def test_write_file_constrained_but_nothing_constrains_it(self):
        # The constraint is prose, so the gate cannot read it. What it can read
        # is whether the positional URI rule actually applies.
        import copy
        inv = copy.deepcopy(self.inv)
        for svc in inv["surfaces"]["a_mainthread_rpc"]["services"]:
            if svc["sid"] == "MainThreadFileSystem":
                svc["uri_arg_positions"].pop("$writeFile", None)
        mapping = dict(self.mapping)
        mapping["rpc:MainThreadFileSystem.$writeFile"] = "allow_with_constraint#abc"
        errors = CD.check_log_trust(mapping, inv)
        self.assertTrue(errors)
        self.assertIn("no URI argument positions", errors[0])

    def test_write_file_denied_outright_is_acceptable(self):
        # Stricter than constrained must never be reported as a problem, or
        # the gate pushes people towards the weaker verdict.
        mapping = dict(self.mapping)
        mapping["rpc:MainThreadFileSystem.$writeFile"] = "deny"
        self.assertEqual(CD.check_log_trust(mapping, self.inv), [])

    def test_delete_must_be_denied(self):
        # Deleting the log stops forwarding; silence is not a safe failure for
        # an audit log.
        mapping = dict(self.mapping)
        mapping["rpc:MainThreadFileSystem.$delete"] = "allow#abc"
        self.assertTrue(CD.check_log_trust(mapping, self.inv))

    def test_other_host_file_writers_must_be_denied(self):
        for key, verdict in (
                ("rpc:MainThreadBulkEdits.$tryApplyWorkspaceEdit", "allow#abc"),
                ("rpc:MainThreadDocuments.$trySaveDocument", "prompt")):
            with self.subTest(key=key):
                mapping = dict(self.mapping)
                mapping[key] = verdict
                errors = CD.check_log_trust(mapping, self.inv)
                self.assertTrue(errors)
                self.assertIn(key, errors[0])

    def test_a_surface_missing_from_the_mapping_is_not_silently_skipped(self):
        # In this codebase the scanner has lost surfaces more than once, so
        # absence is at least as likely to be a scanner regression as an
        # upstream removal. Either way a human should look.
        mapping = dict(self.mapping)
        del mapping["rpc:MainThreadFileSystem.$delete"]
        errors = CD.check_log_trust(mapping, self.inv)
        self.assertTrue(errors)
        self.assertIn("not in the surface mapping", errors[0])

    def test_logger_methods_must_stay_denied(self):
        mapping = dict(self.mapping)
        mapping["rpc:MainThreadLogger.$log"] = "allow#abc"
        self.assertTrue(CD.check_log_trust(mapping, self.inv))


if __name__ == "__main__":
    unittest.main(verbosity=2)


class CategoryGrantRevertTest(unittest.TestCase):
    """rpc-lockdown-design findings 1 and 2: a substring rule must never grant.

    389 commands were once reachable through category rules, and `editor-local` captured an
    external-link opener and `_workbench.editor.configureDefaultEditor`. The fix is two checks:
    a rule may only carry `deny` (check_keys), and every reachable command must have its own
    `commands.exact` entry over the RESOLVED mapping (check_invariants). Each test here fails
    if its half of the fix is reverted.
    """

    CAPTURED = ("editor.action.accessibilityHelpOpenHelpLink", "_workbench.editor.configureDefaultEditor")

    def setUp(self):
        self.inv = CD._load(CD.INVENTORY)
        self.policy = CD._load(CD.POLICY)

    def granting(self):
        # The original shape: the whole `editor-local` category granted at once.
        import copy
        policy = copy.deepcopy(self.policy)
        rule = {"match": {"category": "editor-local"}, "verdict": "allow", "impact": ["ui-spoofing"]}
        policy["commands"]["rules"] = [rule] + list(policy["commands"].get("rules") or [])
        return policy

    def command(self, cid):
        return next(c for c in self.inv["surfaces"]["b_command_registry"]["commands"] if c["id"] == cid)

    def test_control_the_shipped_policy_grants_nothing_by_category(self):
        errors = CD.check_keys(self.inv, self.policy) + CD.check_invariants(self.inv, self.policy)
        self.assertEqual([e for e in errors if "Category rules" in e or "through a category rule" in e], [])

    def test_a_granting_rule_fails_the_keys_check(self):
        errors = CD.check_keys(self.inv, self.granting())
        self.assertTrue(any("Category rules are a substring heuristic" in e for e in errors), errors)

    def test_a_granting_rule_is_caught_over_the_resolved_mapping_too(self):
        # Independently of check_keys: the invariant runs over what each id resolves to.
        errors = CD.check_invariants(self.inv, self.granting())
        hits = [e for e in errors if "through a category rule" in e]
        self.assertTrue(hits)
        for cid in self.CAPTURED:
            self.assertTrue(any("'%s'" % cid in e for e in hits), cid)

    def test_the_ids_editor_local_captured_resolve_to_deny(self):
        for cid in self.CAPTURED:
            verdict, _ = CD.resolve_command(self.policy, self.command(cid))
            self.assertEqual(verdict, "deny", cid)


class InventoryScannerRevertTest(unittest.TestCase):
    """rpc-lockdown-design finding 3: the scanner modelled named helpers, so
    `terminal.newLocal` and `sendSequence` were absent and their deny entries matched nothing.

    The fix matches the shape `register*({ id: ... })` and resolves enum members, and the keys
    check fails a `commands.exact` entry the inventory lacks. Each half is pinned here.
    """

    IDS = ("workbench.action.terminal.newLocal", "workbench.action.terminal.sendSequence")

    def test_the_committed_inventory_has_both_and_they_resolve_to_deny(self):
        inv, policy = CD._load(CD.INVENTORY), CD._load(CD.POLICY)
        by_id = {c["id"]: c for c in inv["surfaces"]["b_command_registry"]["commands"]}
        for cid in self.IDS:
            self.assertIn(cid, by_id)
            self.assertEqual(CD.resolve_command(policy, by_id[cid])[0], "deny", cid)

    def test_an_exact_entry_the_inventory_lacks_fails_the_keys_check(self):
        import copy
        inv, policy = CD._load(CD.INVENTORY), CD._load(CD.POLICY)
        policy = copy.deepcopy(policy)
        policy["commands"]["exact"]["workbench.action.terminal.newLocal"] = {"verdict": "deny"}
        inv = copy.deepcopy(inv)
        inv["surfaces"]["b_command_registry"]["commands"] = [
            c for c in inv["surfaces"]["b_command_registry"]["commands"] if c["id"] != "workbench.action.terminal.newLocal"]
        errors = CD.check_keys(inv, policy)
        self.assertTrue(any("newLocal'] is not in the inventory" in e for e in errors), errors)

    def test_the_scanner_finds_a_helper_registration_by_shape(self):
        from seclab_inventory import commands as C
        from seclab_inventory.sources import SourceTree
        root = tempfile.mkdtemp(prefix="seclab-scan-test-")
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        files = {
            "src/vs/workbench/contrib/terminal/common/terminal.ts":
                "export const enum TerminalCommandId {\n\tNewLocal = 'workbench.action.terminal.newLocal',\n}\n",
            "src/vs/workbench/contrib/terminal/electron-browser/terminalRemote.ts":
                "import { TerminalCommandId } from '../common/terminal.js';\n"
                "registerTerminalAction({\n\tid: TerminalCommandId.NewLocal,\n\ttitle: 'x',\n\trun: () => { }\n});\n",
            "src/vs/workbench/contrib/terminalContrib/sendSequence/browser/terminal.sendSequence.contribution.ts":
                "registerTerminalAction({\n\tid: 'workbench.action.terminal.sendSequence',\n\trun: () => { }\n});\n",
        }
        for rel, text in files.items():
            os.makedirs(os.path.dirname(os.path.join(root, rel)), exist_ok=True)
            with open(os.path.join(root, rel), "w", encoding="utf-8") as fh:
                fh.write(text)
        ids = {c["id"] for c in C.build(SourceTree(root=root, sha="x"))["commands"]}
        for cid in self.IDS:
            self.assertIn(cid, ids)


class CallerGateSelfTest(unittest.TestCase):
    """The dead-entry-point gate (sync_patch.check_callers) fails on each shape it exists for.

    rpc-filter-patches finding 4 and rpc-core-landing finding 4: `seclabRegisterTab` had no
    caller, so `seclabFilterFor` threw for every tab, and nothing showed the gate that should
    have caught it could fail. Each case builds a tiny tree (one patch-src file, one patch) and
    runs the real gate over it.
    """

    SRC = "rpc-filter/patch-src/seclabX.ts"
    TARGET = "src/vs/x/seclabX.ts"

    def setUp(self):
        import sync_patch as SP
        self.SP = SP
        self.root = tempfile.mkdtemp(prefix="seclab-callers-test-")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        os.makedirs(os.path.join(self.root, "rpc-filter", "patch-src"))
        os.makedirs(os.path.join(self.root, "patches"))
        saved = (SP.REPO, SP.PATCH_DIR, SP.MAPPING, SP.CALLER_EXEMPT)
        self.addCleanup(lambda: setattr_all(SP, saved))

        def setattr_all(mod, vals):
            mod.REPO, mod.PATCH_DIR, mod.MAPPING, mod.CALLER_EXEMPT = vals
        SP.REPO, SP.PATCH_DIR = self.root, os.path.join(self.root, "patches")
        SP.MAPPING, SP.CALLER_EXEMPT = {self.TARGET: self.SRC}, {}

    def tree(self, source, added_lines, own_section_lines=()):
        with open(os.path.join(self.root, self.SRC), "w") as fh:
            fh.write(source)
        upstream = ["diff -ruN a/src/vs/y/user.ts b/src/vs/y/user.ts", "--- a/src/vs/y/user.ts",
                    "+++ b/src/vs/y/user.ts", "@@ -1,1 +1,%d @@" % (len(added_lines) + 1), " x"]
        upstream += ["+" + l for l in added_lines]
        own = ["diff -ruN a/%s b/%s" % (self.TARGET, self.TARGET), "--- a/%s" % self.TARGET,
               "+++ b/%s" % self.TARGET, "@@ -0,0 +1,%d @@" % len(own_section_lines)]
        own += ["+" + l for l in own_section_lines]
        with open(os.path.join(self.root, "patches", "0005-x.patch"), "w") as fh:
            fh.write("\n".join(upstream + (own if own_section_lines else [])) + "\n")

    SOURCE = ("export function seclabA(): void {\n\tseclabB();\n}\n"
              "export function seclabB(): void { }\n")

    def errors(self):
        return self.SP.check_callers()

    def test_control_a_called_entry_and_its_helper_pass(self):
        self.tree(self.SOURCE, ["seclabA();"])
        self.assertEqual(self.errors(), [])

    def test_an_uncalled_export_fails(self):
        self.tree(self.SOURCE + "export function seclabDead(): void { }\n", ["seclabA();"])
        self.assertTrue(any("seclabDead" in e for e in self.errors()))

    def test_a_comment_is_not_a_caller(self):
        self.tree(self.SOURCE, ["// seclabA() used to be called here"])
        self.assertTrue(any("seclabA" in e for e in self.errors()))

    def test_an_import_is_not_a_caller(self):
        self.tree(self.SOURCE, ["import { seclabA } from './seclabX.js';"])
        self.assertTrue(any("seclabA" in e for e in self.errors()))

    def test_the_declaring_patch_section_does_not_vouch_for_itself(self):
        self.tree(self.SOURCE, [], own_section_lines=self.SOURCE.splitlines() + ["seclabA();"])
        self.assertTrue(any("seclabA" in e for e in self.errors()))

    def test_a_cycle_of_uncalled_entries_does_not_make_itself_live(self):
        cyc = ("export function seclabC(): void {\n\tseclabD();\n}\n"
               "export function seclabD(): void {\n\tseclabC();\n}\n")
        self.tree(self.SOURCE + cyc, ["seclabA();"])
        errs = self.errors()
        self.assertTrue(any("seclabC" in e for e in errs) and any("seclabD" in e for e in errs), errs)

    def test_an_exemption_must_name_a_real_consumer_and_go_stale_when_called(self):
        self.tree(self.SOURCE + "export function seclabE(): void { }\n", ["seclabA();"])
        self.SP.CALLER_EXEMPT = {"seclabE": {"consumer": "nowhere.ts", "reason": "x"}}
        self.assertTrue(any("does not exist" in e for e in self.errors()))
        self.SP.CALLER_EXEMPT = {"seclabA": {"consumer": None, "reason": "x"}}
        self.assertTrue(any("is stale" in e for e in self.errors()))

    def test_the_real_tree_passes_and_resolve_tab_id_is_live(self):
        import importlib
        import sync_patch as fresh
        importlib.reload(fresh)
        self.assertEqual(fresh.check_callers(), [])
        added = fresh._code_only(fresh._patch_added_text())
        self.assertRegex(added, r"\bseclabResolveTabId\b",
                         "seclabResolveTabId has no caller in the patch queue's upstream hunks")
