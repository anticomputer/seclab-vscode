"""The probe-safety lint's structural rules, each shown failing on the shape it forbids.

Run: python3 -m unittest test_lint_probes  (from rpc-filter/tools)

Probes read only harness-seeded canaries, the clipboard only through the test build's
in-memory canary clipboard, never the system pasteboard; and a run record holds facts
(booleans, numbers, canary tokens, source literals), never values. Every rule is held in
both directions: the forbidden shape fails, the permitted shape passes.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lint_probes as L  # noqa: E402


def code(*lines):
    return list(enumerate(lines, start=1))


def ids(violations):
    return [v[2] for v in violations]


class ClipboardTest(unittest.TestCase):
    def clip(self, text):
        return ids(L.clipboard_violations("x.js", text))

    def test_a_clipboard_read_outside_the_canary_clipboard_fails(self):
        self.assertEqual(self.clip("async () => vscode.env.clipboard.readText()"), ["clipboard-outside-canary"])

    def test_a_check_of_a_targets_flag_is_not_enough(self):
        # A workspace flag is attacker-writable and says nothing about the app under test; both
        # the flag and the read are clipboard touches outside the canary call.
        self.assertEqual(self.clip("if (targets.clipboard !== '1') { throw new Error('x'); }\n"
                                   "return await vscode.env.clipboard.readText();"),
                         ["clipboard-outside-canary"] * 2)

    def test_a_raw_rpc_clipboard_read_fails(self):
        self.assertEqual(self.clip("await proxy.$readText();"), ["clipboard-outside-canary"])

    def test_a_policy_ref_naming_readText_is_not_a_read(self):
        self.assertEqual(self.clip("probe(results, 'clipboard-read', 'rpc:MainThreadClipboard.$readText', f)"), [])

    def test_a_read_inside_withCanaryClipboard_passes(self):
        self.assertEqual(self.clip("() => safety.withCanaryClipboard(ctx, () => vscode.env.clipboard.readText())"), [])

    def test_aliasing_and_computed_access_fail(self):
        # Round 16: a surface regex missed these; the identifier rule cannot be dodged by them.
        self.assertEqual(self.clip("const cb = vscode.env.clipboard; await cb.readText();"), ["clipboard-outside-canary"])
        self.assertEqual(self.clip("await vscode.env.clipboard['read' + 'Text']();"), ["clipboard-outside-canary"])
        self.assertEqual(self.clip("const { readText } = vscode.env.clipboard;"), ["clipboard-outside-canary"])

    def test_paste_actions_and_page_clipboard_fail(self):
        self.assertEqual(self.clip("await vscode.commands.executeCommand('editor.action.clipboardPasteAction');"),
                         ["clipboard-outside-canary"])
        self.assertEqual(self.clip("html = `<script>navigator.clipboard.readText()</script>`;"), ["clipboard-outside-canary"])
        self.assertEqual(self.clip("html = \"<script>document.execCommand('paste')</script>\";"), ["clipboard-outside-canary"])

    def test_the_word_in_a_string_or_comment_is_not_a_use(self):
        self.assertEqual(self.clip("// the clipboard is never read\nconst s = 'clipboard-read';"), [])

    def test_template_substitutions_and_dynamic_access_fail(self):
        # Round 18: blanking whole template literals hid code inside ${...}.
        self.assertEqual(self.clip("const t = `${vscode.env.clipboard.readText()}`;"), ["clipboard-outside-canary"])
        self.assertEqual(self.clip("const k = 'clip' + 'board'; await vscode.env[k].readText();"), ["clipboard-outside-canary"])
        self.assertEqual(self.clip("await Reflect.get(vscode.env, 'clip' + 'board').readText();"), ["clipboard-outside-canary"])
        self.assertEqual(self.clip("const t = `plain ${count} text`;"), [])


class RecordTest(unittest.TestCase):
    def rec(self, text):
        return ids(L.record_violations("x.js", text, text.splitlines()))

    def test_a_json_stringify_record_fails(self):
        self.assertEqual(self.rec("fs.writeFileSync(p, JSON.stringify({ home: os.homedir() }));"), ["raw-record"])

    def test_a_raw_value_written_to_a_marker_fails(self):
        self.assertEqual(self.rec("fs.writeFileSync(marker, String(resolved[0]));"), ["raw-record"])

    def test_a_workspace_fs_record_must_go_through_recordJson(self):
        self.assertEqual(self.rec("await vscode.workspace.fs.writeFile(out, enc.encode(JSON.stringify(r)));"), ["raw-record"])
        self.assertEqual(self.rec("await vscode.workspace.fs.writeFile(out, enc.encode(safety.recordJson(r)));"), [])

    def test_recordJson_and_literals_pass(self):
        self.assertEqual(self.rec("fs.writeFileSync(p, safety.recordJson({ ok: true }));\n"
                                  "fs.writeFileSync(q, 'written by a tab\\n');\n"
                                  "await vscode.workspace.fs.writeFile(t, Buffer.from('written by a tab\\n'));"), [])

    def test_lit_takes_a_string_literal_only(self):
        self.assertEqual(self.rec("safety.lit(os.hostname())"), ["lit-not-literal"])
        self.assertEqual(self.rec("safety.lit(`x${y}`)"), ["lit-not-literal"])
        self.assertEqual(self.rec("safety.lit('registered')"), [])

    def test_the_probe_head_pragma_is_line_scoped(self):
        self.assertEqual(self.rec("const h = safety.lit(id); // lint-allow: lit-probe-head"), [])
        self.assertEqual(self.rec("const h = safety.lit(id); // lint-allow: lit-probe-head\nconst g = safety.lit(v);"),
                         ["lit-not-literal"])

    def test_a_templated_probe_id_fails(self):
        self.assertEqual(self.rec("await probe(results, `launder-${hop}`, 'cmd:x', f);"), ["probe-id-not-literal"])
        self.assertEqual(self.rec("await probe(results, 'launder-await', 'cmd:x', f);"), [])

    def test_a_member_access_probe_id_fails_unless_v_id_or_a_constant(self):
        self.assertEqual(self.rec("await probe(results, targets.something, cfg.ref, f);"), ["probe-id-not-literal"] * 2)
        self.assertEqual(self.rec("await probe(results, v.id, REF, f);"), [])

    def test_a_computed_record_key_fails(self):
        self.assertEqual(self.rec("write('x.json', { [os.userInfo().username]: true });"), ["computed-record-key"])
        self.assertEqual(self.rec("write('x.json', { ok: true, n: 1 });"), [])


class PasteboardTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(dir=os.path.join(L.REPO, ".work") if os.path.isdir(os.path.join(L.REPO, ".work")) else None)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def plant(self, rel, body):
        p = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(body)

    def test_pbpaste_anywhere_in_the_harness_fails(self):
        self.plant("test/containment/check-evidence.ts", "const saved = spawnSync('pbpaste', []);\n")
        self.plant("build/tool.sh", "printf x | pbcopy\n")
        self.plant("test/focus/x.jxa", "ObjC.import('AppKit'); $.NSPasteboard.generalPasteboard\n")
        self.plant("test/demo.applescript", "set the clipboard to \"x\"\n")
        self.plant("test/read.sh", "osascript -e 'return (the clipboard as text)'\n")
        self.plant("patches/x.patch", "+ ObjC.import('AppKit'); $.NSPasteboard\n")
        self.assertEqual(sorted(ids(L.pasteboard_violations(self.root))), ["pasteboard"] * 6)

    def test_prose_about_the_clipboard_is_not_a_use(self):
        self.plant("test/containment/x.ts", "// the clipboard is never read\n")
        self.assertEqual(ids(L.pasteboard_violations(self.root)), [])


class GuardedSourceTest(unittest.TestCase):
    def ids(self, *lines):
        return [v[2] for v in L.guarded_source_violations("x.js", code(*lines))]
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
