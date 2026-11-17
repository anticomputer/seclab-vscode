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


REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
# The guard copies the harnesses write next to each extension before packaging. They are
# gitignored, so a checkout has none; a worktree keeps whatever its last run copied.
GUARD_COPIES = tuple(p for p in L.EXEMPT if p != "test/containment/probe-safety.js")


def tree_copy(case):
    """test/ as a checkout has it: no node_modules, no .work, no build-time guard copies, so a
    stale copy a local run left behind can't decide a unit test."""
    root = tempfile.mkdtemp(prefix="seclab-lint-test-")
    case.addCleanup(shutil.rmtree, root, ignore_errors=True)

    def ignore(d, names):
        rel = os.path.relpath(d, REPO)
        out = {n for n in names if n in ("node_modules", ".work")}
        return out | {n for n in names if os.path.join(rel, n) in GUARD_COPIES}
    shutil.copytree(os.path.join(REPO, "test"), os.path.join(root, "test"), ignore=ignore)
    return root


def lint(root):
    import contextlib
    import io
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        status = L.main([root])
    return status, out.getvalue()


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
        status, out = lint(tree_copy(self))
        self.assertEqual(status, 0, out)

    def test_a_root_with_no_payloads_fails_rather_than_passing_vacuously(self):
        # The first version of this test passed while linting 0 files (it read
        # unittest's own argv as the root).
        self.assertEqual(L.main([os.path.dirname(os.path.abspath(__file__))]), 1)



class ArmingGateTest(unittest.TestCase):
    """probe-safety finding 4: every payload entry point bails unless the run armed it.

    The fix lives in the payloads (each calls safety.context() and returns when not armed) and is
    held by the lint's `no-arming` rule. Run over a copy of the tree: the shipped payloads pass,
    and each payload with its bail-out removed fails, so reverting either half is caught.
    """

    def copy(self):
        return tree_copy(self)

    def lint_ids(self, root):
        return lint(root)

    def test_control_the_copied_payloads_pass(self):
        status, out = self.lint_ids(self.copy())
        self.assertEqual(status, 0, out)

    def test_a_payload_without_its_arming_bail_fails(self):
        for rel in L.MUST_ARM:
            root = self.copy()
            path = os.path.join(root, rel)
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            gutted = text.replace("if (!ctx.armed) {", "if (false) {")
            self.assertNotEqual(gutted, text, "%s no longer has the bail this test removes" % rel)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(gutted)
            status, out = self.lint_ids(root)
            self.assertEqual(status, 1, rel)
            self.assertIn("no-arming", out, rel)


class GuardCopyTest(unittest.TestCase):
    """The packaged guard copies are exempt from the content rules only because they match the
    single source byte for byte. A checkout has no copies, so this is the only place CI sees the
    guard-divergence rule run."""

    def write(self, root, rel, data):
        with open(os.path.join(root, rel), "wb") as fh:
            fh.write(data)

    def source(self):
        with open(os.path.join(REPO, "test/containment/probe-safety.js"), "rb") as fh:
            return fh.read()

    def test_an_exact_copy_passes(self):
        root = tree_copy(self)
        for rel in GUARD_COPIES:
            self.write(root, rel, self.source())
        status, out = lint(root)
        self.assertEqual(status, 0, out)

    def test_a_stale_copy_fails(self):
        for rel in GUARD_COPIES:
            root = tree_copy(self)
            self.write(root, rel, self.source() + b"// stale\n")
            status, out = lint(root)
            self.assertEqual(status, 1, rel)
            self.assertIn("FAIL [guard-divergence] %s" % rel, out)

    def test_the_guard_copies_are_ignored_by_git(self):
        # A tracked copy would be a second source of truth.
        with open(os.path.join(REPO, ".gitignore"), encoding="utf-8") as fh:
            ignored = {l.strip() for l in fh}
        for rel in GUARD_COPIES:
            self.assertIn(rel, ignored)


class CommentScopeTest(unittest.TestCase):
    """A rule sees the code after a block comment (PR review, 2026-11-17): blanking whole comment
    lines removed a block's closing `*/`, and the rest of the payload read as comment."""

    def test_code_after_a_block_comment_is_linted(self):
        root = tree_copy(self)
        path = os.path.join(root, "test/containment/rogue-reh/probes.js")
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("\n/**\n * A block comment whose closing line starts with a star.\n */\nconst seclabLintProbe = { [SOME_KEY]: 1 };\n")
        status, out = lint(root)
        self.assertEqual(status, 1, out)
        self.assertIn("computed-record-key", out)

    def test_a_regex_ending_in_slashes_is_not_a_comment(self):
        # Directly after `=`, after a comment, and as a statement after an `if (…)` condition.
        for code in (
            "const seclabLintPattern = /^https?:\\/\\//; fs.writeFileSync('out', raw);",
            "const seclabLintPattern = /* note */ /^https?:\\/\\//; fs.writeFileSync('out', raw);",
            "if (seclabLintReady) /^https?:\\/\\//.test(u); fs.writeFileSync('out', raw);",
        ):
            with self.subTest(code=code):
                root = tree_copy(self)
                path = os.path.join(root, "test/containment/rogue-reh/probes.js")
                with open(path, "a", encoding="utf-8") as fh:
                    fh.write("\n" + code + "\n")
                status, out = lint(root)
                self.assertEqual(status, 1, out)
                self.assertIn("raw-record", out)

    def test_a_comment_after_a_slash_on_its_line_fails_closed(self):
        # Placements a token heuristic gets wrong: postfix `++` before division, a regex statement
        # after `break` and a newline, and after a `for await (…)` head. Each must fail the lint.
        for code in (
            "let n = 4; const q = n++ / 2; const r = /\\//; fs.writeFileSync('out', raw);",
            "for (;;) { break\n/\\//.test(u); fs.writeFileSync('out', raw); }",
            "async function f(y) { for await (const x of y) /\\//.test(x); fs.writeFileSync('out', raw); }",
            "debugger\n/\\//; fs.writeFileSync('out', raw);",
        ):
            with self.subTest(code=code):
                root = tree_copy(self)
                path = os.path.join(root, "test/containment/rogue-reh/probes.js")
                with open(path, "a", encoding="utf-8") as fh:
                    fh.write("\n" + code + "\n")
                status, out = lint(root)
                self.assertEqual(status, 1, out)
                self.assertRegex(out, r"raw-record|ambiguous-slash")

    def test_a_misread_slash_cannot_move_a_string_boundary(self):
        # No comment at all: `n++ / 2` read as a regex ends at the quoted '/', and the string's
        # closing quote then opens one that blanks the computed key.
        root = tree_copy(self)
        path = os.path.join(root, "test/containment/rogue-reh/probes.js")
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("\nlet n = 4; const q = n++ / 2; const s = '/'; const seclabLintX = { [K]: 1 };\n")
        status, out = lint(root)
        self.assertEqual(status, 1, out)
        self.assertRegex(out, r"ambiguous-slash|computed-record-key")

    def test_only_a_comment_after_a_code_slash_is_ambiguous(self):
        def amb(text):
            found = []
            L._strip_comments(text, found)
            return found
        # Only a parser could tell, and something later on the line could move a boundary.
        self.assertEqual(amb("q = n++ / 2; r = /\\//; w();\n"), [1])
        self.assertEqual(amb("q = n++ / 2; s = '/';\n"), [1])
        self.assertEqual(amb("f();\n}\n/a/.test('b');\n"), [3])
        # Certain readings are trusted, and an unsure slash with nothing after it can't hide code.
        self.assertEqual(amb("x = a / b; /* c */\nif (/^x/.test(s)) return 'a';\n"), [])
        self.assertEqual(amb("x = 1; // c\n/* d */\ny = '/'; // e\n"), [])
        self.assertEqual(amb("a = /x/;\n// own line\nb = 'a//b';\nq = n++ / 2;\n"), [])

    def test_a_code_line_starting_with_a_star_is_linted(self):
        # A continued product puts code at the start of a line where a comment's `*` would be.
        root = tree_copy(self)
        path = os.path.join(root, "test/containment/rogue-reh/probes.js")
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("\nconst seclabLintA = 2\n* 3; fs.rmSync(seclabLintP);\n")
        status, out = lint(root)
        self.assertEqual(status, 1, out)
        self.assertIn("destructive-fs", out)

    def test_property_names_and_contextual_words(self):
        def amb(text):
            found = []
            return L._code_only(L._strip_comments(text, found)), found
        # A property is never a keyword: division, so the string and the key after it stay put.
        for text in ("x = a.return / 2; y = '/'; z = { [K]: 1 };\n",
                     "x = o.if(a) / 2; y = '/'; z = { [K]: 1 };\n"):
            code, found = amb(text)
            self.assertEqual(found, [], text)
            self.assertIn("[K]", code, text)
        # `of` and `default` can be identifiers: unsure, so a later quote fails closed.
        for text in ("let of = 4; q = of / 2; s = '/';\n", "q = o.x || default / 2; s = '/';\n"):
            self.assertEqual(amb(text)[1], [1], text)
        # Any reserved word but a value keyword is unsure; a value keyword reads as division.
        for word in ("debugger", "class", "var", "try", "finally", "import", "export"):
            self.assertEqual(amb(word + "\n/a/; s = '/';\n")[1], [2], word)
        for word in ("this", "null", "true"):
            self.assertEqual(amb("x = " + word + " / 2; s = '/';\n")[1], [], word)

    def test_nested_templates_keep_their_boundaries(self):
        found = []
        text = "t = `a ${f(`b/${c}`)} d`; // e\nw(`x//y`);\n"
        got = L._strip_comments(text, found)
        self.assertEqual(found, [])
        self.assertNotIn("// e", got)
        self.assertIn("`x//y`", got)

    def test_regex_literals_division_and_comments(self):
        cases = [
            ("a = /^https?:\\/\\//; b(); // c\n", "b();", "// c"),
            ("x = /[/]/g; y(); /* c */\n", "y();", "/* c */"),
            ("return /\\/\\//.test(s) && z(); // c\n", "z();", "// c"),
            ("q = a / b; r(); // c\n", "r();", "// c"),
            ("q = f(a) / 2; r(); // c\n", "r();", "// c"),
            ("a = /* x */ /\\/\\//; b(); // c\n", "b();", "// c"),
            ("if (ok) /\\/\\//.test(s); b(); // c\n", "b();", "// c"),
            ("while (f(a)) /\\/\\//.exec(s); b(); // c\n", "b();", "// c"),
            ("q = g(a) / h(b) / 2; r(); // c\n", "r();", "// c"),
        ]
        for text, code, comment in cases:
            for fn in (L._strip_comments, L._code_only):
                got = fn(text)
                self.assertIn(code, got, (fn.__name__, text))
                self.assertNotIn(comment, got, (fn.__name__, text))

    def test_comments_and_strings_are_not_code(self):
        text = "a(); /* { [K]: 1 } */ b('{ [K]: 1 }'); // { [K]: 1 }\n"
        self.assertNotRegex(L._code_only(L._strip_comments(text)), r"\[K\]")
        self.assertIn("'{ [K]: 1 }'", L._strip_comments(text))


class PersistenceRuleTest(unittest.TestCase):
    def rule(self):
        return next(p for rid, p, _ in L.RULES if rid == "persistence")

    def test_profile_paths_fail(self):
        for line in ("fs.readFileSync(home + '/.profile')", "const p = '~/.profile';", "cat .profile"):
            self.assertTrue(self.rule().search(line), line)

    def test_profile_properties_pass(self):
        for line in ("p.profileName !== NAME", "args.profile", "x[0].profile", "f().profile"):
            self.assertFalse(self.rule().search(line), line)


if __name__ == "__main__":
    unittest.main(verbosity=2)
