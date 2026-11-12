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
from seclab_inventory import pushes as PUSHES  # noqa: E402
from seclab_inventory.sources import SourceTree, strip_block_comments


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


class StripBlockComments(unittest.TestCase):
    """Review 20261105-agent-host-patches #1: a comment stripper that doesn't know string
    literals opened a "comment" at the `/*` inside a glob and deleted half a file."""

    def test_a_comment_marker_inside_a_string_does_not_open_a_comment(self):
        src = "const g = '**/*plan*.md';\nregister('chat.agent.enabled');\n/* real */ x();\n"
        out = strip_block_comments(src)
        self.assertIn("register('chat.agent.enabled');", out)
        self.assertIn("'**/*plan*.md'", out)
        self.assertNotIn("real", out)

    def test_output_is_length_and_line_preserving(self):
        src = "a(); // one\n/* two\n three */ b('//x', \"/*y*/\", `/*z`);\n"
        out = strip_block_comments(src)
        self.assertEqual(len(out), len(src))
        self.assertEqual(out.count("\n"), src.count("\n"))
        self.assertIn("b('//x', \"/*y*/\", `/*z`);", out)
        self.assertNotIn("one", out)
        self.assertNotIn("two", out)


class RealTreeDeterminism(unittest.TestCase):
    """Double-run over the pinned upstream checkout.

    rpc-filter/tools/test.sh (the required unit job) sets SECLAB_REQUIRE_UPSTREAM=1, so a
    missing checkout FAILS there instead of skipping: a gate that quietly drops its upstream
    tests is a gate that passes without testing anything (gate audit GATE-12). Elsewhere it
    still skips, so the fast tests run anywhere.
    """

    SRC = os.environ.get("SECLAB_UPSTREAM", "/src")

    def test_full_inventory_is_order_independent(self):
        if not os.path.isdir(os.path.join(self.SRC, "src/vs")):
            if os.environ.get("SECLAB_REQUIRE_UPSTREAM") == "1":
                self.fail("no upstream checkout at %s, and this run requires it" % self.SRC)
            self.skipTest("no upstream checkout at %s" % self.SRC)
        tree = SourceTree(root=self.SRC, sha="x")
        first = json.dumps(C.build(tree), sort_keys=True)
        with _ReversedWalk(C):
            second = json.dumps(C.build(SourceTree(root=self.SRC, sha="x")),
                                sort_keys=True)
        self.assertEqual(first, second,
                         "the real inventory is not reproducible across "
                         "filesystem orderings")


class RequiredUpstreamTest(unittest.TestCase):
    """GATE-12: with the upstream required, its absence fails; it never skips."""

    def run_upstream_case(self, env):
        saved = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        try:
            RealTreeDeterminism.SRC = os.environ.get("SECLAB_UPSTREAM", "/src")
            result = unittest.TestResult()
            RealTreeDeterminism("test_full_inventory_is_order_independent").run(result)
            return result
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            RealTreeDeterminism.SRC = os.environ.get("SECLAB_UPSTREAM", "/src")

    def test_a_missing_checkout_fails_when_required(self):
        r = self.run_upstream_case({"SECLAB_REQUIRE_UPSTREAM": "1", "SECLAB_UPSTREAM": "/nonexistent-upstream"})
        self.assertEqual((len(r.failures), len(r.skipped)), (1, 0))

    def test_a_missing_checkout_only_skips_when_not_required(self):
        r = self.run_upstream_case({"SECLAB_REQUIRE_UPSTREAM": "0", "SECLAB_UPSTREAM": "/nonexistent-upstream"})
        self.assertEqual((len(r.failures), len(r.skipped)), (0, 1))


class ServerInitiatedPushSweepTest(unittest.TestCase):
    """Surface (c2): the sweep must find pushes it was never told about.

    The predecessor of this sweep was five regexes naming ``onExecuteCommand``
    and three ``_remoteCLI`` commands. It was perfectly green, and it could
    only ever rediscover what a human had already found. These tests are built
    the other way round: each one injects a push the generator has no knowledge
    of and requires it to come back out.
    """

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="seclab-push-test-")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def _client(self, extra_event=""):
        _write(self.root, "src/vs/workbench/contrib/x/xChannel.ts", """
export const enum XEvent {
	OnSomething = '$onSomething',
	OnInvented = '$onInvented',
}

export class XChannelClient {
	constructor(private readonly _channel: IChannel) { }
	get onSomething(): Event<{ id: number }> {
		return this._channel.listen<{ id: number }>(XEvent.OnSomething);
	}
""" + extra_event + """
}
""")

    def _backend(self, handler="this._log(e);"):
        _write(self.root, "src/vs/workbench/contrib/x/xBackend.ts", """
export class XBackend {
	constructor(connection: IRemoteAgentConnection) {
		const channel = instantiationService.createInstance(XChannelClient,
			connection.getChannel('xchannel'));
		channel.onSomething(e => { """ + handler + """ });
	}
}
""")

    def build(self):
        return PUSHES.build(SourceTree(root=self.root, sha="t"))

    def keys(self, built):
        return {p["key"] for p in built["server_initiated_pushes"]}

    def test_finds_a_push_the_generator_was_never_told_about(self):
        self._client()
        self._backend()
        built = self.build()
        self.assertIn("push:xchannel:$onSomething", self.keys(built))
        self.assertEqual(built["unresolved_channel_count"], 0)

    def test_a_newly_added_upstream_push_appears(self):
        # The upstream-bump case: a second event shows up in the channel
        # client. Nothing names it anywhere in the generator.
        self._client(extra_event="""
	get onInvented(): Event<void> {
		return this._channel.listen<void>(XEvent.OnInvented);
	}
""")
        self._backend()
        self.assertIn("push:xchannel:$onInvented", self.keys(self.build()))

    def test_control_the_old_hint_list_would_have_missed_it(self):
        # The superseded approach, transliterated: a fixed set of patterns.
        # It must fail on the same input, or the test above proves nothing
        # about why the hint list was replaced.
        self._client(extra_event="""
	get onInvented(): Event<void> {
		return this._channel.listen<void>(XEvent.OnInvented);
	}
""")
        self._backend()
        hints = ("onExecuteCommand", "_remoteCLI.windowOpen",
                 "_remoteCLI.openExternal", "_remoteCLI.manageExtensions")
        source = open(os.path.join(
            self.root, "src/vs/workbench/contrib/x/xChannel.ts")).read()
        self.assertFalse(any(h in source for h in hints),
                         "the hint list finds nothing here, which is the point")

    def test_extends_resolves_through_an_import_alias(self):
        # Upstream's real shape: the base is imported under another name, so
        # `extends` names a local binding and not the class. Searching the tree
        # for the binding finds nothing, which silently lost the five
        # `extensions` pushes including onDidInstallExtensions.
        _write(self.root, "src/vs/platform/e/base.ts", """
export class RealBaseClient {
	constructor(private readonly _channel: IChannel) { }
	get onDidInstall(): Event<void> {
		return this._channel.listen<void>('onDidInstall');
	}
}
""")
        _write(self.root, "src/vs/workbench/contrib/e/derived.ts", """
import { RealBaseClient as AliasedBase } from '../../../platform/e/base.ts';

export class DerivedClient extends AliasedBase { }
""")
        _write(self.root, "src/vs/workbench/contrib/e/use.ts", """
export class User {
	constructor(connection: IRemoteAgentConnection) {
		instantiationService.createInstance(DerivedClient,
			connection.getChannel('echannel'));
	}
}
""")
        built = self.build()
        self.assertIn("push:echannel:onDidInstall", self.keys(built))
        self.assertEqual(built["unresolved_channel_count"], 0)

    def test_an_unresolvable_base_is_reported_not_called_silent(self):
        # The base is named but does not exist. Reporting "this channel pushes
        # nothing" on the strength of a failed lookup is the confidently wrong
        # answer the module exists to avoid.
        _write(self.root, "src/vs/workbench/contrib/f/derived.ts", """
export class FClient extends SomeBaseThatIsNotInTheTree { }
""")
        _write(self.root, "src/vs/workbench/contrib/f/use.ts", """
export class FUser {
	constructor(connection: IRemoteAgentConnection) {
		instantiationService.createInstance(FClient,
			connection.getChannel('fchannel'));
		other.listen('keep-the-module-listening');
	}
}
""")
        built = self.build()
        self.assertEqual(built["unresolved_channel_count"], 1)
        self.assertIn("could not be resolved",
                      built["unresolved_channels"][0]["problem"])

    def test_a_new_on_the_previous_statement_is_not_the_sink(self):
        # The 300-char lookbehind used to take the last `new X(` it saw, which
        # was the *preceding* statement. That is how the logger channel
        # resolved to DownloadServiceChannel and reported no pushes.
        _write(self.root, "src/vs/platform/g/client.ts", """
export class GLoggerClient {
	constructor(private readonly _channel: IChannel) { }
	get onDidChangeLoggers(): Event<void> {
		return this._channel.listen<void>('onDidChangeLoggers');
	}
}
""")
        _write(self.root, "src/vs/workbench/contrib/g/use.ts", """
export class GUser {
	constructor(connection: IRemoteAgentConnection) {
		connection.registerChannel('download', new UnrelatedChannel(service));
		connection.withChannel('glogger', async channel =>
			this._register(new GLoggerClient(channel)));
	}
}
""")
        built = self.build()
        self.assertIn("push:glogger:onDidChangeLoggers", self.keys(built))

    def test_an_acting_subscription_is_flagged(self):
        self._client()
        self._backend(handler="this._commandService.executeCommand(e.commandId);")
        acting = {p["key"] for p in self.build()["server_initiated_pushes"]
                  if p["acts_on_push"]}
        self.assertIn("push:xchannel:$onSomething", acting)

    def test_the_wire_name_and_the_accessor_are_distinguished(self):
        # The wire carries '$onSomething'; subscribers write 'onSomething'.
        # Conflating them is what made the terminal push look inert.
        self._client()
        self._backend(handler="this._commandService.executeCommand(e.id);")
        push = next(p for p in self.build()["server_initiated_pushes"])
        self.assertEqual(push["event"], "$onSomething")
        self.assertEqual(push["accessor"], "onSomething")
        self.assertTrue(push["subscriptions"], "subscription must be located")

    def test_an_unfollowable_channel_is_reported_not_dropped(self):
        # A channel whose sink cannot be determined, in a module that *does*
        # listen elsewhere, must surface as unresolved rather than vanish.
        _write(self.root, "src/vs/workbench/contrib/y/yThing.ts", """
export class YThing {
	constructor(connection: IRemoteAgentConnection) {
		handOff(connection.getChannel('ychannel'));
		other.listen('zzz');
	}
}
""")
        built = self.build()
        self.assertEqual(built["unresolved_channel_count"], 1)
        self.assertEqual(built["server_initiated_push_count"], 0)

    def test_a_call_only_channel_is_resolved_as_silent(self):
        _write(self.root, "src/vs/workbench/contrib/z/zThing.ts", """
export class ZThing {
	constructor(connection: IRemoteAgentConnection) {
		const channel = connection.getChannel('zchannel');
		channel.call('setThing', [1]);
	}
}
""")
        built = self.build()
        self.assertEqual(built["unresolved_channel_count"], 0)
        self.assertEqual(built["channels_without_pushes_count"], 1)

    def test_trusted_process_channels_are_not_swept(self):
        _write(self.root, "src/vs/platform/ipc/electron-browser/m.ts", """
export class M {
	f() { return this.mainProcessService.getChannel('whatever'); }
}
""")
        self.assertEqual(self.build()["server_initiated_push_count"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
