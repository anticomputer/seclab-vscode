// Patch 0018: a chat request in a tab window may address only this window's own agent-host
// session.
//
// The point of these tests is the thing the patch's security argument actually rests on: the
// allowed case is decided by object IDENTITY, not by a session-type or authority string. A
// string check would pass every case below except the forged one, which is exactly the case a
// regression would produce, so that case is what makes this suite worth having.

import { strict as assert } from 'node:assert';
import { test } from 'node:test';

import {
	seclabChatSessionAllowed,
	seclabChatSessionVerdict,
	type SeclabSessionConnections,
} from '../../../agentic/patch-src/src/vs/platform/agentHost/common/seclabChatSessions.ts';
import { SECLAB_CHAT_AUTHORITY_PREFIX } from '../../../agentic/patch-src/src/vs/platform/agentHost/common/seclabChatSessions.ts';
import { SECLAB_AGENTS_ENABLED_SETTING, SECLAB_AUTHORITY_PREFIX, seclabAgentsEnabled } from '../../../agentic/patch-src/src/vs/platform/agentHost/common/seclabAhpGateCheck.ts';
import { SECLAB_TAB_AUTHORITY_PREFIX as FIXED_SETTINGS_PREFIX } from '../../../agentic/patch-src/src/vs/workbench/services/configuration/common/seclabFixedSettings.ts';

const TAB = 'seclab+t-abc123';
const uri = (s: string) => ({ toString: () => s }) as never;

/** The window's own connection, as upstream hands it back: one stable object. */
function connections(over: Partial<SeclabSessionConnections> = {}): SeclabSessionConnections {
	const ambient = { id: 'this window agent host' };
	return {
		ambientConnection: ambient,
		resolveSessionResource: () => ({ connection: ambient, backendSessionIsAdvertised: true as const }),
		...over,
	};
}

test('outside a tab window the patch changes nothing', () => {
	// An ordinary window, and a remote window that is not ours: both unchanged, even for a
	// session that resolves to nothing at all.
	const none = connections({ resolveSessionResource: () => undefined });
	for (const authority of [undefined, '', 'ssh-remote+box', 'wsl+ubuntu']) {
		assert.equal(seclabChatSessionAllowed(authority, true, none, uri('x')), true, String(authority));
	}
});

test("this window's own agent-host session is allowed", () => {
	assert.equal(seclabChatSessionAllowed(TAB, true, connections(), uri('agent-host-copilot:/s1')), true);
});

test('a built-in agent or extension participant is refused: it resolves to no session', () => {
	// This is 0009's behaviour kept: every chat path that is not the agent host's own still
	// runs a model loop on the trusted side, so it stays refused.
	const c = connections({ resolveSessionResource: () => undefined });
	assert.equal(seclabChatSessionAllowed(TAB, true, c, uri('vscode-chat://builtin/s1')), false);
});

test("another connection's session is refused", () => {
	// A remote agent host this window also knows about. Its connection is a different object,
	// so it is not this window's own session.
	const ambient = { id: 'ours' };
	const other = { id: 'some other agent host' };
	const c: SeclabSessionConnections = {
		ambientConnection: ambient,
		resolveSessionResource: () => ({ connection: other, backendSessionIsAdvertised: true as const }),
	};
	assert.equal(seclabChatSessionAllowed(TAB, true, c, uri('agent-host://elsewhere/s1')), false);
});

test('THE POINT: a look-alike connection is refused, because the check is identity', () => {
	// The regression this patch exists to survive. Suppose something a tab can influence
	// produces a connection that matches ours on every readable field -- same authority, same
	// shape -- but is not the object upstream resolved for this window. A string or structural
	// comparison would allow it and hand the tab a trusted-side model loop. Identity refuses.
	const ambient = { authority: 'ambient', kind: 'agent-host' };
	const lookAlike = { authority: 'ambient', kind: 'agent-host' };
	assert.deepEqual(lookAlike, ambient, 'the fixture must be indistinguishable by value');
	const c: SeclabSessionConnections = {
		ambientConnection: ambient,
		resolveSessionResource: () => ({ connection: lookAlike, backendSessionIsAdvertised: true as const }),
	};
	assert.equal(seclabChatSessionAllowed(TAB, true, c, uri('agent-host://ambient/s1')), false);
});

test('a resolution with no connection at all is refused', () => {
	const c = connections({ resolveSessionResource: () => ({ connection: undefined, backendSessionIsAdvertised: true as const }) });
	assert.equal(seclabChatSessionAllowed(TAB, true, c, uri('agent-host://ambient/s1')), false);
});

test('ambientConnection being undefined cannot make an unresolved session look like ours', () => {
	// Fail closed if upstream ever hands back `undefined` on both sides: two undefineds are
	// reference-equal, so the resolution must be rejected before the comparison.
	const c: SeclabSessionConnections = {
		ambientConnection: undefined,
		resolveSessionResource: () => ({ connection: undefined, backendSessionIsAdvertised: true as const }),
	};
	assert.equal(seclabChatSessionAllowed(TAB, true, c, uri('agent-host://ambient/s1')), false);
});

test('the tab-authority test matches the prefix, not a substring', () => {
	assert.equal(seclabChatSessionAllowed('seclab+t-1', true, { ambientConnection: undefined, resolveSessionResource: () => undefined }, uri('x')), false, 'a tab authority is gated');
	assert.equal(seclabChatSessionAllowed('ssh-remote+seclab+t-1', true, { ambientConnection: undefined, resolveSessionResource: () => undefined }, uri('x')), true, 'must anchor at the start');
	assert.equal(seclabChatSessionAllowed(undefined, true, { ambientConnection: undefined, resolveSessionResource: () => undefined }, uri('x')), true);
	assert.equal(seclabChatSessionAllowed('', true, { ambientConnection: undefined, resolveSessionResource: () => undefined }, uri('x')), true);
});

test('the duplicated authority prefix stays equal across patch modules', () => {
	// Each patch module declares its own copy, because a value import across them does not
	// resolve under node --test's type stripping. This is the guarantee that replaces it.
	assert.equal(SECLAB_CHAT_AUTHORITY_PREFIX, FIXED_SETTINGS_PREFIX);
	assert.equal(SECLAB_CHAT_AUTHORITY_PREFIX, SECLAB_AUTHORITY_PREFIX);
	assert.equal(SECLAB_AUTHORITY_PREFIX, 'seclab+');
});

test('THE OTHER POINT: an ambient-synthesised identity is refused unless it is advertised', () => {
	// Upstream's `resolveSessionResourceIdentity` does NOT fail on an unknown session. On a
	// `_backendSessions` miss it SYNTHESISES an identity from the scheme: any
	// `agent-host-*` scheme becomes the ambient authority, and `getConnectionByAuthority`
	// then returns the very same object as `ambientConnection`. An identity-only check
	// would therefore have been a scheme-prefix string test one layer down, which is what
	// this patch exists to avoid. Requiring `backendSessionIsAdvertised` is what makes the
	// check mean "a session this window's own host actually registered".
	const ambient = { id: 'this window agent host' };
	const synthesised: SeclabSessionConnections = {
		ambientConnection: ambient,
		// Same connection object, but no registry hit: not advertised.
		resolveSessionResource: () => ({ connection: ambient, backendSessionIsAdvertised: false }),
	};
	assert.equal(seclabChatSessionVerdict(TAB, true, synthesised, uri('agent-host-anything:/attacker')), 'deny:not-advertised');
	assert.equal(seclabChatSessionAllowed(TAB, true, synthesised, uri('agent-host-anything:/attacker')), false);

	// And the control: identical in every way except the registry hit.
	const advertised: SeclabSessionConnections = {
		ambientConnection: ambient,
		resolveSessionResource: () => ({ connection: ambient, backendSessionIsAdvertised: true }),
	};
	assert.equal(seclabChatSessionVerdict(TAB, true, advertised, uri('agent-host-anything:/attacker')), 'allow');
});

test('a missing advertised flag is not a pass', () => {
	// `undefined` must not be read as "fine"; only an explicit true is.
	const ambient = { id: 'ours' };
	const c = { ambientConnection: ambient, resolveSessionResource: () => ({ connection: ambient }) } as unknown as SeclabSessionConnections;
	assert.equal(seclabChatSessionVerdict(TAB, true, c, uri('agent-host-copilot:/s1')), 'deny:not-advertised');
});

test('agents being off refuses even this window\'s own advertised session', () => {
	assert.equal(seclabChatSessionVerdict(TAB, false, connections(), uri('agent-host-copilot:/s1')), 'deny:agents-off');
});

test('every verdict except allow is a refusal, and each is distinguishable', () => {
	// The verdict exists so a refusal is provable from the gate log. If two causes collapsed
	// to one string, a run could not tell which rule fired.
	const seen = new Set<string>();
	const ambient = { id: 'ours' };
	const cases: [string, SeclabSessionConnections, boolean][] = [
		['deny:agents-off', connections(), false],
		['deny:unresolved', connections({ resolveSessionResource: () => undefined }), true],
		['deny:not-advertised', { ambientConnection: ambient, resolveSessionResource: () => ({ connection: ambient, backendSessionIsAdvertised: false }) }, true],
		['deny:other-connection', { ambientConnection: ambient, resolveSessionResource: () => ({ connection: { id: 'other' }, backendSessionIsAdvertised: true }) }, true],
		['allow', connections(), true],
	];
	for (const [expected, c, enabled] of cases) {
		const v = seclabChatSessionVerdict(TAB, enabled, c, uri('agent-host-copilot:/s1'));
		assert.equal(v, expected);
		assert.equal(seen.has(v), false, `duplicate verdict ${v}`);
		seen.add(v);
		assert.equal(seclabChatSessionAllowed(TAB, enabled, c, uri('agent-host-copilot:/s1')), expected === 'allow');
	}
	assert.equal(seen.size, cases.length);
});

test('the shared enablement rule ignores every layer a tab can write', () => {
	// `seclabAgentsEnabled` takes only the two trustworthy fields of an `inspect()` result.
	// A tab extension can write the user, workspace and remote layers through
	// `$updateConfigurationOption`, and `getValue()` would merge them; passing them here
	// must change nothing. This is the rule BOTH gates use, so proving it once proves it
	// for 0015's transport gate and 0018's chat gate alike.
	const tabWritable = { userValue: true, workspaceValue: true, workspaceFolderValue: true, memoryValue: true };
	assert.equal(seclabAgentsEnabled({ ...tabWritable } as never, undefined), false);
	assert.equal(seclabAgentsEnabled({ ...tabWritable, defaultValue: false } as never, undefined), false);

	// Policy wins, in either direction, and outranks the default.
	assert.equal(seclabAgentsEnabled({ policyValue: true, defaultValue: false }, undefined), true);
	assert.equal(seclabAgentsEnabled({ policyValue: false, defaultValue: true }, undefined), false);

	// The host main process environment, stamped onto the window configuration at load.
	assert.equal(seclabAgentsEnabled({ ...tabWritable } as never, true), true);
	// ...and only an explicit true.
	assert.equal(seclabAgentsEnabled({ ...tabWritable } as never, undefined), false);

	// A registered default of true, with no policy, is the ordinary non-tab case.
	assert.equal(seclabAgentsEnabled({ defaultValue: true }, undefined), true);
});

test('the setting is named once', () => {
	assert.equal(SECLAB_AGENTS_ENABLED_SETTING, 'seclab.agents.enabled');
});
