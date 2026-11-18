// Patch 0018: on the chat paths that bypass `sendRequest` (which patch 0009 refuses outright in a
// tab window), no session but this window's own agent-host session is dispatched.
//
// The point of these tests is the thing the patch's security argument actually rests on: the
// allowed case is decided by object IDENTITY, not by a session-type or authority string. A
// string check would pass every case below except the forged one, which is exactly the case a
// regression would produce, so that case is what makes this suite worth having.

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';

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

test('the patch gates the queued path, which never reaches the dispatch function', () => {
	// Security review round 2, alert 1. A request submitted with `options.queue` returns from
	// `sendRequestInternal` BEFORE `_sendRequestAsync`, and for an agent-host session the
	// queue is server-managed, so the gated local drain never runs either: the pending
	// messages are synced straight to the agent host over its connection. `migrateRequests`
	// and `sendPendingRequestImmediately` both arrive there with `queue` set.
	//
	// The patch text is the artifact that ships, so assert against it rather than against a
	// copy of the call site that could drift away from it.
	const patch = readFileSync(new URL('../../../patches/0018-seclab-agent-host-sessions-only.patch', import.meta.url), 'utf8');
	const added = patch.split('\n').filter(l => l.startsWith('+')).join('\n');

	// One implementation...
	assert.equal((added.match(/private seclabCheckSession\(/g) ?? []).length, 1);
	// ...called from the queued path and from the dispatch function, and from nowhere else.
	assert.equal((added.match(/this\.seclabCheckSession\(sessionResource\);/g) ?? []).length, 2);

	// The queued call must sit inside the `options?.queue` branch, above the queueing itself,
	// or the message is already on its way to the host by the time it is checked. Ordering is
	// read from the patch as a whole, because the branch and the `queuePendingRequest` call
	// are upstream context lines, not added ones.
	const queueBranch = patch.indexOf('if (options?.queue) {');
	const queueCall = patch.indexOf('+\t\t\tthis.seclabCheckSession(sessionResource);', queueBranch);
	const queued = patch.indexOf('this.queuePendingRequest(', queueBranch);
	assert.ok(queueBranch >= 0, 'the queue branch should be in the patch context');
	assert.ok(queueCall > queueBranch, 'the queued path should be checked');
	assert.ok(queued > queueCall, 'the check must come before the request is queued');

	// And the dispatch-function call must be the first statement of `_sendRequestAsync`.
	assert.match(patch, /private _sendRequestAsync\([^)]*\)[^\n]*\n\+\t\tthis\.seclabCheckSession\(sessionResource\);/);
});

test('the gate refuses by throwing, and never by returning a value a caller could ignore', () => {
	// A gate that returned false would depend on every call site checking it. Round 2 found
	// callers that catch and re-queue, so the refusal has to be unignorable at the point it
	// is made.
	const patch = readFileSync(new URL('../../../patches/0018-seclab-agent-host-sessions-only.patch', import.meta.url), 'utf8');
	const added = patch.split('\n').filter(l => l.startsWith('+')).join('\n');
	const body = added.slice(added.indexOf('private seclabCheckSession('));
	assert.match(body.slice(0, body.indexOf('\n+\t}')), /throw new Error\('Unsupported operation'\);/);
	assert.doesNotMatch(body.slice(0, body.indexOf('\n+\t}')), /return (true|false)/);
});

test('the gate log counts per rule, so one rule cannot crowd out the refusals of another', () => {
	// Security review round 2, alert 3. The cap was per connection number, and patch 0018's
	// chat verdicts share connection 0 with `ahp-gate.disabled`. A tab can drive chat
	// refusals cheaply, so a per-connection budget let it silently stop either kind from
	// being recorded. An unlogged refusal is indistinguishable from nothing happening, which
	// is the one thing these events exist to rule out.
	const gate = readFileSync(new URL('../../../agentic/patch-src/src/vs/workbench/services/agentHost/browser/seclabAhpGate.ts', import.meta.url), 'utf8');
	const sink = gate.slice(gate.indexOf('const counts ='), gate.indexOf('emitWindow = sink;'));

	// Keyed by connection AND rule, not by connection alone.
	assert.match(sink, /const counts = new Map<string, number>\(\);/);
	assert.match(sink, /const key = `\$\{connection\}\\u0000\$\{rule\}`;/);
	assert.match(sink, /counts\.set\(key, n\);/);
	assert.doesNotMatch(sink, /counts\.(get|set)\(connection[,)]/);

	// And when it does cap, the notice says which rule it capped, or the evidence is
	// ambiguous in exactly the way the per-rule counting was meant to remove.
	assert.match(sink, /cappedRule: rule/);
});

test('the upstream facts patch 0018 depends on are pinned, each to the file that states them', () => {
	// Security review round 2, alert 4. These are the facts no unit test can hold, because
	// the unit container has no upstream checkout: they are checked over the patched tree by
	// the patch-build job. This test only guards that they remain pinned at all, so that
	// dropping one is a failure here rather than a silent weakening of the argument.
	const rules = JSON.parse(readFileSync(new URL('../../../patches/sole-consumer.json', import.meta.url), 'utf8')).__upstreamInvariants.rules as { file: string; mustContain: string[] }[];
	const pinned = (file: string, needle: string) =>
		rules.some(r => r.file === file && r.mustContain.some(m => m.includes(needle)));

	const connections = 'src/vs/platform/agentHost/browser/agentHostConnectionsService.ts';
	// The advertised flag is set only on a registry hit...
	assert.ok(pinned(connections, 'backendSessionIsAdvertised: true as const'), 'advertised-flag origin');
	// ...an unknown session is SYNTHESISED into an ambient identity rather than refused,
	// which is why identity alone was not enough...
	assert.ok(pinned(connections, 'AMBIENT_AGENT_HOST_AUTHORITY, provider, normalized'), 'ambient synthesis');
	// ...and the flag reaches the resolution the gate reads only through this spread.
	assert.ok(pinned(connections, '{ ...identity, connection }'), 'identity spread into the resolution');

	// The one remaining route to `defaultValue` is closed by upstream's scope filter.
	assert.ok(pinned('src/vs/workbench/api/common/configurationExtensionPoint.ts', 'const allowedScopes ='), 'configurationDefaults scope filter');
});
