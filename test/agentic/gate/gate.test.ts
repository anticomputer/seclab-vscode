// Unit tests for patch 0015's gate filter (agentic/patch-src), run under node's type stripping.
// The probe runner proves the same rules in the shipped build; these pin the logic.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { check } from '../../../agentic/tools/sync-patch.ts';
import { SECLAB_AHP_REFUSED, SeclabAhpFilter, seclabAhpSanitize, type SeclabAhpEvent } from '../../../agentic/patch-src/src/vs/platform/agentHost/common/seclabAhpPolicy.ts';
import { SECLAB_AHP_TABLES } from '../../../agentic/patch-src/src/vs/platform/agentHost/common/seclabAhpPolicyData.ts';
import { isSeclabAuthority, seclabAhpBrandTransport, seclabAhpCheckTransport, seclabAhpInstallWindow } from '../../../agentic/patch-src/src/vs/platform/agentHost/common/seclabAhpGateCheck.ts';

function gate() {
	const events: SeclabAhpEvent[] = [];
	return { f: new SeclabAhpFilter(SECLAB_AHP_TABLES, 7, e => events.push(e)), events };
}
const j = (v: unknown) => JSON.stringify(v);
const rules = (events: SeclabAhpEvent[]) => events.map(e => `${e.detail.gateRule}:${e.detail.verdict}`);

test('patch 0015 ships exactly agentic/patch-src', () => {
	assert.deepEqual(check(), []);
});

test('every event has the tab.events.report shape', () => {
	const { f, events } = gate();
	f.fromUpstream(j({ jsonrpc: '2.0', id: 1, method: 'resourceRead', params: { uri: 'file:///etc/passwd' } }));
	f.fromClient(j({ jsonrpc: '2.0', id: 2, method: 'authenticate', params: {} }));
	assert.ok(events.length >= 2);
	for (const e of events) {
		assert.equal(e.source, 'ahp-gate');
		assert.equal(e.class, 'ahp.decision');
		assert.ok(['critical', 'warning', 'notice', 'informational'].includes(e.priority));
		assert.ok(Object.keys(e.detail).length <= 16);
		assert.ok(Object.values(e.detail).every(v => ['string', 'number', 'boolean'].includes(typeof v)));
		assert.equal(e.detail.connection, 7);
		assert.equal(typeof e.detail.gateRule, 'string');
	}
});

test('A16/A5/A26: every agent-host request is refused by the gate itself', () => {
	for (const method of ['resourceRead', 'resourceWrite', 'resourceList', '_vscode/loadClientCertificates', '_vscode/resolveClientProxy', 'brandNewThing']) {
		const { f, events } = gate();
		const out = f.fromUpstream(j({ jsonrpc: '2.0', id: 41, method, params: { uri: 'file:///outside-the-tab/canary.txt' } }));
		assert.deepEqual(out.toClient, [], method);
		assert.equal(out.toUpstream.length, 1);
		const reply = JSON.parse(out.toUpstream[0]);
		assert.equal(reply.id, 41);
		assert.equal(reply.error.code, SECLAB_AHP_REFUSED);
		assert.deepEqual(rules(events), ['ahp-gate.reverse-request:deny']);
	}
});

test('A14: unknown methods and action types are denied in both directions', () => {
	const { f, events } = gate();
	const out = f.fromClient(j({ jsonrpc: '2.0', id: 3, method: '_vscode/unknown', params: {} }));
	assert.deepEqual(out.toUpstream, []);
	assert.equal(JSON.parse(out.toClient[0]).error.code, SECLAB_AHP_REFUSED);
	assert.deepEqual(f.fromUpstream(j({ jsonrpc: '2.0', method: 'vendor/notify', params: {} })).toClient, []);
	assert.deepEqual(f.fromUpstream(j({ jsonrpc: '2.0', method: 'action', params: { action: { type: 'evil/do' } } })).toClient, []);
	assert.deepEqual(f.fromClient(j({ jsonrpc: '2.0', method: 'dispatchAction', params: { action: { type: 'chat/delta' } } })).toUpstream, [], 'a server-only action from the client');
	assert.deepEqual(rules(events), ['ahp-gate.method:deny', 'ahp-gate.method:deny', 'ahp-gate.action:deny', 'ahp-gate.action:deny']);
});

test('responses pass only for requests the gate let through', () => {
	const { f, events } = gate();
	assert.deepEqual(f.fromUpstream(j({ jsonrpc: '2.0', id: 9, result: {} })).toClient, []);
	const req = j({ jsonrpc: '2.0', id: 9, method: 'listSessions', params: {} });
	assert.deepEqual(f.fromClient(req).toUpstream, [req]);
	const res = j({ jsonrpc: '2.0', id: 9, result: { items: [] } });
	assert.deepEqual(f.fromUpstream(res).toClient, [res]);
	assert.deepEqual(f.fromUpstream(res).toClient, [], 'only once');
	assert.deepEqual(rules(events), ['ahp-gate.unsolicited-response:deny', 'ahp-gate.unsolicited-response:deny']);
});

test('A1: protected resources and auth/required never reach the client; authenticate never leaves', () => {
	const { f, events } = gate();
	const init = j({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { _meta: { 'vscode.ahpSessionUris': true, 'vscode.clientProxy': true, 'vscode.clientCertificates': true, 'vscode.machineId': 'm' } } });
	const sent = JSON.parse(f.fromClient(init).toUpstream[0]);
	assert.deepEqual(Object.keys(sent.params._meta), ['vscode.ahpSessionUris']);
	const result = { snapshots: [{ resource: 'ahp-root://', state: { agents: [{ provider: 'x', protectedResources: [{ resource: 'https://beacon.test', authorization_servers: ['http://127.0.0.1:9'] }] }] } }] };
	const got = JSON.parse(f.fromUpstream(j({ jsonrpc: '2.0', id: 1, result })).toClient[0]);
	assert.equal(got.result.snapshots[0].state.agents[0].protectedResources, undefined);
	assert.equal(got.result.snapshots[0].state.agents[0].provider, 'x');
	assert.deepEqual(f.fromUpstream(j({ jsonrpc: '2.0', method: 'auth/required', params: {} })).toClient, []);
	const auth = f.fromClient(j({ jsonrpc: '2.0', id: 2, method: 'authenticate', params: { resource: 'r', token: 'seclabcanary_x' } }));
	assert.deepEqual(auth.toUpstream, []);
	assert.deepEqual(rules(events), ['ahp-gate.client-meta:strip', 'ahp-gate.initialize:allow', 'ahp-gate.strip:strip', 'ahp-gate.method:deny', 'ahp-gate.method:deny']);
	assert.equal(events[1].detail.agents, 1);
});

test('A7: no TCP tunnel in either direction', () => {
	const { f } = gate();
	assert.deepEqual(f.fromClient(j({ jsonrpc: '2.0', id: 5, method: 'createTcpConnection', params: { host: '127.0.0.1', port: 9 } })).toUpstream, []);
	assert.deepEqual(f.fromUpstream(j({ jsonrpc: '2.0', method: 'tcp/data', params: {} })).toClient, []);
	assert.deepEqual(f.fromClient(j({ jsonrpc: '2.0', method: 'tcp/data', params: {} })).toUpstream, []);
});

test('A19: host config is not mirrored; client tools and customizations are not advertised', () => {
	const { f, events } = gate();
	assert.deepEqual(f.fromClient(j({ jsonrpc: '2.0', method: 'dispatchAction', params: { action: { type: 'root/configChanged', config: { 'http.proxy': 'http://seclabcanary_u:x@proxy.invalid' } } } })).toUpstream, []);
	const set = f.fromClient(j({ jsonrpc: '2.0', method: 'dispatchAction', params: { channel: 's', action: { type: 'session/activeClientSet', activeClient: { clientId: 'c', tools: [{ name: 'runInHost' }], customizations: [{ uri: 'file:///host/.github/x.md' }] } } } }));
	const a = JSON.parse(set.toUpstream[0]).params.action.activeClient;
	assert.deepEqual(a, { clientId: 'c', tools: [] });
	assert.deepEqual(rules(events), ['ahp-gate.root-config:strip', 'ahp-gate.client-tools:strip']);
});

test('A20/A21: MCP App UI and ui: resources are stripped from inbound content', () => {
	const v = { a: { mcpApp: { capabilities: {} }, b: 'ui://server/app.html', c: ['ok', 'UI://x'], d: 'fine' } };
	assert.equal(seclabAhpSanitize(v as never), 3);
	assert.deepEqual(v, { a: { c: ['ok'], d: 'fine' } });
	let deep: unknown = 'x';
	for (let i = 0; i < 100; i++) {
		deep = [deep];
	}
	assert.throws(() => seclabAhpSanitize(deep as never));
});

test('fragments are filtered as whole messages and cannot carry requests', () => {
	const { f, events } = gate();
	const inner = j({ jsonrpc: '2.0', id: 77, method: 'resourceRead', params: { uri: 'file:///etc/passwd' } });
	const frag = (data: string, final: boolean) => j({ jsonrpc: '2.0', method: 'channel/frame', params: { channel: 'c', data, final } });
	assert.deepEqual(f.fromUpstream(frag(inner.slice(0, 10), false)).toClient, []);
	assert.deepEqual(f.fromUpstream(frag(inner.slice(10), true)).toClient, []);
	assert.deepEqual(rules(events), ['ahp-gate.reverse-request:deny']);
	const ok = j({ jsonrpc: '2.0', method: 'action', params: { channel: 'c', action: { type: 'chat/delta' } } });
	const a = frag(ok.slice(0, 5), false), b = frag(ok.slice(5), true);
	f.fromUpstream(a);
	assert.deepEqual(f.fromUpstream(b).toClient, [a, b], 'unchanged messages keep their original fragments');
	const bad = j({ jsonrpc: '2.0', method: 'action', params: { channel: 'c', action: { type: 'chat/delta', mcpApp: {} } } });
	f.fromUpstream(frag(bad.slice(0, 5), false));
	const out = f.fromUpstream(frag(bad.slice(5), true)).toClient;
	assert.equal(out.length, 1);
	assert.equal(JSON.parse(JSON.parse(out[0]).params.data).params.action.mcpApp, undefined);
});

test('malformed and oversized frames are dropped', () => {
	const { f, events } = gate();
	assert.deepEqual(f.fromUpstream('not json').toClient, []);
	assert.deepEqual(f.fromUpstream(j({ id: 1, result: {} })).toClient, []);
	assert.deepEqual(f.fromUpstream('x'.repeat(32 * 1024 * 1024 + 1)).toClient, []);
	assert.deepEqual(rules(events), ['ahp-gate.malformed:deny', 'ahp-gate.malformed:deny', 'ahp-gate.size:deny']);
});

test('construction invariant: tab identities need a branded transport; opened then verified share a connection', () => {
	assert.ok(isSeclabAuthority('seclab+abc'));
	assert.ok(!isSeclabAuthority('ssh-remote+abc'));
	seclabAhpCheckTransport('vscode-remote://ssh-remote+x', {});
	assert.throws(() => seclabAhpCheckTransport('vscode-remote://seclab+t1', {}));
	const events: SeclabAhpEvent[] = [];
	seclabAhpInstallWindow(e => events.push(e));
	// Once the window is a tab window, every transport must be gated, whatever its identity.
	assert.throws(() => seclabAhpCheckTransport('vscode-remote://ssh-remote+x', {}));
	const t = {};
	seclabAhpBrandTransport(t, 42);
	seclabAhpCheckTransport('vscode-remote://seclab+t1', t);
	assert.deepEqual(events.map(e => `${e.detail.gateRule}:${e.detail.connection}`).slice(-2), ['ahp-gate.opened:42', 'ahp-gate.verified:42']);
	assert.equal(events.filter(e => e.detail.gateRule === 'ahp-gate.refused').length, 1);
});
