import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { test } from 'node:test';
import { encodeData, encodeFrame, encodeJson, FrameDecoder, FrameError, MAX_FRAME } from '../src/frames.ts';
import { checkFence, parsePolicyJson, resourcesToMirror } from '../src/fence.ts';
import { TabStore } from '../src/state.ts';
import { assertPolicyResource, canonicalWorkspacePath, mintTabId, sandboxNameFor, TAB_ID_RE, ValidationError } from '../src/validate.ts';

// Durable scratch under the repo (never /tmp): .work/test-tabd
const SCRATCH = path.resolve(import.meta.dirname, '../../.work/test-tabd');
fs.rmSync(SCRATCH, { recursive: true, force: true });
fs.mkdirSync(SCRATCH, { recursive: true });

test('frames: roundtrip, split, partial delivery', () => {
	const dec = new FrameDecoder();
	const big = Buffer.alloc(MAX_FRAME + 10, 7);
	const wire = Buffer.concat([encodeJson({ a: 1 }), ...encodeData(3, big)]);
	const out = [];
	for (let i = 0; i < wire.length; i += 4093) {
		out.push(...dec.push(wire.subarray(i, i + 4093)));
	}
	assert.equal(out.length, 3);
	assert.deepEqual(JSON.parse(out[0].payload.toString()), { a: 1 });
	assert.equal(out[1].channel, 3);
	assert.equal(out[1].payload.length + out[2].payload.length, big.length);
});

test('frames: oversize header is fatal', () => {
	const h = Buffer.alloc(8);
	h.writeUInt32BE(MAX_FRAME + 1, 0);
	assert.throws(() => new FrameDecoder().push(h), FrameError);
	assert.throws(() => encodeFrame(1, Buffer.alloc(MAX_FRAME + 1)), FrameError);
});

test('validate: tab ids are random, well-formed, map to sbx-safe names', () => {
	const ids = new Set(Array.from({ length: 200 }, mintTabId));
	assert.equal(ids.size, 200);
	for (const id of ids) {
		assert.match(id, TAB_ID_RE);
		assert.match(sandboxNameFor(id), /^seclab-t-[a-z2-7]{26}$/);
	}
	assert.throws(() => sandboxNameFor('t-../../x'), ValidationError);
	assert.throws(() => sandboxNameFor('--help'), ValidationError);
});

test('validate: workspace paths', () => {
	const home = path.join(SCRATCH, 'home');
	const ws = path.join(home, 'src', 'proj');
	fs.mkdirSync(ws, { recursive: true });
	fs.mkdirSync(path.join(home, '.ssh'), { recursive: true });
	const pol = { home };
	assert.equal(canonicalWorkspacePath(ws, pol), fs.realpathSync.native(ws));
	const bad = (p: unknown, why: RegExp) => assert.throws(() => canonicalWorkspacePath(p, pol), why);
	bad('relative/x', /absolute/);
	bad(home, /sensitive/);
	bad(path.join(home, '.ssh'), /inside|sensitive/);
	bad(path.join(home, '.SSH'), /inside|sensitive|exist|symlink/); // case-folded on APFS, nonexistent on case-sensitive FS
	bad('/', /sensitive/);
	for (const c of [',', ':', '=', '\n']) {
		const p = path.join(home, `x${c}source=${home}`);
		bad(p, /forbidden/);
	}
	// symlinked component
	const link = path.join(home, 'link');
	fs.symlinkSync(path.join(home, '.ssh'), link);
	bad(link, /symlink/);
	// allowlist
	assert.throws(() => canonicalWorkspacePath(ws, { home, allowedRoots: [path.join(home, 'other')] }), /allowed roots/);
	// ancestor of an extra sensitive dir
	assert.throws(() => canonicalWorkspacePath(path.join(home, 'src'), { home, sensitive: [ws] }), /contains/);
});

test('validate: policy resources', () => {
	for (const ok of ['api.anthropic.com:443', '**.openai.com:443', '**', 'localhost:18080', 'api[12].example.com']) {
		assert.equal(assertPolicyResource(ok), ok);
	}
	for (const bad of ['--sandbox', '-x', 'a b', 'a\nb', '', 'host:99999x', 'é.com']) {
		assert.throws(() => assertPolicyResource(bad), ValidationError);
	}
});

const RULES = (extra: object[] = []) => JSON.stringify({
	rules: [
		{ id: 'default-deny-all', applies_to: 'all', scope: 'global', decision: 'deny', resource_type: 'network', resources: ['**'], actions: ['net:connect:tcp', 'net:connect:udp'], status: 'active' },
		{ id: 'default-ai', applies_to: 'all', scope: 'global', decision: 'allow', resource_type: 'network', resources: ['api.anthropic.com:443', '**.openai.com:443'], actions: ['net:connect:tcp'], status: 'active' },
		{ id: 'fs', applies_to: 'all', scope: 'global', decision: 'allow', resource_type: 'filesystem:read', resources: ['**'], actions: ['fs:mount:read'], status: 'active' },
		{ id: 'other-sbx', applies_to: 'sandbox:copilot-x', scope: 'sandbox:copilot-x', decision: 'allow', resource_type: 'network', resources: ['deb.debian.org'], actions: ['net:connect:tcp'], status: 'active' },
		...extra,
	],
});
const S = 'seclab-t-aaaaaaaaaaaaaaaaaaaaaaaaaa';
const deny = (res: string[]) => ({ id: 'd1', applies_to: `sandbox:${S}`, scope: `sandbox:${S}`, decision: 'deny', resource_type: 'network', resources: res, actions: ['net:connect:tcp', 'net:connect:udp'], status: 'active' });

test('fence: global allows must be mirrored as sandbox denies', () => {
	assert.deepEqual(resourcesToMirror(parsePolicyJson(RULES())), ['**.openai.com:443', 'api.anthropic.com:443']);
	const p1 = checkFence(parsePolicyJson(RULES()), S);
	assert.equal(p1.length, 2);
	assert.match(p1.join(), /api\.anthropic\.com:443/);
	assert.deepEqual(checkFence(parsePolicyJson(RULES([deny(['api.anthropic.com:443', '**.openai.com:443'])])), S), []);
});

test('fence: only our own broker allow is exempt', () => {
	const brokerAllow = { id: 'b', applies_to: `sandbox:${S}`, scope: `sandbox:${S}`, decision: 'allow', resource_type: 'network', resources: ['localhost:18080'], actions: ['net:connect:tcp'], status: 'active' };
	const rules = parsePolicyJson(RULES([deny(['api.anthropic.com:443', '**.openai.com:443']), brokerAllow]));
	assert.deepEqual(checkFence(rules, S, 18080), []);
	assert.equal(checkFence(rules, S, 18081).length, 1, 'a different broker port is not exempt');
	assert.equal(checkFence(rules, S).length, 1, 'no broker: the allow is a leak');
	// A *global* allow for the broker port is not exempt.
	const globalBroker = { ...brokerAllow, id: 'g', applies_to: 'all', scope: 'global' };
	assert.equal(checkFence(parsePolicyJson(RULES([deny(['api.anthropic.com:443', '**.openai.com:443']), globalBroker])), S, 18080).length, 1);
});

test('fence: fails closed on unknown shapes', () => {
	assert.throws(() => parsePolicyJson('not json'));
	assert.throws(() => parsePolicyJson('{"rules":[{"id":1}]}'));
	const weird = { id: 'w', applies_to: 'all', scope: 'global', decision: 'maybe', resource_type: 'network', resources: ['x'], actions: ['net:connect:tcp'], status: 'active' };
	assert.match(checkFence(parsePolicyJson(RULES([weird])), S).join(), /unknown decision/);
	const kind = { ...weird, decision: 'allow', resource_type: 'network:dns' };
	assert.match(checkFence(parsePolicyJson(RULES([kind])), S).join(), /unknown resource type/);
	const act = { ...weird, decision: 'allow', actions: ['net:connect:quic'] };
	assert.match(checkFence(parsePolicyJson(RULES([act])), S).join(), /unknown action/);
	const badRes = { ...weird, decision: 'allow', resources: ['--sandbox'] };
	assert.throws(() => resourcesToMirror(parsePolicyJson(RULES([badRes]))), ValidationError);
});

test('state: claim is idempotent per path, rejects overlaps, persists identity', () => {
	const store = new TabStore(path.join(SCRATCH, 'state'));
	const a = path.join(SCRATCH, 'home', 'src', 'proj');
	const r1 = store.claim(a, 'default');
	const r2 = store.claim(a, 'default');
	assert.equal(r1.created, true);
	assert.equal(r2.created, false);
	assert.equal(r1.record.tabId, r2.record.tabId);
	assert.match(r1.record.dev, /^[0-9]+$/);
	const nested = path.join(a, 'nested');
	fs.mkdirSync(nested, { recursive: true });
	assert.throws(() => store.claim(nested, 'default'), /overlaps/);
	assert.throws(() => store.claim(path.join(SCRATCH, 'home', 'src'), 'default'), /overlaps/);
	assert.equal(store.list().length, 1);
	store.forget(r1.record.tabId);
	assert.equal(store.list().length, 0);
});
