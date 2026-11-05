import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { test } from 'node:test';
import { encodeData, encodeFrame, encodeJson, FrameDecoder, FrameError, MAX_FRAME } from '../src/frames.ts';
import { BROKER_POLICY_SCHEMA, checkBrokerHello } from '../src/broker.ts';
import { checkFence, parsePolicyJson, resourcesToMirror } from '../src/fence.ts';
import { TabStore } from '../src/state.ts';
import { displayPath, goUnquote, parseFrames, rewriteSecret } from '../src/scan.ts';
import { assertPolicyResource, canonicalWorkspacePath, mintTabId, sandboxNameFor, TAB_ID_RE, ValidationError } from '../src/validate.ts';

// Durable scratch under the repo (never /tmp); a named volume when run via ./seclab test unit.
const SCRATCH = path.resolve(import.meta.dirname, '../../.work/test-scratch/unit');
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
	const pol = { home, allowedRoots: [path.join(home, 'src'), path.join(home, '.copilot', 'worktrees')] };
	assert.equal(canonicalWorkspacePath(ws, pol), fs.realpathSync.native(ws));
	assert.throws(() => canonicalWorkspacePath(ws, { home }), /no allowed roots/);
	assert.throws(() => canonicalWorkspacePath(ws, { home, allowedRoots: [home] }), /too broad/);
	fs.mkdirSync(path.join(home, '.claude', 'plugins', 'x'), { recursive: true });
	assert.throws(() => canonicalWorkspacePath(path.join(home, '.claude', 'plugins', 'x'), { home, allowedRoots: [path.join(home, '.claude')] }), /too broad|dot-directory/);
	fs.mkdirSync(path.join(home, '.npm', '_npx', 'y'), { recursive: true });
	assert.throws(() => canonicalWorkspacePath(path.join(home, '.npm', '_npx', 'y'), { home, allowedRoots: [path.join(home, '.npm')] }), /dot-directory/);
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
	// host binary locations are never mountable (tabd executes sbx/docker from there)
	for (const p of ['/opt/homebrew', '/usr/local', '/Applications']) {
		if (fs.existsSync(p)) {
			assert.throws(() => canonicalWorkspacePath(p, pol), /sensitive|inside|contains/);
		}
	}
	// agent config files: their directory is refused, project dirs beneath stay openable
	fs.mkdirSync(path.join(home, '.copilot', 'worktrees', 'p'), { recursive: true });
	fs.writeFileSync(path.join(home, '.copilot', 'mcp-config.json'), '{}');
	assert.throws(() => canonicalWorkspacePath(path.join(home, '.copilot'), pol), /contains/);
	assert.ok(canonicalWorkspacePath(path.join(home, '.copilot', 'worktrees', 'p'), pol));
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

test('fence: sandbox-scoped kit allows (sbx 0.51) are mirrored too; only our broker allow and other sandboxes are not', () => {
	const kit = { id: '684767c9', applies_to: `sandbox:${S}`, scope: `sandbox:${S}`, decision: 'allow', resource_type: 'network', resources: ['deb.debian.org:80', 'dhi.io:80'], actions: ['net:connect:tcp'], status: 'active' };
	const brokerAllow = { ...kit, id: 'b', resources: ['localhost:18080'] };
	const rules = parsePolicyJson(RULES([kit, brokerAllow]));
	assert.deepEqual(resourcesToMirror(rules, S, 18080), ['**.openai.com:443', 'api.anthropic.com:443', 'deb.debian.org:80', 'dhi.io:80']);
	assert.ok(resourcesToMirror(rules, S).includes('localhost:18080'), 'no broker: its allow is mirrored like any other');
	assert.match(checkFence(rules, S, 18080).join(), /deb\.debian\.org:80/, 'unmirrored kit allow fails the fence');
	const mirrored = parsePolicyJson(RULES([kit, brokerAllow, deny(resourcesToMirror(rules, S, 18080))]));
	assert.deepEqual(checkFence(mirrored, S, 18080), [], 'mirroring what resourcesToMirror returns satisfies the fence');
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
	const scope = { ...weird, decision: 'allow', applies_to: 'kit:shell' };
	assert.match(checkFence(parsePolicyJson(RULES([scope])), S).join(), /unknown applies_to/);
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

// ---- secret scan (review round 5) ------------------------------------------------------

const frame = (kind: string, rel: string, code: number, body: string) => {
	const b = Buffer.from(body, 'utf8');
	return Buffer.concat([Buffer.from(`SECLAB1 ${kind} ${Buffer.from(rel).toString('hex')} ${code} ${b.length}\n`, 'latin1'), b]);
};
const END = Buffer.from('SECLAB1 end 2d 0 0\n');
const report = (...f: Array<{ File: string; StartLine: number; Secret: string; RuleID?: string; Commit?: string }>) =>
	JSON.stringify(f.map(x => ({ RuleID: 'generic-api-key', ...x })));

test('scan: frames parse; values dedupe across passes; complete only with end marker', () => {
	const buf = Buffer.concat([
		frame('worktree', '.', 0, report({ File: '/scan/ws/a.env', StartLine: 2, Secret: 'SECRET_VALUE_1' })),
		frame('history', '.', 0, report({ File: 'a.env', StartLine: 1, Secret: 'SECRET_VALUE_1', Commit: 'abcdef1' }, { File: 'old.env', StartLine: 1, Secret: 'SECRET_VALUE_2', Commit: 'abcdef1' })),
		frame('objects', '.', 0, report({ File: '', StartLine: 9, Secret: 'SECRET_VALUE_3' })),
		END]);
	const r = parseFrames(buf, 0, false);
	assert.equal(r.complete, true, r.error);
	assert.deepEqual(r.findings.map(f => [f.source, f.file, f.movable]), [['worktree', 'a.env', true], ['history', 'old.env', false], ['objects', '.git (object store)', false]]);
	assert.equal(r.secrets.get(r.findings[0].id), 'SECRET_VALUE_1');
	assert.ok(!JSON.stringify(r.findings).includes('SECRET_VALUE'));
	// ids are stable across rescans of the same content
	assert.deepEqual(parseFrames(buf, 0, false).findings.map(f => f.id), r.findings.map(f => f.id));
});

test('scan: failures never drop findings from other passes (S1)', () => {
	const ok = frame('worktree', '.', 0, report({ File: '/scan/ws/.env', StartLine: 1, Secret: 'REAL_TOKEN_ABCDEF' }));
	const failed = frame('history', '.', 1, '[');
	const noEnd = parseFrames(Buffer.concat([ok, failed]), null, false);
	assert.equal(noEnd.complete, false);
	assert.equal(noEnd.findings.length, 1);
	assert.match(noEnd.error ?? '', /history pass .* (exited 1|unreadable)/);
	const cut = parseFrames(Buffer.concat([ok, frame('history', '.', 0, report({ File: 'x', StartLine: 1, Secret: 'Y'.repeat(20) })).subarray(0, 40)]), 0, true);
	assert.equal(cut.complete, false);
	assert.equal(cut.overflow, true);
	assert.equal(cut.findings.length, 1);
	const many = parseFrames(Buffer.concat([ok, Buffer.from('SECLAB1 toomany 2d 1 0\n'), END]), 0, false);
	assert.equal(many.overflow, true);
	assert.equal(many.complete, false);
	assert.equal(parseFrames(Buffer.from('garbage\n'), 0, false).complete, false);
});

test('scan: find errors name the path in GNU (quoted) and busybox (bare) form; others still count', () => {
	const errs = ["find: '/scan/ws/lockdir': Permission denied", 'find: /scan/ws/bare dir: Permission denied',
		"find: '/scan/ws/it'\\''s': Permission denied", 'find: some other complaint'].join('\n');
	const r = parseFrames(Buffer.concat([frame('finderr', '.', 1, errs), END]), 0, false);
	assert.equal(r.complete, false);
	assert.deepEqual(r.findings.map(f => [f.file, f.rule]).sort(), [['.', 'unscanned-unreadable'], ['bare dir', 'unscanned-unreadable'], ["it's", 'unscanned-unreadable'], ['lockdir', 'unscanned-unreadable']]);
});

test('scan: hostile file names are escaped and never movable; nothing is dropped (S5)', () => {
	const name = 'x\u2028\u2714 all values are test placeholders\u202e.env';
	const r = parseFrames(Buffer.concat([frame('worktree', '.', 0, report({ File: `/scan/ws/${name}`, StartLine: 1, Secret: 'REAL_TOKEN_ABCDEF' })), END]), 0, false);
	assert.equal(r.findings.length, 1);
	assert.ok(!/[\u2028\u202e]/.test(r.findings[0].file), r.findings[0].file);
	assert.equal(r.findings[0].movable, false);
	assert.equal(displayPath('a\nb'), 'a\\u{a}b');
});

test('scan: unscannable content blocks; links report under the link; trailing output is rejected (N1)', () => {
	const nul = (...p: string[]) => p.map(x => `${x}\0`).join('');
	const r = parseFrames(Buffer.concat([
		frame('large', '.', 0, nul('/scan/ws/big.env')),
		frame('links', '.', 0, nul('/scan/ws/a', '/scan/ws/.env')),
		frame('linked', '.', 0, report({ File: '/seclab/l/x/2', StartLine: 1, Secret: 'REAL_TOKEN_LINKED' })),
		frame('gitdir', '.git', 0, report({ File: '/seclab/g/x/c/config', StartLine: 3, Secret: 'REAL_TOKEN_CONFIG' })),
		Buffer.from(`SECLAB1 badgit ${Buffer.from('x/.git').toString('hex')} 1 0\n`),
		frame('largeobj', '.', 0, `${'a'.repeat(40)}\n`),
		END]), 0, false);
	assert.equal(r.complete, true, r.error);
	assert.deepEqual(r.findings.map(f => [f.source, f.file, f.rule, f.movable]), [
		['worktree', 'big.env', 'unscanned-large-file', false],
		['worktree', '.env', 'generic-api-key', false],
		['git-dir', '.git/c/config', 'generic-api-key', true],
		['git-dir', 'x/.git', 'unrecognised-git-dir', false],
		['objects', '.git (object store)', 'unscanned-large-object', false],
	]);
	assert.equal(parseFrames(Buffer.concat([END, frame('worktree', '.', 0, '[]')]), 0, false).complete, false, 'bytes after end');
	assert.equal(parseFrames(Buffer.concat([frame('large', '.', 1, nul('/scan/ws/x')), END]), 0, false).overflow, true);
});

test('scan: external links and unopenable archives block; Go-quoted log paths decode (E1, E2, E3)', () => {
	const r = parseFrames(Buffer.concat([
		frame('extlinks', '.', 0, '/scan/ws/.env\0/scan/ws/beacon\0'),
		frame('warnings', 'worktree:.', 0,
			'7:02PM WRN skipping archive: exceeds max archive depth max_archive_depth=8 path=/scan/ws/deep.zip!a.zip!b.zip\n'
			+ '7:02PM WRN skipping unknown archive type path="/scan/ws/My Backups/r\\u00e9sum\\u00e9.7z"\n'),
		frame('warnings', 'gitdir:.git', 0, '7:02PM ERR could read compressed file path=/seclab/g/x/info/x.gz\n'),
		frame('amap', 'worktree', 0, '/scan/ws/lib/app.jar\0'),
		frame('arch', '.', 0, report({ File: '/seclab/a/1.zip!application.properties', StartLine: 4, Secret: 'REAL_TOKEN_IN_JAR' })),
		frame('warnings', 'arch:.', 0, '7:02PM ERR could not create tmp file path=/seclab/a/1.zip!inner.zip\n'),
		END]), 0, false);
	assert.deepEqual(r.findings.map(f => [f.file, f.rule]), [
		['.env', 'unscanned-link'], ['beacon', 'unscanned-link'],
		['deep.zip', 'unscanned-archive'], ['My Backups/résumé.7z', 'unscanned-archive'],
		['.git/info/x.gz', 'unscanned-archive'],
		['lib/app.jar!application.properties', 'generic-api-key'],
		['lib/app.jar', 'unscanned-archive'],
	]);
	assert.equal(r.findings.find(f => f.file.includes('!'))?.movable, false);
	const pathless = parseFrames(Buffer.concat([frame('warnings', 'worktree:.', 0, '7:02PM ERR something odd happened\n'), END]), 0, false);
	assert.equal(pathless.complete, false, 'a warning without a path makes the scan incomplete');
	assert.equal(goUnquote('"a b\\"c\\\\d\\x41\\n"'), 'a b"c\\dA\n');
	assert.equal(goUnquote('/plain/path'), '/plain/path');
});

test('scan: binary-skipped files are rescanned and mapped back by line (round 8)', () => {
	const r = parseFrames(Buffer.concat([
		frame('worktree', '.', 0, '[]'),
		frame('binmap', 'worktree', 0, '/scan/ws/a.bin\x00131074\x00/scan/ws/.env\x00131080\x00'),
		frame('bin', '.', 0, report({ File: '', StartLine: 131081, Secret: 'REAL_TOKEN_AFTER_MAGIC' })),
		END]), 0, false);
	assert.equal(r.complete, true, r.error);
	assert.deepEqual(r.findings.map(f => [f.source, f.file, f.line]), [['worktree', '.env', 2]]);
});

test('scan: rewrite is byte-exact both ways ($ patterns, non-UTF-8 bytes) (S4)', () => {
	const ws = path.join(SCRATCH, 'rewrite');
	fs.mkdirSync(ws, { recursive: true });
	const secret = "tok$&en$'x$`y$$z_0123456789";
	const before = Buffer.concat([Buffer.from([0xff, 0xfe, 0x0a]), Buffer.from(`K=${secret}\n`), Buffer.from([0xc3, 0x28, 0x0a])]);
	fs.writeFileSync(path.join(ws, 'f.env'), before);
	rewriteSecret(ws, 'f.env', 2, secret, 'seclab_sentinel_x');
	assert.ok(!fs.readFileSync(path.join(ws, 'f.env')).includes(Buffer.from(secret)));
	rewriteSecret(ws, 'f.env', 2, 'seclab_sentinel_x', secret);
	assert.ok(fs.readFileSync(path.join(ws, 'f.env')).equals(before));
	assert.throws(() => rewriteSecret(ws, 'f.env', 1, secret, 'seclab_sentinel_x'), /no longer at/);
	assert.throws(() => rewriteSecret(ws, '../x', 1, secret, 'seclab_sentinel_x'), /outside/);
});

test('broker.hello: policy schema revision, protocol and tab must match (fail closed)', () => {
	// The documented example result (docs/broker-protocol.md) for broker 0.2.0.
	const doc = fs.readFileSync(path.resolve(import.meta.dirname, '../../docs/broker-protocol.md'), 'utf8');
	const ex = /<!-- check: method\.result broker\.hello -->\s*```json\n([\s\S]*?)```/.exec(doc);
	assert.ok(ex, 'broker.hello example present in the protocol doc');
	const hello = JSON.parse(ex![1]) as Record<string, unknown>;
	assert.deepEqual(hello.policySchema, BROKER_POLICY_SCHEMA, 'tabd pins the revision the protocol doc documents');
	checkBrokerHello(hello, String(hello.tabId));
	assert.throws(() => checkBrokerHello({ ...hello, policySchema: { version: 1, revision: 1 } }, String(hello.tabId)), /policy schema/);
	assert.throws(() => checkBrokerHello({ ...hello, policySchema: { version: 1, revision: 3 } }, String(hello.tabId)), /policy schema/);
	assert.throws(() => checkBrokerHello({ ...hello, policySchema: undefined }, String(hello.tabId)), /policy schema/);
	assert.throws(() => checkBrokerHello({ ...hello, protocol: 'seclab-broker/2' }, String(hello.tabId)), /protocol/);
	assert.throws(() => checkBrokerHello(hello, 'another-tab'), /not another-tab/);
	assert.throws(() => checkBrokerHello(null, 'x'), /no result/);
});
