/**
 * Tab-authored evidence cannot steer the harness that assesses it.
 *
 * Run: node test/containment/evidence-shape.test.ts
 *
 * Review round 9 alert 2. `check-evidence.ts` now reads the rogue extension's
 * evidence from inside the tab, so these bytes are chosen by the thing under
 * test. `readEvidence` guarded `JSON.parse` but not the shape, and the `check`
 * branch registered none of the `uncaughtException` handlers `prepare` has, so
 * one malformed field threw out of `checkEvidence`, skipped `report()`, the
 * `.git` disarm and `teardownGate()` -- and left the editor running with the
 * armed rogue extension on the host.
 *
 * So: every hostile shape must produce a FAILING CHECK, never a throw. Each
 * case asserts both, because "it did not throw" alone would also be satisfied
 * by a harness that silently passed.
 */

import assert from 'node:assert/strict';
import { checkEvidence, readEvidence, type Evidence } from './assert.ts';

const tests: Array<[string, () => void]> = [];
const test = (name: string, fn: () => void) => tests.push([name, fn]);

const OPTS = { marker: '/nonexistent/seclab-marker', proxy: 'sbx-broker' as const };
const run = (ev: unknown) => checkEvidence(ev as Evidence, 'task', OPTS);

/** A well-formed evidence object, as the fixture writes it when it behaves. */
const GOOD = {
	vector: 'task', hostname: 'seclab-t-xyz', uid: '1000', seclab_tab_env: '1',
	canary_read: 'no', othertab_read: 'no', docker_sock_writable: 'no', sudo: 'no',
	secret_env: '', ui_bridge: '',
	http_proxy: 'http://seclab:0123456789abcdef0123456789abcdef@host.docker.internal:62410',
	HTTPS_PROXY: 'http://seclab:0123456789abcdef0123456789abcdef@host.docker.internal:62410',
	egress: { dns_external: 'blocked', testnet_direct: '000' },
};

const hostile: Array<[string, unknown]> = [
	['egress is null', { ...GOOD, egress: null }],
	['egress is an array', { ...GOOD, egress: ['a', 'b'] }],
	['egress is a string', { ...GOOD, egress: 'blocked' }],
	['egress values are objects', { ...GOOD, egress: { dns_external: { toString: 'x' } } }],
	['secret_env is missing', (() => { const e: Record<string, unknown> = { ...GOOD }; delete e.secret_env; return e; })()],
	['secret_env is a number', { ...GOOD, secret_env: 42 }],
	['hostname is null', { ...GOOD, hostname: null }],
	['http_proxy is an object', { ...GOOD, http_proxy: { } }],
	['ui_bridge is a number', { ...GOOD, ui_bridge: 7 }],
	['every field is null', Object.fromEntries(Object.keys(GOOD).map(k => [k, null]))],
	['the object is empty', {}],
];

for (const [name, ev] of hostile) {
	test(`${name}: fails a check, does not throw`, () => {
		let checks;
		try {
			checks = run(ev);
		} catch (e) {
			assert.fail(`threw instead of failing a check: ${(e as Error).message}`);
		}
		assert.ok(checks.length > 0, 'produced no checks at all');
		assert.ok(checks.some(c => !c.ok && !c.knownGap),
			`every check passed on hostile evidence: ${JSON.stringify(checks.map(c => c.name))}`);
	});
}

test('well-formed evidence still passes, so the guards did not just fail everything', () => {
	const checks = run(GOOD);
	const bad = checks.filter(c => !c.ok && !c.knownGap);
	assert.deepEqual(bad.map(c => c.name), [], 'a benign evidence file must pass');
});

test('a missing evidence file is one honest failing check', () => {
	const checks = run(undefined);
	assert.equal(checks.length, 1);
	assert.equal(checks[0].ok, false);
	assert.match(checks[0].detail, /no evidence file/);
});

test('readEvidence returns undefined for non-JSON, a JSON array and a JSON scalar', () => {
	for (const text of ['not json', '[1,2,3]', '"a string"', '7', 'null']) {
		const ev = readEvidence('/ws', 'task', () => text);
		// An array or scalar must not reach checkEvidence as if it were an object.
		const checks = checkEvidence(ev, 'task', OPTS);
		assert.ok(checks.some(c => !c.ok), `${text} was accepted as evidence`);
	}
});

test('a huge evidence body is not parsed into an assertion', () => {
	// The fixture chooses the size. A 40 MB field must not hang or crash the check.
	const big = { ...GOOD, secret_env: 'A'.repeat(40 << 20) };
	const checks = run(big);
	assert.ok(checks.some(c => !c.ok && c.name.includes('host secrets')));
});

let failed = 0;
for (const [name, fn] of tests) {
	try {
		fn();
		console.log(`ok   ${name}`);
	} catch (err) {
		failed++;
		console.error(`FAIL ${name}\n     ${(err as Error).message}`);
	}
}
console.log(`\n${tests.length - failed}/${tests.length} passed`);
process.exit(failed ? 1 : 0);
