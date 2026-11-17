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
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { checkEvidence, hostRunChecks, levelBVectors, readEvidence, unattributedMarkers, type Evidence } from './assert.ts';

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

test('a missing evidence file is one honest failing check, and the host-marker check stands', () => {
	const checks = run(undefined);
	assert.deepEqual(checks.map(c => [c.name, c.ok]), [
		['ran (evidence written into the workspace)', false],
		['cannot write host file outside the workspace', true],
	]);
	assert.match(checks[0].detail, /no evidence file/);
});

test('with no evidence, a host marker still fails (a tab cannot withhold a host run)', () => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'seclab-evshape-'));
	const marker = path.join(dir, 'probe-marker');
	fs.writeFileSync(`${marker}.fsmonitor`, 'pwned by fsmonitor\n');
	const checks = checkEvidence(undefined, 'fsmonitor', { ...OPTS, marker });
	assert.deepEqual(checks.filter(c => !c.ok).map(c => c.name), ['ran (evidence written into the workspace)', 'cannot write host file outside the workspace']);
	fs.rmSync(dir, { recursive: true, force: true });
});

/** A run directory and a workspace laid out as check-evidence prepares them. */
function hostRun(): { run: string; ws: string; marker: string; done: () => void } {
	const run = fs.mkdtempSync(path.join(os.tmpdir(), 'seclab-hostrun-'));
	const ws = path.join(run, 'ws');
	const marker = path.join(run, 'probe-marker');
	fs.mkdirSync(path.join(ws, '.seclab'), { recursive: true });
	fs.writeFileSync(path.join(ws, '.seclab', 'targets'), `canary=${run}/canary\nmarker=${marker}\nrun=${run}\n`);
	return { run, ws, marker, done: () => fs.rmSync(run, { recursive: true, force: true }) };
}
const failing = (checks: Array<{ ok: boolean; name: string }>) => checks.filter(c => !c.ok).map(c => c.name);

test('FXF-6: on OCI a host fsmonitor marker is unattributed (no fsmonitor row covers it)', () => {
	const r = hostRun();
	try {
		fs.writeFileSync(`${r.marker}.fsmonitor`, 'pwned by fsmonitor\n');
		assert.deepEqual(failing(unattributedMarkers(r.run, r.marker, levelBVectors('oci'), new Set())), ['no unattributed host marker']);
		assert.deepEqual(failing(unattributedMarkers(r.run, r.marker, levelBVectors('sbx'), new Set())), [], 'on sbx its own row covers it');
	} finally {
		r.done();
	}
});

test('a clean host run passes the host-run checks on both drivers', () => {
	const r = hostRun();
	try {
		for (const d of ['sbx', 'oci']) {
			assert.deepEqual(failing(hostRunChecks(d, r.ws, r.marker, levelBVectors(d))), [], d);
		}
	} finally {
		r.done();
	}
});

test('on sbx, evidence in the host checkout fails (the vector ran host-side)', () => {
	const r = hostRun();
	try {
		fs.mkdirSync(path.join(r.ws, '.seclab-evidence'));
		fs.writeFileSync(path.join(r.ws, '.seclab-evidence', 'fsmonitor.json'), '{}');
		assert.deepEqual(failing(hostRunChecks('sbx', r.ws, r.marker, levelBVectors('sbx'))), ['no evidence file in the host checkout (did not run host-side)']);
	} finally {
		r.done();
	}
});

test('FXF-7: a blanked or missing marker line in the checkout\'s targets fails', () => {
	const r = hostRun();
	try {
		const t = path.join(r.ws, '.seclab', 'targets');
		for (const text of [fs.readFileSync(t, 'utf8').replace(/^marker=.*$/m, 'marker='), `marker=${r.marker}.elsewhere\n`, '']) {
			fs.writeFileSync(t, text);
			assert.deepEqual(failing(hostRunChecks('oci', r.ws, r.marker, levelBVectors('oci'))), ['the probe targets in the host checkout still name the run marker'], JSON.stringify(text));
		}
		fs.rmSync(t);
		assert.deepEqual(failing(hostRunChecks('oci', r.ws, r.marker, levelBVectors('oci'))), ['the probe targets in the host checkout still name the run marker'], 'missing file');
	} finally {
		r.done();
	}
});

/** Runs the real probe.sh from a workspace inside a scratch run dir (no network: the HTTP
 *  client's name lives in probe.parts.json, which isn't copied, so no request is made). */
const NONCE = 'a'.repeat(32);
function probeRun(env: (run: string) => Record<string, string>, targets: (run: string) => string): { marker: boolean; evidence: boolean } {
	const run = fs.mkdtempSync(path.join(os.tmpdir(), 'seclab-probesh-'));
	try {
		const ws = path.join(run, 'ws');
		fs.mkdirSync(path.join(ws, '.seclab'), { recursive: true });
		fs.copyFileSync(path.join(import.meta.dirname, 'fixtures', 'malicious-workspace', '.seclab', 'probe.sh'), path.join(ws, '.seclab', 'probe.sh'));
		fs.writeFileSync(path.join(ws, '.seclab', 'targets'), targets(run));
		fs.writeFileSync(path.join(run, '.seclab-probe-nonce'), NONCE);
		execFileSync('sh', [path.join(ws, '.seclab', 'probe.sh'), 'task'], { env: { PATH: process.env.PATH ?? '/usr/bin:/bin', ...env(run) }, stdio: 'ignore' });
		return { marker: fs.existsSync(path.join(run, 'probe-marker.task')), evidence: fs.existsSync(path.join(ws, '.seclab-evidence', 'task.json')) };
	} finally {
		fs.rmSync(run, { recursive: true, force: true });
	}
}
const armed = (run: string) => `arm=${NONCE}\nrun=${run}\nuntil=${Math.floor(Date.now() / 1000) + 600}\nmarker=${run}/probe-marker\n`;
const blanked = () => 'marker=\narm=\nuntil=1\n';

test('FXF-7: a host run (trusted env) writes its marker though the tab blanked and expired the targets', () => {
	assert.deepEqual(probeRun(run => ({ SECLAB_PROBE_RUNDIR: run, SECLAB_PROBE_NONCE: NONCE }), blanked), { marker: true, evidence: true });
	// Control: with no trusted env, blanked targets leave the probe inert (the old blind spot).
	assert.deepEqual(probeRun(() => ({}), blanked), { marker: false, evidence: false });
});

test('the trusted route stays inert without the matching nonce file (a tab setting the env itself)', () => {
	assert.deepEqual(probeRun(() => ({ SECLAB_PROBE_RUNDIR: '/nonexistent/run', SECLAB_PROBE_NONCE: NONCE }), armed), { marker: false, evidence: false }, 'unreadable run dir');
	assert.deepEqual(probeRun(run => ({ SECLAB_PROBE_RUNDIR: run, SECLAB_PROBE_NONCE: 'b'.repeat(32) }), armed), { marker: false, evidence: false }, 'wrong nonce');
	assert.deepEqual(probeRun(run => ({ SECLAB_PROBE_RUNDIR: run, SECLAB_PROBE_NONCE: 'not-a-nonce' }), armed), { marker: false, evidence: false }, 'malformed nonce');
	// Control: the targets route (an in-tab run) still arms as before.
	assert.deepEqual(probeRun(() => ({}), armed), { marker: true, evidence: true });
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
