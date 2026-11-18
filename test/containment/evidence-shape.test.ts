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
import { armingDigest, armingRecord, type ArmingRecord, checkEvidence, hostRunChecks, levelBVectors, parseArmingRecord, readEvidence, readRegular, unattributedMarkers, withheldEvidence, type Evidence } from './assert.ts';

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

/** A run directory and a workspace laid out as check-evidence prepares them, with the arming
 *  record prepare writes. */
function hostRun(): { run: string; ws: string; marker: string; arming: ArmingRecord; done: () => void } {
	const run = fs.mkdtempSync(path.join(os.tmpdir(), 'seclab-hostrun-'));
	const ws = path.join(run, 'ws');
	const marker = path.join(run, 'probe-marker');
	fs.mkdirSync(path.join(ws, '.seclab'), { recursive: true });
	fs.mkdirSync(path.join(ws, '.vscode'), { recursive: true });
	fs.writeFileSync(path.join(ws, '.seclab', 'probe.sh'), '#!/bin/sh\n');
	fs.writeFileSync(path.join(ws, '.vscode', 'tasks.json'), '{}\n');
	fs.writeFileSync(path.join(ws, '.vscode', 'settings.json'), '{}\n');
	fs.writeFileSync(path.join(ws, '.seclab', 'targets'), `canary=${run}/canary\nmarker=${marker}\nrun=${run}\n`);
	return { run, ws, marker, arming: armingRecord(ws), done: () => fs.rmSync(run, { recursive: true, force: true }) };
}
const failing = (checks: Array<{ ok: boolean; name: string }>) => checks.filter(c => !c.ok).map(c => c.name);
const ARMING_ROW = 'the arming files in the host checkout are exactly as prepared';
const ADDED_ROW = 'nothing added to the host checkout beyond the run\'s own output';

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
			assert.deepEqual(failing(hostRunChecks(d, r.ws, r.arming)), [], d);
		}
	} finally {
		r.done();
	}
});

test('FXF-20: evidence synced to the host checkout is run output on both drivers, not a host run', () => {
	const r = hostRun();
	try {
		put(r.ws, '.seclab-evidence/task.json', '{}');
		put(r.ws, '.seclab-evidence/benign.json', '{}');
		for (const d of ['sbx', 'oci']) {
			assert.deepEqual(failing(hostRunChecks(d, r.ws, r.arming)), [], d);
		}
	} finally {
		r.done();
	}
});

test('FXF-17/18: an unreadable directory fails the added-files row and the record; OS artifacts are ignored', () => {
	// Root reads any directory, so this case needs an unprivileged user (./seclab runs it as one).
	assert.notEqual(process.getuid?.(), 0, 'run as an unprivileged user');
	const r = hostRun();
	try {
		put(r.ws, '.DS_Store');
		put(r.ws, '.vscode/._tasks.json');
		assert.deepEqual(failing(hostRunChecks('sbx', r.ws, r.arming)), [], 'OS artifacts');
		put(r.ws, 'hidden/launch.json');
		fs.chmodSync(path.join(r.ws, 'hidden'), 0);
		try {
			assert.deepEqual(failing(hostRunChecks('oci', r.ws, r.arming)), [ADDED_ROW]);
			assert.throws(() => armingRecord(r.ws), /can't list hidden/);
		} finally {
			fs.chmodSync(path.join(r.ws, 'hidden'), 0o700);
		}
	} finally {
		r.done();
	}
});

test('FXF-7, 10-12: any edit to what a host run reads fails, however small', () => {
	const edits: Array<[string, (r: ReturnType<typeof hostRun>) => void]> = [
		['blanked marker line', r => fs.writeFileSync(path.join(r.ws, '.seclab', 'targets'), fs.readFileSync(path.join(r.ws, '.seclab', 'targets'), 'utf8').replace(/^marker=.*$/m, 'marker='))],
		['prepended empty marker line (FXF-11)', r => fs.writeFileSync(path.join(r.ws, '.seclab', 'targets'), 'marker=\n' + fs.readFileSync(path.join(r.ws, '.seclab', 'targets'), 'utf8'))],
		['canary pointed outside the run (FXF-10)', r => fs.appendFileSync(path.join(r.ws, '.seclab', 'targets'), 'othertab=/etc/passwd\n')],
		['probe replaced (FXF-12)', r => fs.writeFileSync(path.join(r.ws, '.seclab', 'probe.sh'), '#!/bin/sh\nexit 0\n')],
		['task repointed (FXF-12)', r => fs.writeFileSync(path.join(r.ws, '.vscode', 'tasks.json'), '{"tasks":[]}\n')],
		['targets deleted', r => fs.rmSync(path.join(r.ws, '.seclab', 'targets'))],
	];
	for (const [what, edit] of edits) {
		const r = hostRun();
		try {
			edit(r);
			assert.deepEqual(failing(hostRunChecks('oci', r.ws, r.arming)), [ARMING_ROW], what);
		} finally {
			r.done();
		}
	}
	const r = hostRun();
	try {
		fs.mkdirSync(path.join(r.ws, '.git'));
		assert.deepEqual(failing(hostRunChecks('oci', r.ws, r.arming)), ['no .git in the host checkout'], 'a host .git (fsmonitor repointed)');
		assert.ok(failing(hostRunChecks('oci', r.ws, undefined)).includes(ARMING_ROW), 'no arming record');
		assert.equal(parseArmingRecord({ digest: {}, tree: [] }), undefined, 'an empty arming record is no record');
	} finally {
		r.done();
	}
});

const put = (ws: string, rel: string, text = 'x') => {
	fs.mkdirSync(path.dirname(path.join(ws, rel)), { recursive: true });
	fs.writeFileSync(path.join(ws, rel), text);
};

test('FXF-14: on OCI the run output (rogue settings payload, its instructions, evidence) stays green', () => {
	const r = hostRun();
	try {
		put(r.ws, '.vscode/settings.json', '{"rogue":true}\n');
		put(r.ws, '.github/instructions/seclab-probe.instructions.md');
		put(r.ws, '.github/copilot-instructions.md');
		put(r.ws, '.seclab-evidence/benign.json', '{}');
		assert.deepEqual(failing(hostRunChecks('oci', r.ws, r.arming)), []);
		// On sbx none of it may reach the host checkout.
		assert.deepEqual(failing(hostRunChecks('sbx', r.ws, r.arming)), [ADDED_ROW]);
	} finally {
		r.done();
	}
});

test('FXF-15: a file a tab adds to the checkout fails on both drivers', () => {
	for (const rel of ['.vscode/launch.json', '.githooks/pre-commit', '.github/workflows/x.yml', '.seclab/extra.sh']) {
		const r = hostRun();
		try {
			put(r.ws, rel);
			for (const d of ['sbx', 'oci']) {
				assert.ok(failing(hostRunChecks(d, r.ws, r.arming)).includes(ADDED_ROW), `${d} ${rel}`);
			}
		} finally {
			r.done();
		}
	}
});

test('FXF-16: an arming record naming a path outside the workspace is no record', () => {
	const digest = { '.seclab/probe.sh': 'a'.repeat(64) };
	for (const bad of [{ digest: { '../x': null }, tree: [] }, { digest: { '/etc/passwd': null }, tree: [] }, { digest, tree: ['a/../../b'] }, { digest, tree: '.seclab' }, { digest: { k: 'nothex' }, tree: [] }, null, []]) {
		assert.equal(parseArmingRecord(bad), undefined, JSON.stringify(bad));
	}
	assert.deepEqual(parseArmingRecord({ digest, tree: ['.seclab/probe.sh'] }), { digest, tree: ['.seclab/probe.sh'] });
});

test('FXF-22: evidence on the host but not in the tab is a failure, not a missing file', () => {
	const r = hostRun();
	try {
		assert.equal(withheldEvidence(r.ws, 'task', undefined), undefined, 'nothing anywhere: just a missing file');
		put(r.ws, '.seclab-evidence/task.json', '{}');
		const c = withheldEvidence(r.ws, 'task', undefined);
		assert.ok(c && !c.ok && !c.knownGap, 'host copy only: a plain failure');
		assert.equal(withheldEvidence(r.ws, 'task', GOOD as unknown as Evidence), undefined, 'both: fine');
	} finally {
		r.done();
	}
});

test('FXF-23: a tab-added file cannot hide behind an OS artifact name', () => {
	for (const rel of ['._launch.json', '.vscode/._hook', 'sub/.Spotlight-V100', 'sub/.fseventsd/x']) {
		const r = hostRun();
		try {
			put(r.ws, rel);
			assert.ok(failing(hostRunChecks('sbx', r.ws, r.arming)).includes(ADDED_ROW), rel);
		} finally {
			r.done();
		}
	}
});

test('PR 26 review: a directory named like an OS artifact is walked; only the real ones are skipped', () => {
	for (const rel of ['.DS_Store/payload.sh', '._.vscode/payload.sh', '.vscode/.DS_Store/x', '.fseventsd', 'sub/.fseventsd/x']) {
		const r = hostRun();
		try {
			put(r.ws, rel);
			assert.ok(failing(hostRunChecks('sbx', r.ws, r.arming)).includes(ADDED_ROW), rel);
		} finally {
			r.done();
		}
	}
	const r = hostRun();
	try {
		put(r.ws, '.fseventsd/fseventsd-uuid');
		put(r.ws, '.vscode/.DS_Store');
		assert.deepEqual(failing(hostRunChecks('sbx', r.ws, r.arming)), [], 'the real artifacts');
	} finally {
		r.done();
	}
});

test('PR 26 review: a FIFO, symlink or oversized file in place of an arming file fails, never blocks', () => {
	for (const [what, swap] of [
		['FIFO', (f: string) => execFileSync('mkfifo', [f])],
		['symlink', (f: string) => fs.symlinkSync('/etc/hostname', f)],
	] as Array<[string, (f: string) => void]>) {
		const r = hostRun();
		try {
			const f = path.join(r.ws, '.seclab', 'targets');
			fs.rmSync(f);
			swap(f);
			assert.ok(failing(hostRunChecks('oci', r.ws, r.arming)).includes(ARMING_ROW), what);
		} finally {
			r.done();
		}
	}
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'seclab-big-'));
	try {
		fs.writeFileSync(path.join(dir, 'f'), 'x'.repeat(100));
		assert.equal(readRegular(path.join(dir, 'f'), 10), undefined, 'over the bound');
		assert.equal(readRegular(path.join(dir, 'f'))?.length, 100);
		// A symlinked parent directory leads out of the workspace: not read, not hashed (Copilot
		// review on PR 26). Control: the same file through a real directory.
		const ws = path.join(dir, 'ws'), out = path.join(dir, 'outside');
		fs.mkdirSync(path.join(ws, '.seclab'), { recursive: true });
		fs.mkdirSync(out);
		fs.writeFileSync(path.join(out, 'tasks.json'), '{}');
		fs.symlinkSync(out, path.join(ws, '.vscode'));
		assert.equal(readRegular(path.join(ws, '.vscode', 'tasks.json'), undefined, ws), undefined, 'a symlinked parent');
		assert.equal(armingDigest(ws, ['.vscode/tasks.json'])['.vscode/tasks.json'], null, 'a symlinked parent is hashed');
		fs.rmSync(path.join(ws, '.vscode'));
		fs.mkdirSync(path.join(ws, '.vscode'));
		fs.writeFileSync(path.join(ws, '.vscode', 'tasks.json'), '{}');
		assert.notEqual(armingDigest(ws, ['.vscode/tasks.json'])['.vscode/tasks.json'], null, 'the control');
	} finally {
		fs.rmSync(dir, { recursive: true, force: true });
	}
});

/** Runs the real probe.sh from a workspace inside a scratch run dir (no HTTP: the client's
 *  name lives in probe.parts.json, which isn't copied; its one DNS lookup is of a reserved
 *  *.example.test name). */
const NONCE = 'a'.repeat(32);
const later = () => String(Math.floor(Date.now() / 1000) + 600);
function probeRun(env: (run: string) => Record<string, string>, targets: (run: string) => string, until = later()): { marker: boolean; evidence: boolean } {
	const run = fs.mkdtempSync(path.join(os.tmpdir(), 'seclab-probesh-'));
	try {
		const ws = path.join(run, 'ws');
		fs.mkdirSync(path.join(ws, '.seclab'), { recursive: true });
		fs.copyFileSync(path.join(import.meta.dirname, 'fixtures', 'malicious-workspace', '.seclab', 'probe.sh'), path.join(ws, '.seclab', 'probe.sh'));
		fs.writeFileSync(path.join(ws, '.seclab', 'targets'), targets(run));
		fs.writeFileSync(path.join(run, '.seclab-probe-nonce'), NONCE);
		fs.writeFileSync(path.join(run, '.seclab-probe-until'), until);
		execFileSync('sh', [path.join(ws, '.seclab', 'probe.sh'), 'task'], { env: { PATH: process.env.PATH ?? '/usr/bin:/bin', ...env(run) }, stdio: 'ignore' });
		return { marker: fs.existsSync(path.join(run, 'probe-marker.task')), evidence: fs.existsSync(path.join(ws, '.seclab-evidence', 'task.json')) };
	} finally {
		fs.rmSync(run, { recursive: true, force: true });
	}
}
const armed = (run: string) => `arm=${NONCE}\nrun=${run}\nuntil=${later()}\nmarker=${run}/probe-marker\n`;
const blanked = () => 'marker=\narm=\nuntil=1\n';
const trusted = (run: string) => ({ SECLAB_PROBE_RUNDIR: run, SECLAB_PROBE_NONCE: NONCE });

test('FXF-7: a host run (trusted env) writes its marker though the tab blanked and expired the targets', () => {
	assert.deepEqual(probeRun(trusted, blanked), { marker: true, evidence: true });
	// Control: with no trusted env, blanked targets leave the probe inert (the old blind spot).
	assert.deepEqual(probeRun(() => ({}), blanked), { marker: false, evidence: false });
});

test('FXF-10: on the trusted route a canary path outside the run is skipped, not a reason to stay silent', () => {
	assert.deepEqual(probeRun(trusted, run => armed(run) + 'canary=/etc/hostname\nothertab=/etc/passwd\n'), { marker: true, evidence: true });
	// Control: the targets route still refuses an out-of-run target outright.
	assert.deepEqual(probeRun(() => ({}), run => 'canary=/etc/hostname\n' + armed(run)), { marker: false, evidence: false });
});

test('the trusted route stays inert without the matching nonce file or past its window (FXF-13)', () => {
	assert.deepEqual(probeRun(() => ({ SECLAB_PROBE_RUNDIR: '/nonexistent/run', SECLAB_PROBE_NONCE: NONCE }), armed), { marker: false, evidence: false }, 'unreadable run dir');
	assert.deepEqual(probeRun(run => ({ SECLAB_PROBE_RUNDIR: run, SECLAB_PROBE_NONCE: 'b'.repeat(32) }), armed), { marker: false, evidence: false }, 'wrong nonce');
	assert.deepEqual(probeRun(run => ({ SECLAB_PROBE_RUNDIR: run, SECLAB_PROBE_NONCE: 'not-a-nonce' }), armed), { marker: false, evidence: false }, 'malformed nonce');
	assert.deepEqual(probeRun(trusted, armed, '1'), { marker: false, evidence: false }, 'expired window');
	assert.deepEqual(probeRun(trusted, armed, 'soon'), { marker: false, evidence: false }, 'malformed window');
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
