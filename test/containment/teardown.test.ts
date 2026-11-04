// Regression test for the teardown miss of 2026-11-04 (from the RPC-lockdown session).
//
// The unpatched proof run left an orphaned editor on the user's desktop, running the
// unpatched build with the armed rogue extension installed, and the post-run check
// reported the host clean: it had no idea processes existed.
//
// This plants a process tree whose root carries the run's user-data-dir (as the editor's
// does) and a child that does not (as an Electron helper or tabd's `sbx exec` stream may
// not), and asserts that verify stops both and only then reports clean. A clean run must
// still verify clean, and the caller's own process must never be touched.
//   node test/containment/teardown.test.ts

import { spawn, spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { checkIsolatedProfile, NODE_IMAGE } from '../harness.ts';
import { runLeftovers, runProcesses, verifyTeardown, writeManifest, writeSnapshot } from './teardown.ts';

const repo = path.resolve(import.meta.dirname, '../..');
const base = path.join(repo, '.work', 'teardown-test');
fs.rmSync(base, { recursive: true, force: true });
const runDir = path.join(base, 'run');
const udd = path.join(base, 'udd');
fs.mkdirSync(runDir, { recursive: true });
fs.mkdirSync(udd, { recursive: true });
writeManifest(runDir, { userDataDir: udd, tabs: [] });

let failures = 0;
const check = (name: string, ok: boolean, detail = ''): void => {
	if (!ok) {
		failures++;
	}
	console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  ${detail}` : ''}`);
};
const alive = (pid: number): boolean => {
	// ps, not kill(pid, 0): a killed child of ours lingers as a reapable zombie.
	const r = spawnSync('ps', ['-o', 'stat=', '-p', String(pid)], { encoding: 'utf8' });
	return r.status === 0 && !!r.stdout.trim() && !r.stdout.trim().startsWith('Z');
};

writeSnapshot(runDir);
// The stand-in editor is a script launched with the flag as a script argument, so it
// stays in argv and shows in ps (macOS `sleep` rejects extra arguments, and `sh -c` execs
// and drops them: both earlier stubs planted nothing and the test passed vacuously). It
// forks a helper whose argv does not name the run.
const stub = path.join(runDir, 'editor-stub.js');
fs.writeFileSync(stub, `const { spawn } = require('node:child_process');
const c = spawn(process.execPath, ['-e', 'process.on("SIGTERM", () => {}); setTimeout(() => {}, 600000)'], { stdio: 'ignore' });
require('node:fs').writeFileSync(process.argv[3], String(c.pid));
process.on('SIGTERM', () => {}); // a stubborn editor: needs SIGKILL
setTimeout(() => {}, 600000);
`);
const childPidFile = path.join(runDir, 'child.pid');
const editor = spawn(process.execPath, [stub, `--user-data-dir=${udd}`, childPidFile], { detached: true, stdio: 'ignore' });
editor.unref();
for (let i = 0; i < 50 && !fs.existsSync(childPidFile); i++) {
	spawnSync('sleep', ['0.1']);
}
const helper = Number(fs.readFileSync(childPidFile, 'utf8'));
check('planted editor and helper are running', alive(editor.pid!) && alive(helper));
// Decoys that must survive (T-1): a concurrent run's profile sharing our prefix, and a
// process that merely names the run dir (the user's editor or a `tail` on a run log).
const decoyStub = path.join(base, 'decoy.js');
fs.writeFileSync(decoyStub, 'setTimeout(() => {}, 600000);\n');
const decoys = [
	spawn(process.execPath, [decoyStub, `--user-data-dir=${udd}2`], { detached: true, stdio: 'ignore' }),
	spawn(process.execPath, [decoyStub, path.join(runDir, 'run.log')], { detached: true, stdio: 'ignore' }),
];
decoys.forEach(d => d.unref());
spawnSync('sleep', ['0.5']);
const seen = runProcesses(runDir).map(p => p.pid);
check('the helper is attributed to the run through its parent', seen.includes(editor.pid!) && seen.includes(helper), JSON.stringify(seen));
check('the caller is never attributed to the run', !seen.includes(process.pid));
check('a prefix-sharing profile and a bare run-dir mention are not attributed (T-1)', !decoys.some(d => seen.includes(d.pid!)));

const checks = verifyTeardown(runDir);
const proc = checks.find(c => c.name.startsWith('no process'));
check('verify reports the process check as passed after stopping the tree', proc?.ok === true, proc?.detail);
spawnSync('sleep', ['0.5']);
check('the SIGTERM-ignoring editor is gone', !alive(editor.pid!));
check('its helper is gone', !alive(helper));
check('the decoys are untouched', decoys.every(d => alive(d.pid!)));
check('the run user-data-dir was removed', !fs.existsSync(udd));
check('verify passes overall', checks.every(c => c.ok), checks.filter(c => !c.ok).map(c => `${c.name}: ${c.detail}`).join(' | '));

writeSnapshot(runDir);
check('a clean run verifies clean', verifyTeardown(runDir).every(c => c.ok));

// OCI leftovers: a container labelled as a tab known only from the run's tabd state (not
// recorded in run.json: T-2b) is found, removed, and the run verifies clean once it's gone.
const fakeTab = `t-${'a'.repeat(26)}`;
spawnSync('docker', ['rm', '-f', `seclab-${fakeTab}`], { stdio: 'ignore' }); // from an aborted earlier run
const c = spawnSync('docker', ['run', '-d', '--rm', '--network', 'none', '--label', `seclab.tab=${fakeTab}`, '--name', `seclab-${fakeTab}`,
	NODE_IMAGE, 'sleep', '600'], { encoding: 'utf8' });
if (c.status === 0) {
	const stateDir = path.join(runDir, 'state');
	fs.mkdirSync(path.join(stateDir, 'tabs'), { recursive: true });
	fs.writeFileSync(path.join(stateDir, 'tabs', `${fakeTab}.json`), '{}');
	writeManifest(runDir, { stateDirs: [stateDir], driver: 'oci' });
	check('a leftover tab container is reported', runLeftovers(runDir).left.includes(`container seclab-${fakeTab}`), runLeftovers(runDir).left.join(', '));
	check('verify removes it and passes', verifyTeardown(runDir, { snapshot: false }).every(x => x.ok));
	check('the container is gone', !runLeftovers(runDir).left.length);
} else {
	console.log(`SKIP  OCI leftover case (docker unavailable: ${c.stderr.trim().slice(0, 80)})`);
}

// A tampered run.json is refused before anything is killed or deleted (T-4).
const victimDir = path.join(base, 'not-the-runs');
fs.mkdirSync(victimDir, { recursive: true });
fs.writeFileSync(path.join(runDir, 'run.json'), JSON.stringify({
	userDataDir: path.join(os.homedir(), 'Documents'), stateDirs: [victimDir], containers: ['copilot-bla'],
}));
const refused = verifyTeardown(runDir, { snapshot: false });
check('a run.json naming a real profile, a foreign state dir or container is refused', refused.length === 1 && !refused[0].ok
	&& /isolated profile/.test(refused[0].detail) && /state dir outside/.test(refused[0].detail) && /helper container/.test(refused[0].detail), refused.map(x => x.detail).join(' | '));
check('nothing was deleted on its say-so', fs.existsSync(victimDir));

// A mistyped `verify <dir>` (no harness run.json, or a dir outside the test roots) acts on nothing (R-2).
const stray = path.join(base, 'not-a-run');
fs.mkdirSync(stray, { recursive: true });
const noRun = verifyTeardown(stray, { snapshot: false });
check('verify on a dir without a harness run.json refuses (R-2)', noRun.length === 1 && !noRun[0].ok && /no run.json/.test(noRun[0].detail), noRun.map(x => x.detail).join(' | '));
const outside = verifyTeardown(os.homedir(), { snapshot: false });
check('verify on a dir outside the test roots refuses (R-2)', outside.length === 1 && !outside[0].ok, outside.map(x => x.detail).join(' | '));
// A command mark that is the bare run dir is refused (R-1).
fs.writeFileSync(path.join(runDir, 'run.json'), JSON.stringify({ startedAt: 'x', commandMarks: [runDir] }));
check('a bare run-dir command mark is refused (R-1)', verifyTeardown(runDir, { snapshot: false }).some(x => !x.ok && /command mark/.test(x.detail)));
// A profile path that resolves out of the test roots through a link is refused (R-3).
const link = path.join(base, 'link-out');
fs.symlinkSync(os.homedir(), link);
let linkRefused = false;
try {
	checkIsolatedProfile(path.join(link, 'sub'));
} catch {
	linkRefused = true;
}
check('a profile reached through a symlink out of the test roots is refused (R-3)', linkRefused);
fs.unlinkSync(link);

for (const d of decoys) {
	try {
		process.kill(d.pid!, 'SIGKILL');
	} catch { /* gone */ }
}

for (const pid of [editor.pid!, helper]) {
	try {
		process.kill(pid, 'SIGKILL');
	} catch { /* gone */ }
}
fs.rmSync(base, { recursive: true, force: true });
console.log(failures === 0 ? '\nteardown regression holds' : `\n${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);
