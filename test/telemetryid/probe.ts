// Telemetry-id probe: does a tab's extension host learn the host's telemetry identifiers? The runtime
// regression test for DOCSYNC-R4 (EDR tab-telemetry-ids). macOS, sbx, local only. One run:
//   node test/telemetryid/probe.ts prepare [--app PATH]   # benign tab + probe extension; seeded ids in the isolated profile
//   node test/window.ts launch …                          # (the printed line) background launch, focus watcher
//   node test/telemetryid/probe.ts check                  # report + assertions, then the teardown gate
// The isolated profile's state (User/globalStorage/storage.json) is seeded with generated machine,
// SQM and device ids before launch; the editor uses stored ids as they are. The probe reports only
// SHA-256 hashes and shapes of what the tab sees (vscode.env.machineId, sessionId). Its report is
// tab-controlled data, read through a fixed schema. With telemetry off (product.json, enforced by
// product.jq and build/check-release.sh) every tab sees the product placeholder, never the seeded ids.

import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import { checkUserDataDir, editorLaunchCommand, focusStealLog } from '../harness.ts';
import { readManifest, verifyTeardown, writeManifest, writeSnapshot } from '../containment/teardown.ts';

const repo = path.resolve(import.meta.dirname, '../..');
const base = path.join(repo, '.work', 'telemetryid');
const ws = path.join(base, 'ws');
const seededFile = path.join(base, 'seeded.json');
const resultsFile = path.join(repo, '.work', 'telemetryid-results.jsonl');
// One profile per worktree: the previous-run guard lives in this worktree's .work, so a shared
// profile could be wiped or torn down by another worktree's run (PR #12 review).
const userData = path.join(os.homedir(), '.seclab-test', `ti-${createHash('sha256').update(repo).digest('hex').slice(0, 8)}`);
const stateDir = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');
const SBX = '/opt/homebrew/bin/sbx';
const VSCE_IMAGE = 'seclab-vsce:3.9.2';
const [mode, ...rest] = process.argv.slice(2);
const appArg = rest.includes('--app') ? path.resolve(rest[rest.indexOf('--app') + 1]) : undefined;
const sha = (s: string) => createHash('sha256').update(s).digest('hex');
const tabId = () => (readManifest(base).tabs ?? [])[0];
const inTab = (args: string[]) => spawnSync(SBX, ['exec', '-u', 'agent', `seclab-${tabId()}`, ...args], { encoding: 'utf8', maxBuffer: 16 << 20 });

if (mode === 'prepare') {
	checkUserDataDir(userData);
	if (fs.existsSync(path.join(base, 'run.json'))) {
		console.error('a previous telemetryid run is still recorded: run `node test/telemetryid/probe.ts check` first');
		process.exit(1);
	}
	fs.rmSync(base, { recursive: true, force: true });
	fs.rmSync(userData, { recursive: true, force: true });
	fs.mkdirSync(path.join(ws, '.seclab'), { recursive: true });
	const seeded = { machineId: randomBytes(32).toString('hex'), sqmId: `{${randomUUID().toUpperCase()}}`, devDeviceId: randomUUID() };
	fs.writeFileSync(seededFile, JSON.stringify(seeded));
	writeSnapshot(base);
	writeManifest(base, { driver: 'sbx', userDataDir: userData, stateDirs: [stateDir] });
	fs.writeFileSync(path.join(ws, 'README.md'), '# telemetryid probe workspace\n');
	fs.mkdirSync(path.join(userData, 'User', 'globalStorage'), { recursive: true });
	fs.writeFileSync(path.join(userData, 'User', 'globalStorage', 'storage.json'), JSON.stringify({
		'telemetry.machineId': seeded.machineId, 'telemetry.sqmId': seeded.sqmId, 'telemetry.devDeviceId': seeded.devDeviceId,
	}));
	fs.writeFileSync(path.join(userData, 'User', 'settings.json'), JSON.stringify({
		'security.workspace.trust.enabled': false, 'seclab.tabs.driver': 'sbx', 'seclab.tabs.allowedRoots': [base], 'window.restoreWindows': 'none',
	}, null, '\t'));
	const until = Math.floor(Date.now() / 1000) + 2 * 3600;
	fs.writeFileSync(path.join(ws, '.seclab', 'targets'), `arm=${randomBytes(16).toString('hex')}\nrun=${base}\nuntil=${until}\n`);

	const vsixDir = path.join(base, 'vsix');
	fs.mkdirSync(vsixDir, { recursive: true });
	execFileSync('docker', ['run', '--rm', '--network', 'none', '--user', `${process.getuid!()}:${process.getgid!()}`,
		'-v', `${path.join(import.meta.dirname, 'probe-extension')}:/ext:ro`, '-v', `${vsixDir}:/out`,
		VSCE_IMAGE, 'sh', '-c', 'cp -r /ext /tmp/e && cd /tmp/e && vsce package --allow-missing-repository --skip-license -o /out/telemetryid-probe.vsix'], { stdio: 'ignore' });
	const client = new TabdClient({
		command: process.execPath,
		args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', 'sbx', '--allowed-root', base],
		env: { HOME: process.env.HOME, USER: process.env.USER },
	});
	await client.initialize('telemetryid-probe', '0');
	const { tab } = await client.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
	writeManifest(base, { tabs: [tab.metadata.name] });
	await client.request('tab.ensureRunning', { tabId: tab.metadata.name });
	fs.copyFileSync(path.join(vsixDir, 'telemetryid-probe.vsix'), path.join(ws, '.telemetryid-probe.vsix'));
	const r = inTab(['/opt/seclab/bin/seclab-tab-env', '/opt/seclab-reh/bin/seclab-code-server', '--install-extension', path.join(ws, '.telemetryid-probe.vsix')]);
	client.dispose();
	await new Promise(res => client.once('exit', res));
	if (r.status !== 0) {
		console.error('could not install the probe extension in the tab; run `node test/telemetryid/probe.ts check` to tear down');
		process.exit(1);
	}
	console.log(`prepared tab ${tab.metadata.name}. Launch in the BACKGROUND:\n`);
	console.log(`  ${editorLaunchCommand(userData, `vscode-remote://seclab+${tab.metadata.name}${ws}`, {}, appArg)}\n`);
	console.log('then, after about 30 seconds:  node test/telemetryid/probe.ts check\n');
} else if (mode === 'check') {
	const seeded = JSON.parse(fs.readFileSync(seededFile, 'utf8')) as { machineId: string };
	const reportPath = path.join(ws, '.seclab-telemetryid', 'report.json');
	for (let i = 0; i < 90 && tabId() && inTab(['test', '-e', reportPath]).status !== 0; i++) {
		spawnSync('sleep', ['1']);
	}
	let rep: any;
	try {
		rep = JSON.parse(tabId() ? inTab(['cat', reportPath]).stdout ?? '' : '');
	} catch {
		rep = undefined;
	}
	const armed = (fs.readFileSync(path.join(ws, '.seclab', 'targets'), 'utf8').match(/^arm=([0-9a-f]{32})$/m) ?? [])[1];
	const field = (f: any) => !!f && /^[0-9a-f]{64}$/.test(f.sha256) && typeof f.shape === 'string' && /^[\x20-\x7e]{0,120}$/.test(f.shape);
	const valid = !!rep && rep.schema === 'seclab-telemetryid-report/1' && rep.arm === armed && field(rep.machineId) && field(rep.sessionId)
		&& (rep.devDeviceId === null || field(rep.devDeviceId));
	const launched = (() => {
		try {
			return String(JSON.parse(fs.readFileSync(path.join(userData, 'seclab-launch.json'), 'utf8')).app ?? '');
		} catch {
			return '';
		}
	})();
	const steals = fs.existsSync(focusStealLog(userData)) ? fs.readFileSync(focusStealLog(userData), 'utf8').trim() : '';
	const results: Array<{ name: string; ok: boolean }> = [];
	const expect = (name: string, ok: boolean) => results.push({ name, ok });
	expect('report present, from this run, and matches the schema', valid);
	if (valid) {
		console.log(`tab machineId: ${rep.machineId.shape} (${rep.machineId.sha256 === sha(seeded.machineId) ? 'THE HOST\'S' : 'not the host\'s'})`);
		console.log(`tab sessionId: ${rep.sessionId.shape}; devDeviceId: ${rep.devDeviceId ? rep.devDeviceId.shape : 'not readable (proposed API)'}`);
		expect('DOCSYNC-R4 the tab\'s machineId is not the host\'s', rep.machineId.sha256 !== sha(seeded.machineId));
		const host = new Set(Object.values(seeded).map(sha));
		expect('no id the tab can read is any seeded host id (machine, SQM, device)', [rep.machineId, rep.sessionId, rep.devDeviceId].every(f => !f || !host.has(f.sha256)));
		expect('control: the tab read a non-empty machineId', rep.machineId.shape.length > 0);
	}
	expect('no focus steal', !steals);
	const gate = verifyTeardown(base);
	if (gate.every(g => g.ok)) {
		fs.renameSync(path.join(base, 'run.json'), path.join(base, `run-checked-${Date.now()}.json`));
	}
	for (const r of [...results, ...gate]) {
		console.log(`${r.ok ? 'OK  ' : 'FAIL'}  ${r.name}`);
	}
	const pass = results.every(r => r.ok) && gate.every(g => g.ok);
	fs.appendFileSync(resultsFile, JSON.stringify({ at: new Date().toISOString(), app: launched, pass, machineIdIsHost: valid ? rep.machineId.sha256 === sha(seeded.machineId) : null, machineIdSha256: valid ? rep.machineId.sha256 : null }) + '\n');
	process.exit(pass ? 0 : 1);
} else {
	console.error('usage: probe.ts prepare [--app PATH] | check');
	process.exit(2);
}
