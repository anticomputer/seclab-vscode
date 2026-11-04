// Containment suite, level B: the real editor triggers the vectors.
//   prepare <user-data-dir> [sbx|oci]  create the fixture workspace, claim its tab in the
//                                      editor's tabd state, preinstall the rogue extension
//                                      into the tab, write test user settings
//   check   <user-data-dir>            assert the evidence the editor-run vectors left behind
// In between, open the workspace with the fork, e.g.
//   .work/app/seclab-vscode.app/Contents/Resources/app/bin/seclab-code --user-data-dir <dir> <workspace>

import { execFileSync, spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import { checkEvidence, readEvidence, report, type Check } from './assert.ts';

const [mode, userDataArg, driverArg] = process.argv.slice(2);
if ((mode !== 'prepare' && mode !== 'check') || !userDataArg) {
	console.error('usage: check-evidence.ts prepare|check <user-data-dir> [sbx|oci]');
	process.exit(2);
}
const driver = driverArg ?? 'sbx';
const repo = path.resolve(import.meta.dirname, '../..');
const userData = path.resolve(userDataArg);
const base = path.join(repo, '.work', 'containment-editor');
const ws = path.join(base, 'ws-editor');
const canary = path.join(base, 'canary', 'secret.txt');
const marker = path.join(base, 'PWNED');
const stateDir = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');

if (mode === 'prepare') {
	fs.rmSync(base, { recursive: true, force: true });
	fs.mkdirSync(path.dirname(canary), { recursive: true });
	fs.writeFileSync(canary, 'HOST-SECRET-CANARY\n');
	fs.cpSync(path.join(import.meta.dirname, 'fixtures', 'malicious-workspace'), ws, { recursive: true });
	fs.writeFileSync(path.join(ws, '.seclab', 'targets'), `canary=${canary}\nmarker=${marker}\nloopback=18099\n`);
	// Git repo with a hostile core.fsmonitor. Only `init` and `config` run on the host;
	// neither reads core.fsmonitor. Nothing here may run `git status` on the host.
	execFileSync('git', ['-C', ws, 'init', '-q']);
	execFileSync('git', ['-C', ws, 'config', 'core.fsmonitor', 'sh .seclab/probe.sh fsmonitor']);
	// Test profile: Workspace Trust off and automatic tasks on, i.e. the worst case for us
	// (trust is UX, not a boundary).
	fs.mkdirSync(path.join(userData, 'User'), { recursive: true });
	fs.writeFileSync(path.join(userData, 'User', 'settings.json'), JSON.stringify({
		'security.workspace.trust.enabled': false,
		'task.allowAutomaticTasks': 'on',
		'seclab.tabs.driver': driver,
		'seclab.tabs.allowedRoots': [base],
	}, null, '\t'));
	// Package the rogue extension (vsce in a container) and preinstall it into the tab.
	const vsixDir = path.join(ws, '.seclab');
	execFileSync('docker', ['run', '--rm', '-v', `${path.join(import.meta.dirname, 'rogue-extension')}:/ext:ro`, '-v', `${vsixDir}:/out`,
		'node:24.22.1-trixie', 'sh', '-c', 'cp -r /ext /tmp/e && cd /tmp/e && npx --yes @vscode/vsce@3 package --allow-missing-repository --skip-license -o /out/rogue.vsix'], { stdio: 'inherit' });
	const client = new TabdClient({
		command: process.execPath,
		args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', driver, '--allowed-root', base],
		env: { HOME: process.env.HOME, USER: process.env.USER },
	});
	await client.initialize('containment-editor', '0');
	const { tab } = await client.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
	await client.request('tab.ensureRunning', { tabId: tab.metadata.name });
	const name = `seclab-${tab.metadata.name}`;
	const runtime = driver === 'sbx' ? '/opt/homebrew/bin/sbx' : 'docker';
	const user = driver === 'sbx' ? 'agent' : '1000:1000';
	const r = spawnSync(runtime, ['exec', '-u', user, name, '/opt/seclab/bin/seclab-tab-env',
		'/opt/seclab-reh/bin/seclab-code-server', '--install-extension', path.join(vsixDir, 'rogue.vsix')], { encoding: 'utf8' });
	console.log(r.stdout.trim(), r.stderr.trim());
	client.dispose(); // stops the tab; the editor restarts it (extensions persist in the tab)
	await new Promise(res => client.once('exit', res));
	console.log(`\nprepared tab ${tab.metadata.name} for ${ws}\nnow open it with the fork:\n  <app>/Contents/Resources/app/bin/seclab-code --user-data-dir ${userData} ${ws}`);
} else {
	const checks: Check[] = [];
	for (const vector of ['task', 'fsmonitor', 'rogue-extension']) {
		checks.push(...checkEvidence(readEvidence(ws, vector), vector, { marker }));
	}
	const hostFile = path.join(ws, '.seclab-evidence', 'rogue-extension-host.json');
	const host = fs.existsSync(hostFile) ? JSON.parse(fs.readFileSync(hostFile, 'utf8')) : undefined;
	checks.push({ vector: 'rogue-extension', name: 'ui-kind rogue extension was forced into the tab (remoteName=seclab)', ok: host?.remoteName === 'seclab' && host?.seclabTab === '1', detail: JSON.stringify(host) });
	checks.push({ vector: 'host', name: 'canary intact', ok: fs.readFileSync(canary, 'utf8') === 'HOST-SECRET-CANARY\n', detail: '' });
	const ok = report(checks);
	// Disarm the hostile git config left in the host work dir.
	fs.rmSync(path.join(ws, '.git'), { recursive: true, force: true });
	process.exit(ok ? 0 : 1);
}
