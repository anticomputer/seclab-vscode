// Containment suite, level B: the real editor triggers the vectors.
//   prepare <user-data-dir> [sbx|oci]  create the fixture workspace, claim its tab in the
//                                      editor's tabd state, preinstall the rogue extension
//                                      into the tab, write test user settings
//   check   <user-data-dir>            assert the evidence the editor-run vectors left behind
// In between, open the workspace with the fork, e.g.
//   .work/app/seclab-vscode.app/Contents/Resources/app/bin/code --user-data-dir <dir> --folder-uri <printed>  (the build keeps upstream's CLI name)

import { execFileSync, spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import { deserialize, mintCanary, scan, serialize } from '../canary/canary.ts';
import { beaconPort, checkUserDataDir, lockRun } from '../harness.ts';
import { checkEvidence, readEvidence, report, type Check } from './assert.ts';

const [mode, userDataArg, driverArg] = process.argv.slice(2);
if ((mode !== 'prepare' && mode !== 'check') || !userDataArg) {
	console.error('usage: check-evidence.ts prepare|check <user-data-dir> [sbx|oci]');
	process.exit(2);
}
const driver = driverArg ?? 'sbx';
const repo = path.resolve(import.meta.dirname, '../..');
const userData = path.resolve(userDataArg);
checkUserDataDir(userData);
const base = path.resolve(process.env.SECLAB_EVIDENCE_DIR ?? path.join(repo, '.work', 'containment-editor'));
lockRun(path.join(base, '..', `${path.basename(base)}.lock.d`));
const ws = path.join(base, 'ws-editor');
const canary = path.join(base, 'canary', 'secret.txt');
const marker = path.join(base, 'PWNED');
const stateDir = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');

if (mode === 'prepare') {
	// A previous run's claim points at the old fixture (a new folder has a new inode, which
	// tabd rightly refuses): remove its tabs and sandboxes, then start from clean state.
	if (fs.existsSync(stateDir)) {
		const old = new TabdClient({
			command: process.execPath,
			args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', driver, '--allowed-root', base],
			env: { HOME: process.env.HOME, USER: process.env.USER },
		});
		await old.initialize('containment-editor-cleanup', '0');
		for (const t of (await old.request<{ tabs: Array<{ metadata: { name: string } }> }>('tab.list')).tabs) {
			await old.request('tab.remove', { tabId: t.metadata.name }).catch(() => undefined);
		}
		old.dispose();
		fs.rmSync(stateDir, { recursive: true, force: true });
	}
	fs.rmSync(base, { recursive: true, force: true });
	fs.mkdirSync(path.dirname(canary), { recursive: true });
	fs.writeFileSync(canary, 'HOST-SECRET-CANARY\n');
	fs.cpSync(path.join(import.meta.dirname, 'fixtures', 'malicious-workspace'), ws, { recursive: true });
	const port = await beaconPort();
	fs.writeFileSync(path.join(ws, '.seclab', 'targets'), `canary=${canary}\nmarker=${marker}\nloopback=${port}\n`);
	// Git repo with a hostile core.fsmonitor. Only `init` and `config` run on the host;
	// neither reads core.fsmonitor. Nothing here may run `git status` on the host.
	execFileSync('git', ['-C', ws, 'init', '-q']);
	execFileSync('git', ['-C', ws, 'config', 'core.fsmonitor', 'sh .seclab/probe.sh fsmonitor']);
	// Test profile: Workspace Trust off and automatic tasks on, i.e. the worst case for us
	// (trust is UX, not a boundary). Plus editor-side canaries (shared canary harness):
	// user settings (incl. a real secret-bearing setting) and the host clipboard.
	const canaries = [mintCanary('user-settings'), mintCanary('user-settings-proxy-auth'), mintCanary('clipboard'), mintCanary('editor-env')];
	fs.writeFileSync(path.join(base, 'canaries.json'), serialize(canaries));
	fs.mkdirSync(path.join(userData, 'User'), { recursive: true });
	fs.writeFileSync(path.join(userData, 'User', 'settings.json'), JSON.stringify({
		'security.workspace.trust.enabled': false,
		'task.allowAutomaticTasks': 'on',
		'seclab.tabs.driver': driver,
		'seclab.tabs.allowedRoots': [base],
		'seclab.test.canary': canaries[0].value,
		'http.proxyAuthorization': `Basic ${canaries[1].value}`,
	}, null, '\t'));
	spawnSync('pbcopy', [], { input: canaries[2].value });
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
	const user = driver === 'sbx' ? ['-u', 'agent'] : [];
	const r = spawnSync(runtime, ['exec', ...user, name, '/opt/seclab/bin/seclab-tab-env',
		'/opt/seclab-reh/bin/seclab-code-server', '--install-extension', path.join(vsixDir, 'rogue.vsix')], { encoding: 'utf8' });
	console.log(r.stdout.trim(), r.stderr.trim());
	client.dispose(); // stops the tab; the editor restarts it (extensions persist in the tab)
	await new Promise(res => client.once('exit', res));
	console.log(`\nprepared tab ${tab.metadata.name} for ${ws}\nnow open the TAB directly (never the local path: a local window must not open this hostile workspace):\n  env SECLAB_EDITOR_CANARY=${canaries[3].value} <app>/Contents/Resources/app/bin/code --user-data-dir ${userData} --folder-uri vscode-remote://seclab+${tab.metadata.name}${ws}`);
} else {
	const checks: Check[] = [];
	for (const vector of ['task', 'fsmonitor', 'rogue-extension']) {
		checks.push(...checkEvidence(readEvidence(ws, vector), vector, { marker }));
	}
	const hostFile = path.join(ws, '.seclab-evidence', 'rogue-extension-host.json');
	const host = fs.existsSync(hostFile) ? JSON.parse(fs.readFileSync(hostFile, 'utf8')) : undefined;
	checks.push({ vector: 'rogue-extension', name: 'ui-kind rogue extension was forced into the tab (remoteName=seclab)', ok: host?.remoteName === 'seclab' && host?.seclabTab === '1', detail: JSON.stringify(host) });
	checks.push({ vector: 'host', name: 'canary intact', ok: fs.readFileSync(canary, 'utf8') === 'HOST-SECRET-CANARY\n', detail: '' });
	// Shared canary harness, editor side: nothing the rogue extension observed through the
	// API (env, configuration, clipboard, auth sessions, secrets) nor any evidence may
	// contain an editor-side canary in any encoding.
	const canaries = deserialize(fs.readFileSync(path.join(base, 'canaries.json'), 'utf8'));
	const evDir = path.join(ws, '.seclab-evidence');
	const observedOk = fs.existsSync(path.join(evDir, 'rogue-observed.json'));
	checks.push({ vector: 'canary', name: 'rogue extension recorded its API observations', ok: observedOk, detail: '' });
	// Stores the rogue extension can still read through the extension API until the RPC
	// capability filter (M4) lands: configuration (user settings) and the clipboard.
	const M4 = 'M4 RPC capability filter (docs/adr/20261104-rpc-capability-filter.md)';
	const knownUntilM4 = new Set(['user-settings', 'clipboard']);
	for (const f of fs.existsSync(evDir) ? fs.readdirSync(evDir) : []) {
		for (const h of scan(canaries, f, fs.readFileSync(path.join(evDir, f)))) {
			checks.push({ vector: 'canary', name: `no ${h.store} canary in tab-observable data`, ok: false, detail: `${h.encoding} in ${h.source}`,
				knownGap: knownUntilM4.has(h.store) ? M4 : undefined });
		}
	}
	checks.push({ vector: 'canary', name: 'no editor-side canary observed by the tab (outside known gaps)', ok: !checks.some(c => c.vector === 'canary' && !c.ok && !c.knownGap), detail: '' });
	const ok = report(checks);
	// Disarm the hostile git config left in the host work dir.
	fs.rmSync(path.join(ws, '.git'), { recursive: true, force: true });
	process.exit(ok ? 0 : 1);
}
