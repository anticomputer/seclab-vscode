// Tab observability demo in the real editor (README screenshot): the inert loader workspace in
// a sandboxed tab with an isolated profile. Uses the shared run manifest and teardown gate.
//   node test/observability/demo.ts prepare ~/.seclab-test/obs [sbx|oci]   # prints the launch command
//   node test/observability/demo.ts teardown ~/.seclab-test/obs            # kills the editor tree, removes the tab, verifies
// Fixture safety: same arming as the e2e (nonce, run dir, expiry); demo values are fake.
// Never bring a demo window over the user's work: launch with `open -g -n -a` (not `bin/code`,
// whose hand-off to the main process calls app.focus({steal:true})), never activate it, and
// capture by window id (`screencapture -o -l`), which works while the window is covered.

import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import { printChecks, removeRunResources, stopRunProcesses, verifyTeardown, writeManifest, writeSnapshot } from '../containment/teardown.ts';
import { checkUserDataDir, editorLaunchCommand } from '../harness.ts';
import { folderOpenTasks, LOADER_IN_TAB, loaderScript, writeStdinTo } from './loader.ts';

const [mode, userDataArg, driverArg] = process.argv.slice(2);
if ((mode !== 'prepare' && mode !== 'teardown') || !userDataArg) {
	console.error('usage: demo.ts prepare|teardown USER_DATA_DIR [sbx|oci]');
	process.exit(2);
}
const driver = driverArg ?? 'sbx';
if (driver !== 'sbx') {
	// The loader and its hidden task are written inside the tab. Only sbx holds in-tab
	// workspace writes in the write-back overlay; an OCI tab's writes would reach host disk.
	console.error('demo.ts: sbx only (in-tab files must never reach the host)');
	process.exit(2);
}
const repo = path.resolve(import.meta.dirname, '../..');
const userData = path.resolve(userDataArg);
checkUserDataDir(userData);
const base = path.join(repo, '.work', 'obs-demo');
const ws = path.join(base, 'tabs', 'demo-app');
const stateDir = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');

if (mode === 'teardown') {
	const killed = stopRunProcesses(base);
	console.log(`stopped ${killed.length} run process(es)`);
	removeRunResources(base);
	const ok = printChecks(verifyTeardown(base));
	process.exit(ok ? 0 : 1);
}

fs.rmSync(base, { recursive: true, force: true });
fs.rmSync(stateDir, { recursive: true, force: true });
fs.mkdirSync(base, { recursive: true });
writeSnapshot(base);
writeManifest(base, { driver, userDataDir: userData, stateDirs: [stateDir] });
writeManifest(base, { workspaces: [ws] }); // teardown deletes it
fs.mkdirSync(path.join(ws, '.seclab'), { recursive: true });
const arm = randomBytes(16).toString('hex');
fs.writeFileSync(path.join(ws, '.seclab', 'targets'), `arm=${arm}\nrun=${base}\nuntil=${Math.floor(Date.now() / 1000) + 3600}\nmarker=${path.join(ws, '.envrc')}\n`);
fs.writeFileSync(path.join(ws, 'README.md'), '# demo-app\n\nAn inert demo workspace: its folder-open task imitates a loader (seclab-vscode tab observability demo).\n');
// Worst case for us: trust off, automatic tasks on (trust is UX, not a boundary).
fs.mkdirSync(path.join(userData, 'User'), { recursive: true });
fs.writeFileSync(path.join(userData, 'User', 'settings.json'), JSON.stringify({
	'security.workspace.trust.enabled': false,
	'task.allowAutomaticTasks': 'on',
	'seclab.tabs.driver': driver,
	'seclab.tabs.allowedRoots': [base],
	'seclab.activity.revealOnAlert': true,
	'workbench.startupEditor': 'none',
	'workbench.tips.enabled': false,
	'workbench.welcomePage.experimentalOnboarding': false,
	'chat.disableAIFeatures': true,
	'workbench.secondarySideBar.defaultVisibility': 'hidden',
	'workbench.panel.opensMaximized': 'always',
	'window.newWindowDimensions': 'default',
}, null, '\t'));

const client = new TabdClient({
	command: process.execPath,
	args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', driver, '--allowed-root', base],
	env: { HOME: process.env.HOME, USER: process.env.USER },
});
await client.initialize('obs-demo', '0');
const { tab } = await client.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
writeManifest(base, { tabs: [tab.metadata.name] });
// The loader (tab home) and the hidden folder-open task (workspace, held in the write-back
// overlay) are assembled in memory and written inside the tab, never on the host.
await client.request('tab.ensureRunning', { tabId: tab.metadata.name });
const inTab = (cmd: string, input: string) => spawnSync('/opt/homebrew/bin/sbx', ['exec', '-i', '-u', 'agent', '-w', ws, `seclab-${tab.metadata.name}`, '/opt/seclab/bin/seclab-tab-env', 'sh', '-c', cmd], { encoding: 'utf8', input, timeout: 60_000 });
for (const [dest, text] of [[`"$HOME/${LOADER_IN_TAB}"`, loaderScript()], [JSON.stringify(path.join(ws, '.vscode', 'tasks.json')), folderOpenTasks()]]) {
	const r = inTab(writeStdinTo(dest), text);
	if (r.status !== 0) {
		throw new Error(`writing ${dest} in the tab failed: ${r.stderr}`);
	}
}
if (fs.existsSync(path.join(ws, '.vscode'))) {
	throw new Error('the in-tab tasks.json reached the host checkout: is the write-back overlay mounted?');
}
await client.request('shutdown', {}).catch(() => undefined);
client.dispose();
console.log(`prepared tab ${tab.metadata.name} for ${ws}`);
console.log(`\n  ${editorLaunchCommand(userData, `vscode-remote://seclab+${tab.metadata.name}${ws}`)}\n`);
console.log(`screenshot (window stays behind yours): node test/window.ts shot ${userData} .work/shots/obs-demo.png`);
console.log(`then: node test/observability/demo.ts teardown ${userData}`);
