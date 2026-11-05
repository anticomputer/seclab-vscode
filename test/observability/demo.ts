// Tab observability demo in the real editor (README screenshot): the inert loader workspace in
// a sandboxed tab with an isolated profile. Uses the shared run manifest and teardown gate.
//   node test/observability/demo.ts prepare ~/.seclab-test/obs [sbx|oci]   # prints the launch command
//   node test/observability/demo.ts teardown ~/.seclab-test/obs            # kills the editor tree, removes the tab, verifies
// Fixture safety: same arming as the e2e (nonce, run dir, expiry); demo values are fake.

import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import { printChecks, removeRunResources, stopRunProcesses, verifyTeardown, writeManifest, writeSnapshot } from '../containment/teardown.ts';
import { checkUserDataDir, editorLaunchCommand } from '../harness.ts';

const [mode, userDataArg, driverArg] = process.argv.slice(2);
if ((mode !== 'prepare' && mode !== 'teardown') || !userDataArg) {
	console.error('usage: demo.ts prepare|teardown USER_DATA_DIR [sbx|oci]');
	process.exit(2);
}
const driver = driverArg === 'oci' ? 'oci' : 'sbx';
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
fs.cpSync(path.join(import.meta.dirname, 'fixtures', 'loader-workspace'), ws, { recursive: true });
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
client.dispose();
console.log(`prepared tab ${tab.metadata.name} for ${ws}`);
console.log(`\n  ${editorLaunchCommand(userData, `vscode-remote://seclab+${tab.metadata.name}${ws}`)}\n`);
console.log(`screenshot (window stays behind yours): node test/window.ts shot ${userData} .work/shots/obs-demo.png`);
console.log(`then: node test/observability/demo.ts teardown ${userData}`);
