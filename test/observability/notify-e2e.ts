// Detection notifications end to end (ADR detection notifications): the inert Contagious-Interview
// fixture opened as a sandboxed tab in the real editor, its folder-open loader run by the editor
// as a real task, and the Tab Manager's notifications checked from its record of what it showed.
//   node test/observability/notify-e2e.ts ~/.seclab-test/notify [--shot docs/media/notifications.png] [--keep]
// sbx only: the hidden folder-open tasks.json is written inside the tab, where the write-back
// gate holds it; it never exists on the host (EDR fixture-safety, AV rule). The editor window is
// launched in the background and never takes focus; the screenshot captures it by window id
// while it stays covered. The run ends with the shared teardown gate.

import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import { armCampaignTab, loaderCommand, setupCampaign } from '../containment/campaign.ts';
import { printChecks, removeRunResources, stopRunProcesses, verifyTeardown, writeManifest, writeSnapshot } from '../containment/teardown.ts';
import { captureWindow, checkUserDataDir, launchEditorInBackground } from '../harness.ts';
import { hasHostCap, skipReason } from '../host-caps.ts';
import { writeStdinTo } from './loader.ts';

const args = process.argv.slice(2);
const userDataArg = args.find((a, i) => !a.startsWith('--') && !['--shot', '--app'].includes(args[i - 1]));
const shot = args.includes('--shot') ? args[args.indexOf('--shot') + 1] : undefined;
const keep = args.includes('--keep');
/** A branch test build (./seclab fetch macos-branch) when given, else the main build. */
const app = args.includes('--app') ? path.resolve(args[args.indexOf('--app') + 1]) : undefined;
if (!userDataArg) {
	console.error('usage: notify-e2e.ts USER_DATA_DIR [--app PATH.app] [--shot OUT.png] [--keep]');
	process.exit(2);
}
const repo = path.resolve(import.meta.dirname, '../..');
const userData = path.resolve(userDataArg);
checkUserDataDir(userData);
const base = path.join(repo, '.work', 'notify-e2e');
const stateDir = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');
const notifications = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'notifications.jsonl');
/** What the fixture's loader must raise, as a folder-open task (EDR fixture-safety: inert). Tasks
 *  run under the REH's terminal host, not the extension host, so the critical folder-open form of
 *  task.network-tool depends on how the task is launched; it is reported, not required. */
const EXPECTED = ['loader.pipe-to-interpreter'];

let failures = 0;
const check = (name: string, ok: boolean, detail = '') => {
	console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : `: ${detail}`}`);
	failures += ok ? 0 : 1;
};
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
function teardown(): void {
	stopRunProcesses(base);
	removeRunResources(base);
	if (!printChecks(verifyTeardown(base))) {
		failures++;
	}
}

fs.rmSync(base, { recursive: true, force: true });
fs.rmSync(path.join(userData), { recursive: true, force: true });
fs.mkdirSync(base, { recursive: true });
writeSnapshot(base);
writeManifest(base, { driver: 'sbx', userDataDir: userData, stateDirs: [stateDir] });
const arm = randomBytes(16).toString('hex');
const marker = path.join(base, 'containment-failure.marker');
const campaign = setupCampaign(base, arm, 9, marker);
const ws = path.join(base, 'tabs', 'take-home-exercise');
fs.renameSync(campaign.ws, ws);
campaign.ws = ws;
writeManifest(base, { workspaces: [ws] });
// Worst case for us: trust off, automatic tasks on (trust is UX, not a boundary).
fs.mkdirSync(path.join(userData, 'User'), { recursive: true });
fs.writeFileSync(path.join(userData, 'User', 'settings.json'), JSON.stringify({
	'security.workspace.trust.enabled': false,
	'task.allowAutomaticTasks': 'on',
	'seclab.tabs.driver': 'sbx',
	'seclab.tabs.allowedRoots': [base],
	'seclab.activity.revealOnAlert': false,
	'workbench.startupEditor': 'none',
	'workbench.tips.enabled': false,
	'workbench.welcomePage.experimentalOnboarding': false,
	'chat.disableAIFeatures': true,
	'workbench.secondarySideBar.defaultVisibility': 'hidden',
	'window.newWindowDimensions': 'default',
}, null, '\t'));

const client = new TabdClient({
	command: process.execPath,
	args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', 'sbx', '--allowed-root', base],
	env: { HOME: process.env.HOME, USER: process.env.USER },
});
try {
	await client.initialize('notify-e2e', '0');
	const { tab } = await client.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
	const tabId = tab.metadata.name;
	writeManifest(base, { tabs: [tabId] });
	armCampaignTab(campaign, `seclab-${tabId}`);
	await client.request('tab.ensureRunning', { tabId });
	// The folder-open task, assembled in memory from loader.parts.json, written inside the tab only.
	const tasks = JSON.stringify({ version: '2.0.0', tasks: [{ label: 'eslint-check', type: 'shell', command: loaderCommand(ws), runOptions: { runOn: 'folderOpen' }, presentation: { reveal: 'never' }, problemMatcher: [] }] }, null, '\t');
	const w = spawnSync('/opt/homebrew/bin/sbx', ['exec', '-i', '-u', 'agent', '-w', ws, `seclab-${tabId}`, '/opt/seclab/bin/seclab-tab-env', 'sh', '-c', writeStdinTo(JSON.stringify(path.join(ws, '.vscode', 'tasks.json')))], { encoding: 'utf8', input: tasks, timeout: 60_000 });
	check('folder-open task written inside the tab only', w.status === 0 && !fs.existsSync(path.join(ws, '.vscode', 'tasks.json')), w.stderr);
	await client.request('shutdown', {}).catch(() => undefined);
	client.dispose();

	const launch = await launchEditorInBackground(userData, `vscode-remote://seclab+${tabId}${ws}`, {}, 90_000, app);
	check('editor launched in the background (no focus taken)', !launch.stoleFocus, `pid ${launch.pid}`);
	if (launch.stoleFocus) {
		throw new Error('focus stolen: stop (AGENTS rule)');
	}
	let shown: Array<{ kind: string; message: string; actions: string[]; tabId: string; count: number }> = [];
	for (const end = Date.now() + 180_000; Date.now() < end; await sleep(2000)) {
		try {
			shown = fs.readFileSync(notifications, 'utf8').trim().split('\n').filter(Boolean).map(l => JSON.parse(l));
		} catch { /* not yet */ }
		if (EXPECTED.every(k => shown.some(s => s.kind === k))) {
			break;
		}
	}
	const kinds = shown.map(s => s.kind);
	console.log(`notifications shown: ${kinds.join(', ') || 'none'}`);
	for (const k of EXPECTED) {
		check(`notification: ${k}`, kinds.includes(k), kinds.join(', '));
	}
	check('every notification names the tab (trusted name) and offers Stop Tab', shown.length > 0 && shown.every(s => s.tabId === tabId && s.message.startsWith('Tab “take-home-exercise”:') && s.actions.includes('stop-tab')), JSON.stringify(shown.map(s => s.message.slice(0, 80))));
	check('no link, command or markup from tab text in any message', shown.every(s => !/\]\(|command:|:\/\/|\$\(|[\u202a-\u202e\u2066-\u2069]/.test(s.message)), JSON.stringify(shown.map(s => s.message)));
	check('rate-limited: a handful of notifications, not one per event', shown.length <= 6, String(shown.length));
	const detail = shown.find(s => s.kind === 'loader.pipe-to-interpreter');
	check('the loader notification explains itself with the chain and its integrity', !!detail && /Chain: “.*”/.test(detail.message) && /inside the tab's VM/.test(detail.message), detail?.message);
	if (shot && !hasHostCap('screen-capture')) {
		console.log(skipReason('screen-capture', `the screenshot ${shot}`));
	} else if (shot) {
		await sleep(1500);
		captureWindow(launch.windowId, path.resolve(shot));
		console.log(`captured window ${launch.windowId} -> ${shot}`);
	}
} catch (e) {
	check('run', false, (e as Error).message);
} finally {
	client.dispose();
	if (keep) {
		console.log(`KEEP: not torn down. Later: node test/containment/teardown.ts verify ${base}`);
		failures++;
	} else {
		teardown();
	}
}
console.log(failures ? `\n${failures} check(s) failed` : '\nNOTIFICATIONS OK');
process.exit(failures ? 1 : 0);
