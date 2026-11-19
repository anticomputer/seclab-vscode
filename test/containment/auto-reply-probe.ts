// Terminal auto replies from a tab window never reach the local pty host every window shares
// (patch 0061, review R5-32), proven in a real OCI tab of the containment test build, driven
// headlessly.
//
//   node test/containment/auto-reply-probe.ts baseline|patched <user-data-dir> --app <test app.app>
//
// The tab image is seclab-tab-oci:test-containment, built from the same run's REH
// (`./seclab fetch macos-containment RUN`, `./seclab image oci --test-variant containment`).
//
// What it does, in one app:
//   1. a tab window opens; as the tab, the run writes one auto reply (a match and a reply, both
//      `seclabcanary` strings with this run's nonce, no newline) into the REH's remote user
//      settings, which a tab window's settings include;
//   2. positive control: a terminal in the tab window, the tab's own, echoes the match and gets the
//      reply, so the tab window loaded the pair and installed it on its tab's backend;
//   3. the tab window opens a normal (empty) window in the same app. Its local terminal runs
//      /bin/cat as the profile's executable, never a shell. It echoes a host-user control match,
//      which must get its reply (the mechanism works there), then the tab's match;
//   4. baseline: the tab's reply appears in the normal window's terminal (the shared pty host had
//      it), and the host user's reply comes back in the tab's own terminal (the tab's server had
//      the host's pair). Patched: neither does.
// Every terminal is killed, and the run checks that no /bin/cat outlives it before teardown.
//
// Inert (EDR fixture safety): the local terminal is cat, which only echoes; the replies hold no
// newline or shell metacharacter; terminal text is read in memory and only booleans are recorded.
// Windows open in the background and never take focus. Teardown runs on every exit.

import { execFileSync, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import { DrivenEditor } from '../driver/editor.ts';
import { checkUserDataDir, lockRun, repoRoot } from '../harness.ts';
import { report, type Check } from './assert.ts';
import { exitOnSignals, reapOrRefuse, teardownGate, writeManifest, writeSnapshot } from './teardown.ts';

const IMAGE = 'seclab-tab-oci:test-containment';
const CAT = '/bin/cat';

const argv = process.argv.slice(2);
const [mode, userDataArg] = argv;
const appArg = argv[argv.indexOf('--app') + 1];
if ((mode !== 'baseline' && mode !== 'patched') || !userDataArg || !argv.includes('--app') || !appArg) {
	console.error('usage: auto-reply-probe.ts baseline|patched <user-data-dir> --app <test app.app>');
	process.exit(2);
}
const app = path.resolve(appArg);
if (!app.endsWith('.app') || !fs.existsSync(app)) {
	console.error(`--app must name an existing .app, got ${JSON.stringify(appArg)}`);
	process.exit(2);
}
if (!fs.existsSync(CAT)) {
	console.error(`${CAT} is missing`);
	process.exit(2);
}
const userData = path.resolve(userDataArg);
checkUserDataDir(userData);
execFileSync(process.execPath, [path.join(repoRoot, 'test', 'builds', 'require-hooks.ts'), '--variant', 'containment', '--hook', 'rogue-reh', '--image', IMAGE], { stdio: 'inherit' });

const base = path.join(repoRoot, '.work', 'auto-reply-probe', mode);
lockRun(path.join(base, '..', `${mode}.lock.d`));
const ws = path.join(base, 'ws');
const stateDir = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

// ------------------------------------------------------------------ prepare
reapOrRefuse(base, 'auto-reply-probe');
fs.rmSync(base, { recursive: true, force: true });
fs.rmSync(userData, { recursive: true, force: true });
fs.mkdirSync(ws, { recursive: true });
const nonce = randomBytes(8).toString('hex');
const TAB_MATCH = `seclabcanary_tabmatch_${nonce}`;
const TAB_REPLY = `seclabcanary_tabreply_${nonce}`;
const HOST_MATCH = `seclabcanary_hostmatch_${nonce}`;
const HOST_REPLY = `seclabcanary_hostreply_${nonce}`;
for (const s of [TAB_MATCH, TAB_REPLY, HOST_MATCH, HOST_REPLY]) {
	if (!/^[a-z0-9_]+$/.test(s)) {
		throw new Error('a canary holds more than [a-z0-9_]');
	}
}
fs.writeFileSync(path.join(ws, 'README.md'), 'auto-reply-probe workspace\n');
writeSnapshot(base);
writeManifest(base, { driver: 'oci', userDataDir: userData, stateDirs: [stateDir], workspaces: [ws] });
let ed: DrivenEditor | undefined;
exitOnSignals();
process.on('exit', code => {
	if (!teardownGate(base) && code === 0) {
		process.exitCode = 1;
	}
});

fs.mkdirSync(path.join(userData, 'User'), { recursive: true });
fs.writeFileSync(path.join(userData, 'User', 'settings.json'), JSON.stringify({
	'security.workspace.trust.enabled': false,
	'seclab.tabs.driver': 'oci',
	'seclab.tabs.image': IMAGE,
	'seclab.tabs.allowedRoots': [base],
	'workbench.welcomePage.experimentalOnboarding': false,
	'workbench.startupEditor': 'none',
	'workbench.tips.enabled': false,
	'chat.disableAIFeatures': true,
	'window.restoreWindows': 'none',
	// The normal window's local terminal is cat, never a shell, and dies with its window.
	'terminal.integrated.profiles.osx': { 'seclab-cat': { path: CAT } },
	'terminal.integrated.defaultProfile.osx': 'seclab-cat',
	'terminal.integrated.enablePersistentSessions': false,
	'terminal.integrated.gpuAcceleration': 'off',
	'terminal.integrated.autoReplies': { [HOST_MATCH]: HOST_REPLY },
}, null, '\t'));

const tabd = new TabdClient({
	command: process.execPath,
	args: [path.join(repoRoot, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', 'oci', '--image', IMAGE, '--allowed-root', base],
	env: { HOME: process.env.HOME, USER: process.env.USER },
});
await tabd.initialize('auto-reply-probe', '0');
const { tab } = await tabd.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
const tabId = tab.metadata.name;
writeManifest(base, { tabs: [tabId] });
tabd.dispose();
await new Promise(res => tabd.once('exit', res));

const inTab = (script: string, input?: string) => spawnSync('docker', ['exec', '-i', '-u', '1000:1000', '--', `seclab-${tabId}`, '/opt/seclab/bin/seclab-tab-env', 'sh', '-c', script],
	{ encoding: 'utf8', input, timeout: 30_000 });
const waitFor = async (ok: () => boolean | Promise<boolean>, ms: number): Promise<boolean> => {
	for (const until = Date.now() + ms; Date.now() < until;) {
		if (await ok()) {
			return true;
		}
		await sleep(500);
	}
	return false;
};

/** One workbench window of the driven app: its own CDP session on the shared pipe. */
class Win {
	readonly ed: DrivenEditor;
	readonly session: string;
	constructor(ed: DrivenEditor, session: string) {
		this.ed = ed;
		this.session = session;
	}
	async evaluate<T>(expression: string): Promise<T> {
		const r = await this.ed.cdp.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }, this.session, 30_000);
		if (r.exceptionDetails) {
			throw new Error(`evaluate: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
		}
		return r.result?.value as T;
	}
	async key(key: 'Enter' | 'F1'): Promise<void> {
		const code = key === 'Enter' ? 13 : 112;
		for (const type of ['rawKeyDown', 'keyUp']) {
			await this.ed.cdp.send('Input.dispatchKeyEvent', { type, key, code: key, windowsVirtualKeyCode: code, nativeVirtualKeyCode: code }, this.session);
		}
	}
	async type(text: string): Promise<void> {
		await this.ed.cdp.send('Input.insertText', { text }, this.session);
	}
	async command(label: string): Promise<void> {
		await this.key('F1');
		await waitFor(() => this.evaluate<boolean>(`!!document.querySelector('.quick-input-widget') && getComputedStyle(document.querySelector('.quick-input-widget')).display !== 'none'`).catch(() => false), 15_000);
		await this.type(label);
		await sleep(750);
		await this.key('Enter');
	}
	/** Whether the window's terminal text (DOM renderer) holds `s`; the text itself never leaves. */
	terminalHas(s: string): Promise<boolean> {
		return this.evaluate<boolean>(`[...document.querySelectorAll('.xterm-rows')].some(e => e.textContent.includes(${JSON.stringify(s)}))`).catch(() => false);
	}
	terminalReady(): Promise<boolean> {
		return this.evaluate<boolean>(`!!document.querySelector('.xterm-rows') && document.activeElement?.classList.contains('xterm-helper-textarea')`).catch(() => false);
	}
}

/** Descendants of `root` running `command` (exact argv[0]). */
function descendantsRunning(root: number, command: string): number[] {
	const rows = spawnSync('ps', ['-axo', 'pid=,ppid=,command='], { encoding: 'utf8' }).stdout.split('\n').map(l => /^\s*(\d+)\s+(\d+)\s+(.*)$/.exec(l)).filter(m => m);
	const kids = new Map<number, number[]>();
	for (const m of rows) {
		kids.set(Number(m![2]), [...(kids.get(Number(m![2])) ?? []), Number(m![1])]);
	}
	const all = new Set<number>();
	const walk = (p: number) => (kids.get(p) ?? []).forEach(k => { if (!all.has(k)) { all.add(k); walk(k); } });
	walk(root);
	return rows.filter(m => all.has(Number(m![1])) && m![3].trim() === command).map(m => Number(m![1]));
}

const checks: Check[] = [];
const c = (vector: string, ok: boolean, name: string, detail = '') => checks.push({ vector, ok, name, detail });

// ------------------------------------------------------------------ run
try {
	ed = await DrivenEditor.launch({ app, userData, folderUri: `vscode-remote://seclab+${tabId}${ws}` });
	const tabWin = new Win(ed, ed.session);
	c('setup', await waitFor(() => inTab('true').status === 0, 120_000), 'the tab is running');
	c('setup', await waitFor(() => inTab('test -d "$HOME/.seclab-vscode-server/data"').status === 0, 60_000), 'the REH has its data directory');

	// As the tab: one pair in the REH's remote user settings.
	const w = inTab('mkdir -p "$HOME/.seclab-vscode-server/data/Machine" && cat > "$HOME/.seclab-vscode-server/data/Machine/settings.json"', JSON.stringify({ 'terminal.integrated.autoReplies': { [TAB_MATCH]: TAB_REPLY } }));
	c('setup', w.status === 0, 'the tab wrote its auto reply into the REH\'s remote user settings', w.stderr.trim().slice(0, 200));

	// Positive control: the tab's own terminal answers the tab's pair.
	await sleep(5000);
	await tabWin.command('Terminal: Create New Terminal');
	await waitFor(() => tabWin.terminalReady(), 30_000);
	await sleep(3000);
	await tabWin.type(TAB_MATCH);
	c('control', await waitFor(() => tabWin.terminalHas(TAB_REPLY), 15_000), 'the tab\'s own terminal got the tab\'s reply (the tab window loaded the pair)');
	// The other way (R5-31): the host user's pair, installed on the tab's server, answers there.
	await sleep(1500);
	await tabWin.type(HOST_MATCH);
	const hostInTab = await waitFor(() => tabWin.terminalHas(HOST_REPLY), 10_000);
	if (mode === 'baseline') {
		c('r5-31', hostInTab, 'baseline: the host user\'s reply came back from the tab\'s server');
	} else {
		c('r5-31', !hostInTab, 'patched: the tab\'s server never got the host user\'s pair');
	}

	// A normal window in the same app.
	const before = new Set((await ed.cdp.send<{ targetInfos: Array<{ targetId: string; type: string; url: string }> }>('Target.getTargets')).targetInfos.map(t => t.targetId));
	await tabWin.command('New Window');
	let target: { targetId: string } | undefined;
	await waitFor(async () => {
		const { targetInfos } = await ed!.cdp.send<{ targetInfos: Array<{ targetId: string; type: string; url: string }> }>('Target.getTargets');
		target = targetInfos.find(t => t.type === 'page' && /\/workbench\/workbench\.html/.test(t.url) && !before.has(t.targetId));
		return !!target;
	}, 60_000);
	c('setup', !!target, 'a normal window opened in the same app');
	if (target) {
		const { sessionId } = await ed.cdp.send<{ sessionId: string }>('Target.attachToTarget', { targetId: target.targetId, flatten: true });
		await ed.cdp.send('Emulation.setFocusEmulationEnabled', { enabled: true }, sessionId);
		const normal = new Win(ed, sessionId);
		c('setup', await waitFor(() => normal.evaluate<boolean>(`!!document.querySelector('.monaco-workbench')`).catch(() => false), 60_000), 'the normal window\'s workbench is up');
		c('setup', await normal.evaluate<boolean>(`!location.href.includes('seclab+')`).catch(() => false), 'the normal window is not a tab window');
		await sleep(3000);
		await normal.command('Terminal: Create New Terminal');
		c('setup', await waitFor(() => normal.terminalReady(), 30_000), 'the normal window\'s local terminal is up');
		// Nothing is typed into a local terminal unless it is cat (fixture safety).
		const isCat = descendantsRunning(ed.child.pid!, CAT).length === 1;
		c('setup', isCat, 'it runs cat, not a shell');
		if (!isCat) {
			throw new Error('the local terminal is not cat; nothing typed');
		}
		await sleep(2000);
		// Control: the host user's own pair answers in the local terminal.
		await normal.type(HOST_MATCH);
		c('control', await waitFor(() => normal.terminalHas(HOST_REPLY), 15_000), 'the local terminal got the host user\'s reply (auto replies work there)');
		await sleep(1500);
		await normal.type(TAB_MATCH);
		const got = await waitFor(() => normal.terminalHas(TAB_REPLY), 10_000);
		if (mode === 'baseline') {
			c('r5-32', got, 'baseline: the tab\'s reply was typed into the normal window\'s local terminal');
		} else {
			c('r5-32', !got, 'patched: the tab\'s reply never reached the normal window\'s local terminal');
		}
		await normal.command('Terminal: Kill All Terminals');
	}
	await tabWin.command('Terminal: Kill All Terminals');
	c('cleanup', await waitFor(() => descendantsRunning(ed!.child.pid!, CAT).length === 0, 15_000), 'no cat outlives the terminals');
} catch (err) {
	c('run', false, 'the run completed', (err as Error).message);
} finally {
	await ed?.close();
}

process.exit(report(checks) ? 0 : 1);
