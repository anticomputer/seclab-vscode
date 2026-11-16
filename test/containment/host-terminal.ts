// Patch 0050: a tab window opens no host terminal (project owner decision 2026-11-16), proven in
// a real OCI tab, driven headlessly.
//
//   node test/containment/host-terminal.ts baseline|patched <user-data-dir> --app <test app.app>
//
// The tab image is seclab-tab-oci:test-containment, built from the same run's REH
// (`./seclab fetch macos-containment RUN`, `./seclab image oci --test-variant containment`).
//
// In one tab window:
//   1. the command palette is searched for "Create New Integrated Terminal (Local)" and "Open New
//      External Terminal"; the rows it shows are recorded;
//   2. if the palette offers the local terminal, it is run, and the shells under the editor's own
//      process tree on the host are counted before and after (a tab's shells are in its sandbox,
//      never there);
//   3. a user keybinding runs `workbench.action.terminal.new` with a `file:` cwd, which upstream
//      launches on the local (host) backend; the host shells are counted again;
//   0. first, the tab's own terminal runs `uname -s`, which must say Linux.
// Baseline: the palette offers both; each route starts a host shell. Patched: the palette offers
// neither, neither route starts a host shell, and the tab's terminal still works.
//
// "Open New External Terminal" (Ctrl+Shift+C) is never run: on a baseline it opens the host's
// terminal application, a window outside the run's control. Its palette row is checked here, its
// keybinding and handler by host-terminal.test.ts.
//
// Inert (EDR fixture safety): nothing is typed into a host shell; the only command typed runs in
// the tab's terminal and writes one marker in the run's workspace. No network target. Teardown
// runs on every exit (teardown.ts) and fails the run on anything left.

import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import { DrivenEditor } from '../driver/editor.ts';
import { checkUserDataDir, lockRun, repoRoot } from '../harness.ts';
import { report, type Check } from './assert.ts';
import { teardownGate, writeManifest, writeSnapshot } from './teardown.ts';

const IMAGE = 'seclab-tab-oci:test-containment';
const LOCAL_LABEL = 'Create New Integrated Terminal (Local)';
const EXTERNAL_LABEL = 'Open New External Terminal';

const argv = process.argv.slice(2);
const [mode, userDataArg] = argv;
const appArg = argv[argv.indexOf('--app') + 1];
if ((mode !== 'baseline' && mode !== 'patched') || !userDataArg || !argv.includes('--app') || !appArg) {
	console.error('usage: host-terminal.ts baseline|patched <user-data-dir> --app <test app.app>');
	process.exit(2);
}
const app = path.resolve(appArg);
if (!app.endsWith('.app') || !fs.existsSync(app)) {
	console.error(`--app must name an existing .app, got ${JSON.stringify(appArg)}`);
	process.exit(2);
}
const userData = path.resolve(userDataArg);
checkUserDataDir(userData);

const base = path.join(repoRoot, '.work', 'host-terminal', mode);
lockRun(path.join(base, '..', `${mode}.lock.d`));
const ws = path.join(base, 'ws');
const stateDir = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

// ------------------------------------------------------------------ prepare
fs.rmSync(base, { recursive: true, force: true });
fs.rmSync(userData, { recursive: true, force: true });
fs.mkdirSync(ws, { recursive: true });
const arm = randomBytes(8).toString('hex');
fs.writeFileSync(path.join(ws, 'README.md'), 'host-terminal proof workspace\n');
writeSnapshot(base);
writeManifest(base, { driver: 'oci', userDataDir: userData, stateDirs: [stateDir], workspaces: [ws] });
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
}, null, '\t'));
// The user's own keybinding: a new terminal whose cwd is a host (file:) folder. Upstream gives a
// terminal with a non-remote cwd to the local backend, so on a baseline this is a host shell.
fs.writeFileSync(path.join(userData, 'User', 'keybindings.json'), JSON.stringify([
	{ key: 'ctrl+alt+shift+f12', command: 'workbench.action.terminal.new', args: { cwd: { scheme: 'file', authority: '', path: ws, query: '', fragment: '', fsPath: ws } } },
	// The control: the same command with no cwd, a terminal in the tab, so the run shows the
	// keybinding path itself works whatever the file: one does.
	{ key: 'ctrl+alt+shift+f11', command: 'workbench.action.terminal.new' },
], null, '\t'));

const tabd = new TabdClient({
	command: process.execPath,
	args: [path.join(repoRoot, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', 'oci', '--image', IMAGE, '--allowed-root', base],
	env: { HOME: process.env.HOME, USER: process.env.USER },
});
await tabd.initialize('host-terminal', '0');
const { tab } = await tabd.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
const tabId = tab.metadata.name;
writeManifest(base, { tabs: [tabId] });
tabd.dispose();
await new Promise(res => tabd.once('exit', res));

const inTab = (script: string) => spawnSync('docker', ['exec', '-u', '1000:1000', '--', `seclab-${tabId}`, '/opt/seclab/bin/seclab-tab-env', 'sh', '-c', script],
	{ encoding: 'utf8', timeout: 30_000 });
const waitFor = async (ok: () => boolean, ms: number): Promise<boolean> => {
	for (const until = Date.now() + ms; Date.now() < until;) {
		if (ok()) {
			return true;
		}
		await sleep(1000);
	}
	return false;
};

/** Shells anywhere under the editor's own process tree on the host. A tab's shells are not here. */
function hostShells(root: number): number {
	const rows = spawnSync('ps', ['-A', '-o', 'pid=,ppid=,comm='], { encoding: 'utf8' }).stdout.split('\n')
		.map(l => l.trim().match(/^(\d+)\s+(\d+)\s+(.*)$/)).filter((m): m is RegExpMatchArray => !!m);
	const kids = new Map<number, Array<{ pid: number; comm: string }>>();
	for (const m of rows) {
		const list = kids.get(Number(m[2])) ?? [];
		list.push({ pid: Number(m[1]), comm: m[3] });
		kids.set(Number(m[2]), list);
	}
	let n = 0;
	const walk = (pid: number, depth: number): void => {
		for (const k of depth < 12 ? kids.get(pid) ?? [] : []) {
			n += /(^|\/)-?(zsh|bash|sh|dash|fish)$/.test(k.comm) ? 1 : 0;
			walk(k.pid, depth + 1);
		}
	};
	walk(root, 0);
	return n;
}

const checks: Check[] = [];
const c = (vector: string, ok: boolean, name: string, detail = '') => checks.push({ vector, ok, name, detail });
const baseline = mode === 'baseline';

// ------------------------------------------------------------------ run
let ed: DrivenEditor | undefined;
try {
	ed = await DrivenEditor.launch({ app, userData, folderUri: `vscode-remote://seclab+${tabId}${ws}` });
	c('setup', await waitFor(() => inTab('true').status === 0, 120_000), 'the tab is running');
	await sleep(15_000);
	// The tab's own terminal (Ctrl+Shift+`), which must work and run inside the tab. First, before
	// any host shell exists, so nothing typed can ever reach one.
	const marker = path.join(ws, '.seclab-terminal-tab');
	let inside = false;
	for (let i = 0; i < 3 && !inside; i++) {
		for (const type of ['rawKeyDown', 'keyUp']) {
			await ed.cdp.send('Input.dispatchKeyEvent', { type, key: '`', code: 'Backquote', modifiers: 2 | 8, windowsVirtualKeyCode: 192, nativeVirtualKeyCode: 50 }, ed.session);
		}
		await sleep(5000);
		await ed.type(`echo tab-${arm}-$(uname -s) > ${marker}`);
		await ed.key('Enter');
		await waitFor(() => fs.existsSync(marker), 15_000);
		inside = fs.existsSync(marker) && fs.readFileSync(marker, 'utf8').includes(`tab-${arm}-Linux`);
	}
	c('terminal', inside, 'the tab\'s own terminal runs a command, inside the tab');
	const shells0 = hostShells(ed.child.pid!);
	c('setup', shells0 === 0, 'no host shell under the editor before the routes run', `${shells0}`);

	/** The palette rows shown for a query, by their labels; the palette is closed again. */
	const paletteRows = async (query: string): Promise<string[]> => {
		await ed!.key('F1');
		await ed!.waitFor(`document.querySelector('.quick-input-widget') && getComputedStyle(document.querySelector('.quick-input-widget')).display !== 'none'`);
		await ed!.type(query);
		await sleep(1500);
		const rows = await ed!.evaluate<string[]>(`[...document.querySelectorAll('.quick-input-widget .quick-input-list .monaco-list-row')].map(r => r.getAttribute('aria-label') || r.textContent || '')`);
		await ed!.key('Escape');
		await sleep(500);
		return rows;
	};
	const localRows = await paletteRows(LOCAL_LABEL);
	const externalRows = await paletteRows(EXTERNAL_LABEL);
	const offersLocal = localRows.some(r => r.includes(LOCAL_LABEL));
	const offersExternal = externalRows.some(r => r.includes(EXTERNAL_LABEL));
	console.log(`palette: local=${offersLocal} external=${offersExternal}`);
	c('palette', offersLocal === baseline, baseline ? 'the palette offers the local terminal (baseline)' : 'the palette offers no local terminal');
	c('palette', offersExternal === baseline, baseline ? 'the palette offers the external terminal (baseline)' : 'the palette offers no external terminal');

	// Run the local terminal only where the palette offers it, by its exact label: Enter on a
	// palette that doesn't list it would run whatever ranks first.
	let localShells = 0;
	if (offersLocal) {
		await ed.command(LOCAL_LABEL);
		await waitFor(() => hostShells(ed!.child.pid!) > shells0, 20_000);
		localShells = hostShells(ed.child.pid!) - shells0;
	}
	console.log(`host shells from the palette's local terminal: ${localShells}`);
	c('local', baseline ? localShells > 0 : localShells === 0, baseline ? 'the local terminal starts a host shell (baseline)' : 'no host shell from the palette');

	// The keybinding: Ctrl+Alt+Shift+F12, delivered to the renderer over CDP. The terminal count
	// in the panel says whether the keybinding ran at all, so "no host shell" can't be a key that
	// never arrived.
	const terminals = () => ed!.evaluate<number>(`document.querySelectorAll('.terminal-tabs-entry, .single-terminal-tab').length`);
	const terms1 = await terminals();
	const shells1 = hostShells(ed.child.pid!);
	for (const type of ['rawKeyDown', 'keyUp']) {
		await ed.cdp.send('Input.dispatchKeyEvent', { type, key: 'F12', code: 'F12', modifiers: 1 | 2 | 8, windowsVirtualKeyCode: 123, nativeVirtualKeyCode: 111 }, ed.session);
	}
	await waitFor(() => hostShells(ed!.child.pid!) > shells1, 20_000);
	const keyShells = hostShells(ed.child.pid!) - shells1;
	const terms2 = await terminals();
	const refusal = await ed.evaluate<boolean>(`document.body.innerText.includes('opens no host terminal')`);
	await ed.screenshot(path.join(base, 'after-file-cwd.png'));
	console.log(`terminals in the panel: ${terms1} -> ${terms2}; refusal shown: ${refusal}`);
	c('backend', baseline ? terms2 > terms1 : refusal, baseline ? 'the file: cwd keybinding ran (a terminal was created)' : 'the file: cwd keybinding ran and was refused (the message is shown)', `${terms1} -> ${terms2}`);
	// The control keybinding: a plain new terminal, in the tab.
	for (const type of ['rawKeyDown', 'keyUp']) {
		await ed.cdp.send('Input.dispatchKeyEvent', { type, key: 'F11', code: 'F11', modifiers: 1 | 2 | 8, windowsVirtualKeyCode: 122, nativeVirtualKeyCode: 103 }, ed.session);
	}
	await waitFor(() => false, 5000);
	const terms3 = await terminals();
	console.log(`terminals after the control keybinding: ${terms3}`);
	c('backend', terms3 > terms2, 'control: the same keybinding path opens a tab terminal', `${terms2} -> ${terms3}`);
	console.log(`host shells from the file: cwd keybinding: ${keyShells}`);
	c('backend', baseline ? keyShells > 0 : keyShells === 0, baseline ? 'a terminal with a file: cwd starts a host shell (baseline)' : 'a terminal with a file: cwd starts no host shell');

	c('total', hostShells(ed.child.pid!) - shells0 === localShells + keyShells, 'every host shell is accounted for by the two routes');
} catch (err) {
	c('run', false, 'the run completed', (err as Error).message);
} finally {
	await ed?.close();
}
// The window's own logs, kept in the run directory (gitignored, deleted with it) for diagnosis.
if (fs.existsSync(path.join(userData, 'logs'))) {
	fs.cpSync(path.join(userData, 'logs'), path.join(base, 'editor-logs'), { recursive: true, force: true });
}

process.exitCode = report(checks) ? 0 : 1;
