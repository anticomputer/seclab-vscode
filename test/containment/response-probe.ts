// The response-side control (ADR 20261116-response-side-control), proven in a real OCI tab of
// the containment test build, driven headlessly.
//
//   node test/containment/response-probe.ts pre-control|control <user-data-dir> --app <test app.app>
//
// The tab image is seclab-tab-oci:test-containment, built from the same run's REH. The run
// refuses an image without the containment variant's hooks.
//
// One window, one extension (test/containment/response-probe): a completion provider and a
// hover provider for the workspace's plain-text file. Each returns two things: a command or
// `command:` link naming `workbench.action.terminal.newLocal`, which opens a shell on the host
// when the trusted side runs it, and the same naming the extension's own command, the positive
// control. The driver then, as a user would:
//   1. hovers the file's first word and clicks the `hostlink` link, then the `ownlink` one;
//   2. types `@` and accepts the host-command completion, then `#` and accepts the own one.
// After each host-command vector it counts the shells under the editor's own process tree on
// the host, so each vector is judged on its own.
// Pre-control (the landing commit without patch 0033): both vectors open a host shell.
// Control: neither does; the decision log records `cmd:workbench.action.terminal.newLocal`
// refused for each; the hover renders and both own-command controls run in the tab.
//
// Inert beyond the escape it measures (EDR fixture safety): the extension writes markers only
// in its own workspace, no network target exists, and teardown stops the editor's whole tree
// (including any host shell the pre-control build opened) and removes the tab and profile.

import { execFileSync, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import { DrivenEditor } from '../driver/editor.ts';
import { checkUserDataDir, ensureVsceImage, lockRun, repoRoot, VSCE_IMAGE } from '../harness.ts';
import { report, rpcDecisions, type Check } from './assert.ts';
import { teardownGate, writeManifest, writeSnapshot } from './teardown.ts';

const IMAGE = 'seclab-tab-oci:test-containment';
const HOST_REF = 'cmd:workbench.action.terminal.newLocal';

const argv = process.argv.slice(2);
const [mode, userDataArg] = argv;
const appArg = argv[argv.indexOf('--app') + 1];
if ((mode !== 'pre-control' && mode !== 'control') || !userDataArg || !argv.includes('--app') || !appArg) {
	console.error('usage: response-probe.ts pre-control|control <user-data-dir> --app <test app.app>');
	process.exit(2);
}
const app = path.resolve(appArg);
if (!app.endsWith('.app') || !fs.existsSync(app)) {
	console.error(`--app must name an existing .app, got ${JSON.stringify(appArg)}`);
	process.exit(2);
}
const userData = path.resolve(userDataArg);
checkUserDataDir(userData);
execFileSync(process.execPath, [path.join(repoRoot, 'test', 'builds', 'require-hooks.ts'), '--variant', 'containment', '--hook', 'rogue-reh', '--image', IMAGE], { stdio: 'inherit' });

const base = path.join(repoRoot, '.work', 'response-probe', mode);
lockRun(path.join(base, '..', `${mode}.lock.d`));
const ws = path.join(base, 'ws');
const stateDir = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

// ------------------------------------------------------------------ prepare
fs.rmSync(base, { recursive: true, force: true });
fs.rmSync(userData, { recursive: true, force: true });
fs.mkdirSync(path.join(ws, '.seclab'), { recursive: true });
const arm = randomBytes(16).toString('hex');
fs.writeFileSync(path.join(ws, '.seclab', 'targets'), `arm=${arm}\nrun=${base}\nuntil=${Math.floor(Date.now() / 1000) + 3600}\n`);
fs.writeFileSync(path.join(ws, 'probe.txt'), 'hoverword is here\n\n\n');
writeSnapshot(base);
writeManifest(base, { driver: 'oci', userDataDir: userData, stateDirs: [stateDir], workspaces: [ws] });
let ed: DrivenEditor | undefined;
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
	'editor.hover.delay': 200,
	'editor.quickSuggestions': { other: false, comments: false, strings: false },
}, null, '\t'));

// Package the probe (vsce in a container, no network) and install it into the tab.
const extDir = path.join(import.meta.dirname, 'response-probe');
fs.copyFileSync(path.join(import.meta.dirname, 'probe-safety.js'), path.join(extDir, 'probe-safety.js'));
ensureVsceImage();
execFileSync('docker', ['run', '--rm', '--network', 'none', '--user', `${process.getuid!()}:${process.getgid!()}`, '-v', `${extDir}:/ext:ro`, '-v', `${path.join(ws, '.seclab')}:/out`,
	VSCE_IMAGE, 'sh', '-c', 'cp -r /ext /tmp/e && cd /tmp/e && vsce package --allow-missing-repository --skip-license -o /out/response-probe.vsix'], { stdio: 'inherit' });
const tabd = new TabdClient({
	command: process.execPath,
	args: [path.join(repoRoot, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', 'oci', '--image', IMAGE, '--allowed-root', base],
	env: { HOME: process.env.HOME, USER: process.env.USER },
});
await tabd.initialize('response-probe', '0');
const { tab } = await tabd.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
const tabId = tab.metadata.name;
writeManifest(base, { tabs: [tabId] });
await tabd.request('tab.ensureRunning', { tabId });
const install = spawnSync('docker', ['exec', `seclab-${tabId}`, '/opt/seclab/bin/seclab-tab-env', '/opt/seclab-reh/bin/seclab-code-server', '--install-extension', path.join(ws, '.seclab', 'response-probe.vsix')], { encoding: 'utf8' });
tabd.dispose();
await new Promise(res => tabd.once('exit', res));

const checks: Check[] = [];
const c = (vector: string, ok: boolean, name: string, detail = '') => checks.push({ vector, ok, name, detail });
c('setup', install.status === 0, 'the probe extension installed in the tab', install.status === 0 ? '' : install.stderr.trim().slice(0, 200));

const waitFor = async (ok: () => boolean | Promise<boolean>, ms: number): Promise<boolean> => {
	for (const until = Date.now() + ms; Date.now() < until;) {
		if (await ok()) {
			return true;
		}
		await sleep(500);
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

/** Total recorded refusals of the host-terminal command, repeats included. */
const refusals = (): number => rpcDecisions(userData).map(d => d.detail ?? {})
	.filter(d => d.ref === HOST_REF && d.verdict === 'deny').reduce((n, d) => n + (typeof d.count === 'number' ? d.count : 1), 0);

const exists = (f: string) => fs.existsSync(path.join(ws, '.seclab-response', f));

// ------------------------------------------------------------------ run
const results: Record<string, boolean | number> = {};
try {
	ed = await DrivenEditor.launch({ app, userData, folderUri: `vscode-remote://seclab+${tabId}${ws}` });
	const e = ed;
	c('setup', await waitFor(() => exists('ready'), 180_000), 'the probe registered its providers and opened its file');
	await e.waitFor(`[...document.querySelectorAll('.view-line')].some(l => l.textContent.includes('hoverword'))`, 60_000);

	const mouse = async (type: string, x: number, y: number) =>
		e.cdp.send('Input.dispatchMouseEvent', { type, x, y, button: type === 'mouseMoved' ? 'none' : 'left', clickCount: type === 'mouseMoved' ? 0 : 1 }, e.session);
	const click = async (x: number, y: number) => {
		await mouse('mouseMoved', x, y);
		await mouse('mousePressed', x, y);
		await mouse('mouseReleased', x, y);
	};
	const rectOf = (js: string) => e.evaluate<{ x: number; y: number } | null>(`(() => { const el = ${js}; if (!el) return null; const r = el.getBoundingClientRect(); return { x: r.left + Math.min(r.width / 2, 20), y: r.top + r.height / 2 }; })()`);
	const word = `[...document.querySelectorAll('.view-line span span')].find(s => s.textContent.includes('hoverword'))`;
	const link = (text: string) => `[...document.querySelectorAll('.monaco-hover a')].find(a => a.textContent.trim() === '${text}')`;
	const emptyLine = `[...document.querySelectorAll('.view-line')].sort((a, b) => a.getBoundingClientRect().top - b.getBoundingClientRect().top)[2]`;

	// Hover: host link, then own link.
	const hoverAndClick = async (text: string): Promise<boolean> => {
		const w = await rectOf(word);
		if (!w) {
			return false;
		}
		await click(w.x, w.y);
		await mouse('mouseMoved', w.x + 1, w.y);
		const shown = await waitFor(async () => !!(await rectOf(link(text))), 15_000);
		if (!shown) {
			return false;
		}
		const a = (await rectOf(link(text)))!;
		await click(a.x, a.y);
		return true;
	};
	const before = hostShells(e.child.pid!);
	const refusedBefore = refusals();
	results.hoverRendered = await hoverAndClick('hostlink');
	await sleep(6000);
	results.hoverHostShells = hostShells(e.child.pid!) - before;
	results.hoverRefused = await waitFor(() => refusals() > refusedBefore, 15_000);
	await e.key('Escape');
	results.hoverOwnClicked = await hoverAndClick('ownlink');
	results.hoverOwnRan = await waitFor(() => exists('own-hover'), 20_000);
	await e.key('Escape');

	// Completion: host item, then own item.
	const accept = async (trigger: string, label: string): Promise<boolean> => {
		const l = await rectOf(emptyLine);
		if (!l) {
			return false;
		}
		await click(l.x, l.y);
		await e.type(trigger);
		const shown = await waitFor(async () => !!(await e.evaluate<boolean>(`[...document.querySelectorAll('.suggest-widget .monaco-list-row')].some(r => r.textContent.includes('${label}'))`).catch(() => false)), 15_000);
		if (shown) {
			await e.key('Enter');
		}
		return shown;
	};
	const before2 = hostShells(e.child.pid!);
	const refusedBefore2 = refusals();
	results.completionShown = await accept('@', 'seclabHostCommand');
	await sleep(6000);
	results.completionHostShells = hostShells(e.child.pid!) - before2;
	// Repeats of one key collapse into a follow-up line after the 10 s window.
	results.completionRefused = await waitFor(() => refusals() > refusedBefore2, 25_000);
	results.completionOwnShown = await accept('#', 'seclabOwnCommand');
	results.completionOwnRan = await waitFor(() => exists('own-completion'), 20_000);
} catch (err) {
	c('run', false, 'the run completed', (err as Error).message);
} finally {
	await ed?.close();
}

// ------------------------------------------------------------------ judge
fs.writeFileSync(path.join(base, 'facts.json'), JSON.stringify({ mode, ...results }, null, '\t'));
console.log(JSON.stringify(results));
c('control', results.hoverRendered === true, 'positive control: the tab\'s hover rendered in the window with its links');
c('control', results.hoverOwnRan === true, 'positive control: the hover\'s own-command link ran in the tab');
c('control', results.completionShown === true && results.completionOwnShown === true, 'positive control: the tab\'s completion items were offered');
c('control', results.completionOwnRan === true, 'positive control: the own-command completion ran in the tab');
if (mode === 'pre-control') {
	c('hover', Number(results.hoverHostShells) > 0, 'pre-control: the hover link opened a shell on the host', `+${results.hoverHostShells}`);
	c('completion', Number(results.completionHostShells) > 0, 'pre-control: the accepted completion opened a shell on the host', `+${results.completionHostShells}`);
} else {
	c('hover', results.hoverHostShells === 0, 'control: the hover link opened no shell on the host', `+${results.hoverHostShells}`);
	c('hover', results.hoverRefused === true, `control: the hover link's command is refused in the decision log (${HOST_REF})`);
	c('completion', results.completionHostShells === 0, 'control: the accepted completion opened no shell on the host', `+${results.completionHostShells}`);
	c('completion', results.completionRefused === true, `control: the completion's command is refused in the decision log (${HOST_REF})`);
}
process.exit(report(checks) ? 0 : 1);
