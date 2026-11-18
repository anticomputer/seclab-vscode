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
// `command:` link naming a trusted-side command that opens one of the host user's files in the
// window (hover: `workbench.action.openGlobalKeybindingsFile`, the host user's keybindings;
// completion: `workbench.action.openDefaultKeybindingsFile`) when the trusted side runs it. (Patch 0050 removed
// `workbench.action.terminal.newLocal`, the earlier host command, from tab windows.) Each also
// returns the same naming the extension's own command, the positive control. The driver then, as a user would:
//   1. hovers the file's first word and clicks the `hostlink` link, then the `ownlink` one;
//   2. types `@` and accepts the host-command completion, then `#` and accepts the own one.
// After each host-command vector it counts the window's editor tabs showing that host file, so
// each vector is judged on its own. Inert: the files open read as editors; nothing is typed.
// Pre-control (the landing commit without patch 0033): both vectors open their host file.
// Control: neither does; the decision log records each command refused; the hover renders and
// both own-command controls run in the tab.
//
// Two data vectors from the 0033 review (RSC-1, RSC-2), judged in a third mode too, `reviewed`
// (0033 as first reviewed, which they get past):
//   - the hover carries three images (plain, nested `![x![]y](…)`, an `<img>` inside a `<span>`
//     HTML block), each at its own port on this host's loopback. The CSP admits only https
//     images, so each port is a plain TCP listener counting connections: a fetch attempt is a
//     connection (the TLS handshake then fails). Only the trusted renderer can reach them;
//   - a completion item inserted as a snippet naming the CLIPBOARD variable, accepted with `%`.
//     The app must be a containment test build whose clipboard is an in-memory store seeded with
//     this run's canary (hook `canary-clipboard`); the run refuses any other app. The extension
//     records only whether the inserted text holds a canary token.
// Pre-control and reviewed: the nested and span images are fetched and the snippet inserts the
// canary (pre-control also fetches the plain image). Control: no image port sees a connection,
// and the snippet inserts the variable as literal text.
//
// Inert beyond the escape it measures (EDR fixture safety): the extension writes markers only
// in its own workspace, no network target exists, and teardown stops the editor's whole tree
// (including any host shell the pre-control build opened) and removes the tab and profile.

import { execFileSync, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as path from 'node:path';
import { mintCanary } from '../canary/canary.ts';
import { TabdClient } from '../../tabd/src/client.ts';
import { DrivenEditor } from '../driver/editor.ts';
import { beaconPort, checkUserDataDir, ensureVsceImage, lockRun, repoRoot, VSCE_IMAGE } from '../harness.ts';
import { report, rpcDecisions, type Check } from './assert.ts';
import { exitOnSignals, reapOrRefuse, teardownGate, writeManifest, writeSnapshot } from './teardown.ts';

const IMAGE = 'seclab-tab-oci:test-containment';
const HOVER_REF = 'cmd:workbench.action.openGlobalKeybindingsFile';
const COMPLETION_REF = 'cmd:workbench.action.openDefaultKeybindingsFile';

const argv = process.argv.slice(2);
const [mode, userDataArg] = argv;
const appArg = argv[argv.indexOf('--app') + 1];
if ((mode !== 'pre-control' && mode !== 'reviewed' && mode !== 'control') || !userDataArg || !argv.includes('--app') || !appArg) {
	console.error('usage: response-probe.ts pre-control|reviewed|control <user-data-dir> --app <test app.app>');
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
// The previous run's manifest is its only record: reap it before wiping the directory.
reapOrRefuse(base, 'response-probe');
fs.rmSync(base, { recursive: true, force: true });
fs.rmSync(userData, { recursive: true, force: true });
fs.mkdirSync(path.join(ws, '.seclab'), { recursive: true });
const arm = randomBytes(16).toString('hex');
// The canary store (test/builds/variants.json hook `canary-clipboard`) must be in this app, or
// the snippet vector would read the real one: refuse the run.
const CANARY_STORE_MARK = 'SECLAB_TEST_ONLY:canary-clipboard';
const mainBundle = path.join(app, 'Contents', 'Resources', 'app', 'out', 'mainImpl.js');
if (!fs.existsSync(mainBundle) || !fs.readFileSync(mainBundle, 'utf8').includes(CANARY_STORE_MARK)) {
	console.error('the app has no in-memory canary clipboard (containment test build hook); refusing to run');
	process.exit(2);
}
const storeCanary = mintCanary('clipboard');
// One loopback listener per image form; it counts connections and never answers.
const imagePorts: number[] = [];
const imageHits: number[] = [0, 0, 0];
const listeners: net.Server[] = [];
for (let i = 0; i < 3; i++) {
	imagePorts.push(await beaconPort());
	const srv = net.createServer(sock => {
		imageHits[i]++;
		sock.destroy();
	});
	await new Promise<void>((res, rej) => srv.once('error', rej).listen(imagePorts[i], '127.0.0.1', () => res()));
	listeners.push(srv);
}
process.on('exit', () => listeners.forEach(l => l.close()));
fs.writeFileSync(path.join(ws, '.seclab', 'targets'), `arm=${arm}\nrun=${base}\nuntil=${Math.floor(Date.now() / 1000) + 3600}\nclipboard=variant\n`
	+ imagePorts.map((p, i) => `img${i + 1}=${p}\n`).join(''));
fs.writeFileSync(path.join(ws, 'probe.txt'), 'hoverword is here\n\n\n');
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

/** Editor tabs in the window whose label is this name. */
const hostFileTabs = (e: DrivenEditor, name: string) => e.evaluate<number>(`[...document.querySelectorAll('.tabs-container .tab')].filter(t => (t.getAttribute('aria-label') || '').split(',')[0].trim() === ${JSON.stringify(name)}).length`);

/** Total recorded refusals of a host command, repeats included. */
const refusals = (ref: string): number => rpcDecisions(userData).map(d => d.detail ?? {})
	.filter(d => d.ref === ref && d.verdict === 'deny').reduce((n, d) => n + (typeof d.count === 'number' ? d.count : 1), 0);

const exists = (f: string) => fs.existsSync(path.join(ws, '.seclab-response', f));

// ------------------------------------------------------------------ run
const results: Record<string, boolean | number> = {};
try {
	// Each listener answers a connection from the harness itself: the positive control that a
	// silent port means no fetch, not a listener that was never up.
	for (const p of imagePorts) {
		await new Promise<void>(res => net.connect(p, '127.0.0.1').on('connect', function (this: net.Socket) { this.destroy(); res(); }).on('error', () => res()));
	}
	await sleep(500);
	results.listenersUp = imageHits.every(h => h === 1);
	imageHits.fill(0);
	ed = await DrivenEditor.launch({ app, userData, folderUri: `vscode-remote://seclab+${tabId}${ws}`, env: { SECLAB_TEST_CLIPBOARD_CANARY: storeCanary.value } });
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
	// Everything is scoped to the probe file's own editor: on a pre-control build the host
	// commands open host files in the window, and no click or key may ever land in one.
	const probeEditor = `[...document.querySelectorAll('.monaco-editor')].find(m => m.getBoundingClientRect().width > 0 && [...m.querySelectorAll('.view-line')].some(l => l.textContent.includes('hoverword')))`;
	const word = `[...((${probeEditor})?.querySelectorAll('.view-line span span') ?? [])].find(s => s.textContent.includes('hoverword'))`;
	// Only a visible link: a hover that hid after the first click can keep its DOM, with a zero box.
	const link = (text: string) => `[...document.querySelectorAll('.monaco-hover a')].find(a => a.textContent.trim() === '${text}' && a.getBoundingClientRect().width > 0 && a.getBoundingClientRect().height > 0)`;
	const emptyLine = `[...((${probeEditor})?.querySelectorAll('.view-line') ?? [])].sort((a, b) => a.getBoundingClientRect().top - b.getBoundingClientRect().top)[2]`;
	const probeTab = `[...document.querySelectorAll('.tabs-container .tab')].find(t => (t.getAttribute('aria-label') || '').split(',')[0].trim() === 'probe.txt')`;
	// Keys and text go only to the probe file's editor, never to a host file a pre-control build
	// opened (fixture safety).
	const inEditor = () => e.evaluate<boolean>(`!!document.activeElement && document.activeElement.closest('.monaco-editor') === (${probeEditor})`);
	const focusEditor = async (): Promise<boolean> => {
		const t = await rectOf(probeTab);
		if (t) {
			await click(t.x, t.y);
			await sleep(500);
		}
		const l = await rectOf(emptyLine);
		if (l) {
			await click(l.x, l.y);
		}
		return inEditor();
	};
	const editorKey = async (key: 'Escape' | 'Enter') => {
		if (!await inEditor()) {
			throw new Error(`focus left the editor before ${key}; nothing typed`);
		}
		await e.key(key);
	};

	// Hover: host link, then own link.
	const hoverAndClick = async (text: string): Promise<boolean> => {
		if (!await focusEditor()) {
			return false;
		}
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
	const before = await hostFileTabs(e, 'keybindings.json');
	const refusedBefore = refusals(HOVER_REF);
	results.hoverRendered = await hoverAndClick('hostlink');
	await sleep(6000);
	results.hoverHostFile = (await hostFileTabs(e, 'keybindings.json')) - before;
	if (process.env.SECLAB_RESPONSE_DEBUG) {
		await e.screenshot(path.join(base, 'after-hostlink.png'));
	}
	if (process.env.SECLAB_RESPONSE_DEBUG) {
		console.log(`debug tabs: ${JSON.stringify(await e.evaluate<string[]>(`[...document.querySelectorAll('.tabs-container .tab')].map(t => t.getAttribute('aria-label'))`))}`);
	}
	results.hoverRefused = await waitFor(() => refusals(HOVER_REF) > refusedBefore, 15_000);
	if (await focusEditor()) {
		await editorKey('Escape');
	}
	results.hoverOwnClicked = await hoverAndClick('ownlink');
	if (process.env.SECLAB_RESPONSE_DEBUG) {
		const href = await e.evaluate<string>(`(${link('ownlink')})?.getAttribute('data-href') ?? (${link('ownlink')})?.getAttribute('href') ?? 'none'`).catch(() => 'gone');
		console.log(`debug ownlink href: ${href}`);
		await e.screenshot(path.join(base, 'after-ownlink.png'));
	}
	results.hoverOwnRan = await waitFor(() => exists('own-hover'), 20_000);
	if (await focusEditor()) {
		await editorKey('Escape');
	}

	// Completion: host item, then own item.
	const accept = async (trigger: string, label: string): Promise<boolean> => {
		if (!await focusEditor()) {
			return false;
		}
		await e.type(trigger);
		const shown = await waitFor(async () => !!(await e.evaluate<boolean>(`[...document.querySelectorAll('.suggest-widget .monaco-list-row')].some(r => r.textContent.includes('${label}'))`).catch(() => false)), 15_000);
		if (shown) {
			await editorKey('Enter');
		}
		return shown;
	};
	const before2 = await hostFileTabs(e, 'Default Keybindings (Default Keybindings)');
	const refusedBefore2 = refusals(COMPLETION_REF);
	results.completionShown = await accept('@', 'seclabHostCommand');
	await sleep(6000);
	results.completionHostFile = (await hostFileTabs(e, 'Default Keybindings (Default Keybindings)')) - before2;
	if (process.env.SECLAB_RESPONSE_DEBUG) {
		console.log(`debug tabs 2: ${JSON.stringify(await e.evaluate<string[]>(`[...document.querySelectorAll('.tabs-container .tab')].map(t => t.getAttribute('aria-label'))`))}`);
	}
	// Repeats of one key collapse into a follow-up line after the 10 s window.
	results.completionRefused = await waitFor(() => refusals(COMPLETION_REF) > refusedBefore2, 25_000);
	results.completionOwnShown = await accept('#', 'seclabOwnCommand');
	results.completionOwnRan = await waitFor(() => exists('own-completion'), 20_000);

	// RSC-1: the snippet item, accepted with `%` then Enter.
	results.snippetShown = await accept('%', 'seclabSnippetCommand');
	results.snippetInserted = await waitFor(() => exists('snippet'), 20_000);
	if (results.snippetInserted) {
		const f = JSON.parse(fs.readFileSync(path.join(ws, '.seclab-response', 'snippet'), 'utf8')) as { sawCanary?: unknown; literalVariable?: unknown };
		results.snippetCanary = f.sawCanary === true;
		results.snippetLiteral = f.literalVariable === true;
	}
	await sleep(2000);
	[results.imgPlain, results.imgNested, results.imgSpan] = imageHits;
} catch (err) {
	c('run', false, 'the run completed', (err as Error).message);
} finally {
	await ed?.close();
}
// The window's own logs, kept in the run directory (gitignored, deleted with it) for diagnosis.
if (fs.existsSync(path.join(userData, 'logs'))) {
	fs.cpSync(path.join(userData, 'logs'), path.join(base, 'editor-logs'), { recursive: true, force: true });
}

// ------------------------------------------------------------------ judge
fs.writeFileSync(path.join(base, 'facts.json'), JSON.stringify({ mode, ...results }, null, '\t'));
console.log(JSON.stringify(results));
c('control', results.hoverRendered === true, 'positive control: the tab\'s hover rendered in the window with its links');
c('control', results.hoverOwnRan === true, 'positive control: the hover\'s own-command link ran in the tab');
c('control', results.completionShown === true && results.completionOwnShown === true, 'positive control: the tab\'s completion items were offered');
c('control', results.completionOwnRan === true, 'positive control: the own-command completion ran in the tab');
c('control', results.listenersUp === true, 'positive control: each image port\'s listener counted the harness\'s own connection');
c('control', results.snippetShown === true && results.snippetInserted === true, 'positive control: the snippet item was offered, accepted and inserted');
if (mode === 'control') {
	c('rsc-2', results.imgPlain === 0 && results.imgNested === 0 && results.imgSpan === 0, 'control: no hover image form reached a loopback port', `${results.imgPlain}/${results.imgNested}/${results.imgSpan}`);
	c('rsc-1', results.snippetCanary === false && results.snippetLiteral === true, 'control: the snippet inserted the variable as text, not the canary store\'s content');
} else {
	c('rsc-2', Number(results.imgNested) > 0 && Number(results.imgSpan) > 0, `${mode}: the nested and span-block hover images were fetched by the trusted renderer`, `${results.imgNested}/${results.imgSpan}`);
	c('rsc-2', mode === 'reviewed' ? results.imgPlain === 0 : Number(results.imgPlain) > 0, mode === 'reviewed' ? 'reviewed: the plain image form was stripped' : 'pre-control: the plain image was fetched', `${results.imgPlain}`);
	c('rsc-1', results.snippetCanary === true, `${mode}: the snippet inserted the canary store's content into the tab's document`);
}
if (mode === 'pre-control') {
	c('hover', Number(results.hoverHostFile) > 0, 'pre-control: the hover link opened the host keybindings file', `+${results.hoverHostFile}`);
	c('completion', Number(results.completionHostFile) > 0, 'pre-control: the accepted completion opened the default keybindings file', `+${results.completionHostFile}`);
} else {
	c('hover', results.hoverHostFile === 0, 'control: the hover link opened no host file', `+${results.hoverHostFile}`);
	c('hover', results.hoverRefused === true, `control: the hover link's command is refused in the decision log (${HOVER_REF})`);
	c('completion', results.completionHostFile === 0, 'control: the accepted completion opened no host file', `+${results.completionHostFile}`);
	c('completion', results.completionRefused === true, `control: the completion's command is refused in the decision log (${COMPLETION_REF})`);
}
process.exit(report(checks) ? 0 : 1);
