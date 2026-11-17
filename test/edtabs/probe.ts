// Editor-tabs probe: what does the window's editor-tab model tell a tab's extension host about
// host-side editors open in its window? (sibling DOCSYNC-R3 of patch 0035). macOS, sbx, local only.
//   node test/edtabs/probe.ts drive --app PATH [--measure]   # prepare, drive the window, check, teardown
// The isolated profile's directory is named with a generated fake `seclabcanary_` token, so every
// host path under it (user settings.json, keybindings.json) carries the canary. The window opens host-side editors as
// a user would (command palette, headless driver). The probe reports input kinds, URI schemes and
// hashes of label and URI tokens; it is tab-controlled data, read through a fixed schema.

import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import { DrivenEditor } from '../driver/editor.ts';
import { checkUserDataDir, focusStealLog } from '../harness.ts';
import { readManifest, verifyTeardown, writeManifest, writeSnapshot } from '../containment/teardown.ts';

const repo = path.resolve(import.meta.dirname, '../..');
const base = path.join(repo, '.work', 'edtabs');
const ws = path.join(base, 'ws');
const runFile = path.join(base, 'canaries.json');
const resultsFile = path.join(repo, '.work', 'edtabs-results.jsonl');
const SBX = '/opt/homebrew/bin/sbx';
const VSCE_IMAGE = 'seclab-vsce:3.9.2';
const [mode, ...rest] = process.argv.slice(2);
const appArg = rest.includes('--app') ? path.resolve(rest[rest.indexOf('--app') + 1]) : undefined;
const measure = rest.includes('--measure');
const sha = (s: string) => createHash('sha256').update(s).digest('hex');
const tabId = () => (readManifest(base).tabs ?? [])[0];
const inTab = (args: string[]) => spawnSync(SBX, ['exec', '-u', 'agent', `seclab-${tabId()}`, ...args], { encoding: 'utf8', maxBuffer: 16 << 20 });
// What the window opens, by palette label, and the editor tab label each should produce.
const HOST_EDITORS: Array<[string, string]> = [
	['Preferences: Open User Settings (JSON)', 'settings.json'],
	['Preferences: Open Keyboard Shortcuts (JSON)', 'keybindings.json'],
];

if (mode !== 'drive' || !appArg) {
	console.error('usage: probe.ts drive --app PATH [--measure]');
	process.exit(2);
}
if (fs.existsSync(path.join(base, 'run.json'))) {
	console.error('a previous edtabs run is still recorded: remove it with its teardown first');
	process.exit(1);
}
const canary = `seclabcanary_${randomBytes(8).toString('hex')}`;
const userData = path.join(os.homedir(), '.seclab-test', canary);
const stateDir = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');
checkUserDataDir(userData);
fs.rmSync(base, { recursive: true, force: true });
fs.mkdirSync(path.join(ws, '.seclab'), { recursive: true });
fs.writeFileSync(runFile, JSON.stringify({ canary }));
writeSnapshot(base);
writeManifest(base, { driver: 'sbx', userDataDir: userData, stateDirs: [stateDir] });
fs.writeFileSync(path.join(ws, 'README.md'), '# edtabs probe workspace\n');
// The tab's own files for the scale phases (EDT-14): SCALE[0], then SCALE[1], then SCALE[2] more.
const SCALE = [50, 400, 50];
fs.mkdirSync(path.join(ws, 'scale'));
for (let i = 0; i < SCALE[0] + SCALE[1] + SCALE[2]; i++) {
	fs.writeFileSync(path.join(ws, 'scale', `f${i}.txt`), `scale ${i}\n`);
}
fs.mkdirSync(path.join(userData, 'User'), { recursive: true });
fs.writeFileSync(path.join(userData, 'User', 'settings.json'), JSON.stringify({
	'security.workspace.trust.enabled': false, 'seclab.tabs.driver': 'sbx', 'seclab.tabs.allowedRoots': [base], 'window.restoreWindows': 'none',
	'workbench.welcomePage.experimentalOnboarding': false, 'workbench.startupEditor': 'none', 'workbench.tips.enabled': false, 'chat.disableAIFeatures': true,
}, null, '\t'));
fs.writeFileSync(path.join(userData, 'User', 'keybindings.json'), '[]\n');
// A host media file outside the tab's mount, in a folder named with the canary (a few bytes: the
// editor is chosen by the file extension).
const mediaCanary = `seclabcanary_${randomBytes(8).toString('hex')}`;
const mediaFile = path.join(base, 'host', mediaCanary, 'clip.mp4');
fs.mkdirSync(path.dirname(mediaFile), { recursive: true });
fs.writeFileSync(mediaFile, Buffer.alloc(64));
const until = Math.floor(Date.now() / 1000) + 2 * 3600;
fs.writeFileSync(path.join(ws, '.seclab', 'targets'), `arm=${randomBytes(16).toString('hex')}\nrun=${base}\nuntil=${until}\n`);

// Setup failures still end in the teardown gate (PR #24 review): nothing below may skip it.
let installed = false;
let tabName = '';
let setupError = '';
let client: TabdClient | undefined;
try {
	const vsixDir = path.join(base, 'vsix');
	fs.mkdirSync(vsixDir, { recursive: true });
	execFileSync('docker', ['run', '--rm', '--network', 'none', '--user', `${process.getuid!()}:${process.getgid!()}`,
		'-v', `${path.join(import.meta.dirname, 'probe-extension')}:/ext:ro`, '-v', `${vsixDir}:/out`,
		VSCE_IMAGE, 'sh', '-c', 'cp -r /ext /tmp/e && cd /tmp/e && vsce package --allow-missing-repository --skip-license -o /out/edtabs-probe.vsix'], { stdio: 'ignore' });
	client = new TabdClient({
		command: process.execPath,
		args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', 'sbx', '--allowed-root', base],
		env: { HOME: process.env.HOME, USER: process.env.USER },
	});
	await client.initialize('edtabs-probe', '0');
	const { tab } = await client.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
	tabName = tab.metadata.name;
	writeManifest(base, { tabs: [tabName] });
	await client.request('tab.ensureRunning', { tabId: tabName });
	fs.copyFileSync(path.join(vsixDir, 'edtabs-probe.vsix'), path.join(ws, '.edtabs-probe.vsix'));
	installed = inTab(['/opt/seclab/bin/seclab-tab-env', '/opt/seclab-reh/bin/seclab-code-server', '--install-extension', path.join(ws, '.edtabs-probe.vsix')]).status === 0;
} catch (e) {
	setupError = String(e).slice(0, 300);
	console.error(`setup: ${setupError}`);
} finally {
	if (client) {
		const c = client;
		c.dispose();
		await Promise.race([new Promise(res => c.once('exit', res)), new Promise(res => setTimeout(res, 15_000))]);
	}
}

const reportPath = path.join(ws, '.seclab-edtabs', 'report.json');
const read = () => {
	try {
		return JSON.parse(tabId() ? inTab(['cat', reportPath]).stdout ?? '' : '');
	} catch {
		return undefined;
	}
};
let windowLabels: string[] = [];
// Per renderer function, its call count in each scale phase (precise coverage, call counts).
const phaseCounts: Array<Map<string, number>> = [];
let phasesDone = 0;
const opened: Record<string, boolean> = {};
let ed: DrivenEditor | undefined;
if (installed) {
	try {
		ed = await DrivenEditor.launch({ app: appArg, userData, folderUri: `vscode-remote://seclab+${tabName}${ws}` });
		for (let i = 0; i < 90 && !read(); i++) {
			spawnSync('sleep', ['1']);
		}
		const labels = () => ed!.evaluate<string[]>(`[...document.querySelectorAll('.tabs-container .tab .label-name')].map(e => e.textContent ?? '')`).catch(() => [] as string[]);
		// Settings and keybindings open in a modal editor in 1.145, outside the tab strip: look for
		// the editor title anywhere in the window.
		const shown = (label: string) => ed!.evaluate<boolean>(`[...document.querySelectorAll('.label-name, .title-label, .modal-editor-title')].some(e => (e.textContent ?? '').trim() === ${JSON.stringify(label)})`).catch(() => false);
		for (const [cmd, label] of HOST_EDITORS) {
			// Close a modal editor left by the previous step (its own close action, in the renderer).
			await ed.evaluate(`(() => { const m = [...document.querySelectorAll('[class*="modal"]')].find(e => e.querySelector('.codicon-close')); m?.querySelector('.codicon-close')?.closest('a,.action-label,.monaco-button')?.dispatchEvent(new MouseEvent('click', { bubbles: true })); m?.querySelector('.codicon-close')?.dispatchEvent(new MouseEvent('click', { bubbles: true })); })()`).catch(() => undefined);
			await new Promise(r => setTimeout(r, 800));
			await ed.command(cmd).catch(() => undefined);
			for (let i = 0; i < 20 && !(await shown(label)); i++) {
				await new Promise(r => setTimeout(r, 500));
			}
			opened[label] = await shown(label);
			spawnSync('sleep', ['2']);
		}
		// The user's own untitled document, typed in the window: the tab owns it (0035), so it must
		// show as a text tab, even though its editor joins the group before its model exists.
		await ed.evaluate(`(() => { const m = [...document.querySelectorAll('[class*="modal"]')].find(e => e.querySelector('.codicon-close')); m?.querySelector('.codicon-close')?.closest('a,.action-label,.monaco-button')?.dispatchEvent(new MouseEvent('click', { bubbles: true })); m?.querySelector('.codicon-close')?.dispatchEvent(new MouseEvent('click', { bubbles: true })); })()`).catch(() => undefined);
		await new Promise(r => setTimeout(r, 800));
		// New Untitled Text File by its keybinding (Cmd+N), sent to the renderer over CDP: the palette's
		// fuzzy match prefers "Compare New Untitled Text Files".
		for (const type of ['rawKeyDown', 'keyUp']) {
			await ed.cdp.send('Input.dispatchKeyEvent', { type, key: 'n', code: 'KeyN', windowsVirtualKeyCode: 78, nativeVirtualKeyCode: 78, modifiers: process.platform === 'darwin' ? 4 : 2 }, ed.session);
		}
		await new Promise(r => setTimeout(r, 1000));
		// Not typed into: a label change would carry the input along and hide a missing ownership update.
		opened['Untitled-1'] = (await labels()).some(l => /^Untitled-\d+$/.test(l) || l === 'edtabs untitled control');
		spawnSync('sleep', ['3']);
		// A host media file dropped on the editor area, as from Finder (CDP drag events in the
		// renderer, no OS input). Its folder carries the canary; the built-in media preview is a
		// webview editor that shows a file (review EDT-1).
		await ed.evaluate(`(() => { const m = [...document.querySelectorAll('[class*="modal"]')].find(e => e.querySelector('.codicon-close')); m?.querySelector('.codicon-close')?.dispatchEvent(new MouseEvent('click', { bubbles: true })); })()`).catch(() => undefined);
		await new Promise(r => setTimeout(r, 800));
		const at = await ed.evaluate<{ x: number; y: number }>(`(() => { const r = document.querySelector('.part.editor')?.getBoundingClientRect(); return r ? { x: Math.round(r.x + r.width / 2), y: Math.round(r.y + r.height / 2) } : { x: 700, y: 450 }; })()`);
		const data = { items: [], files: [mediaFile], dragOperationsMask: 1 };
		for (const type of ['dragEnter', 'dragOver', 'drop']) {
			await ed.cdp.send('Input.dispatchDragEvent', { type, x: at.x, y: at.y, data }, ed.session);
			await new Promise(r => setTimeout(r, 300));
		}
		for (let i = 0; i < 20 && !(await labels()).includes(path.basename(mediaFile)); i++) {
			await new Promise(r => setTimeout(r, 500));
		}
		opened[path.basename(mediaFile)] = (await labels()).includes(path.basename(mediaFile));
		spawnSync('sleep', ['3']);
		windowLabels = (await labels()).filter(l => /^[\w. -]{1,60}$/.test(l));
		await ed.screenshot(path.join(base, 'drive.png')).catch(() => 0);
		spawnSync('sleep', ['4']);
		// Scale phases (review EDT-14): the tab opens SCALE[0], SCALE[1], then SCALE[2] more of its own
		// files in the background. The first and last phases add as many models; work per add that
		// rescans every model is about ten times more in the last, with 450 more models open.
		type Coverage = { result: Array<{ scriptId: string; functions: Array<{ functionName: string; ranges: Array<{ startOffset: number; count: number }> }> }> };
		await ed.cdp.send('Profiler.enable', {}, ed.session);
		await ed.cdp.send('Profiler.startPreciseCoverage', { callCount: true, detailed: false }, ed.session);
		await ed.cdp.send('Profiler.takePreciseCoverage', {}, ed.session);
		for (let k = 1; k <= 3; k++) {
			fs.writeFileSync(path.join(ws, '.seclab', `scale-${k}`), `${SCALE.slice(0, k - 1).reduce((a, b) => a + b, 0)} ${SCALE[k - 1]}`);
			const done = path.join(ws, '.seclab-edtabs', `scale-${k}.done`);
			for (let i = 0; i < 300 && inTab(['test', '-e', done]).status !== 0; i++) {
				spawnSync('sleep', ['1']);
			}
			const cov = await ed.cdp.send('Profiler.takePreciseCoverage', {}, ed.session) as Coverage;
			const m = new Map<string, number>();
			for (const sc of cov.result) {
				for (const f of sc.functions) {
					m.set(`${sc.scriptId}:${f.ranges[0].startOffset}:${f.functionName}`, f.ranges[0].count);
				}
			}
			phaseCounts.push(m);
			phasesDone += inTab(['test', '-e', done]).status === 0 ? 1 : 0;
		}
		await ed.cdp.send('Profiler.stopPreciseCoverage', {}, ed.session).catch(() => undefined);
	} catch (e) {
		console.error(`drive: ${String(e).slice(0, 300)}`);
	}
}
fs.writeFileSync(path.join(ws, '.seclab', 'stop'), '');
let rep: any = read();
for (let i = 0; i < 30 && tabId() && rep?.done !== true; i++) {
	spawnSync('sleep', ['1']);
	rep = read();
}
await ed?.close().catch(() => undefined);

const armed = (fs.readFileSync(path.join(ws, '.seclab', 'targets'), 'utf8').match(/^arm=([0-9a-f]{32})$/m) ?? [])[1];
const counts = (o: unknown, key: RegExp) => !!o && typeof o === 'object' && Object.entries(o as object).every(([k, v]) => key.test(k) && Number.isInteger(v));
const valid = !!rep && rep.schema === 'seclab-edtabs-report/1' && rep.arm === armed && typeof rep.done === 'boolean' && Number.isInteger(rep.tabs)
	&& counts(rep.kinds, /^[A-Za-z]{1,40}$/) && counts(rep.schemes, /^[a-z0-9.+-]{1,40}$/)
	&& typeof rep.untitledText === 'boolean' && typeof rep.untitledEvent === 'boolean' && Array.isArray(rep.tokens) && rep.tokens.length <= 5000
	&& rep.tokens.every((x: any) => !!x && (x.field === 'label' || x.field === 'uri') && /^[0-9a-f]{64}$/.test(x.sha256));
// Not the login name: the tab's own folder is a host path under the user's home (sbx mounts it at
// the same path), which the tab is given on purpose; the canary names only the host profile.
const markers: Record<string, string> = { canary: sha(canary), media: sha(mediaCanary) };
const leaks = valid ? Object.entries(markers).flatMap(([name, h]) => (rep.tokens as Array<{ field: string; sha256: string }>).filter(x => x.sha256 === h).map(x => `${name}@${x.field}`)) : [];
// Per-add work independent of the documents already open gives the same counts in the first and
// last phase; a rescan per add about 9x more. Only functions busy enough to matter are judged.
const growth = phaseCounts.length === 3 ? [...phaseCounts[2]].filter(([, c]) => c >= 5_000).map(([k, c]) => ({ fn: k.slice(k.lastIndexOf(':') + 1).slice(0, 40), c1: phaseCounts[0].get(k) ?? 0, c3: c, ratio: c / Math.max(phaseCounts[0].get(k) ?? 0, 1) })).sort((a, b) => b.ratio - a.ratio) : [];
const steals = fs.existsSync(focusStealLog(userData)) ? fs.readFileSync(focusStealLog(userData), 'utf8').trim() : '';
const results: Array<{ name: string; ok: boolean }> = [];
const expect = (name: string, ok: boolean) => results.push({ name, ok });
console.log(`window editors: ${JSON.stringify(windowLabels)}; opened by the window: ${JSON.stringify(opened)}`);
if (valid) {
	console.log(`tab saw: up to ${rep.tabs} tabs; kinds ${JSON.stringify(rep.kinds)}; schemes ${JSON.stringify(rep.schemes)}`);
	console.log(`host markers in the tab's tab model: ${[...new Set(leaks)].join(', ') || 'none'}`);
}
expect('setup completed (tab claimed, running, probe installed)', !setupError);
expect('probe installed in the tab', installed);
expect('report present, from this run, and matches the schema', valid);
expect('control: the window opened the host editors (settings.json, keybindings.json, an untitled file, a dropped media file)', Object.values(opened).length === HOST_EDITORS.length + 2 && Object.values(opened).every(Boolean));
if (valid && !measure) {
	expect('the probe finished', rep.done === true);
	expect('control: the tab sees its own editor (its workspace file)', (rep.schemes['file+own'] ?? 0) > 0);
	// Without this a run where the host editors never reached the tab's model would pass (review EDT-4).
	expect('control: the host editors reached the tab\'s editor-tab model (anonymous or not)', (rep.kinds.unknown ?? 0) > 0 || (rep.schemes['vscode-userdata'] ?? 0) > 0);
	expect('DOCSYNC-R3 no host path reaches the tab through the editor-tab model (profile canary)', leaks.length === 0);
	expect('EDT-1 a host media file dropped in the window reaches the tab without its path', !leaks.some(l => l.startsWith('media@')));
	expect('control: an untitled document the user created in the window shows to the tab as its own text tab (EDT-10)', rep.untitledText === true);
	expect('control: the tab learned of its untitled text tab through onDidChangeTabs (EDT-13)', rep.untitledEvent === true);
	console.log(`scale: phases done ${phasesDone}/3; fastest-growing busy renderer functions ${JSON.stringify(growth.slice(0, 5))}`);
	expect('control: all three scale phases ran (the tab opened its own files in the background)', phasesDone === 3);
	expect('EDT-14 no renderer function\'s call count grows quadratically with the tab\'s background document opens', phasesDone === 3 && growth.every(g => g.ratio < 3));
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
fs.appendFileSync(resultsFile, JSON.stringify({ at: new Date().toISOString(), app: appArg, measure, pass, leaks: [...new Set(leaks)], kinds: valid ? rep.kinds : null, schemes: valid ? rep.schemes : null, opened }) + '\n');
process.exit(pass ? 0 : 1);
