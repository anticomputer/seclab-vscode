// Scheme-squatting probe: can a tab take over a host scheme by registering its own provider for it?
// (sibling DOCSYNC-R7 of patch 0035). macOS, sbx, local only.
//   node test/squat/probe.ts drive --app PATH   # prepare, drive the window, check, teardown
// The probe extension in the tab registers a filesystem provider for `vscode-userdata` and a
// text-content provider for `output`, each serving a generated `seclabsquat_` marker. The window
// then opens the user's settings and its own log, as a user would (command palette, headless
// driver). The RPC filter must refuse both registrations (its decision log names them), and the
// marker must never show in the window. The probe's report is tab-controlled data, read through a
// fixed schema; the decision log is the window's, and only fixed-shape refs are read from it.

import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import { DrivenEditor } from '../driver/editor.ts';
import { checkUserDataDir, focusStealLog, tabExec } from '../harness.ts';
import { readManifest, verifyTeardown, writeManifest, writeSnapshot } from '../containment/teardown.ts';

const repo = path.resolve(import.meta.dirname, '../..');
const base = path.join(repo, '.work', 'squat');
const ws = path.join(base, 'ws');
const runFile = path.join(base, 'canaries.json');
const resultsFile = path.join(repo, '.work', 'squat-results.jsonl');
const VSCE_IMAGE = 'seclab-vsce:3.9.2';
const [mode, ...rest] = process.argv.slice(2);
const appArg = rest.includes('--app') ? path.resolve(rest[rest.indexOf('--app') + 1]) : undefined;
const tabId = () => (readManifest(base).tabs ?? [])[0];
// Bounded (review SQ-6): the tab can stall anything read from its workspace.
const inTab = (args: string[], timeoutMs?: number) => tabExec(`seclab-${tabId()}`, args, { timeoutMs });
// What the window opens, by palette label, and the editor tab label each should produce.
const HOST_EDITORS: Array<[string, string]> = [
	['Preferences: Open User Settings (JSON)', 'settings.json'],
];
const REFS = ['rpc:MainThreadFileSystem.$registerFileSystemProvider', 'rpc:MainThreadDocumentContentProviders.$registerTextContentProvider'];

if (mode !== 'drive' || !appArg) {
	console.error('usage: probe.ts drive --app PATH');
	process.exit(2);
}
if (fs.existsSync(path.join(base, 'run.json'))) {
	console.error('a previous squat run is still recorded: remove it with its teardown first');
	process.exit(1);
}
const marker = `seclabsquat_${randomBytes(8).toString('hex')}`;
// One profile per worktree: the previous-run guard lives in this worktree's .work (PR #33 review).
const userData = path.join(os.homedir(), '.seclab-test', `sq-${createHash('sha256').update(repo).digest('hex').slice(0, 8)}`);
const stateDir = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');
checkUserDataDir(userData);
fs.rmSync(base, { recursive: true, force: true });
fs.mkdirSync(path.join(ws, '.seclab'), { recursive: true });
fs.writeFileSync(runFile, JSON.stringify({ marker }));
writeSnapshot(base);
writeManifest(base, { driver: 'sbx', userDataDir: userData, stateDirs: [stateDir] });
fs.writeFileSync(path.join(ws, 'README.md'), '# squat probe workspace\n');
fs.mkdirSync(path.join(userData, 'User'), { recursive: true });
fs.writeFileSync(path.join(userData, 'User', 'settings.json'), JSON.stringify({
	'security.workspace.trust.enabled': false, 'seclab.tabs.driver': 'sbx', 'seclab.tabs.allowedRoots': [base], 'window.restoreWindows': 'none',
	'workbench.welcomePage.experimentalOnboarding': false, 'workbench.startupEditor': 'none', 'workbench.tips.enabled': false, 'chat.disableAIFeatures': true,
}, null, '\t'));
fs.writeFileSync(path.join(userData, 'User', 'keybindings.json'), '[]\n');
const until = Math.floor(Date.now() / 1000) + 2 * 3600;
// The harness keeps its own arm and never reads back or writes into the tab's workspace once the
// tab runs: the tab owns it, symlinks included (PR #33 review, SQ-4/SQ-5).
const arm = randomBytes(16).toString('hex');
fs.writeFileSync(path.join(ws, '.seclab', 'targets'), `arm=${arm}\nrun=${base}\nuntil=${until}\nmarker=${marker}\n`);
const sentinel = path.join(base, 'sentinel');
const sentinelText = `seclabsentinel_${randomBytes(8).toString('hex')}\n`;
fs.writeFileSync(sentinel, sentinelText);

// Setup failures still end in the teardown gate (PR #24 review, EDT-12): nothing below may skip it.
let installed = false;
let tabName = '';
let setupError = '';
let client: TabdClient | undefined;
try {
	const vsixDir = path.join(base, 'vsix');
	fs.mkdirSync(vsixDir, { recursive: true });
	execFileSync('docker', ['run', '--rm', '--network', 'none', '--user', `${process.getuid!()}:${process.getgid!()}`,
		'-v', `${path.join(import.meta.dirname, 'probe-extension')}:/ext:ro`, '-v', `${vsixDir}:/out`,
		VSCE_IMAGE, 'sh', '-c', 'cp -r /ext /tmp/e && cd /tmp/e && vsce package --allow-missing-repository --skip-license -o /out/squat-probe.vsix'], { stdio: 'ignore' });
	client = new TabdClient({
		command: process.execPath,
		args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', 'sbx', '--allowed-root', base],
		env: { HOME: process.env.HOME, USER: process.env.USER },
	});
	await client.initialize('squat-probe', '0');
	// Staged before the tab exists: once it runs, the host never writes into its workspace (SQ-7).
	fs.copyFileSync(path.join(vsixDir, 'squat-probe.vsix'), path.join(ws, '.squat-probe.vsix'));
	const { tab } = await client!.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
	tabName = tab.metadata.name;
	writeManifest(base, { tabs: [tabName] });
	await client.request('tab.ensureRunning', { tabId: tabName });
	installed = inTab(['/opt/seclab/bin/seclab-tab-env', '/opt/seclab-reh/bin/seclab-code-server', '--install-extension', path.join(ws, '.squat-probe.vsix')], 300_000) !== undefined;
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

const reportPath = path.join(ws, '.seclab-squat', 'report.json');
const read = () => {
	try {
		return JSON.parse(tabId() ? inTab(['cat', reportPath]) ?? '' : '');
	} catch {
		return undefined;
	}
};
let windowLabels: string[] = [];
let markerInWindow = true;
let settingsShown = false;
let windowLogShown = false;
const denied = new Set<string>();
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
		// Close a modal editor left by the previous step (its own close action, in the renderer).
		const closeModal = async () => {
			await ed!.evaluate(`(() => { const m = [...document.querySelectorAll('[class*="modal"]')].find(e => e.querySelector('.codicon-close')); m?.querySelector('.codicon-close')?.closest('a,.action-label,.monaco-button')?.dispatchEvent(new MouseEvent('click', { bubbles: true })); m?.querySelector('.codicon-close')?.dispatchEvent(new MouseEvent('click', { bubbles: true })); })()`).catch(() => undefined);
			await new Promise(r => setTimeout(r, 800));
		};
		for (const [cmd, label] of HOST_EDITORS) {
			await closeModal();
			await ed.command(cmd).catch(() => undefined);
			for (let i = 0; i < 20 && !(await shown(label)); i++) {
				await new Promise(r => setTimeout(r, 500));
			}
			opened[label] = await shown(label);
			// Read while the modal is still open: the log step below closes it.
			for (let i = 0; i < 20 && !settingsShown; i++) {
				settingsShown = await ed.evaluate<boolean>(`document.body.innerText.includes('seclab.tabs.driver')`).catch(() => false);
				if (!settingsShown) {
					await new Promise(r => setTimeout(r, 500));
				}
			}
			spawnSync('sleep', ['2']);
		}
		await closeModal();
		await ed.command('Developer: Show Window Log').catch(() => undefined);
		// Positive control (PR #33 review): the window log's editor really shows its output channel.
		const logShown = () => ed!.evaluate<boolean>(`[...document.querySelectorAll('.monaco-editor[data-uri]')].some(e => /^output:.*rendererLog/.test(e.getAttribute('data-uri') ?? '') && (e.querySelector('.view-lines')?.textContent ?? '').trim().length > 0)`).catch(() => false);
		for (let i = 0; i < 20 && !(windowLogShown = await logShown()); i++) {
			await new Promise(r => setTimeout(r, 500));
		}
		spawnSync('sleep', ['3']);
		windowLabels = (await labels()).filter(l => /^[\w. -]{1,60}$/.test(l));
		markerInWindow = await ed.evaluate<boolean>(`document.body.innerText.includes(${JSON.stringify(marker)})`).catch(() => true);
		const walk = (d: string): string[] => fs.existsSync(d) ? fs.readdirSync(d, { withFileTypes: true }).flatMap(e => e.isDirectory() ? walk(path.join(d, e.name)) : e.name === 'seclabRpcFilter.log' ? [path.join(d, e.name)] : []) : [];
		for (const f of walk(path.join(userData, 'logs'))) {
			for (const m of fs.readFileSync(f, 'utf8').matchAll(/"ref":"((?:rpc|cmd):[A-Za-z0-9_.$-]{1,120})","verdict":"deny"/g)) {
				denied.add(m[1]);
			}
		}
		await ed.screenshot(path.join(base, 'drive.png')).catch(() => 0);
		spawnSync('sleep', ['4']);
	} catch (e) {
		console.error(`drive: ${String(e).slice(0, 300)}`);
	}
}
// The report is final once the window has opened everything: the extension counts as it goes.
const rep: any = read();
await ed?.close().catch(() => undefined);
const lstat = (p: string) => {
	try {
		return fs.lstatSync(p);
	} catch {
		return undefined;
	}
};
const moves = typeof rep?.moves === 'string' && /^((un)?linked\+untargeted|error|E[A-Z]{2,12})$/.test(rep.moves) ? rep.moves : 'unreported';
console.log(`tab's workspace moves: ${moves}`);
const targetsGone = !lstat(path.join(ws, '.seclab', 'targets'));
let sentinelNow = '';
try {
	sentinelNow = fs.readFileSync(sentinel, 'utf8');
} catch {
	// reported below
}
// Only the validated keys of the tab's report reach host output and evidence (PR #33 review).
const valid = !!rep && rep.schema === 'seclab-squat-report/1' && rep.arm === arm && !!rep.registered && typeof rep.registered === 'object'
	&& ['fs', 'content'].every(k => ['returned', 'threw'].includes(rep.registered[k])) && !!rep.calls && Number.isInteger(rep.calls.fs) && Number.isInteger(rep.calls.content);
const registered = valid ? { fs: rep.registered.fs as string, content: rep.registered.content as string } : null;
const calls = valid ? { fs: rep.calls.fs as number, content: rep.calls.content as number } : null;
const steals = fs.existsSync(focusStealLog(userData)) ? fs.readFileSync(focusStealLog(userData), 'utf8').trim() : '';
const results: Array<{ name: string; ok: boolean }> = [];
const expect = (name: string, ok: boolean) => results.push({ name, ok });
console.log(`window editors: ${JSON.stringify(windowLabels)}; opened by the window: ${JSON.stringify(opened)}`);
console.log(`filter refused: ${JSON.stringify(REFS.filter(r => denied.has(r)))}`);
const tabLine = `tab: registrations ${JSON.stringify(registered)}; provider calls ${JSON.stringify(calls)}`;
if (valid) {
	console.log(tabLine);
}
expect('setup completed (tab claimed, running, probe installed)', !setupError);
expect('probe installed in the tab', installed);
expect('report present, from this run, and matches the schema', valid);
expect('control: the tab attempted both registrations', registered?.fs === 'returned' && registered.content === 'returned');
expect('control: the window opened the host settings and showed their real content', Object.values(opened).every(Boolean) && settingsShown);
expect('DOCSYNC-R7 the RPC filter refused the tab\'s filesystem provider for a host scheme (decision log)', denied.has(REFS[0]));
expect('DOCSYNC-R7 the RPC filter refused the tab\'s text-content provider for a host scheme (decision log)', denied.has(REFS[1]));
expect('control: the window opened its own log in an output editor', windowLogShown);
expect('the window never used a tab provider: no provider call, no marker in the window', calls?.fs === 0 && calls.content === 0 && !markerInWindow);
expect('no focus steal', !steals);
// On sbx the share doesn't carry the tab's symlink to the host (it is gone on both sides by now),
// so the sentinel holds there regardless; a share that does carry it needs the SQ-4 fix.
expect('control (SQ-5): the tab made the stop file a symlink to the host sentinel and deleted its arming file, and the run still got here', moves === 'linked+untargeted' && targetsGone);
expect('SQ-4 no host write followed a tab symlink (the host sentinel is unchanged)', sentinelNow === sentinelText);
const evidence = (ok: boolean) => JSON.stringify({ at: new Date().toISOString(), app: appArg, pass: ok, refused: REFS.filter(r => denied.has(r)), markerInWindow, calls, registered, opened, windowLogShown });
expect('the tab\'s unvalidated report fields reach neither host output nor evidence (SQ-3)', valid && !tabLine.includes(marker) && !evidence(true).includes(marker));
const gate = verifyTeardown(base);
if (gate.every(g => g.ok)) {
	fs.renameSync(path.join(base, 'run.json'), path.join(base, `run-checked-${Date.now()}.json`));
}
for (const r of [...results, ...gate]) {
	console.log(`${r.ok ? 'OK  ' : 'FAIL'}  ${r.name}`);
}
const pass = results.every(r => r.ok) && gate.every(g => g.ok);
fs.appendFileSync(resultsFile, evidence(pass) + '\n');
process.exit(pass ? 0 : 1);
