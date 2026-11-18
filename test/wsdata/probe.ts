// Workspace-data probe: what does the window tell a tab's extension host about its workspace, and
// can a host folder join it? (sibling DOCSYNC-R6 of patch 0035). macOS, sbx, local only.
//   node test/wsdata/probe.ts drive --app PATH [--measure]   # prepare, drive the window, check, teardown
// The isolated profile's directory and a host folder outside the tab's mount are named with a
// generated fake `seclabcanary_` token. The window is launched on the tab with `--add` naming the
// host folder (1.145 ignores it at start-up; adding a folder to a folder window means entering a
// workspace, which patch 0041 refuses: see EDR workspace-data). The
// probe reports folder and configuration schemes and hashes of URI and name tokens; it is
// tab-controlled data, read through a fixed schema.

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
const base = path.join(repo, '.work', 'wsdata');
const ws = path.join(base, 'ws');
const runFile = path.join(base, 'canaries.json');
const resultsFile = path.join(repo, '.work', 'wsdata-results.jsonl');
const SBX = '/opt/homebrew/bin/sbx';
const VSCE_IMAGE = 'seclab-vsce:3.9.2';
const [mode, ...rest] = process.argv.slice(2);
const appArg = rest.includes('--app') ? path.resolve(rest[rest.indexOf('--app') + 1]) : undefined;
const measure = rest.includes('--measure');
const sha = (s: string) => createHash('sha256').update(s).digest('hex');
const tabId = () => (readManifest(base).tabs ?? [])[0];
// Bounded (as review SQ-6): the tab can stall anything read from its workspace.
// A failed or timed-out run yields no stdout: a FIFO could emit a report and then stall (PH-3).
const inTab = (args: string[], timeoutMs = 30_000) => {
	const r = spawnSync(SBX, ['exec', '-u', 'agent', `seclab-${tabId()}`, ...args], { encoding: 'utf8', maxBuffer: 16 << 20, timeout: timeoutMs, killSignal: 'SIGKILL' });
	return r.status === 0 && !r.error ? r : { ...r, stdout: '' };
};

if (mode !== 'drive' || !appArg) {
	console.error('usage: probe.ts drive --app PATH [--measure]');
	process.exit(2);
}
if (fs.existsSync(path.join(base, 'run.json'))) {
	console.error('a previous wsdata run is still recorded: remove it with its teardown first');
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
// The workspace, the packaged probe and the host-folder fixture: the teardown gate removes them
// and checks (WSD-4).
writeManifest(base, { driver: 'sbx', userDataDir: userData, stateDirs: [stateDir], workspaces: [ws, path.join(base, 'vsix'), path.join(base, 'host')] });
fs.writeFileSync(path.join(ws, 'README.md'), '# wsdata probe workspace\n');
const hostDir = path.join(base, 'host', `${canary}_folder`);
fs.mkdirSync(hostDir, { recursive: true });
fs.writeFileSync(path.join(hostDir, 'note.txt'), 'host folder\n');
fs.mkdirSync(path.join(userData, 'User'), { recursive: true });
fs.writeFileSync(path.join(userData, 'User', 'settings.json'), JSON.stringify({
	'security.workspace.trust.enabled': false, 'seclab.tabs.driver': 'sbx', 'seclab.tabs.allowedRoots': [base], 'window.restoreWindows': 'none',
	'workbench.welcomePage.experimentalOnboarding': false, 'workbench.startupEditor': 'none', 'workbench.tips.enabled': false, 'chat.disableAIFeatures': true,
	// The file picker stays inside the renderer (a quick input), never a native dialog.
	'files.simpleDialog.enable': true,
}, null, '\t'));
fs.writeFileSync(path.join(userData, 'User', 'keybindings.json'), '[]\n');
const until = Math.floor(Date.now() / 1000) + 2 * 3600;
// The harness keeps its own arm; once the tab runs it writes into the tab's workspace only through
// the tab (sbx exec), never from the host, where a tab symlink could redirect it (as review SQ-4/SQ-5).
const arm = randomBytes(16).toString('hex');
fs.writeFileSync(path.join(ws, '.seclab', 'targets'), `arm=${arm}\nrun=${base}\nuntil=${until}\n`);

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
		VSCE_IMAGE, 'sh', '-c', 'cp -r /ext /tmp/e && cd /tmp/e && vsce package --allow-missing-repository --skip-license -o /out/wsdata-probe.vsix'], { stdio: 'ignore' });
	client = new TabdClient({
		command: process.execPath,
		args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', 'sbx', '--allowed-root', base],
		env: { HOME: process.env.HOME, USER: process.env.USER },
	});
	await client.initialize('wsdata-probe', '0');
	// Staged before the tab exists: once it runs, the host never writes into its workspace (WSD-1).
	fs.copyFileSync(path.join(vsixDir, 'wsdata-probe.vsix'), path.join(ws, '.wsdata-probe.vsix'));
	const { tab } = await client!.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
	tabName = tab.metadata.name;
	writeManifest(base, { tabs: [tabName] });
	await client.request('tab.ensureRunning', { tabId: tabName });
	installed = inTab(['/opt/seclab/bin/seclab-tab-env', '/opt/seclab-reh/bin/seclab-code-server', '--install-extension', path.join(ws, '.wsdata-probe.vsix')], 300_000).status === 0;
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

const reportPath = path.join(ws, '.seclab-wsdata', 'report.json');
const read = () => {
	try {
		return JSON.parse(tabId() ? inTab(['cat', reportPath]).stdout ?? '' : '');
	} catch {
		return undefined;
	}
};
let launched = false;
let addPicker = false;
let showLocal = false;
let ed: DrivenEditor | undefined;
if (installed) {
	try {
		ed = await DrivenEditor.launch({ app: appArg, userData, folderUri: `vscode-remote://seclab+${tabName}${ws}`, args: ['--add', hostDir] });
		launched = true;
		for (let i = 0; i < 90 && !read(); i++) {
			spawnSync('sleep', ['1']);
		}
		spawnSync('sleep', ['5']);
		// Add Folder to Workspace, as a user would, in-process: the simple file picker (a quick
		// input in the renderer), switched to the local file system, given the host folder.
		await ed.command('Workspaces: Add Folder to Workspace...');
		const pickerOpen = `(() => { const q = document.querySelector('.quick-input-widget'); return !!q && getComputedStyle(q).display !== 'none'; })()`;
		await ed.waitFor(pickerOpen, 15_000);
		addPicker = true;
		// "Show Local" (the picker's title action) when the window is remote: the host folder. If
		// the picker can't reach the host, any folder (the tab's own) still means entering a
		// workspace, which is the step patch 0041 refuses.
		await ed.evaluate(`(() => { const b = [...document.querySelectorAll('.quick-input-widget [aria-label], .quick-input-widget [title]')].find(e => /show local/i.test((e.getAttribute('aria-label') ?? '') + ' ' + (e.getAttribute('title') ?? ''))); b?.dispatchEvent(new MouseEvent('click', { bubbles: true })); return !!b; })()`).then(v => { showLocal = v === true; }).catch(() => undefined);
		await new Promise(r => setTimeout(r, 1500));
		await ed.evaluate(`(() => { const i = document.querySelector('.quick-input-widget input'); if (i) { i.select(); } })()`).catch(() => undefined);
		await ed.type((showLocal ? hostDir : path.join(ws, '.seclab')) + '/');
		await new Promise(r => setTimeout(r, 1500));
		await ed.evaluate(`(() => { const b = [...document.querySelectorAll('.quick-input-widget .monaco-button')].find(e => (e.textContent ?? '').trim() === 'Add'); b?.dispatchEvent(new MouseEvent('click', { bubbles: true })); })()`).catch(() => undefined);
		await new Promise(r => setTimeout(r, 2000));
		if (await ed.evaluate<boolean>(pickerOpen).catch(() => false)) {
			await ed.key('Enter');
		}
		spawnSync('sleep', ['10']);
		await ed.screenshot(path.join(base, 'drive.png')).catch(() => 0);
	} catch (e) {
		console.error(`drive: ${String(e).slice(0, 300)}`);
	}
}
inTab(['touch', path.join(ws, '.seclab', 'stop')]);
let rep: any = read();
for (let i = 0; i < 30 && tabId() && rep?.done !== true; i++) {
	spawnSync('sleep', ['1']);
	rep = read();
}
await ed?.close().catch(() => undefined);

const mainLogs = (d: string): string[] => fs.existsSync(d) ? fs.readdirSync(d, { withFileTypes: true }).flatMap(e => e.isDirectory() ? mainLogs(path.join(d, e.name)) : e.name === 'main.log' ? [path.join(d, e.name)] : []) : [];
const refusedEnter = mainLogs(path.join(userData, 'logs')).some(f => fs.readFileSync(f, 'utf8').includes('[seclab] a window does not enter a workspace'));
const counts = (o: unknown) => !!o && typeof o === 'object' && Object.entries(o as object).every(([k, v]) => /^(folder|config):[a-z0-9.+-]{1,40}$/.test(k) && Number.isInteger(v));
// The report is the tab's: its check must reject anything malformed without throwing, or the run
// would end before its teardown gate (WSD-3). Every value meets a type check before a regex.
const validReport = (r: any) => !!r && r.schema === 'seclab-wsdata-report/1' && r.arm === arm && typeof r.done === 'boolean' && Number.isInteger(r.maxFolders) && Number.isInteger(r.activations)
	&& counts(r.schemes) && Array.isArray(r.tokens) && r.tokens.length <= 5000
	&& r.tokens.every((x: any) => !!x && ['folder', 'folderName', 'name', 'config'].includes(x.field) && typeof x.sha256 === 'string' && /^[0-9a-f]{64}$/.test(x.sha256));
const rejects = (r: unknown) => {
	try {
		return !validReport(r);
	} catch {
		return false;
	}
};
const hostileRejected = rejects({ schema: 'seclab-wsdata-report/1', arm, done: true, maxFolders: 1, activations: 1, schemes: {}, tokens: [{ field: 'folder', sha256: { toString: null } }] });
let valid = false;
try {
	valid = validReport(rep);
} catch {
	// a malformed report is invalid
}
// Not the login name: the tab's own folder is a host path under the user's home (sbx mounts it
// at the same path), which the tab is given on purpose. The host folder's name is one token to the
// extension's tokenizer (it keeps underscores), so it is a marker of its own (WSD-2).
const markers: Record<string, string> = { canary: sha(canary), hostFolder: sha(path.basename(hostDir)) };
const leaksIn = (tokens: Array<{ field: string; sha256: string }>) => Object.entries(markers).flatMap(([name, h]) => tokens.filter(x => x.sha256 === h).map(x => `${name}@${x.field}`));
const leaks = valid ? leaksIn(rep.tokens) : [];
// The extension's own split, applied to the host folder's URI: the check must catch it there.
const hostFolderTokens = `file://${hostDir}`.split(/[\/\\~\s?#&=:.-]+/).filter(t => t.length >= 4 && t.length <= 120).map(t => ({ field: 'folder', sha256: sha(t) }));
const steals = fs.existsSync(focusStealLog(userData)) ? fs.readFileSync(focusStealLog(userData), 'utf8').trim() : '';
const results: Array<{ name: string; ok: boolean }> = [];
const expect = (name: string, ok: boolean) => results.push({ name, ok });
if (valid) {
	console.log(`tab saw (${rep.activations} activation(s)): up to ${rep.maxFolders} folder(s); schemes ${JSON.stringify(rep.schemes)}`);
	console.log(`host markers in the tab's workspace data: ${[...new Set(leaks)].join(', ') || 'none'}`);
}
expect('setup completed (tab claimed, running, probe installed)', !setupError);
expect('WSD-3 the report check rejects a malformed tab value without throwing', hostileRejected);
expect('WSD-2 the leak check catches the host folder\'s URI as the tab would tokenize it', leaksIn(hostFolderTokens).length > 0);
expect('probe installed in the tab', installed);
expect('the window launched with the host folder to add', launched);
expect('report present, from this run, and matches the schema', valid);
console.log(`add folder: picker ${addPicker}, show local ${showLocal}, main refused entering a workspace ${refusedEnter}`);
expect('control: the window ran Add Folder to Workspace with the host folder (in-process picker)', addPicker);
expect('DOCSYNC-R6 the main process refused to turn the tab window into a workspace (patch 0041, main log)', refusedEnter);
if (valid && !measure) {
	expect('the probe finished', rep.done === true);
	expect('control: the tab sees its own folder', (rep.schemes['folder:file+own'] ?? 0) > 0);
	expect('the workspace never held more than the tab\'s own folder', rep.maxFolders === 1);
	expect('DOCSYNC-R6 no host path reaches the tab through the workspace data (canary folder and profile)', leaks.length === 0);
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
fs.appendFileSync(resultsFile, JSON.stringify({ at: new Date().toISOString(), app: appArg, measure, pass, leaks: [...new Set(leaks)], schemes: valid ? rep.schemes : null, maxFolders: valid ? rep.maxFolders : null }) + '\n');
process.exit(pass ? 0 : 1);
