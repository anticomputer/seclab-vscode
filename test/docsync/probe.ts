// Document-sync probe, the runtime regression test for patch 0035 (EDR document-sync-provenance;
// driven since EDT-11, EDR docsync-probe-driven). macOS, sbx, local only:
//   node test/docsync/probe.ts drive --app PATH.app
// The harness opens host-side content in the tab's window through the headless driver (the trusted
// window, as a user would), and a probe extension in the tab records which documents reach it. The
// tab itself only shows its own file and attempts the two hijacks, which the RPC filter refuses.
// Canaries are generated fake `seclabcanary_ds_` values, seeded on the host only: a JSONC comment in
// the isolated profile's settings.json and keybindings.json, a host file outside the tab's mount
// and a line in the window's own log. The tab never learns a canary: the probe reports hashes of what
// it saw. The probe's report is tab-controlled data: it's read through a fixed schema, and nothing
// in it is followed.

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
const base = path.join(repo, '.work', 'docsync');
const ws = path.join(base, 'ws');
const hostFile = path.join(base, 'host', 'note.txt');
const resultsFile = path.join(repo, '.work', 'docsync-results.jsonl');
// One profile per worktree: the previous-run guard lives in this worktree's .work, so a shared
// profile could be wiped or torn down by another worktree's run (PR #12 review).
const userData = path.join(os.homedir(), '.seclab-test', `ds-${createHash('sha256').update(repo).digest('hex').slice(0, 8)}`);
const stateDir = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');
const SBX = '/opt/homebrew/bin/sbx';
const VSCE_IMAGE = 'seclab-vsce:3.9.2';
const TYPED = 'typed-in-window-by-harness';
const EDITED = 'edited-in-window-by-harness';
const [mode, ...rest] = process.argv.slice(2);
const appArg = rest.includes('--app') ? path.resolve(rest[rest.indexOf('--app') + 1]) : undefined;
// Host content, each opened in the window: none may reach the tab. `detect` is the tab's own (its
// file holds it): it must reach the tab, which proves the probe sees what it should on this build.
const HOST_KINDS = ['settingsComment', 'keybindingsComment', 'hostFile', 'windowLog'] as const;
type Canaries = Record<typeof HOST_KINDS[number] | 'detect', string>;
// The two hijacks, which the filter must refuse (its decision log).
const REFS = {
	textProvider: 'rpc:MainThreadDocumentContentProviders.$registerTextContentProvider',
	fsProvider: 'rpc:MainThreadFileSystem.$registerFileSystemProvider',
	hostOpen: 'rpc:MainThreadDocuments.$tryOpenDocument',
};
const sha = (s: string) => createHash('sha256').update(s).digest('hex');
const tabId = () => (readManifest(base).tabs ?? [])[0];
// Bounded (review SQ-6): the tab can stall anything read from its workspace.
// A failed or timed-out run yields no stdout: a FIFO could emit a report and then stall (PH-3).
const inTab = (args: string[], timeoutMs = 30_000) => {
	const r = spawnSync(SBX, ['exec', '-u', 'agent', `seclab-${tabId()}`, ...args], { encoding: 'utf8', maxBuffer: 64 << 20, timeout: timeoutMs, killSignal: 'SIGKILL' });
	return r.status === 0 && !r.error ? r : { ...r, stdout: '' };
};

if (mode !== 'drive' || !appArg) {
	console.error('usage: probe.ts drive --app PATH.app');
	process.exit(2);
}
if (fs.existsSync(path.join(base, 'run.json'))) {
	console.error('a previous docsync run is still recorded: remove it with its teardown first');
	process.exit(1);
}
checkUserDataDir(userData);
fs.rmSync(base, { recursive: true, force: true });
fs.rmSync(userData, { recursive: true, force: true });
fs.mkdirSync(path.join(ws, '.seclab'), { recursive: true });
fs.mkdirSync(path.dirname(hostFile), { recursive: true });
const canaries = Object.fromEntries([...HOST_KINDS, 'detect'].map(k => [k, `seclabcanary_ds_${randomBytes(16).toString('hex')}`])) as Canaries;
writeSnapshot(base);
// The teardown gate removes the workspace, the packaged probe and the host fixtures, and checks
// (review SQ-8).
writeManifest(base, { driver: 'sbx', userDataDir: userData, stateDirs: [stateDir], workspaces: [ws, path.join(base, 'vsix'), path.join(base, 'host')] });

// The tab's workspace: its own file holds the detect canary.
fs.writeFileSync(path.join(ws, 'README.md'), '# docsync probe workspace\n');
fs.writeFileSync(path.join(ws, 'tracked.txt'), `tab file\n${canaries.detect}\n`);
// Host-side content the user may open in the tab window.
fs.writeFileSync(hostFile, `host note\n${canaries.hostFile}\n`);
fs.mkdirSync(path.join(userData, 'User'), { recursive: true });
fs.writeFileSync(path.join(userData, 'User', 'settings.json'), `{
\t// ${canaries.settingsComment}
\t"security.workspace.trust.enabled": false,
\t"seclab.tabs.driver": "sbx",
\t"seclab.tabs.allowedRoots": [${JSON.stringify(base)}],
\t"window.restoreWindows": "none",
\t"workbench.startupEditor": "none",
\t"workbench.tips.enabled": false,
\t"chat.disableAIFeatures": true,
\t"workbench.settings.openDefaultKeybindings": false
}
`);
fs.writeFileSync(path.join(userData, 'User', 'keybindings.json'), `// ${canaries.keybindingsComment}\n[]\n`);
// Arm the probe for this run only. The harness keeps the arm and never reads it back from the
// tab's workspace (review SQ-5).
const until = Math.floor(Date.now() / 1000) + 2 * 3600;
const arm = randomBytes(16).toString('hex');
fs.writeFileSync(path.join(ws, '.seclab', 'targets'), `arm=${arm}\nrun=${base}\nuntil=${until}\nhostfile=${hostFile}\n`);

// Setup failures still end in the teardown gate (review EDT-12): nothing below may skip it.
let installed = false;
let tabName = '';
let setupError = '';
let client: TabdClient | undefined;
try {
	const vsixDir = path.join(base, 'vsix');
	fs.mkdirSync(vsixDir, { recursive: true });
	execFileSync('docker', ['run', '--rm', '--network', 'none', '--user', `${process.getuid!()}:${process.getgid!()}`,
		'-v', `${path.join(import.meta.dirname, 'probe-extension')}:/ext:ro`, '-v', `${vsixDir}:/out`,
		VSCE_IMAGE, 'sh', '-c', 'cp -r /ext /tmp/e && cd /tmp/e && vsce package --allow-missing-repository --skip-license -o /out/docsync-probe.vsix'], { stdio: 'ignore' });
	client = new TabdClient({
		command: process.execPath,
		args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', 'sbx', '--allowed-root', base],
		env: { HOME: process.env.HOME, USER: process.env.USER },
	});
	await client.initialize('docsync-probe', '0');
	// Staged before the tab exists: once it runs, the host never writes into its workspace (review SQ-7).
	fs.copyFileSync(path.join(vsixDir, 'docsync-probe.vsix'), path.join(ws, '.docsync-probe.vsix'));
	const { tab } = await client.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
	tabName = tab.metadata.name;
	writeManifest(base, { tabs: [tabName] });
	await client.request('tab.ensureRunning', { tabId: tabName });
	installed = inTab(['/opt/seclab/bin/seclab-tab-env', '/opt/seclab-reh/bin/seclab-code-server', '--install-extension', path.join(ws, '.docsync-probe.vsix')], 300_000).status === 0;
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

const out = path.join(ws, '.seclab-docsync');
const tabHas = (f: string) => !!tabId() && inTab(['test', '-e', path.join(out, f)]).status === 0;
// What the window did, judged from its own DOM (the trusted side): each must hold for the leak
// checks to mean anything.
const win: Record<string, boolean> = {};
let editOnDisk = false;
const denied = new Set<string>();
let ed: DrivenEditor | undefined;
if (installed) {
	try {
		ed = await DrivenEditor.launch({ app: appArg, userData, folderUri: `vscode-remote://seclab+${tabName}${ws}` });
		const e = ed;
		const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
		const until = async (f: () => Promise<boolean>, tries = 30) => {
			for (let i = 0; i < tries; i++) {
				if (await f().catch(() => false)) {
					return true;
				}
				await sleep(500);
			}
			return false;
		};
		const labels = () => e.evaluate<string[]>(`[...document.querySelectorAll('.tabs-container .tab .label-name')].map(x => x.textContent ?? '')`).catch(() => [] as string[]);
		const shows = (text: string) => e.evaluate<boolean>(`document.body.innerText.includes(${JSON.stringify(text)})`);
		// Settings and keybindings open in a modal editor in 1.145: its own close action, in the renderer.
		const closeModal = async () => {
			await e.evaluate(`(() => { const m = [...document.querySelectorAll('[class*="modal"]')].find(x => x.querySelector('.codicon-close')); m?.querySelector('.codicon-close')?.closest('a,.action-label,.monaco-button')?.dispatchEvent(new MouseEvent('click', { bubbles: true })); m?.querySelector('.codicon-close')?.dispatchEvent(new MouseEvent('click', { bubbles: true })); })()`).catch(() => undefined);
			await sleep(800);
		};
		const keyWithCmd = async (key: string, code: string, vk: number) => {
			for (const type of ['rawKeyDown', 'keyUp']) {
				await e.cdp.send('Input.dispatchKeyEvent', { type, key, code, windowsVirtualKeyCode: vk, nativeVirtualKeyCode: vk, modifiers: process.platform === 'darwin' ? 4 : 2 }, e.session);
			}
		};
		// A palette command by its exact label: the palette's fuzzy match ranks look-alikes first
		// ("Open Default Keyboard Shortcuts (JSON)", "Compare with Saved"), so the harness moves to the
		// row whose label is exactly this one, and fails the step when there's none.
		const command = async (label: string) => {
			await e.key('F1');
			await e.waitFor(`document.querySelector('.quick-input-widget') && getComputedStyle(document.querySelector('.quick-input-widget')).display !== 'none'`);
			await e.type(label);
			let index = -1;
			for (let i = 0; i < 20 && index < 0; i++) {
				await sleep(250);
				index = await e.evaluate<number>(`[...document.querySelectorAll('.quick-input-list .monaco-list-row')].sort((a, b) => Number(a.getAttribute('data-index')) - Number(b.getAttribute('data-index'))).findIndex(r => (r.querySelector('.label-name')?.textContent ?? '').trim() === ${JSON.stringify(label)})`).catch(() => -1);
			}
			if (index < 0) {
				await e.key('Escape');
				throw new Error(`no palette entry labelled ${label}`);
			}
			for (let i = 0; i < index; i++) {
				for (const type of ['rawKeyDown', 'keyUp']) {
					await e.cdp.send('Input.dispatchKeyEvent', { type, key: 'ArrowDown', code: 'ArrowDown', windowsVirtualKeyCode: 40, nativeVirtualKeyCode: 40 }, e.session);
				}
			}
			await e.key('Enter');
		};
		for (let i = 0; i < 120 && !tabHas('ready'); i++) {
			await sleep(1000);
		}

		// Control: the tab's own file, shown by the tab, edited and saved in the window.
		win.ownFile = await until(async () => (await labels()).includes('tracked.txt'));
		await command('View: Focus Active Editor Group');
		await sleep(500);
		await e.type(`${EDITED}\n`);
		await sleep(500);
		await command('File: Save');
		await sleep(2000);
		editOnDisk = (inTab(['cat', path.join(ws, 'tracked.txt')]).stdout ?? '').includes(EDITED);

		// Control: an untitled document the user types in the window (Cmd+N over CDP, not the
		// palette: its fuzzy match prefers "Compare New Untitled Text Files").
		await keyWithCmd('n', 'KeyN', 78);
		await sleep(1000);
		await e.type(TYPED);
		win.untitled = await until(async () => (await labels()).some(l => /^Untitled-\d+$/.test(l) || l.startsWith(TYPED)));

		// Host content, each judged by its canary on screen.
		for (const [cmd, kind] of [['Preferences: Open User Settings (JSON)', 'settingsComment'], ['Preferences: Open Keyboard Shortcuts (JSON)', 'keybindingsComment']] as const) {
			await closeModal();
			await command(cmd);
			win[kind] = await until(() => shows(canaries[kind]));
			await sleep(2000);
		}
		await closeModal();
		// The window's own log, with a canary line seeded into it first.
		const logs = path.join(userData, 'logs');
		const rendererLogs = fs.existsSync(logs) ? fs.readdirSync(logs).flatMap(d => {
			const dir = path.join(logs, d);
			return fs.statSync(dir).isDirectory() ? fs.readdirSync(dir).filter(w => /^window\d+$/.test(w)).map(w => path.join(dir, w, 'renderer.log')) : [];
		}).filter(f => fs.existsSync(f)).sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs) : [];
		if (rendererLogs.length) {
			fs.appendFileSync(rendererLogs[0], `\n[docsync] ${canaries.windowLog}\n`);
		}
		await command('Developer: Show Window Log');
		win.windowLog = await until(() => e.evaluate<boolean>(`[...document.querySelectorAll('.monaco-editor[data-uri]')].some(x => /^output:.*rendererLog/.test(x.getAttribute('data-uri') ?? ''))`));
		await sleep(2000);
		// A host file dropped on the editor area, as from Finder (CDP drag events in the renderer).
		const at = await e.evaluate<{ x: number; y: number }>(`(() => { const r = document.querySelector('.part.editor')?.getBoundingClientRect(); return r ? { x: Math.round(r.x + r.width / 2), y: Math.round(r.y + r.height / 2) } : { x: 700, y: 450 }; })()`);
		for (const type of ['dragEnter', 'dragOver', 'drop']) {
			await e.cdp.send('Input.dispatchDragEvent', { type, x: at.x, y: at.y, data: { items: [], files: [hostFile], dragOperationsMask: 1 } }, e.session);
			await sleep(300);
		}
		win.hostFile = await until(() => shows(canaries.hostFile));
		await sleep(1500);
		// A derived document of the host file: its saved state beside an unsaved edit (never saved).
		await command('View: Focus Active Editor Group');
		await e.type('x');
		await sleep(500);
		await command('File: Compare Active File with Saved');
		win.compareWithSaved = await until(() => e.evaluate<boolean>(`!!document.querySelector('.monaco-diff-editor')`));
		await sleep(2000);
		// A host-seeded untitled document (the keyboard-mapping dump); then the tab tries to claim
		// untitled models by URI.
		const before = (await labels()).filter(l => /^Untitled-\d+$/.test(l)).length;
		await command('Developer: Inspect Key Mappings (JSON)');
		win.hostUntitled = await until(async () => (await labels()).filter(l => /^Untitled-\d+$/.test(l)).length > before);
		inTab(['touch', path.join(ws, '.seclab', 'claim')]);
		await sleep(6000);
		const walk = (d: string): string[] => fs.existsSync(d) ? fs.readdirSync(d, { withFileTypes: true }).flatMap(x => x.isDirectory() ? walk(path.join(d, x.name)) : x.name === 'seclabRpcFilter.log' ? [path.join(d, x.name)] : []) : [];
		for (const f of walk(path.join(userData, 'logs'))) {
			for (const m of fs.readFileSync(f, 'utf8').matchAll(/"ref":"((?:rpc|cmd):[A-Za-z0-9_.$-]{1,120})","verdict":"deny"/g)) {
				denied.add(m[1]);
			}
		}
		await e.screenshot(path.join(base, 'drive.png')).catch(() => 0);
	} catch (err) {
		console.error(`drive: ${String(err).slice(0, 300)}`);
	}
}
// Written through the tab, never from the host (review SQ-4).
if (tabId()) {
	inTab(['touch', path.join(ws, '.seclab', 'stop')]);
}
const readReport = () => tabId() ? inTab(['cat', path.join(out, 'report.json')]).stdout ?? '' : '';
let raw = readReport();
for (let i = 0; i < 20 && tabId() && !/"done":true/.test(raw); i++) {
	spawnSync('sleep', ['1']);
	raw = readReport();
}
// Tab-side text outputs: the REH and extension-host logs and the workspace tree, read through the
// tab with a bounded call that keeps whatever it read; a control requires both reads to complete
// (PH-11, PH-13).
const logRun = tabId() ? spawnSync(SBX, ['exec', '-u', 'agent', `seclab-${tabId()}`, 'sh', '-c', 'cat /run/user/$(id -u)/seclab/reh.log; a=$?; find "$HOME" -maxdepth 7 -name "*.log" -size -8M -exec cat {} + 2>/dev/null; b=$?; find "$1" -type f -size -2M -exec cat {} +; c=$?; [ "$a" -eq 0 ] && [ "$b" -eq 0 ] && [ "$c" -eq 0 ]', 'sh', ws], { encoding: 'utf8', maxBuffer: 64 << 20, timeout: 60_000, killSignal: 'SIGKILL' }) : undefined;
const tabText = logRun?.stdout ?? '';
const logsCollected = !!logRun && logRun.status === 0 && !logRun.error && tabText.length > 0;
await ed?.close().catch(() => undefined);
const steals = fs.existsSync(focusStealLog(userData)) ? fs.readFileSync(focusStealLog(userData), 'utf8').trim() : '';

let rep: any;
try {
	rep = JSON.parse(raw);
} catch {
	rep = undefined;
}
const isCount = (v: unknown) => Number.isInteger(v) && (v as number) >= 0;
// Sorted by name only: the default sort would stringify each tab-made counter object (PH-12).
const schemeLines = (schemes: Record<string, Record<string, number>>) => Object.entries(schemes).sort(([a], [b]) => a.localeCompare(b)).map(([s, c]) => `  ${s.padEnd(28)} ${c.open}/${c.change}/${c.close}/${c.snapshot}`);
const schemeOk = (s: unknown) => typeof s === 'string' && /^[a-z][a-z0-9+.-]{0,63}$/i.test(s);
const settledOk = (v: unknown) => v === 'returned' || v === 'threw' || v === 'timeout';
// The report is the tab's: its check must reject anything malformed without throwing, or the run
// would end before its teardown gate (review EDT-18). Every value meets a type check first.
const validReport = (r: any) => !!r && r.schema === 'seclab-docsync-report/2' && typeof r.done === 'boolean'
	&& !!r.schemes && typeof r.schemes === 'object' && Object.entries(r.schemes).every(([k, c]: [string, any]) => schemeOk(k) && ['open', 'change', 'close', 'snapshot'].every(f => isCount(c?.[f])))
	&& Array.isArray(r.hits) && r.hits.length <= 1000 && r.hits.every((h: any) => schemeOk(h?.scheme) && typeof h?.sha256 === 'string' && /^[0-9a-f]{64}$/.test(h.sha256))
	&& typeof r.untitledForeign === 'boolean'
	&& !!r.hijack && typeof r.hijack === 'object' && ['textProviders', 'fsProviders'].every(f => typeof r.hijack[f] === 'string' && /^[rt]{0,8}$/.test(r.hijack[f]))
	&& ['precreatePerf', 'openHostFile'].every(f => settledOk(r.hijack[f])) && isCount(r.hijack.untitledClaims)
	&& !!r.controls && typeof r.controls === 'object' && ['ownShown', 'editSeen', 'untitledTyped'].every(f => typeof r.controls[f] === 'boolean');
const rejects = (r: unknown) => {
	try {
		return !validReport(r);
	} catch {
		return false;
	}
};
// Each guard on its own: a malformed scheme with a valid hash, a valid scheme with a malformed hash,
// and an otherwise valid report with one malformed field the summary would print.
const goodBase = {
	schema: 'seclab-docsync-report/2', done: true, schemes: {}, hits: [], untitledForeign: false,
	hijack: { textProviders: 'rrrr', fsProviders: 'rr', precreatePerf: 'threw', openHostFile: 'threw', untitledClaims: 0 },
	controls: { ownShown: true, editSeen: true, untitledTyped: true },
};
const hostileRejected = !rejects(goodBase)
	&& rejects({ ...goodBase, hits: [{ scheme: { toString: null }, sha256: '0'.repeat(64) }] })
	&& rejects({ ...goodBase, hits: [{ scheme: 'file', sha256: { toString: null } }] })
	&& rejects({ ...goodBase, hijack: { ...goodBase.hijack, textProviders: { toString: null } } });
// A report the check accepts goes through the summary without throwing (PH-12).
const summaryHolds = (() => {
	const counter = () => ({ open: 0, change: 0, close: 0, snapshot: 0, toString: null });
	try {
		return schemeLines({ file: counter(), output: counter() } as never).length === 2;
	} catch {
		return false;
	}
})();
let valid = false;
try {
	valid = validReport(rep) && rep.arm === arm;
} catch {
	// a malformed report is invalid
}

const results: Array<{ name: string; ok: boolean; detail?: string }> = [];
const expect = (name: string, ok: boolean, detail?: string) => results.push({ name, ok, detail });
expect('setup completed (tab claimed, running, probe installed)', !setupError && installed);
expect('report present, from this run (arming nonce), and matches the schema', valid);
expect('the report schema check rejects a malformed tab value without throwing', hostileRejected);
expect('the report schema check passes nothing the summary cannot print (PH-12)', summaryHolds);
expect('control: the tab-side logs were collected (no timeout or failure)', logsCollected);
console.log(`window: ${JSON.stringify(win)}; filter refused: ${JSON.stringify(Object.values(REFS).filter(r => denied.has(r)))}`);
for (const [k, label] of [
	['ownFile', 'showed the tab\'s own file'], ['untitled', 'opened the untitled document typed in it'],
	['settingsComment', 'showed the host settings.json with its canary'], ['keybindingsComment', 'showed the host keybindings.json with its canary'],
	['windowLog', 'opened its own log in an output editor'], ['hostFile', 'showed the dropped host file with its canary'],
	['compareWithSaved', 'opened the host file compared with its saved state'], ['hostUntitled', 'opened the host-seeded untitled document'],
] as const) {
	expect(`control: the window ${label}`, win[k] === true);
}
expect('control: the edit typed in the window into the tab\'s file was saved to the tab\'s disk', editOnDisk);
const byHash = new Map<string, string>([...HOST_KINDS, 'detect'].map(k => [sha(canaries[k as keyof Canaries]), k]));
const hitKinds = valid ? (rep.hits as Array<{ scheme: string; sha256: string }>).map(h => ({ scheme: h.scheme, kind: byHash.get(h.sha256) ?? 'unknown' })) : [];
if (valid) {
	console.log('documents the tab saw, by scheme (open/change/close/snapshot):');
	for (const line of schemeLines(rep.schemes)) {
		console.log(line);
	}
	console.log(`canary hits: ${hitKinds.map(h => `${h.kind} via ${h.scheme}`).join(', ') || 'none'}`);
	console.log(`tab: controls ${JSON.stringify(rep.controls)}; hijack attempts ${JSON.stringify(rep.hijack)}; untitledForeign=${rep.untitledForeign}`);
	expect('the probe finished', rep.done === true);
	expect('control: detection works on this build (the tab saw the canary in its own file)', hitKinds.some(h => h.kind === 'detect'));
	expect('control: the tab showed its own file', rep.controls.ownShown === true);
	expect('control: the tab saw the edit typed into its own file in the window', rep.controls.editSeen === true);
	expect('control: the tab saw the untitled document typed in its window', rep.controls.untitledTyped === true);
	for (const k of HOST_KINDS) {
		const via = hitKinds.filter(h => h.kind === k).map(h => h.scheme);
		expect(`DOCSYNC no ${k} canary in any tab document`, via.length === 0, via.join(','));
	}
	// The headline: none of the host content the window opened reached a tab document (EDT-11).
	expect('DOCSYNC no host canary in any tab document (settings, keybindings, window log, host file and its diff)', hitKinds.every(h => h.kind === 'detect'));
	expect('no host-seeded untitled text reached the tab (claim by URI refused)', rep.untitledForeign === false);
	expect('a host-seeded untitled document existed and the tab tried to claim it', win.hostUntitled === true && rep.hijack.untitledClaims >= 1);
	// Every step must have run: a step that failed would pass the leak checks vacuously (review
	// round 1, P1).
	expect('every probe step ran and succeeded', rep.done === true && Object.values(win).length === 8 && Object.values(win).every(Boolean)
		&& editOnDisk && ['ownShown', 'editSeen', 'untitledTyped'].every(f => rep.controls[f] === true));
}
expect('hijack 1: the filter refused the tab providers for host schemes (decision log)', denied.has(REFS.textProvider) && denied.has(REFS.fsProvider));
expect('hijack 2: the filter refused the tab opens of host URIs (decision log)', denied.has(REFS.hostOpen));
for (const k of HOST_KINDS) {
	expect(`DOCSYNC no ${k} canary in tab-side output (logs, workspace, report)`, !tabText.includes(canaries[k]) && !raw.includes(canaries[k]));
}
expect('no focus steal', !steals);
const gate = verifyTeardown(base);
if (gate.every(c => c.ok)) {
	fs.renameSync(path.join(base, 'run.json'), path.join(base, `run-checked-${Date.now()}.json`));
}
for (const c of [...results, ...gate]) {
	console.log(`${c.ok ? 'OK  ' : 'FAIL'}  ${c.name}${c.ok || !c.detail ? '' : `  ${c.detail}`}`);
}
const pass = results.every(r => r.ok) && gate.every(c => c.ok);
fs.appendFileSync(resultsFile, JSON.stringify({ at: new Date().toISOString(), app: appArg, pass, window: win, editOnDisk, refused: Object.values(REFS).filter(r => denied.has(r)), hits: hitKinds.map(h => `${h.kind}@${h.scheme}`), failed: results.filter(r => !r.ok).map(r => r.name) }) + '\n');
process.exit(pass ? 0 : 1);
