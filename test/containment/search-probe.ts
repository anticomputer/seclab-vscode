// The search restoration (RPC-LOCKDOWN 7.1), proven in a real OCI tab of the containment test
// build, driven headlessly.
//
//   node test/containment/search-probe.ts before|after <user-data-dir> --app <test app.app>
//   node test/containment/search-probe.ts excludes-baseline|excludes-patched <user-data-dir> --app <test app.app>
//
// The tab image is seclab-tab-oci:test-containment, built from the same run's REH.
//
// One window, one extension (test/containment/search-probe), and three searches for this run's
// needle (a file `seclab-needle-<id>.txt` holding a token `seclabsearch<id>`):
//   1. in the tab, `workspace.findFiles` (the extension records facts: returned within 30 s, how
//      many, every URI on the workspace folder's own scheme and authority, under its path);
//   2. in the trusted window, Quick Open ("Go to File") for the needle's name;
//   3. in the trusted window, the Search view ("Find in Files") for the token.
// before (a build without the restoration, where the tab's search provider registration is
// denied): none of the three finds the needle. after: all three find it, every findFiles result
// on this tab's authority, and the decision log holds the provider registrations as allowed.
// Positive control in both modes: the probe extension ran (its marker exists) and the window
// opened the workspace's README from the explorer's own listing, so a search that found
// nothing is search, not a window that never loaded.
//
// The excludes modes (patch 0060, review SRCH-3) run on builds with the search restoration, so their
// search expectations are after's. The host user settings also exclude two canary files by name,
// one through files.exclude, one through search.exclude, and the tab's own workspace settings
// exclude a third. The extension records whether the host patterns reach the tab's configuration
// and whether findFiles returns the files they exclude; Quick Open looks for the search.exclude one.
// excludes-baseline (main): the host patterns are in the tab's configuration and its searches
// exclude both files. excludes-patched: neither pattern reaches the tab, and both files are found.
// In both, the tab's own exclude holds (the control).
//
// Inert (EDR fixture safety): no network target; the only typing goes to the window's Quick
// Open and Search inputs; the extension writes one marker in its own workspace; teardown stops
// the editor's tree and removes the tab and profile.

import { execFileSync, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import { DrivenEditor } from '../driver/editor.ts';
import { checkUserDataDir, ensureVsceImage, lockRun, repoRoot, VSCE_IMAGE } from '../harness.ts';
import { report, rpcDecisions, type Check } from './assert.ts';
import { exitOnSignals, reapOrRefuse, teardownGate, writeManifest, writeSnapshot } from './teardown.ts';

const IMAGE = 'seclab-tab-oci:test-containment';

const argv = process.argv.slice(2);
const [mode, userDataArg] = argv;
const appArg = argv[argv.indexOf('--app') + 1];
const MODES = ['before', 'after', 'excludes-baseline', 'excludes-patched'];
if (!MODES.includes(mode) || !userDataArg || !argv.includes('--app') || !appArg) {
	console.error(`usage: search-probe.ts ${MODES.join('|')} <user-data-dir> --app <test app.app>`);
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

const base = path.join(repoRoot, '.work', 'search-probe', mode);
lockRun(path.join(base, '..', `${mode}.lock.d`));
const ws = path.join(base, 'ws');
const stateDir = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

// ------------------------------------------------------------------ prepare
// The previous run's manifest is its only record: reap it before wiping the directory.
reapOrRefuse(base, 'search-probe');
fs.rmSync(base, { recursive: true, force: true });
fs.rmSync(userData, { recursive: true, force: true });
fs.mkdirSync(path.join(ws, '.seclab'), { recursive: true });
fs.mkdirSync(path.join(ws, 'sub'), { recursive: true });
const arm = randomBytes(16).toString('hex');
const id = arm.slice(0, 12);
const needle = `seclab-needle-${id}.txt`;
const token = `seclabsearch${id}`;
fs.writeFileSync(path.join(ws, '.seclab', 'targets'), `arm=${arm}\nrun=${base}\nuntil=${Math.floor(Date.now() / 1000) + 3600}\n`);
fs.writeFileSync(path.join(ws, 'README.md'), 'search-probe workspace\n');
fs.writeFileSync(path.join(ws, 'sub', needle), `the token is ${token}\n`);
// Patch 0060 (SRCH-3): files the host user's excludes name, and one the tab's own settings exclude.
const hostFilesExcluded = `seclabcanary_hx${id}.txt`;
const hostSearchExcluded = `seclabcanary_hs${id}.txt`;
const tabExcluded = `seclab-tabexcl-${id}.txt`;
for (const f of [hostFilesExcluded, hostSearchExcluded, tabExcluded]) {
	fs.writeFileSync(path.join(ws, 'sub', f), 'excluded by a setting\n');
}
fs.mkdirSync(path.join(ws, '.vscode'));
fs.writeFileSync(path.join(ws, '.vscode', 'settings.json'), JSON.stringify({ 'files.exclude': { [`**/${tabExcluded}`]: true } }, null, '\t'));
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
	'files.exclude': { [`**/${hostFilesExcluded}`]: true },
	'search.exclude': { [`**/${hostSearchExcluded}`]: true },
}, null, '\t'));

// Package the probe (vsce in a container, no network) and install it into the tab.
const extDir = path.join(import.meta.dirname, 'search-probe');
fs.copyFileSync(path.join(import.meta.dirname, 'probe-safety.js'), path.join(extDir, 'probe-safety.js'));
ensureVsceImage();
execFileSync('docker', ['run', '--rm', '--network', 'none', '--user', `${process.getuid!()}:${process.getgid!()}`, '-v', `${extDir}:/ext:ro`, '-v', `${path.join(ws, '.seclab')}:/out`,
	VSCE_IMAGE, 'sh', '-c', 'cp -r /ext /tmp/e && cd /tmp/e && vsce package --allow-missing-repository --skip-license -o /out/search-probe.vsix'], { stdio: 'inherit' });
const tabd = new TabdClient({
	command: process.execPath,
	args: [path.join(repoRoot, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', 'oci', '--image', IMAGE, '--allowed-root', base],
	env: { HOME: process.env.HOME, USER: process.env.USER },
});
await tabd.initialize('search-probe', '0');
const { tab } = await tabd.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
const tabId = tab.metadata.name;
writeManifest(base, { tabs: [tabId] });
await tabd.request('tab.ensureRunning', { tabId });
const install = spawnSync('docker', ['exec', `seclab-${tabId}`, '/opt/seclab/bin/seclab-tab-env', '/opt/seclab-reh/bin/seclab-code-server', '--install-extension', path.join(ws, '.seclab', 'search-probe.vsix')], { encoding: 'utf8' });
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
const marker = path.join(ws, '.seclab-search', 'findfiles');

// ------------------------------------------------------------------ run
const results: Record<string, boolean | number> = {};
try {
	ed = await DrivenEditor.launch({ app, userData, folderUri: `vscode-remote://seclab+${tabId}${ws}` });
	const e = ed;
	// Positive control: the explorer lists the workspace, so the window and the tab work.
	results.explorerListed = await waitFor(async () => await e.evaluate<boolean>(`[...document.querySelectorAll('.explorer-folders-view .monaco-list-row')].some(r => r.textContent.includes('README.md'))`).catch(() => false), 120_000);

	// 1. findFiles in the tab (the extension bounds it at 30 s).
	results.probeRan = await waitFor(() => fs.existsSync(marker), 90_000);
	if (results.probeRan) {
		const f = JSON.parse(fs.readFileSync(marker, 'utf8')) as { returned?: unknown; count?: unknown; ownAuthority?: unknown };
		results.findFilesReturned = f.returned === true;
		results.findFilesCount = typeof f.count === 'number' ? f.count : -1;
		results.findFilesOwnAuthority = f.ownAuthority === true;
		const g = f as Record<string, unknown>;
		for (const k of ['configHostFilesExclude', 'configHostSearchExclude', 'configTabExclude', 'excludesReturned', 'foundHostFilesExcluded', 'foundTabExcluded']) {
			results[k] = g[k] === true;
		}
	}

	const quickInputOpen = `document.querySelector('.quick-input-widget') && getComputedStyle(document.querySelector('.quick-input-widget')).display !== 'none'`;
	const inQuickInput = () => e.evaluate<boolean>(`!!document.activeElement?.closest('.quick-input-widget')`);

	// 2. Quick Open for the needle's name.
	await e.command('Go to File');
	await e.waitFor(quickInputOpen);
	await sleep(1000);
	if (await inQuickInput()) {
		await e.type(needle);
		results.quickOpenTyped = await e.evaluate<boolean>(`(document.querySelector('.quick-input-widget input')?.value ?? '').endsWith(${JSON.stringify(needle)})`);
		results.quickOpenFound = await waitFor(async () => await e.evaluate<boolean>(`[...document.querySelectorAll('.quick-input-widget .quick-input-list .monaco-list-row')].some(r => (r.getAttribute('aria-label') || r.textContent || '').includes(${JSON.stringify(needle)}))`).catch(() => false), 30_000);
		await e.key('Escape');
	}

	// 2b. Patch 0060: Quick Open for the file the host user's search.exclude names. A search that
	// finds nothing waits out its bound, so this one is judged after the needle's was found.
	if (mode.startsWith('excludes-')) {
		await e.command('Go to File');
		await e.waitFor(quickInputOpen);
		await sleep(1000);
		if (await inQuickInput()) {
			await e.type(hostSearchExcluded);
			results.quickOpenExcludedTyped = await e.evaluate<boolean>(`(document.querySelector('.quick-input-widget input')?.value ?? '').endsWith(${JSON.stringify(hostSearchExcluded)})`);
			results.quickOpenFoundHostSearchExcluded = await waitFor(async () => await e.evaluate<boolean>(`[...document.querySelectorAll('.quick-input-widget .quick-input-list .monaco-list-row')].some(r => (r.getAttribute('aria-label') || r.textContent || '').includes(${JSON.stringify(hostSearchExcluded)}))`).catch(() => false), 30_000);
			await e.key('Escape');
		}
	}

	// 3. The Search view for the token.
	await e.command('Search: Find in Files');
	const searchInput = `document.querySelector('.search-view .search-widget .monaco-findInput textarea, .search-view .search-widget .monaco-findInput input')`;
	await e.waitFor(`!!(${searchInput})`, 30_000);
	await sleep(1000);
	if (await e.evaluate<boolean>(`document.activeElement === (${searchInput})`)) {
		await e.type(token);
		results.searchViewTyped = await e.evaluate<boolean>(`((${searchInput})?.value ?? '').includes(${JSON.stringify(token)})`);
		results.searchViewFound = await waitFor(async () => await e.evaluate<boolean>(`[...document.querySelectorAll('.search-view .monaco-list-row')].some(r => (r.textContent || '').includes(${JSON.stringify(needle)}))`).catch(() => false), 30_000);
	}
} catch (err) {
	c('run', false, 'the run completed', (err as Error).message);
} finally {
	await ed?.close();
}
if (fs.existsSync(path.join(userData, 'logs'))) {
	fs.cpSync(path.join(userData, 'logs'), path.join(base, 'editor-logs'), { recursive: true, force: true });
}

// ------------------------------------------------------------------ judge
const decisions = rpcDecisions(userData).map(d => d.detail ?? {});
const registered = (method: string) => decisions.some(d => d.ref === `rpc:MainThreadSearch.${method}` && typeof d.verdict === 'string' && d.verdict.startsWith('allow'));
results.fileProviderAllowed = registered('$registerFileSearchProvider');
results.textProviderAllowed = registered('$registerTextSearchProvider');
results.fileProviderDenied = decisions.some(d => d.ref === 'rpc:MainThreadSearch.$registerFileSearchProvider' && d.verdict === 'deny');
fs.writeFileSync(path.join(base, 'facts.json'), JSON.stringify({ mode, ...results }, null, '\t'));
console.log(JSON.stringify(results));
c('control', results.explorerListed === true, 'positive control: the window lists the tab\'s workspace');
c('control', results.probeRan === true, 'positive control: the probe extension ran in the tab and recorded its search');
c('control', results.quickOpenTyped === true && results.searchViewTyped === true, 'positive control: both searches were typed into their inputs');
if (mode !== 'before') {
	c('findFiles', results.findFilesReturned === true && Number(results.findFilesCount) === 1, 'after: findFiles in the tab returned the needle', `count ${results.findFilesCount}`);
	c('findFiles', results.findFilesOwnAuthority === true, 'after: every findFiles result is in this tab\'s own workspace folder');
	c('quickOpen', results.quickOpenFound === true, 'after: Quick Open in the window finds the needle');
	c('searchView', results.searchViewFound === true, 'after: the Search view finds the needle\'s token');
	c('policy', results.fileProviderAllowed === true && results.textProviderAllowed === true, 'after: the decision log holds both provider registrations as allowed');
	if (mode.startsWith('excludes-')) {
		const patched = mode === 'excludes-patched';
		c('control', results.excludesReturned === true && results.quickOpenExcludedTyped === true, 'positive control: the excludes search returned and the excluded name was typed');
		c('control', results.configTabExclude === true && results.foundTabExcluded !== true, 'positive control: the tab\'s own workspace exclude reaches it and holds');
		c('config', patched ? results.configHostFilesExclude !== true && results.configHostSearchExclude !== true : results.configHostFilesExclude === true && results.configHostSearchExclude === true,
			patched ? 'patched: the host user\'s exclude patterns are not in the tab\'s configuration' : 'baseline: the host user\'s exclude patterns are in the tab\'s configuration');
		c('query', patched ? results.foundHostFilesExcluded === true : results.foundHostFilesExcluded !== true,
			patched ? 'patched: findFiles returns the file the host user\'s files.exclude names' : 'baseline: the host user\'s files.exclude hides its file from findFiles in the tab');
		c('query', patched ? results.quickOpenFoundHostSearchExcluded === true : results.quickOpenFoundHostSearchExcluded !== true,
			patched ? 'patched: Quick Open finds the file the host user\'s search.exclude names' : 'baseline: the host user\'s search.exclude hides its file from Quick Open');
	}
} else {
	c('findFiles', results.findFilesReturned !== true, 'before: findFiles in the tab never returned (provider registration denied)');
	c('quickOpen', results.quickOpenFound !== true, 'before: Quick Open finds no needle');
	c('searchView', results.searchViewFound !== true, 'before: the Search view finds no token');
	c('policy', results.fileProviderAllowed !== true && results.fileProviderDenied === true, 'before: the decision log holds the file search provider registration denied');
}
process.exit(report(checks) ? 0 : 1);
