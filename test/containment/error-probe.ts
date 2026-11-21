// Review AIP-4, proven in a real OCI tab of the containment test build, driven headlessly: an error
// the trusted window answers a tab's call with reaches the tab with no host stack.
//
//   node test/containment/error-probe.ts baseline|patched <user-data-dir> --app <test app.app> [--image <tab image>]
//
// The tab image (default seclab-tab-oci:test-containment) is built from the same run's REH. The
// baseline is a build of main before patch 0062 (run with SECLAB_APP_SHA set to its commit), the
// patched one a build of this branch.
//
// The run puts a canary in the host's install path: it clones the app (an APFS clone, no copy)
// into `.work/test-builds/error-probe-<mode>/seclabcanary_<id>/`, so any host frame that crosses
// names it. One window, one extension (test/containment/error-probe) making three calls the
// window answers with an error: a call the RPC filter refuses, a command it refuses, and an
// ordinary failure upstream raises for an allowed call (the control). The extension logs each
// error's stack to its own log, in the tab, and records facts.
// The harness then reads the tab's own logs (in memory, out of the tab's container) and looks for
// the canary and the app's bundle path:
//   baseline: the refusals' stacks carry host frames, and the canary is in the tab's log;
//   patched: every stack the tab got is one line, and neither the canary nor the bundle path is
//     anywhere in the tab's logs.
// In both, the refusals say "Unsupported operation" and the control fails with its own message
// naming its file, so a clean log is the fix, not a call that never reached the window.
//
// Inert (EDR fixture safety): no network target; the extension opens nothing that exists and
// writes one marker in its own workspace; the clone and the run's tab and profile are removed at
// teardown.

import { execFileSync, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import { DrivenEditor } from '../driver/editor.ts';
import { checkUserDataDir, ensureVsceImage, lockRun, repoRoot, tabImageProblem, VSCE_IMAGE } from '../harness.ts';
import { report, rpcDecisions, type Check } from './assert.ts';
import { exitOnSignals, reapOrRefuse, teardownGate, writeManifest, writeSnapshot } from './teardown.ts';

const argv = process.argv.slice(2);
const [mode, userDataArg] = argv;
const appArg = argv.includes('--app') ? argv[argv.indexOf('--app') + 1] : undefined;
const IMAGE = argv.includes('--image') ? argv[argv.indexOf('--image') + 1] : 'seclab-tab-oci:test-containment';
if ((mode !== 'baseline' && mode !== 'patched') || !userDataArg || !appArg) {
	console.error('usage: error-probe.ts baseline|patched <user-data-dir> --app <test app.app> [--image <tab image>]');
	process.exit(2);
}
const imageProblem = IMAGE ? tabImageProblem(IMAGE, 'oci') : 'no image';
if (imageProblem) {
	console.error(imageProblem);
	process.exit(2);
}
const app = path.resolve(appArg);
if (!app.endsWith('.app') || !fs.existsSync(app)) {
	console.error(`--app must name an existing .app, got ${JSON.stringify(appArg)}`);
	process.exit(2);
}
const userData = path.resolve(userDataArg);
checkUserDataDir(userData);

const base = path.join(repoRoot, '.work', 'error-probe', mode);
lockRun(path.join(base, '..', `${mode}.lock.d`));
const ws = path.join(base, 'ws');
const stateDir = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

// ------------------------------------------------------------------ prepare
reapOrRefuse(base, 'error-probe');
fs.rmSync(base, { recursive: true, force: true });
fs.rmSync(userData, { recursive: true, force: true });
fs.mkdirSync(path.join(ws, '.seclab'), { recursive: true });
const arm = randomBytes(16).toString('hex');
const id = arm.slice(0, 12);
const canary = `seclabcanary_${id}`;
fs.writeFileSync(path.join(ws, '.seclab', 'targets'), `arm=${arm}\nrun=${base}\nuntil=${Math.floor(Date.now() / 1000) + 3600}\n`);
fs.writeFileSync(path.join(ws, 'README.md'), 'error-probe workspace\n');

// The canary install path. A test build runs only from .work/test-builds/ (EDR fetched-app-binding),
// with its build info beside it.
const cloneRoot = path.join(repoRoot, '.work', 'test-builds', `error-probe-${mode}`);
fs.rmSync(cloneRoot, { recursive: true, force: true });
const cloneDir = path.join(cloneRoot, canary);
fs.mkdirSync(cloneDir, { recursive: true });
execFileSync('cp', ['-c', '-R', app, cloneDir]);
for (const f of fs.readdirSync(path.dirname(app)).filter(f => /^build-info.*\.json$/.test(f))) {
	fs.copyFileSync(path.join(path.dirname(app), f), path.join(cloneDir, f));
}
const clonedApp = path.join(cloneDir, path.basename(app));

writeSnapshot(base);
writeManifest(base, { driver: 'oci', userDataDir: userData, stateDirs: [stateDir], workspaces: [ws] });
let ed: DrivenEditor | undefined;
exitOnSignals();
process.on('exit', code => {
	fs.rmSync(cloneRoot, { recursive: true, force: true });
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

// Package the probe (vsce in a container, no network) and install it into the tab.
const extDir = path.join(import.meta.dirname, 'error-probe');
fs.copyFileSync(path.join(import.meta.dirname, 'probe-safety.js'), path.join(extDir, 'probe-safety.js'));
ensureVsceImage();
execFileSync('docker', ['run', '--rm', '--network', 'none', '--user', `${process.getuid!()}:${process.getgid!()}`, '-v', `${extDir}:/ext:ro`, '-v', `${path.join(ws, '.seclab')}:/out`,
	VSCE_IMAGE, 'sh', '-c', 'cp -r /ext /tmp/e && cd /tmp/e && vsce package --allow-missing-repository --skip-license -o /out/error-probe.vsix'], { stdio: 'inherit' });
const tabd = new TabdClient({
	command: process.execPath,
	args: [path.join(repoRoot, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', 'oci', '--image', IMAGE, '--allowed-root', base],
	env: { HOME: process.env.HOME, USER: process.env.USER },
});
await tabd.initialize('error-probe', '0');
const { tab } = await tabd.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
const tabId = tab.metadata.name;
writeManifest(base, { tabs: [tabId] });
await tabd.request('tab.ensureRunning', { tabId });
const install = spawnSync('docker', ['exec', `seclab-${tabId}`, '/opt/seclab/bin/seclab-tab-env', '/opt/seclab-reh/bin/seclab-code-server', '--install-extension', path.join(ws, '.seclab', 'error-probe.vsix')], { encoding: 'utf8' });
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
const marker = path.join(ws, '.seclab-errors', 'facts');

// ------------------------------------------------------------------ run
const results: Record<string, boolean | number> = {};
let tabLogs = '';
try {
	ed = await DrivenEditor.launch({ app: clonedApp, userData, folderUri: `vscode-remote://seclab+${tabId}${ws}` });
	const e = ed;
	results.explorerListed = await waitFor(async () => await e.evaluate<boolean>(`[...document.querySelectorAll('.explorer-folders-view .monaco-list-row')].some(r => r.textContent.includes('README.md'))`).catch(() => false), 120_000);
	results.probeRan = await waitFor(() => fs.existsSync(marker), 150_000);
	// The extension's log is flushed as it writes; give the logger a moment before reading.
	await sleep(3000);
	// The tab's own logs, read in memory: nothing from the tab is unpacked on the host.
	const read = spawnSync('docker', ['exec', `seclab-${tabId}`, '/opt/seclab/bin/seclab-tab-env', 'sh', '-c',
		'd="$HOME/.seclab-vscode-server/data/logs"; [ -d "$d" ] && find "$d" -type f -name "*.log" -size -8M -exec cat {} +'],
	{ encoding: 'latin1', maxBuffer: 64 << 20, timeout: 30_000, killSignal: 'SIGKILL' });
	tabLogs = read.status === 0 ? read.stdout : '';
	results.tabLogsRead = tabLogs.length > 0;
} catch (err) {
	c('run', false, 'the run completed', (err as Error).message);
} finally {
	await ed?.close();
}
if (fs.existsSync(path.join(userData, 'logs'))) {
	fs.cpSync(path.join(userData, 'logs'), path.join(base, 'editor-logs'), { recursive: true, force: true });
}

// ------------------------------------------------------------------ judge
// The tab's claim, reported: the extension's facts. Judged: what the tab's own log holds.
type Fact = { failed?: unknown; timedOut?: unknown; unsupported?: unknown; namesItsFile?: unknown; oneLineStack?: unknown; stackLines?: unknown; stackCanaries?: unknown };
const facts: Record<string, Fact> = results.probeRan ? JSON.parse(fs.readFileSync(marker, 'utf8')) : {};
/** The stack the probe logged for `key`, read out of the tab's log: up to the next log line. */
const loggedStack = (key: string): string | undefined => {
	const head = `${key} failed; the stack the tab received:\n`;
	const at = tabLogs.indexOf(head);
	if (at < 0) {
		return undefined;
	}
	const rest = tabLogs.slice(at + head.length);
	const end = rest.search(/\n\d{4}-\d\d-\d\d \d\d:\d\d:\d\d/);
	return (end < 0 ? rest : rest.slice(0, end)).replace(/\n+$/, '');
};
for (const k of ['denyRpc', 'denyCommand', 'control']) {
	const f = facts[k] ?? {};
	results[`${k}Failed`] = f.failed === true && f.timedOut !== true;
	results[`${k}Unsupported`] = f.unsupported === true;
	results[`${k}ClaimedOneLine`] = f.oneLineStack === true;
	const logged = loggedStack(k);
	results[`${k}Logged`] = logged !== undefined;
	results[`${k}LoggedLines`] = logged === undefined ? -1 : logged.split('\n').length;
	results[`${k}LoggedFrames`] = logged !== undefined && /\n\s+at\s/.test(logged);
	results[`${k}LoggedCanary`] = logged !== undefined && logged.includes(canary);
	results[`${k}LoggedUnsupported`] = logged !== undefined && logged.split('\n')[0] === 'Error: Unsupported operation';
}
results.controlLoggedNamesItsFile = (loggedStack('control') ?? '').split('\n')[0].includes(`missing-${id}.txt`);
results.controlNamesItsFile = facts.control?.namesItsFile === true;
results.logHasCanary = tabLogs.includes(canary);
results.logHasBundlePath = tabLogs.includes('Contents/Resources/app');
results.logHasProbeLines = tabLogs.includes('denyRpc failed; the stack the tab received');
const decisions = rpcDecisions(userData).map(d => d.detail ?? {});
results.decisionLogDeniedGetCommands = decisions.some(d => d.ref === 'rpc:MainThreadCommands.$getCommands' && d.verdict === 'deny');
fs.writeFileSync(path.join(base, 'facts.json'), JSON.stringify({ mode, ...results }, null, '\t'));
console.log(JSON.stringify(results));

c('control', results.explorerListed === true, 'positive control: the window lists the tab\'s workspace');
c('control', results.probeRan === true, 'positive control: the probe extension ran in the tab and recorded its calls');
c('control', results.tabLogsRead === true && results.logHasProbeLines === true, 'positive control: the tab\'s logs were read and hold the probe\'s lines');
c('control', results.decisionLogDeniedGetCommands === true, 'positive control: the host decision log holds $getCommands denied');
c('control', results.controlLogged === true && results.controlLoggedNamesItsFile === true && results.controlLoggedUnsupported !== true,
	'control: an ordinary upstream failure reaches the tab with its own message (its log)');
for (const k of ['denyRpc', 'denyCommand']) {
	c('refusal', results[`${k}Logged`] === true && results[`${k}LoggedUnsupported`] === true, `${k}: the refusal reaches the tab as "Unsupported operation" (its log)`);
}
if (mode === 'patched') {
	for (const k of ['denyRpc', 'denyCommand', 'control']) {
		c('stack', results[`${k}Logged`] === true && results[`${k}LoggedLines`] === 1 && results[`${k}LoggedFrames`] !== true && results[`${k}LoggedCanary`] !== true,
			`patched: ${k} reached the tab with a one-line stack and no canary (its log)`, `lines ${results[`${k}LoggedLines`]}`);
	}
	c('log', results.logHasCanary !== true, 'patched: the canary in the host install path is nowhere in the tab\'s logs');
	c('log', results.logHasBundlePath !== true, 'patched: the host app\'s bundle path is nowhere in the tab\'s logs');
} else {
	c('stack', results.denyRpcLoggedCanary === true && results.denyRpcLoggedFrames === true, 'baseline: the RPC refusal reached the tab with host frames naming the canary (its log)');
	c('log', results.logHasCanary === true, 'baseline: the canary in the host install path is in the tab\'s log');
}
process.exit(report(checks) ? 0 : 1);
