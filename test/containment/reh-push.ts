// Server-initiated pushes (patches 0030, 0031) and the remote agent-host dial (refused by
// patch 0015's gate), proven in a real OCI tab of the containment test build, driven headlessly.
//
//   node test/containment/reh-push.ts baseline|patched <user-data-dir> --app <test app.app>
//
// The tab image is seclab-tab-oci:test-containment, built from the same run's REH
// (`./seclab fetch macos-containment RUN`, `./seclab image oci --test-variant containment`); the
// app and the REH pair only with each other. The run refuses an image without the rogue-REH hook.
//
// What it does, in one window, with nothing hostile but the staged rogue-REH payload and the
// workspace's own settings file:
//   1. the workspace's .vscode/settings.json lists a remote agent host at this run's loopback
//      port (`chat.workspaceRemoteAgentHosts`, which a tab can write). A listener on that port
//      runs on the host and another inside the tab; a dial from the editor window reaches the
//      host one, so exactly one side records it, or neither does;
//   2. the window opens a terminal through the command palette and runs one command in it;
//   3. the rogue-REH payload is staged in the tab with `only=push`, and fires the three
//      onExecuteCommand pushes and the variable-resolution request against that window;
//   4. the same terminal runs a second command, so a refusal that broke the terminal fails;
//   5. the editor quits, then an EMPTY window with the same kind of entry in user settings dials
//      the host listener: the positive control that the dial works where nothing gates it;
//   6. check-probes.ts judges the REH evidence against the window's decision log; the dial and
//      terminal facts are checked here.
// Baseline: every push probe succeeds. Patched: every push probe is denied, each with its
// decision line. Both: the tab window never dials (0015's gate logs the refusal), the control
// window does, and the terminal works before and after the pushes.
//
// Inert (EDR fixture safety): the network targets are this run's two loopback listeners; the
// pushes run windowOpen (an empty background window), getSystemStatus and an extension LIST;
// variable resolution asks only for this run's canary; nothing writes outside the run.
// Teardown runs on every exit (teardown.ts) and fails the run on anything left.

import { execFileSync, spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import { mintCanary } from '../canary/canary.ts';
import { DrivenEditor } from '../driver/editor.ts';
import { beaconPort, checkUserDataDir, lockRun, repoRoot } from '../harness.ts';
import { report, rpcDecisions, type Check } from './assert.ts';
import { readHits } from './beacon.ts';
import { exitOnSignals, reapOrRefuse, teardownGate, writeManifest, writeSnapshot } from './teardown.ts';

const IMAGE = 'seclab-tab-oci:test-containment';
const PUSH_PROBES = ['reh-onexecutecommand-windowopen', 'reh-onexecutecommand-manageextensions', 'reh-onexecutecommand-getsystemstatus', 'reh-resolve-variables-host-env', 'reh-profile-config-host-setting'];

const argv = process.argv.slice(2);
const [mode, userDataArg] = argv;
const appArg = argv[argv.indexOf('--app') + 1];
if ((mode !== 'baseline' && mode !== 'patched') || !userDataArg || !argv.includes('--app') || !appArg) {
	console.error('usage: reh-push.ts baseline|patched <user-data-dir> --app <test app.app>');
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

const base = path.join(repoRoot, '.work', 'reh-push', mode);
lockRun(path.join(base, '..', `${mode}.lock.d`));
const ws = path.join(base, 'ws');
const evidence = path.join(base, 'evidence');
const stateDir = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

// ------------------------------------------------------------------ prepare
// The previous run's manifest is its only record: reap it before wiping the directory.
reapOrRefuse(base, 'reh-push');
fs.rmSync(base, { recursive: true, force: true });
fs.rmSync(userData, { recursive: true, force: true });
fs.mkdirSync(path.join(ws, '.vscode'), { recursive: true });
fs.mkdirSync(evidence, { recursive: true });
const arm = randomBytes(16).toString('hex');
const port = await beaconPort();
const canary = mintCanary('editor-env');
// A host user setting the REH's profile path names (review RFU-1, patch 0034).
const settingCanary = mintCanary('user-settings');
const dialPath = `/seclab-dial-${arm}`;
fs.writeFileSync(path.join(ws, 'README.md'), 'reh-push proof workspace\n');
fs.writeFileSync(path.join(ws, '.vscode', 'settings.json'), JSON.stringify({
	'chat.workspaceRemoteAgentHosts': [{ address: `127.0.0.1:${port}${dialPath}`, name: 'seclab-probe' }],
}, null, '\t'));
fs.copyFileSync(path.join(repoRoot, 'test', 'agentic', 'browser', 'tab-beacon.mjs'), path.join(ws, '.seclab-tab-beacon.mjs'));
const hostBeaconLog = path.join(base, 'beacon.log');
const tabBeaconLog = path.join(ws, '.seclab-tab-beacon.log');
const beaconArgv = [path.join(repoRoot, 'test', 'containment', 'beacon.ts'), 'start', hostBeaconLog, String(port)];
writeSnapshot(base);
writeManifest(base, {
	driver: 'oci', userDataDir: userData, stateDirs: [stateDir], workspaces: [ws],
	commandMarks: [`beacon.ts start ${hostBeaconLog}`],
});
let ed: DrivenEditor | undefined;
let beacon: ChildProcess | undefined;
exitOnSignals();
process.on('exit', code => {
	beacon?.kill();
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
	'seclab.test.canary': settingCanary.value,
	'workbench.welcomePage.experimentalOnboarding': false,
	'workbench.startupEditor': 'none',
	'workbench.tips.enabled': false,
}, null, '\t'));

// Claim the tab in the editor's own tabd state; the editor restarts it.
const tabd = new TabdClient({
	command: process.execPath,
	args: [path.join(repoRoot, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', 'oci', '--image', IMAGE, '--allowed-root', base],
	env: { HOME: process.env.HOME, USER: process.env.USER },
});
await tabd.initialize('reh-push', '0');
const { tab } = await tabd.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
const tabId = tab.metadata.name;
writeManifest(base, { tabs: [tabId] });
tabd.dispose();
await new Promise(res => tabd.once('exit', res));

/** A shell snippet in the tab, as the tab user, with the tab's own environment (the REH's HOME). */
const inTab = (script: string, input?: string) => spawnSync('docker', ['exec', '-i', '-u', '1000:1000', '--', `seclab-${tabId}`, '/opt/seclab/bin/seclab-tab-env', 'sh', '-c', script],
	{ encoding: 'utf8', input, timeout: 30_000 });
const REH_DIR = '"$HOME/.seclab-test/rogue-reh"';
const waitFor = async (what: string, ok: () => boolean, ms: number): Promise<boolean> => {
	for (const until = Date.now() + ms; Date.now() < until;) {
		if (ok()) {
			return true;
		}
		await sleep(1000);
	}
	console.log(`timed out waiting for ${what}`);
	return false;
};

const checks: Check[] = [];
const c = (vector: string, ok: boolean, name: string, detail = '') => checks.push({ vector, ok, name, detail });

// ------------------------------------------------------------------ run
try {
	beacon = spawn(process.execPath, beaconArgv, { stdio: 'ignore' });
	ed = await DrivenEditor.launch({ app, userData, folderUri: `vscode-remote://seclab+${tabId}${ws}`, env: { SECLAB_EDITOR_CANARY: canary.value } });
	const tabUp = await waitFor('the tab', () => inTab('true').status === 0, 120_000);
	c('setup', tabUp, 'the tab is running');

	// The tab-side listener, up before anything can dial.
	let tabListener = false;
	for (let i = 0; i < 20 && !tabListener; i++) {
		inTab(`cd ${ws} && (setsid /opt/seclab-reh/node .seclab-tab-beacon.mjs ${tabBeaconLog} ${port} ${arm} >> .seclab-tab-beacon.out 2>&1 &) ; `
			+ `for j in $(seq 1 12); do curl -sS -m 2 -o /dev/null http://127.0.0.1:${port}/tab-live-${arm} && break; sleep 0.25; done`);
		tabListener = fs.existsSync(tabBeaconLog) && fs.readFileSync(tabBeaconLog, 'utf8').includes(`tab-live-${arm}`);
		if (!tabListener) {
			await sleep(2000);
		}
	}
	c('setup', tabListener, 'the tab-side listener is up on the dial port');

	// Stage the REH payload first, push probes only: it learns the terminal the window creates.
	const termFile = (tag: string) => path.join(ws, `.seclab-terminal-${tag}`);
	for (const f of ['probes.js', 'probe-safety.js']) {
		const src = f === 'probes.js' ? path.join(import.meta.dirname, 'rogue-reh', 'probes.js') : path.join(import.meta.dirname, 'probe-safety.js');
		const r = inTab(`mkdir -p ${REH_DIR} && cat > ${REH_DIR}/${f}`, fs.readFileSync(src, 'utf8'));
		c('setup', r.status === 0, `staged ${f} in the tab`, r.stderr.trim());
	}
	inTab(`cat > ${REH_DIR}/targets`, `arm=${arm}\nrun=${base}\nuntil=${Math.floor(Date.now() / 1000) + 1800}\nonly=push\nready=${termFile('before')}\n`);
	// The hook polls for targets every 2 s and starts the payload 5 s later; it must be in place
	// before the window creates its terminal, as a hostile REH always is.
	await sleep(12_000);
	// RFU1R-1: make the REH's offered profile the host user's default, as a user's own
	// defaultProfile setting would. The change makes the window ask the (now armed) REH for
	// its profiles again, so the new terminal launches that profile, `env` included.
	const userSettings = path.join(userData, 'User', 'settings.json');
	fs.writeFileSync(userSettings, JSON.stringify({ ...JSON.parse(fs.readFileSync(userSettings, 'utf8')), 'terminal.integrated.defaultProfile.linux': 'seclab-probe' }, null, '\t'));
	await sleep(5000);

	// A terminal the window owns, so the REH has a pty to name, and one command run through it,
	// which also tells the payload to start (its `ready` file).
	const runInTerminal = async (tag: string): Promise<boolean> => {
		// `uname -s` says where the shell runs: Linux in the tab, never the macOS host.
		await ed!.type(`echo ${tag}-${arm}-$(uname -s) > ${termFile(tag)}`);
		await ed!.key('Enter');
		const ran = await waitFor(`terminal ${tag}`, () => fs.existsSync(termFile(tag)) && fs.readFileSync(termFile(tag), 'utf8').includes(`${tag}-${arm}`), 30_000);
		const text = ran ? fs.readFileSync(termFile(tag), 'utf8') : '';
		console.log(`terminal ${tag}: ran=${ran} linux=${text.includes('-Linux')} darwin=${text.includes('-Darwin')}`);
		return text.includes(`${tag}-${arm}-Linux`);
	};
	let before = false;
	for (let i = 0; i < 3 && !before; i++) {
		await sleep(5000);
		// The default new-terminal keybinding (Ctrl+Shift+`), delivered to the renderer over CDP.
		// Not the palette: there "Create New Terminal" ranks the remote window's "Create New
		// Integrated Terminal (Local)", a host shell, first.
		for (const type of ['rawKeyDown', 'keyUp']) {
			await ed.cdp.send('Input.dispatchKeyEvent', { type, key: '`', code: 'Backquote', modifiers: 2 | 8, windowsVirtualKeyCode: 192, nativeVirtualKeyCode: 50 }, ed.session);
		}
		await sleep(5000);
		before = await runInTerminal('before');
	}
	c('terminal', before, 'the tab\'s terminal runs a command, inside the tab, before the pushes');

	let rehJson = '';
	await waitFor('the REH evidence', () => {
		rehJson = inTab(`cat ${REH_DIR}/evidence/reh-probes.json 2>/dev/null`).stdout;
		return rehJson.trim().length > 0;
	}, 150_000);
	c('probes', rehJson.length > 0, 'the rogue-REH payload armed and wrote its evidence');
	if (rehJson) {
		fs.writeFileSync(path.join(evidence, 'reh-probes.json'), rehJson);
	}
	const diag = inTab(`cat ${REH_DIR}/evidence/reh-diagnostics.json 2>/dev/null`).stdout;
	if (diag) {
		fs.writeFileSync(path.join(evidence, 'reh-diagnostics.json'), diag);
	}

	c('terminal', await runInTerminal('after'), 'the tab\'s terminal still runs a command, inside the tab, after the pushes');
	// Dial attempts start at AfterRestored and retry; give a late one time to land.
	await sleep(10_000);
} catch (err) {
	c('run', false, 'the run completed', (err as Error).message);
} finally {
	await ed?.close();
}

// The positive control for the dial: the same kind of entry, in user settings, read by an
// EMPTY window (no tab). It must reach the host listener, which shows the address, the
// listener and the dial all work, so a quiet listener in the tab window is a refusal and not
// a probe that could never connect.
const controlPath = `/seclab-dial-control-${arm}`;
try {
	const settingsFile = path.join(userData, 'User', 'settings.json');
	fs.writeFileSync(settingsFile, JSON.stringify({
		...JSON.parse(fs.readFileSync(settingsFile, 'utf8')),
		'window.restoreWindows': 'none',
		'chat.workspaceRemoteAgentHosts': [{ address: `127.0.0.1:${port}${controlPath}`, name: 'seclab-control' }],
	}, null, '\t'));
	ed = await DrivenEditor.launch({ app, userData });
	await waitFor('the control dial', () => readHits(hostBeaconLog).some(h => h.url.startsWith(controlPath)), 30_000);
} catch (err) {
	c('dial', false, 'the control window ran', (err as Error).message);
} finally {
	await ed?.close();
}

// ------------------------------------------------------------------ judge
// The window's own logs, kept in the run directory (gitignored, deleted with it) for diagnosis.
fs.cpSync(path.join(userData, 'logs'), path.join(base, 'editor-logs'), { recursive: true, force: true });
const decisions = rpcDecisions(userData).map(d => d.detail ?? {});
fs.writeFileSync(path.join(base, 'denials.jsonl'), decisions.filter(d => d.verdict === 'deny').map(d => JSON.stringify({ policyRef: d.ref })).join('\n') + '\n');
const verdict = spawnSync(process.execPath, [path.join(import.meta.dirname, 'check-probes.ts'), mode === 'baseline' ? 'unpatched' : 'patched', evidence,
	'--only', PUSH_PROBES.join(','), '--denials', path.join(base, 'denials.jsonl'), '--beacon', hostBeaconLog],
{ encoding: 'utf8', env: { ...process.env, SECLAB_PROBE_RUNDIR: base } });
console.log(`${verdict.stdout}${verdict.stderr}`.trim());
c('probes', verdict.status === 0, 'check-probes accepts the push probes', `exit ${verdict.status}`);

const hostDialled = readHits(hostBeaconLog).some(h => h.url.startsWith(dialPath));
const tabDialled = fs.existsSync(tabBeaconLog) && fs.readFileSync(tabBeaconLog, 'utf8').includes(dialPath);
const controlDialled = readHits(hostBeaconLog).some(h => h.url.startsWith(controlPath));
// Patch 0015's gate refuses an ungated agent-host transport in a tab window, before the
// socket opens, and logs it to seclabAhpGate.log. Read as structured fields only.
const gateRefusals = (() => {
	let n = 0;
	const walk = (dir: string): void => {
		for (const e of fs.existsSync(dir) ? fs.readdirSync(dir, { withFileTypes: true }) : []) {
			const p = path.join(dir, e.name);
			if (e.isDirectory()) {
				walk(p);
			} else if (e.name === 'seclabAhpGate.log') {
				for (const line of fs.readFileSync(p, 'utf8').split('\n')) {
					try {
						const d = JSON.parse(line.slice(line.indexOf('{')));
						n += d?.source === 'ahp-gate' && d?.detail?.gateRule === 'ahp-gate.refused' && d?.detail?.verdict === 'deny' ? 1 : 0;
					} catch { /* not a decision */ }
				}
			}
		}
	};
	walk(path.join(base, 'editor-logs'));
	return n;
})();
c('dial', controlDialled, 'control: an empty window dials the same kind of entry to the host listener');
c('dial', !hostDialled && !tabDialled, 'the tab window did not dial the tab-written agent-host address', `host=${hostDialled} tab=${tabDialled}`);
c('dial', gateRefusals > 0, 'patch 0015\'s gate logged refusing the agent-host transport in the tab window', `${gateRefusals} refusal(s)`);
// The facts, without the values: booleans and counts only (run records hold facts).
fs.writeFileSync(path.join(base, 'facts.json'), JSON.stringify({
	mode, hostDialled, tabDialled, controlDialled, gateRefusals, denials: decisions.filter(d => d.verdict === 'deny').length,
	pushDenials: decisions.filter(d => typeof d.ref === 'string' && d.ref.startsWith('push:remoteterminal:') && d.verdict === 'deny').length,
	checks: checks.map(k => ({ name: k.name, ok: k.ok })),
}, null, '\t'));
process.exit(report(checks) ? 0 : 1);
