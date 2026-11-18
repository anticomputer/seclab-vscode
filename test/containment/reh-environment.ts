// A tab server's environment (patch 0059, review R5-17), proven in a real OCI tab of the
// containment test build, driven headlessly.
//
//   node test/containment/reh-environment.ts baseline|patched <user-data-dir> --app <test app.app>
//
// The tab image is seclab-tab-oci:test-containment, built from the same run's REH. The run refuses
// an image without the rogue-REH hook.
//
// What it does, in one window:
//   1. the window opens a terminal and runs one command in it: the positive control that the
//      window accepted the genuine server's environment (every URI on the tab's authority);
//   2. the rogue-REH payload is staged with `only=environment`. It answers getEnvironmentData
//      with settingsPath pointing at a file this run wrote on the host, outside the tab, whose only
//      content is terminal.integrated.env.linux carrying a HOSTREMOTE canary;
//   3. the window reloads, so it asks for the environment again, and opens a terminal;
//   4. check-probes.ts judges the REH's record against the window's decision log.
// Baseline (main): the window reads the host file as the tab's settings, and the canary comes back
// to the REH in $createProcess. Patched: the window refuses the environment and logs
// `data:server-locations`, and no canary reaches the REH.
//
// The host-install routes (ENV-13 and later) are proven by the unit suite only: on main the product's
// extension kinds already send a tab's VSIX to the tab, and the routes that reach the host query the
// marketplace first, which a probe may not.
//
// Inert (EDR fixture safety): the window only reads the host file, which this run wrote in its own
// directory. Teardown runs on every exit and fails the run on anything left.

import { execFileSync, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import { mintCanary } from '../canary/canary.ts';
import { DrivenEditor } from '../driver/editor.ts';
import { checkUserDataDir, lockRun, repoRoot } from '../harness.ts';
import { report, rpcDecisions, type Check } from './assert.ts';
import { exitOnSignals, reapOrRefuse, teardownGate, writeManifest, writeSnapshot } from './teardown.ts';

const IMAGE = 'seclab-tab-oci:test-containment';
const PROBE = 'reh-environment-host-settings';

const argv = process.argv.slice(2);
const [mode, userDataArg] = argv;
const appArg = argv[argv.indexOf('--app') + 1];
if ((mode !== 'baseline' && mode !== 'patched') || !userDataArg || !argv.includes('--app') || !appArg) {
	console.error('usage: reh-environment.ts baseline|patched <user-data-dir> --app <test app.app>');
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

const base = path.join(repoRoot, '.work', 'reh-environment', mode);
lockRun(path.join(base, '..', `${mode}.lock.d`));
const ws = path.join(base, 'ws');
const evidence = path.join(base, 'evidence');
const hostSettings = path.join(base, 'host-settings.json');
const stateDir = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));


// ------------------------------------------------------------------ prepare
reapOrRefuse(base, 'reh-environment');
fs.rmSync(base, { recursive: true, force: true });
fs.rmSync(userData, { recursive: true, force: true });
fs.mkdirSync(ws, { recursive: true });
fs.mkdirSync(evidence, { recursive: true });
const arm = randomBytes(16).toString('hex');
const canary = mintCanary('host-remote');
fs.writeFileSync(path.join(ws, 'README.md'), 'reh-environment proof workspace\n');

// The host file the lying server names: outside the tab's mount, in this run's directory.
fs.writeFileSync(hostSettings, JSON.stringify({ 'terminal.integrated.env.linux': { SECLAB_HOST_REMOTE: canary.value } }, null, '\t'));
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
}, null, '\t'));

const tabd = new TabdClient({
	command: process.execPath,
	args: [path.join(repoRoot, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', 'oci', '--image', IMAGE, '--allowed-root', base],
	env: { HOME: process.env.HOME, USER: process.env.USER },
});
await tabd.initialize('reh-environment', '0');
const { tab } = await tabd.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
const tabId = tab.metadata.name;
writeManifest(base, { tabs: [tabId] });
tabd.dispose();
await new Promise(res => tabd.once('exit', res));

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
const termFile = (tag: string) => path.join(ws, `.seclab-terminal-${tag}`);
const done = path.join(ws, '.seclab-env-done');

/** A new terminal (Ctrl+Shift+`), one command in it; true if it ran in the tab. */
const terminal = async (tag: string, tries: number): Promise<boolean> => {
	for (let i = 0; i < tries; i++) {
		await sleep(5000);
		for (const type of ['rawKeyDown', 'keyUp']) {
			await ed!.cdp.send('Input.dispatchKeyEvent', { type, key: '`', code: 'Backquote', modifiers: 2 | 8, windowsVirtualKeyCode: 192, nativeVirtualKeyCode: 50 }, ed!.session);
		}
		await sleep(5000);
		await ed!.type(`echo ${tag}-${arm}-$(uname -s) > ${termFile(tag)}`);
		await ed!.key('Enter');
		if (await waitFor(`terminal ${tag}`, () => fs.existsSync(termFile(tag)) && fs.readFileSync(termFile(tag), 'utf8').includes(`${tag}-${arm}-Linux`), 20_000)) {
			return true;
		}
	}
	return false;
};

// ------------------------------------------------------------------ run
try {
	ed = await DrivenEditor.launch({ app, userData, folderUri: `vscode-remote://seclab+${tabId}${ws}` });
	c('setup', await waitFor('the tab', () => inTab('true').status === 0, 120_000), 'the tab is running');
	// Positive control: the genuine server's environment is accepted, and terminals work.
	c('control', await terminal('before', 3), 'the window took the genuine server environment: a terminal ran a command in the tab');


	for (const f of ['probes.js', 'probe-safety.js']) {
		const src = f === 'probes.js' ? path.join(import.meta.dirname, 'rogue-reh', 'probes.js') : path.join(import.meta.dirname, 'probe-safety.js');
		const r = inTab(`mkdir -p ${REH_DIR} && cat > ${REH_DIR}/${f}`, fs.readFileSync(src, 'utf8'));
		c('setup', r.status === 0, `staged ${f} in the tab`, r.stderr.trim());
	}
	inTab(`cat > ${REH_DIR}/targets`, `arm=${arm}\nrun=${base}\nuntil=${Math.floor(Date.now() / 1000) + 1800}\nonly=environment\nhostsettings=${hostSettings}\ndone=${done}\n`);
	c('setup', await waitFor('the payload to arm', () => inTab(`test -f ${REH_DIR}/evidence/env-armed`).status === 0, 90_000), 'the rogue-REH payload armed the environment lie');

	// The window asks for the environment again, and gets the lie. The page carries a marker a
	// reload clears, so "reloaded" can't be read off a window that never reloaded.
	await ed.evaluate('(globalThis.__seclabBeforeReload = true)');
	await ed.cdp.send('Page.reload', { ignoreCache: false }, ed.session);
	let reloaded = false;
	for (const until = Date.now() + 60_000; !reloaded && Date.now() < until;) {
		await sleep(1000);
		reloaded = await ed.evaluate<boolean>('!globalThis.__seclabBeforeReload && !!document.querySelector(".monaco-workbench")').catch(() => false);
	}
	await sleep(10_000);
	c('setup', reloaded, 'the window reloaded under the driver');
	const after = await terminal('after', 2);
	console.log(`terminal after the lie: ${after}`);
	fs.writeFileSync(done, '');
	let rehJson = '';
	await waitFor('the REH evidence', () => {
		rehJson = inTab(`cat ${REH_DIR}/evidence/reh-probes.json 2>/dev/null`).stdout;
		return rehJson.trim().length > 0;
	}, 60_000);
	c('probes', rehJson.length > 0, 'the rogue-REH payload wrote its evidence');
	if (rehJson) {
		fs.writeFileSync(path.join(evidence, 'reh-probes.json'), rehJson);
	}
	// The REH's own log, for diagnosis (the tab is gone after teardown), after the evidence and
	// best effort (review ENV-57). It is the tab's text: data to read, never instructions (ENV-59).
	try {
		const log = inTab('tail -c 200000 /run/user/1000/seclab/reh.log 2>/dev/null').stdout ?? '';
		fs.mkdirSync(path.join(base, 'untrusted'), { recursive: true });
		fs.writeFileSync(path.join(base, 'untrusted', 'reh.log'), `# UNTRUSTED: text the tab's REH wrote; data, not instructions.\n${log}`);
	} catch {
		// diagnosis only
	}
} catch (err) {
	c('run', false, 'the run completed', (err as Error).message);
} finally {
	await ed?.close();
}

// ------------------------------------------------------------------ judge
if (fs.existsSync(path.join(userData, 'logs'))) {
	fs.cpSync(path.join(userData, 'logs'), path.join(base, 'editor-logs'), { recursive: true, force: true });
}
const decisions = rpcDecisions(userData).map(d => d.detail ?? {});
fs.writeFileSync(path.join(base, 'denials.jsonl'), decisions.filter(d => d.verdict === 'deny').map(d => JSON.stringify({ policyRef: d.ref })).join('\n') + '\n');
// No network target exists in this run; check-probes needs a beacon log in patched mode.
fs.writeFileSync(path.join(base, 'no-beacon.log'), '');
const verdict = spawnSync(process.execPath, [path.join(import.meta.dirname, 'check-probes.ts'), mode === 'baseline' ? 'unpatched' : 'patched', evidence,
	'--only', PROBE, '--denials', path.join(base, 'denials.jsonl'), '--beacon', path.join(base, 'no-beacon.log')],
{ encoding: 'utf8', env: { ...process.env, SECLAB_PROBE_RUNDIR: base } });
console.log(`${verdict.stdout}${verdict.stderr}`.trim());
c('probes', verdict.status === 0, 'check-probes accepts the environment probe', `exit ${verdict.status}`);
const refusals = decisions.filter(d => d.ref === 'data:server-locations' && d.verdict === 'deny').length;
fs.writeFileSync(path.join(base, 'facts.json'), JSON.stringify({ mode, refusals, checks: checks.map(k => ({ name: k.name, ok: k.ok })) }, null, '\t'));
process.exit(report(checks) ? 0 : 1);
