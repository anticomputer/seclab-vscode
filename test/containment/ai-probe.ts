// The built-in chat in a tab window, steered by the tab (agent-host-patches#3): instructions the
// tab wrote, settings the tab wrote to switch chat back on, and a tool call from the tab's own
// extension host, proven in a real OCI tab of the containment test build, driven headlessly.
//
//   node test/containment/ai-probe.ts baseline|patched <user-data-dir> --app <test app.app> [--image IMAGE]
//
// patched: this branch's containment build, its tab image tagged seclab-tab-oci:test-containment-b-aip
//   (`./seclab fetch macos-containment RUN`, then
//   `sandbox/oci/build-images.sh --test-variant containment --tag b-aip`).
// baseline: the build-only baseline branch (patches/series without 0009, 0010 and 0018), its image
//   seclab-tab-oci:test-containment-b-aipbase, and SECLAB_APP_SHA naming that branch's commit.
// The app and the REH pair only with each other. The run refuses an app without the fake-model
// hook or an image without the rogue-REH hook (the containment variant's REH).
//
// There is no agent in this build's windows (no Copilot Chat, nothing but ui built-ins locally),
// so the containment variant's fake model stands in for one: a scripted default chat participant
// that, when this run arms it, matches the instruction files core attaches against the run's
// exact canary lines and makes the one tool call the run armed, the built-in fetch tool on this
// run's loopback beacon (test/containment/fake-model). In one app:
//   1. the tab's workspace holds instructions (applyTo '**', and .github/copilot-instructions.md)
//      with the tab's canary line, and .vscode/settings.json turning the chat settings back on;
//      the test profile holds a user-level instructions file with the ordinary window's line;
//   2. a listener runs on the host and another inside the tab, on the same port;
//   3. control: an ordinary (empty) window in the same app asks chat; its agent fetches the
//      beacon at the ordinary window's path, on the host. The user-level file is then removed;
//   4. the tab window asks chat. Baseline: its agent follows the tab's line and the fetch reaches
//      the host listener. Patched: patch 0009 refuses the request and logs it, and nothing is
//      fetched; the window also reads the tab's re-enable settings (their in-run control);
//   5. arm B: an extension in the tab (test/containment/ai-tab-probe) asks the window to run the
//      fetch tool itself. The RPC filter refuses MainThreadLanguageModelTools.$invokeTool and logs
//      it (0009 refuses invokeTool behind it); the control in step 3 shows the tool fetches;
//   6. check-probes.ts judges what the host measured (harness-probes.json).
//
// Inert (EDR fixture safety): the instruction text is canary data the fake model matches exactly,
// never instructions it follows; the only network target is this run's loopback beacon; the tab
// probe arms from the run's targets file; nothing writes outside the run and its test profile.
// Windows open in the background and never take focus. Teardown runs on every exit.

import { execFileSync, spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import { DrivenEditor } from '../driver/editor.ts';
import { beaconPort, checkUserDataDir, ensureVsceImage, lockRun, repoRoot, VSCE_IMAGE } from '../harness.ts';
import { report, rpcDecisions, type Check } from './assert.ts';
import { readHits } from './beacon.ts';
import { exitOnSignals, reapOrRefuse, teardownGate, writeManifest, writeSnapshot } from './teardown.ts';

const IMAGES = { patched: 'seclab-tab-oci:test-containment-b-aip', baseline: 'seclab-tab-oci:test-containment-b-aipbase' } as const;
export const AI_PROBES = ['ai-instructions-tool-call', 'ai-settings-reenable', 'ai-tab-invoke-tool'];
const FAKE_MODEL_ID = 'seclab-test.fake-model';
/** MainThreadLanguageModelTools.$invokeTool as the filter logs it: by its wire sid, which differs. */
const INVOKE_TOOL_REF = 'rpc:MainThreadChatSkills.$invokeTool';
/** The settings a tab writes to switch the built-in chat back on (the fake model counts them). */
const REENABLE = { 'chat.agent.enabled': true, 'chat.disableAIFeatures': false, 'chat.extensionTools.enabled': true, 'chat.tools.global.autoApprove': true };

const argv = process.argv.slice(2);
const [mode, userDataArg] = argv;
const appArg = argv[argv.indexOf('--app') + 1];
if ((mode !== 'baseline' && mode !== 'patched') || !userDataArg || !argv.includes('--app') || !appArg) {
	console.error('usage: ai-probe.ts baseline|patched <user-data-dir> --app <test app.app> [--image IMAGE]');
	process.exit(2);
}
const IMAGE = argv.includes('--image') ? argv[argv.indexOf('--image') + 1] : IMAGES[mode];
if (!/^seclab-tab-oci:[a-z0-9][a-z0-9.-]{0,60}$/.test(IMAGE ?? '')) {
	console.error(`--image must be a seclab-tab-oci tag, got ${JSON.stringify(IMAGE)}`);
	process.exit(2);
}
const app = path.resolve(appArg);
if (!app.endsWith('.app') || !fs.existsSync(app)) {
	console.error(`--app must name an existing .app, got ${JSON.stringify(appArg)}`);
	process.exit(2);
}
const userData = path.resolve(userDataArg);
checkUserDataDir(userData);

// The fake model must be in this app, built in and ui-kind, or there is nothing to measure.
{
	const variants = JSON.parse(fs.readFileSync(path.join(repoRoot, 'test', 'builds', 'variants.json'), 'utf8')) as Record<string, { hooks?: Array<{ id: string; marker: string; bundle: string }> }>;
	const hook = variants.containment?.hooks?.find(h => h.id === 'fake-model');
	const resources = path.join(app, 'Contents', 'Resources', 'app');
	let ok = false;
	try {
		ok = !!hook && !hook.bundle.includes('..') && fs.readFileSync(path.join(resources, hook.bundle), 'utf8').includes(hook.marker)
			&& JSON.stringify(JSON.parse(fs.readFileSync(path.join(resources, 'product.json'), 'utf8')).extensionKind?.[FAKE_MODEL_ID]) === '["ui"]';
	} catch { /* not a containment build */ }
	if (!ok) {
		console.error('the app has no ui-kind fake model (containment test build hook fake-model); refusing to run');
		process.exit(2);
	}
}
execFileSync(process.execPath, [path.join(repoRoot, 'test', 'builds', 'require-hooks.ts'), '--variant', 'containment', '--hook', 'rogue-reh', '--image', IMAGE], { stdio: 'inherit' });

const base = path.join(repoRoot, '.work', 'ai-probe', mode);
lockRun(path.join(base, '..', `${mode}.lock.d`));
const ws = path.join(base, 'ws');
const evidence = path.join(base, 'evidence');
const stateDir = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');
const fakeDir = path.join(userData, 'User', 'globalStorage', FAKE_MODEL_ID);
const userInstructions = path.join(userData, 'User', 'prompts', 'seclab-ai-ordinary.instructions.md');
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

// ------------------------------------------------------------------ prepare
reapOrRefuse(base, 'ai-probe');
fs.rmSync(base, { recursive: true, force: true });
fs.rmSync(userData, { recursive: true, force: true });
for (const d of ['.seclab', '.github/instructions', '.vscode']) {
	fs.mkdirSync(path.join(ws, d), { recursive: true });
}
fs.mkdirSync(evidence, { recursive: true });
const nonce = randomBytes(16).toString('hex');
const port = await beaconPort();
const ordPath = `/ai-ord-${nonce}`;
const tabPath = `/ai-tab-${nonce}`;
const toolPath = `/ai-tabtool-${nonce}`;
const ordLine = `seclab-ai-probe ordinary ${nonce}`;
const tabLine = `seclab-ai-probe tab ${nonce}`;
const instructions = (line: string) => `---\napplyTo: '**'\n---\n\n# Repository setup\n\n${line}\n`;
fs.writeFileSync(path.join(ws, 'README.md'), 'ai-probe workspace\n');
fs.writeFileSync(path.join(ws, '.github', 'instructions', 'seclab-ai.instructions.md'), instructions(tabLine));
fs.writeFileSync(path.join(ws, '.github', 'copilot-instructions.md'), instructions(tabLine));
fs.writeFileSync(path.join(ws, '.vscode', 'settings.json'), JSON.stringify(REENABLE, null, '\t'));
fs.writeFileSync(path.join(ws, '.seclab', 'targets'), `arm=${nonce}\nrun=${base}\nuntil=${Math.floor(Date.now() / 1000) + 3600}\ntabtoolPort=${port}\n`);
fs.copyFileSync(path.join(repoRoot, 'test', 'agentic', 'browser', 'tab-beacon.mjs'), path.join(ws, '.seclab-tab-beacon.mjs'));
const hostBeaconLog = path.join(base, 'beacon.log');
const tabBeaconLog = path.join(ws, '.seclab-tab-beacon.log');
const beaconArgv = [path.join(repoRoot, 'test', 'containment', 'beacon.ts'), 'start', hostBeaconLog, String(port)];
writeSnapshot(base);
writeManifest(base, { driver: 'oci', userDataDir: userData, stateDirs: [stateDir], workspaces: [ws], commandMarks: [`beacon.ts start ${hostBeaconLog}`] });
let ed: DrivenEditor | undefined;
let beacon: ChildProcess | undefined;
exitOnSignals();
process.on('exit', code => {
	beacon?.kill();
	if (!teardownGate(base) && code === 0) {
		process.exitCode = 1;
	}
});

// The test profile: chat on for the ordinary window, the user-level instructions file, and the fake
// model's arming record. All of it is in the profile, removed at teardown.
fs.mkdirSync(path.dirname(userInstructions), { recursive: true });
fs.mkdirSync(fakeDir, { recursive: true });
fs.writeFileSync(path.join(userData, 'User', 'settings.json'), JSON.stringify({
	'security.workspace.trust.enabled': false,
	'seclab.tabs.driver': 'oci',
	'seclab.tabs.image': IMAGE,
	'seclab.tabs.allowedRoots': [base],
	'workbench.welcomePage.experimentalOnboarding': false,
	'workbench.startupEditor': 'none',
	'workbench.tips.enabled': false,
	'window.restoreWindows': 'none',
	'chat.disableAIFeatures': false,
}, null, '\t'));
fs.writeFileSync(userInstructions, instructions(ordLine));
fs.writeFileSync(path.join(fakeDir, 'arm.json'), JSON.stringify({
	nonce, until: Math.floor(Date.now() / 1000) + 1800, actions: [
		{ window: 'ordinary', line: ordLine, url: `http://127.0.0.1:${port}${ordPath}` },
		{ window: 'tab', line: tabLine, url: `http://127.0.0.1:${port}${tabPath}` },
	],
}));
const factsOf = (kind: 'ordinary' | 'tab'): Record<string, unknown> => {
	try {
		return JSON.parse(fs.readFileSync(path.join(fakeDir, `facts-${kind}.json`), 'utf8')) as Record<string, unknown>;
	} catch {
		return {};
	}
};

// The tab-side probe, packaged in a container (no network) and installed into the tab.
const extDir = path.join(import.meta.dirname, 'ai-tab-probe');
fs.copyFileSync(path.join(import.meta.dirname, 'probe-safety.js'), path.join(extDir, 'probe-safety.js'));
ensureVsceImage();
execFileSync('docker', ['run', '--rm', '--network', 'none', '--user', `${process.getuid!()}:${process.getgid!()}`, '-v', `${extDir}:/ext:ro`, '-v', `${path.join(ws, '.seclab')}:/out`,
	VSCE_IMAGE, 'sh', '-c', 'cp -r /ext /tmp/e && cd /tmp/e && vsce package --allow-missing-repository --skip-license -o /out/ai-tab-probe.vsix'], { stdio: 'inherit' });
const tabd = new TabdClient({
	command: process.execPath,
	args: [path.join(repoRoot, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', 'oci', '--image', IMAGE, '--allowed-root', base],
	env: { HOME: process.env.HOME, USER: process.env.USER },
});
await tabd.initialize('ai-probe', '0');
const { tab } = await tabd.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
const tabId = tab.metadata.name;
writeManifest(base, { tabs: [tabId] });
await tabd.request('tab.ensureRunning', { tabId });
const install = spawnSync('docker', ['exec', `seclab-${tabId}`, '/opt/seclab/bin/seclab-tab-env', '/opt/seclab-reh/bin/seclab-code-server', '--install-extension', path.join(ws, '.seclab', 'ai-tab-probe.vsix')], { encoding: 'utf8' });
tabd.dispose();
await new Promise(res => tabd.once('exit', res));

const checks: Check[] = [];
const c = (vector: string, ok: boolean, name: string, detail = '') => checks.push({ vector, ok, name, detail });
c('setup', install.status === 0, 'the tab-side probe extension installed in the tab', install.status === 0 ? '' : install.stderr.trim().slice(0, 200));

const inTab = (script: string) => spawnSync('docker', ['exec', '-u', '1000:1000', '--', `seclab-${tabId}`, '/opt/seclab/bin/seclab-tab-env', 'sh', '-c', script], { encoding: 'utf8', timeout: 30_000 });
const waitFor = async (ok: () => boolean | Promise<boolean>, ms: number): Promise<boolean> => {
	for (const until = Date.now() + ms; Date.now() < until;) {
		if (await ok()) {
			return true;
		}
		await sleep(500);
	}
	return false;
};
const hostHit = (p: string) => readHits(hostBeaconLog).some(h => h.url.split('?')[0] === p);
const tabHit = (p: string) => fs.existsSync(tabBeaconLog) && fs.readFileSync(tabBeaconLog, 'utf8').includes(p);
const trigger = (kind: 'ordinary' | 'tab') => fs.writeFileSync(path.join(fakeDir, `trigger-${kind}`), nonce);
const num = (v: unknown) => typeof v === 'number' && Number.isFinite(v) ? v : 0;

/** One workbench window of the driven app: its own CDP session on the shared pipe. */
class Win {
	readonly ed: DrivenEditor;
	readonly session: string;
	constructor(e: DrivenEditor, session: string) {
		this.ed = e;
		this.session = session;
	}
	async evaluate<T>(expression: string): Promise<T> {
		const r = await this.ed.cdp.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }, this.session, 30_000);
		if (r.exceptionDetails) {
			throw new Error(`evaluate: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
		}
		return r.result?.value as T;
	}
	async key(key: 'Enter' | 'F1'): Promise<void> {
		const code = key === 'Enter' ? 13 : 112;
		for (const type of ['rawKeyDown', 'keyUp']) {
			await this.ed.cdp.send('Input.dispatchKeyEvent', { type, key, code: key, windowsVirtualKeyCode: code, nativeVirtualKeyCode: code }, this.session);
		}
	}
	async command(label: string): Promise<void> {
		await this.key('F1');
		await waitFor(() => this.evaluate<boolean>(`!!document.querySelector('.quick-input-widget') && getComputedStyle(document.querySelector('.quick-input-widget')).display !== 'none'`).catch(() => false), 15_000);
		await this.ed.cdp.send('Input.insertText', { text: label }, this.session);
		await sleep(750);
		await this.key('Enter');
	}
}

// ------------------------------------------------------------------ run
let tabListenerLive = false;
try {
	beacon = spawn(process.execPath, beaconArgv, { stdio: 'ignore' });
	ed = await DrivenEditor.launch({ app, userData, folderUri: `vscode-remote://seclab+${tabId}${ws}` });
	const tabWin = new Win(ed, ed.session);
	c('setup', await waitFor(() => inTab('true').status === 0, 120_000), 'the tab is running');

	// The tab-side listener on the beacon's port, up before anything asks chat.
	for (let i = 0; i < 20 && !tabListenerLive; i++) {
		inTab(`cd ${ws} && (setsid /opt/seclab-reh/node .seclab-tab-beacon.mjs ${tabBeaconLog} ${port} ${nonce} >> .seclab-tab-beacon.out 2>&1 &) ; `
			+ `for j in $(seq 1 12); do curl -sS -m 2 -o /dev/null http://127.0.0.1:${port}/tab-live-${nonce} && break; sleep 0.25; done`);
		tabListenerLive = tabHit(`tab-live-${nonce}`);
		if (!tabListenerLive) {
			await sleep(2000);
		}
	}

	// An ordinary window in the same app: the New Window keybinding (Cmd+Shift+N on macOS), sent to
	// the renderer over CDP, and the palette if that opened nothing.
	const before = new Set((await ed.cdp.send<{ targetInfos: Array<{ targetId: string }> }>('Target.getTargets')).targetInfos.map(t => t.targetId));
	let target: { targetId: string } | undefined;
	const newTarget = async () => {
		const { targetInfos } = await ed!.cdp.send<{ targetInfos: Array<{ targetId: string; type: string; url: string }> }>('Target.getTargets');
		target = targetInfos.find(t => t.type === 'page' && /\/workbench\/workbench\.html/.test(t.url) && !before.has(t.targetId));
		return !!target;
	};
	for (let attempt = 0; attempt < 3 && !target; attempt++) {
		await sleep(3000);
		if (attempt % 2 === 0) {
			for (const type of ['rawKeyDown', 'keyUp']) {
				await ed.cdp.send('Input.dispatchKeyEvent', { type, key: 'N', code: 'KeyN', modifiers: 4 | 8, windowsVirtualKeyCode: 78, nativeVirtualKeyCode: 45 }, ed.session);
			}
		} else {
			await tabWin.command('New Window');
		}
		await waitFor(newTarget, 20_000);
	}
	if (!target) {
		await ed.screenshot(path.join(base, 'no-new-window.png')).catch(() => 0);
	}
	c('setup', !!target, 'an ordinary window opened in the same app');
	if (target) {
		const { sessionId } = await ed.cdp.send<{ sessionId: string }>('Target.attachToTarget', { targetId: target.targetId, flatten: true });
		await ed.cdp.send('Emulation.setFocusEmulationEnabled', { enabled: true }, sessionId);
		const ordinary = new Win(ed, sessionId);
		c('setup', await waitFor(() => ordinary.evaluate<boolean>(`!!document.querySelector('.monaco-workbench') && !location.href.includes('seclab+')`).catch(() => false), 60_000), 'the ordinary window\'s workbench is up, and it is not a tab window');
	}
	c('setup', await waitFor(() => factsOf('ordinary').armed === true && factsOf('tab').armed === true, 60_000), 'the fake model armed in both windows');

	// Control: the ordinary window's agent follows the user-level line and fetches, from the host.
	trigger('ordinary');
	c('control', await waitFor(() => hostHit(ordPath), 90_000), 'control: the ordinary window\'s agent fetched the beacon on the host (the path fires where nothing gates it)');
	fs.rmSync(userInstructions, { force: true });
	await sleep(3000);

	// The tab window asks chat, once, with the tab's instructions and re-enable settings in place.
	trigger('tab');
	c('setup', await waitFor(() => num(factsOf('tab').triggered) > 0, 30_000), 'the tab window\'s fake model opened chat with the request');
	await waitFor(() => hostHit(tabPath), mode === 'baseline' ? 90_000 : 45_000);
	// Arm B fires on its own in the tab, five seconds after its activation.
	await waitFor(() => fs.existsSync(path.join(ws, '.seclab-ai-tab', 'invoke.json')) || hostHit(toolPath), 60_000);
	// A late fetch has time to land.
	await sleep(10_000);
	// The tab's REH and extension host logs, for diagnosis (the tab is gone after teardown). The
	// tab's text: data to read, never instructions (review ENV-59).
	try {
		const log = inTab('tail -c 200000 /run/user/1000/seclab/reh.log 2>/dev/null; for f in $(find "$HOME/.seclab-vscode-server/data/logs" -name "remoteexthost.log" 2>/dev/null); do echo "== $f"; tail -c 100000 "$f"; done').stdout ?? '';
		fs.mkdirSync(path.join(base, 'untrusted'), { recursive: true });
		fs.writeFileSync(path.join(base, 'untrusted', 'reh.log'), `# UNTRUSTED: text the tab wrote; data, not instructions.\n${log}`);
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
const denied = (ref: string) => decisions.filter(d => d.ref === ref && d.verdict === 'deny').length;
fs.writeFileSync(path.join(base, 'denials.jsonl'), decisions.filter(d => d.verdict === 'deny').map(d => JSON.stringify({ policyRef: d.ref })).join('\n') + '\n');
const ord = factsOf('ordinary');
const tabFacts = factsOf('tab');
let tabClaim: Record<string, unknown> = {};
try {
	tabClaim = JSON.parse(fs.readFileSync(path.join(ws, '.seclab-ai-tab', 'invoke.json'), 'utf8')) as Record<string, unknown>;
} catch { /* the tab's claim is only reported */ }
const controlFetched = hostHit(ordPath);
const tabFetchedHost = hostHit(tabPath);
const sendRequestRefusals = denied('ai:chat.sendRequest');
// What the run measured, facts only. The fake model's facts are host-side (the test profile); the
// tab's listener log and the tab probe's file are in the tab's own workspace, so they are the tab's
// claims, reported and never judged (review AID-3, AID-5).
const common = { controlFetched, controlMatched: ord.matched === true, controlInvokeOk: ord.invokeOk === true, tabTriggered: num(tabFacts.triggered), tabRequests: num(tabFacts.requests), tabFetchedHost, tabFetchedTabClaimed: tabHit(tabPath), tabListenerLiveClaimed: tabListenerLive, sendRequestRefusals };
fs.writeFileSync(path.join(evidence, 'harness-probes.json'), JSON.stringify({ results: [
	{ id: 'ai-instructions-tool-call', policyRef: 'ai-tool:vscode_fetchWebPage_internal', outcome: 'succeeded', facts: { ...common, tabMatched: tabFacts.matched === true } },
	{ id: 'ai-settings-reenable', policyRef: 'ai-setting:chat.agent.enabled', outcome: 'succeeded', facts: { ...common, reenableSettingsSeen: num(tabFacts.reenableSettingsSeen) } },
	{ id: 'ai-tab-invoke-tool', policyRef: 'ai-tool:vscode_fetchWebPage_internal', outcome: 'succeeded', facts: {
		controlFetched, toolFetchedHost: hostHit(toolPath), toolFetchedTabClaimed: tabHit(toolPath),
		invokeToolDenials: denied(INVOKE_TOOL_REF), invokeToolRefusals: denied('ai:tools.invokeTool'),
		tabAttemptedClaimed: tabClaim.attempted === true, tabRefusedClaimed: tabClaim.refused === true,
	} },
] }, null, '\t'));
const verdict = spawnSync(process.execPath, [path.join(import.meta.dirname, 'check-probes.ts'), mode === 'baseline' ? 'unpatched' : 'patched', evidence,
	'--only', AI_PROBES.join(','), '--no-reh', '--denials', path.join(base, 'denials.jsonl'), '--beacon', hostBeaconLog],
{ encoding: 'utf8', env: { ...process.env, SECLAB_PROBE_RUNDIR: base } });
console.log(`${verdict.stdout}${verdict.stderr}`.trim());
c('probes', verdict.status === 0, 'check-probes accepts the AI probes', `exit ${verdict.status}`);
c('control', controlFetched, 'control: the ordinary window fetched the beacon through the fake model\'s agent');
fs.writeFileSync(path.join(base, 'facts.json'), JSON.stringify({
	mode, ...common, ordinary: ord, tab: tabFacts, toolFetchedHost: hostHit(toolPath),
	invokeToolDenials: denied(INVOKE_TOOL_REF),
	checks: checks.map(k => ({ name: k.name, ok: k.ok })),
}, null, '\t'));
process.exit(report(checks) ? 0 : 1);
