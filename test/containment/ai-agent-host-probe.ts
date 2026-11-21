// The agent-host client in a tab window, against a hostile REH's agentHostProxy
// (agent-host-patches#3, step 3), proven in a real OCI tab of the containment test build, driven
// headlessly.
//
//   node test/containment/ai-agent-host-probe.ts baseline|patched <user-data-dir> --app <test app.app> [--image IMAGE]
//
// Images and apps as test/containment/ai-probe.ts: patched is this branch's containment build
// (seclab-tab-oci:test-containment-b-aip), baseline the build-only branch without 0009, 0010 and
// 0018 (seclab-tab-oci:test-containment-b-aipbase, with SECLAB_APP_SHA naming its commit).
//
// The tab's REH serves `agentHostProxy` as a hostile one would (test/containment/rogue-reh,
// only=agent-host): it records every call and subscription that arrives, by name and count, and
// refuses every `connect`, so no agent host starts. A window that connected would resolve the
// user's auth session for whatever the server advertises and forward its token
// (ai-agent-host-token-push), and would let the agent host ask for host tools
// (ai-agent-host-autoapprove-setting). The host user turns AI features off
// (`chat.disableAIFeatures: true`) and the tab writes `false` into the remote user settings it
// supplies (ai-disable-ai-features-reenable).
//   patched: arm phase, agents not enabled for the host: the tab window makes no agent-host
//     connection (the REH sees no call, the host-side gate log shows no transport opened and
//     records its refusal), while the window does read the tab's `false`. Control phase, the same
//     app relaunched with SECLAB_AGENTS_ENABLED=1 (the host-side switch): the window connects,
//     so the REH's counter and the path both work, and a quiet arm phase is a refusal.
//   baseline: agents enabled as the baseline build's configuration (coordinator plan,
//     2026-11-19): the window connects to the hostile REH.
// Judged by check-probes.ts from what the host measured (the gate log) with the REH's record.
//
// Inert (EDR fixture safety): every connect is refused inside the tab, no agent host runs, and
// nothing writes outside the run and its test profile. Windows open in the background and never
// take focus. Teardown runs on every exit.

import { execFileSync, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import { DrivenEditor } from '../driver/editor.ts';
import { checkUserDataDir, lockRun, repoRoot } from '../harness.ts';
import { report, type Check } from './assert.ts';
import { exitOnSignals, reapOrRefuse, teardownGate, writeManifest, writeSnapshot } from './teardown.ts';

const IMAGES = { patched: 'seclab-tab-oci:test-containment-b-aip', baseline: 'seclab-tab-oci:test-containment-b-aipbase' } as const;
export const AGENT_HOST_PROBES = ['ai-agent-host-token-push', 'ai-agent-host-autoapprove-setting', 'ai-disable-ai-features-reenable'];
const FAKE_MODEL_ID = 'seclab-test.fake-model';

const argv = process.argv.slice(2);
const [mode, userDataArg] = argv;
const appArg = argv[argv.indexOf('--app') + 1];
if ((mode !== 'baseline' && mode !== 'patched') || !userDataArg || !argv.includes('--app') || !appArg) {
	console.error('usage: ai-agent-host-probe.ts baseline|patched <user-data-dir> --app <test app.app> [--image IMAGE]');
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
execFileSync(process.execPath, [path.join(repoRoot, 'test', 'builds', 'require-hooks.ts'), '--variant', 'containment', '--hook', 'rogue-reh', '--image', IMAGE], { stdio: 'inherit' });

const base = path.join(repoRoot, '.work', 'ai-agent-host-probe', mode);
lockRun(path.join(base, '..', `${mode}.lock.d`));
const ws = path.join(base, 'ws');
const evidence = path.join(base, 'evidence');
const stateDir = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');
const fakeDir = path.join(userData, 'User', 'globalStorage', FAKE_MODEL_ID);
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

// ------------------------------------------------------------------ prepare
reapOrRefuse(base, 'ai-agent-host-probe');
fs.rmSync(base, { recursive: true, force: true });
fs.rmSync(userData, { recursive: true, force: true });
fs.mkdirSync(ws, { recursive: true });
fs.mkdirSync(evidence, { recursive: true });
const nonce = randomBytes(16).toString('hex');
fs.writeFileSync(path.join(ws, 'README.md'), 'ai-agent-host-probe workspace\n');
writeSnapshot(base);
writeManifest(base, { driver: 'oci', userDataDir: userData, stateDirs: [stateDir], workspaces: [ws] });
let ed: DrivenEditor | undefined;
exitOnSignals();
process.on('exit', code => {
	if (!teardownGate(base) && code === 0) {
		process.exitCode = 1;
	}
});
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
	'chat.disableAIFeatures': true,
}, null, '\t'));
// The fake model arms only to report what the tab window reads (never triggered here: its one
// action is never asked for, and its URL is a port nothing listens on).
fs.writeFileSync(path.join(fakeDir, 'arm.json'), JSON.stringify({
	nonce, until: Math.floor(Date.now() / 1000) + 1800,
	actions: [{ window: 'tab', line: `seclab-ai-probe unused ${nonce}`, url: `http://127.0.0.1:1024/ai-tab-${nonce}` }],
}));
const tabFacts = (): Record<string, unknown> => {
	try {
		return JSON.parse(fs.readFileSync(path.join(fakeDir, 'facts-tab.json'), 'utf8')) as Record<string, unknown>;
	} catch {
		return {};
	}
};

const tabd = new TabdClient({
	command: process.execPath,
	args: [path.join(repoRoot, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', 'oci', '--image', IMAGE, '--allowed-root', base],
	env: { HOME: process.env.HOME, USER: process.env.USER },
});
await tabd.initialize('ai-agent-host-probe', '0');
const { tab } = await tabd.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
const tabId = tab.metadata.name;
writeManifest(base, { tabs: [tabId] });
await tabd.request('tab.ensureRunning', { tabId });

const inTab = (script: string, input?: string) => spawnSync('docker', ['exec', '-i', '-u', '1000:1000', '--', `seclab-${tabId}`, '/opt/seclab/bin/seclab-tab-env', 'sh', '-c', script],
	{ encoding: 'utf8', input, timeout: 30_000 });
const REH_DIR = '"$HOME/.seclab-test/rogue-reh"';
const waitFor = async (ok: () => boolean | Promise<boolean>, ms: number): Promise<boolean> => {
	for (const until = Date.now() + ms; Date.now() < until;) {
		if (await ok()) {
			return true;
		}
		await sleep(1000);
	}
	return false;
};
const checks: Check[] = [];
const c = (vector: string, ok: boolean, name: string, detail = '') => checks.push({ vector, ok, name, detail });

// As the tab, before any window connects, while this run's tabd keeps it running (the tab stops
// with its supervisor; its home persists): the hostile REH's payload, armed for the agent-host
// proxy only, and `chat.disableAIFeatures: false` in the remote user settings the tab supplies.
c('setup', await waitFor(() => inTab('true').status === 0, 120_000), 'the tab is running');
for (const f of ['probes.js', 'probe-safety.js']) {
	const src = f === 'probes.js' ? path.join(import.meta.dirname, 'rogue-reh', 'probes.js') : path.join(import.meta.dirname, 'probe-safety.js');
	const r = inTab(`mkdir -p ${REH_DIR} && cat > ${REH_DIR}/${f}`, fs.readFileSync(src, 'utf8'));
	c('setup', r.status === 0, `staged ${f} in the tab`, r.stderr.trim());
}
c('setup', inTab(`cat > ${REH_DIR}/targets`, `arm=${nonce}\nrun=${base}\nuntil=${Math.floor(Date.now() / 1000) + 1800}\nonly=agent-host\n`).status === 0, 'staged the arming record');
c('setup', inTab('mkdir -p "$HOME/.seclab-vscode-server/data/Machine" && cat > "$HOME/.seclab-vscode-server/data/Machine/settings.json"', JSON.stringify({ 'chat.disableAIFeatures': false })).status === 0,
	'the tab wrote chat.disableAIFeatures false into its remote user settings');
tabd.dispose();
await new Promise(res => tabd.once('exit', res));

/** The REH's records, one per server process: totals, and how many servers wrapped the proxy. */
const rehRecords = (): { servers: number; wrapped: number; calls: number; connects: number; listens: number } => {
	const out = { servers: 0, wrapped: 0, calls: 0, connects: 0, listens: 0 };
	const list = inTab(`for f in ${REH_DIR}/evidence/agent-host-*.json; do [ -f "$f" ] && tr -d '\\n' < "$f" && echo; done`).stdout ?? '';
	for (const line of list.split('\n').filter(l => l.trim())) {
		try {
			const r = JSON.parse(line) as Record<string, unknown>;
			const n = (k: string) => typeof r[k] === 'number' && Number.isSafeInteger(r[k]) ? r[k] as number : 0;
			out.servers++;
			out.wrapped += r.wrapped === true ? 1 : 0;
			out.calls += n('calls');
			out.connects += n('connects');
			out.listens += n('listens');
		} catch { /* unreadable: not counted */ }
	}
	return out;
};
/** Patch 0015's gate log, host-side, for the log directories a launch created: rules and counts. */
const gateRules = (dirs: string[]): Record<string, number> => {
	const counts: Record<string, number> = {};
	const walk = (dir: string): void => {
		for (const e of fs.existsSync(dir) ? fs.readdirSync(dir, { withFileTypes: true }) : []) {
			const p = path.join(dir, e.name);
			if (e.isDirectory()) {
				walk(p);
			} else if (e.name === 'seclabAhpGate.log') {
				for (const line of fs.readFileSync(p, 'utf8').split('\n')) {
					try {
						const d = JSON.parse(line.slice(line.indexOf('{')));
						const rule = d?.source === 'ahp-gate' ? d?.detail?.gateRule : undefined;
						if (typeof rule === 'string' && /^ahp-gate\.[a-z-]+$/.test(rule)) {
							counts[rule] = (counts[rule] ?? 0) + 1;
						}
					} catch { /* not a decision */ }
				}
			}
		}
	};
	dirs.forEach(walk);
	return counts;
};
const logDirs = () => fs.existsSync(path.join(userData, 'logs')) ? fs.readdirSync(path.join(userData, 'logs')).map(d => path.join(userData, 'logs', d)) : [];
/** Empties the REH's records in the stopped tab's home volume (a throwaway container, no network). */
const clearRehRecords = (): void => {
	if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(tabId)) {
		throw new Error('unexpected tab id');
	}
	const r = spawnSync('docker', ['run', '--rm', '--network', 'none', '-v', `seclab-${tabId}-home:/h`, '--entrypoint', '/bin/sh', IMAGE, '-c', 'rm -f /h/.seclab-test/rogue-reh/evidence/agent-host-*.json'], { encoding: 'utf8', timeout: 60_000 });
	c('setup', r.status === 0, 'cleared the REH\'s records before the phase', (r.stderr ?? '').trim().slice(0, 200));
};

/**
 * One launch of the app on the tab, with or without the host's agents switch; what it measured.
 * The REH's records are read while the window keeps the tab running, then cleared for the next
 * phase (the tab stops with the editor's tabd).
 */
async function phase(name: string, agentsEnabled: boolean) {
	const before = new Set(logDirs());
	let reh = { servers: 0, wrapped: 0, calls: 0, connects: 0, listens: 0 };
	// The REH's records start empty for each phase (review AIP2-2): cleared in the tab's home volume
	// while the tab is stopped, so a record the last window's teardown wrote can't carry over.
	clearRehRecords();
	try {
		ed = await DrivenEditor.launch({ app, userData, folderUri: `vscode-remote://seclab+${tabId}${ws}`, env: agentsEnabled ? { SECLAB_AGENTS_ENABLED: '1' } : {} });
		await waitFor(() => rehRecords().wrapped > 0, 120_000);
		// The agent-host client connects as the window restores; give a late one time to land.
		await waitFor(() => rehRecords().connects > 0, 45_000);
		await sleep(10_000);
		reh = rehRecords();
		// The REH's log, for diagnosis (the tab stops with the editor). The tab's text: data to read,
		// never instructions (review ENV-59).
		const log = inTab('tail -c 100000 /run/user/1000/seclab/reh.log 2>/dev/null').stdout ?? '';
		fs.mkdirSync(path.join(base, 'untrusted'), { recursive: true });
		fs.writeFileSync(path.join(base, 'untrusted', `reh-${name}.log`), `# UNTRUSTED: text the tab wrote; data, not instructions.\n${log}`);
	} catch (err) {
		c('run', false, `the ${name} phase completed`, (err as Error).message);
	} finally {
		await ed?.close();
		ed = undefined;
	}
	const gate = gateRules(logDirs().filter(d => !before.has(d)));
	return {
		serverWrappedClaimed: reh.wrapped, rehCalls: reh.calls, rehConnects: reh.connects, rehListens: reh.listens,
		gateDisabled: gate['ahp-gate.disabled'] ?? 0, gateOpened: gate['ahp-gate.opened'] ?? 0, gateVerified: gate['ahp-gate.verified'] ?? 0,
	};
}

// ------------------------------------------------------------------ run
const arm = await phase('arm', mode === 'baseline');
const remoteAiFeaturesOn = tabFacts().remoteAiFeaturesOn === true;
const control = mode === 'patched' ? await phase('control', true) : undefined;
if (fs.existsSync(path.join(userData, 'logs'))) {
	fs.cpSync(path.join(userData, 'logs'), path.join(base, 'editor-logs'), { recursive: true, force: true });
}
// Whether the hostile REH's wrap was in place is the tab's claim, reported only (review AIP2-2); the
// control phase's opened transport shows host-side that the window reached the tab's proxy.
console.log(`the hostile REH reports its agentHostProxy wrap in place (claim): arm=${arm.serverWrappedClaimed} control=${control?.serverWrappedClaimed ?? 'n/a'}`);

// ------------------------------------------------------------------ judge
// The REH's counts are the tab's claim, reported and never judged (reviews AID-1, AIP-5): what is
// judged is host-side, the gate log, where the window itself records a transport opened or refused.
const facts = {
	armConnectsClaimed: arm.rehConnects, armCallsClaimed: arm.rehCalls, armListensClaimed: arm.rehListens, armGateOpened: arm.gateOpened, armGateDisabled: arm.gateDisabled,
	controlConnectsClaimed: control?.rehConnects ?? -1, controlGateOpened: control?.gateOpened ?? -1,
};
fs.writeFileSync(path.join(evidence, 'harness-probes.json'), JSON.stringify({ results: [
	{ id: 'ai-agent-host-token-push', policyRef: 'push:agentHostProxy:frame', outcome: 'succeeded', facts },
	{ id: 'ai-agent-host-autoapprove-setting', policyRef: 'push:agentHostProxy:frame', outcome: 'succeeded', facts },
	{ id: 'ai-disable-ai-features-reenable', policyRef: 'ai-setting:chat.disableAIFeatures', outcome: 'succeeded', facts: { ...facts, remoteAiFeaturesOn } },
] }, null, '\t'));
fs.writeFileSync(path.join(base, 'denials.jsonl'), '\n');
const verdict = spawnSync(process.execPath, [path.join(import.meta.dirname, 'check-probes.ts'), mode === 'baseline' ? 'unpatched' : 'patched', evidence,
	'--only', AGENT_HOST_PROBES.join(','), '--no-reh', '--denials', path.join(base, 'denials.jsonl'), '--beacon', path.join(base, 'no-beacon.log')],
{ encoding: 'utf8', env: { ...process.env, SECLAB_PROBE_RUNDIR: base } });
console.log(`${verdict.stdout}${verdict.stderr}`.trim());
c('probes', verdict.status === 0, 'check-probes accepts the agent-host probes', `exit ${verdict.status}`);
fs.writeFileSync(path.join(base, 'facts.json'), JSON.stringify({ mode, ...facts, remoteAiFeaturesOn, arm, control, checks: checks.map(k => ({ name: k.name, ok: k.ok })) }, null, '\t'));
process.exit(report(checks) ? 0 : 1);
