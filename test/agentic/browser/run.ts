// Increment 2 (patch 0017): where does a browser view's page actually get fetched from?
//
//   node test/agentic/browser/run.ts prepare <user-data-dir> --build u|f [--driver sbx|oci]
//   node test/agentic/browser/run.ts check   <user-data-dir> [--phase first|restore]
//
// The question, from the increment 2 EDR. Two settings decide whether a browser view in a
// `seclab+` window fetches on the TAB's network or the HOST's, and a tab can write both:
//   - `workbench.browser.enableRemoteProxy`: off => the public `resolveNetwork` yields
//     undefined => the page loads on the host network;
//   - `workbench.browser.dataStorage`: `global` => upstream drops the network entirely, so
//     even with the proxy on the page lands on the host network and the host's cookie jar.
// Patch 0017 fixes both in a tab window (`true`, `ephemeral`). This run measures it.
//
// WHAT COUNTS AS EVIDENCE. Not absence. Two independent facts are read on every run:
//   1. the HOST beacon. A hit means the page was fetched from the host network. The beacon
//      binds 127.0.0.1 and is unreachable from inside a tab (the fence allows the broker
//      port only), so a hit can only have come from the host side.
//   2. the hook's own line in the window log, which records the network the browser service
//      RESOLVED for the page: `network=none` (host) or `network=seclab+<tab>` (the tab).
// Fact 2 is what makes a quiet run meaningful: a build that simply never opened a page also
// produces no beacon hit, and only the resolved network tells the two apart. A run whose
// hook never fired is INCONCLUSIVE, never "contained".
//
// The tab is hostile in the way the threat model says it can be: before the window starts,
// the run writes the two settings into the REH's remote user settings, which is the layer a
// tab controls. On an unfixed build the window obeys them.
//
// Inert (EDR fixture safety): the only network target is this run's loopback beacon, the
// only marker is under the run directory, and the build hook is armed by a host-side file
// with a per-run nonce and an expiry that fails closed.

import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { TabdClient } from '../../../tabd/src/client.ts';
import { beaconPort, checkIsolatedProfile, checkUserDataDir, editorLaunchCommand, lockRun, repoRoot } from '../../harness.ts';
import { report, type Check } from '../../containment/assert.ts';
import { beaconSpawn } from '../runner/marks.ts';
import { reapPreviousRun, teardownGate, writeManifest, writeSnapshot } from '../../containment/teardown.ts';

const argv = process.argv.slice(2);
const mode = argv.shift();
const userDataArg = argv.shift();
const opt = (name: string, fallback?: string): string | undefined => {
	const i = argv.indexOf(`--${name}`);
	return i >= 0 ? argv[i + 1] : fallback;
};
if ((mode !== 'prepare' && mode !== 'check') || !userDataArg) {
	console.error('usage: run.ts prepare|check <user-data-dir> [--build u|f] [--driver sbx|oci] [--phase first|restore]');
	process.exit(2);
}
const userData = path.resolve(userDataArg);
checkUserDataDir(userData);
const driver = opt('driver', 'sbx')!;
const base = path.join(repoRoot, '.work', 'agentic-browser');
const ws = path.join(base, 'ws');
checkIsolatedProfile(path.join(base, 'ws'));
const stateDir = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');
const beaconLog = path.join(base, 'beacon.log');
const runFacts = path.join(base, 'probe.json');
/** The host-side file the browser-drive hook reads. Fixed path, never from the environment. */
const armDir = path.join(os.homedir(), '.seclab-test', 'browser-drive');

/**
 * U is main without 0017; F is this branch with it. Both carry the `agentic-browser` hook,
 * and both are UNSAFE test builds: the app is renamed by the variant build and lands in the
 * variant's own directory, never the release location.
 */
const VARIANT_APP = 'seclab-vscode UNSAFE TEST BUILD (agentic-browser).app';
const APPS: Record<string, string> = {
	u: path.join(repoRoot, '.work', 'ubranch', '.work', 'test-builds', 'agentic-browser', VARIANT_APP),
	f: path.join(repoRoot, '.work', 'test-builds', 'agentic-browser', VARIANT_APP),
};

function tabExec(name: string, args: string[]): { status: number | null; stdout: string; stderr: string } {
	const runtime = driver === 'sbx' ? '/opt/homebrew/bin/sbx' : 'docker';
	const user = driver === 'sbx' ? ['-u', 'agent'] : [];
	const r = spawnSync(runtime, ['exec', ...user, `seclab-${name}`, ...args], { encoding: 'utf8' });
	return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

/** Every line of the window's own logs. The hook writes through ILogService. */
function readWindowLog(dir: string): string[] {
	const out: string[] = [];
	const logs = path.join(dir, 'logs');
	const stack = fs.existsSync(logs) ? [logs] : [];
	while (stack.length) {
		const d = stack.pop()!;
		for (const e of fs.readdirSync(d, { withFileTypes: true })) {
			const p = path.join(d, e.name);
			if (e.isDirectory()) {
				stack.push(p);
			} else if (e.name.endsWith('.log')) {
				out.push(...fs.readFileSync(p, 'utf8').split('\n'));
			}
		}
	}
	return out;
}

if (mode === 'prepare') {
	const build = (opt('build') ?? '') as 'u' | 'f';
	if (build !== 'u' && build !== 'f') {
		console.error('prepare needs --build u (main, no 0017) or --build f (this branch)');
		process.exit(2);
	}
	const app = APPS[build];
	const buildInfo = path.join(path.dirname(app), 'build-info-app.json');
	if (!fs.existsSync(app) || !fs.existsSync(buildInfo)) {
		console.error(`no app or build-info.json for build ${build} at ${app}\n` +
			'fetch it first: ./seclab fetch macos-agentic-browser <run-id> (for u, run it from .work/ubranch)');
		process.exit(2);
	}
	if (fs.existsSync(stateDir)) {
		const old = new TabdClient({
			command: process.execPath,
			args: [path.join(repoRoot, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', driver, '--allowed-root', base],
			env: { HOME: process.env.HOME, USER: process.env.USER },
		});
		await old.initialize('agentic-browser-cleanup', '0');
		for (const t of (await old.request<{ tabs: Array<{ metadata: { name: string } }> }>('tab.list')).tabs) {
			await old.request('tab.remove', { tabId: t.metadata.name }).catch(() => undefined);
		}
		old.dispose();
		fs.rmSync(stateDir, { recursive: true, force: true });
	}
	lockRun(path.join(base, '..', `${path.basename(base)}.lock.d`));
	const reaped = reapPreviousRun(base);
	if (reaped.refused) {
		for (const p of [...reaped.problems, ...reaped.survivors.map(s => `${s.pid} ${s.args.slice(0, 160)}`)]) {
			console.error(`prepare: ${p}`);
		}
		console.error(`prepare: refusing to wipe ${base}: the previous run could not be reaped.`);
		process.exit(1);
	}
	fs.rmSync(base, { recursive: true, force: true });
	fs.mkdirSync(ws, { recursive: true });
	fs.writeFileSync(path.join(ws, 'README.md'), '# agentic browser probe workspace\n\nInert: the probe is driven by the build hook, not by this folder.\n');

	const arm = randomBytes(16).toString('hex');
	// Created BEFORE the snapshot: it lives under the user's home, so a directory made after
	// the baseline makes teardown report `~/` as changed.
	fs.rmSync(armDir, { recursive: true, force: true });
	fs.mkdirSync(armDir, { recursive: true, mode: 0o700 });
	const port = await beaconPort();
	const beacon = beaconSpawn(repoRoot, beaconLog, port);
	spawn(process.execPath, beacon.argv, { detached: true, stdio: 'ignore' }).unref();
	writeSnapshot(base);
	writeManifest(base, { driver, userDataDir: userData, stateDirs: [stateDir], commandMarks: [beacon.mark] });

	// The probe URL. Loopback only, and unique to this run so a hit cannot be anything else.
	const probeUrl = `http://127.0.0.1:${port}/browser-probe-${arm}`;
	fs.mkdirSync(path.join(userData, 'User'), { recursive: true });
	fs.writeFileSync(path.join(userData, 'seclab-run-build.json'), JSON.stringify({ build, app, buildInfo: JSON.parse(fs.readFileSync(buildInfo, 'utf8')) }, null, '\t'));
	// The HOST profile leaves both settings alone: the point is that the TAB sets them, and
	// that a fixed build ignores it.
	fs.writeFileSync(path.join(userData, 'User', 'settings.json'), JSON.stringify({
		'security.workspace.trust.enabled': false,
		'seclab.tabs.driver': driver,
		'seclab.tabs.allowedRoots': [base],
	}, null, '\t'));

	const client = new TabdClient({
		command: process.execPath,
		args: [path.join(repoRoot, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', driver, '--allowed-root', base],
		env: { HOME: process.env.HOME, USER: process.env.USER },
	});
	await client.initialize('agentic-browser', '0');
	const { tab } = await client.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
	const tabId = tab.metadata.name;
	writeManifest(base, { tabs: [tabId] });
	await client.request('tab.ensureRunning', { tabId });

	// THE TAB ACTS. Both settings go into the REH's remote user settings, the layer a tab
	// controls (REMOTE_MACHINE_SCOPES covers every non-APPLICATION scope, and both of these
	// are WINDOW). An unfixed window obeys them and puts the page on the host network.
	// The sentinel is a neutral WINDOW-scoped key that 0017 does NOT fix, so it becomes
	// visible on both builds once the tab's remote layer is applied. The hook waits for it
	// before measuring: without that wait the hook ran before the remote configuration had
	// loaded, read the registered default, and reported the tab's network on a build that
	// would have obeyed the tab a second later. U looked contained. That is the
	// false-negative this whole runner exists to prevent.
	const sentinel = 37_000 + Math.floor(Math.random() * 1000);
	const remoteSettings = JSON.stringify({
		'workbench.browser.enableRemoteProxy': false,
		'workbench.browser.dataStorage': 'global',
		'workbench.browser.maxHistoryEntries': sentinel,
	});
	const wrote = tabExec(tabId, ['sh', '-c',
		`mkdir -p ~/.seclab-vscode-server/data/Machine && cat > ~/.seclab-vscode-server/data/Machine/settings.json <<'EOF'\n${remoteSettings}\nEOF\ncat ~/.seclab-vscode-server/data/Machine/settings.json`]);
	if (wrote.status !== 0 || !wrote.stdout.includes('dataStorage')) {
		console.error(`prepare: could not write the tab's remote settings: ${wrote.stderr.slice(0, 300)}`);
		process.exit(1);
	}
	console.log(`prepare: the tab wrote ${wrote.stdout.trim()}`);

	// Arm the build hook, on the HOST. `until` is epoch milliseconds; the hook fails closed
	// on anything malformed.
	fs.writeFileSync(path.join(armDir, 'targets'), `arm=${arm}\nurl=${probeUrl}\nready=${sentinel}\nuntil=${Date.now() + 10 * 60_000}\n`, { mode: 0o600 });

	fs.writeFileSync(runFacts, JSON.stringify({ build, tabId, arm, probeUrl, beaconPort: port, sentinel }, null, '\t'));
	client.dispose(); // stops the tab; the editor restarts it
	await new Promise(res => client.once('exit', res));

	const folderUri = `vscode-remote://seclab+${tabId}${ws}`;
	console.log(`\nprepared tab ${tabId} for build ${build} (${app})\n`);
	console.log('now launch the window in the BACKGROUND (never activated; AGENTS.md):\n');
	console.log(`  ${editorLaunchCommand(userData, folderUri, {}, app)}\n`);
	console.log(`then, after about 60s:  node test/agentic/browser/run.ts check ${userData}`);
	process.exit(0);
}

// ---- check ---------------------------------------------------------------------------

const facts = JSON.parse(fs.readFileSync(runFacts, 'utf8')) as {
	build: 'u' | 'f'; tabId: string; arm: string; probeUrl: string; beaconPort: number;
};
const phase = opt('phase', 'first')!;
const checks: Check[] = [];

const recorded = JSON.parse(fs.readFileSync(path.join(userData, 'seclab-run-build.json'), 'utf8')) as { build: string; buildInfo: { repoSha: string } };
checks.push({
	vector: 'build', name: 'ran the requested build', ok: recorded.build === facts.build,
	detail: `${recorded.build} (repo ${recorded.buildInfo.repoSha.slice(0, 7)})`,
});

// Fact 2, and the one that makes a quiet run mean anything: the network the browser service
// resolved for the page, from the hook's own line in the window log.
const hookLines = readWindowLog(userData).filter(l => l.includes('SECLAB_TEST_ONLY:browser-drive-hook'));
const opened = hookLines.filter(l => l.includes(' opening '));
const resolvedNetwork = /network=(\S+)/.exec(opened[opened.length - 1] ?? '')?.[1];
checks.push({
	vector: 'hook', name: 'the build hook drove a page open (otherwise the run is inconclusive)', ok: opened.length > 0,
	detail: opened.length ? `${opened.length} open(s), last network=${resolvedNetwork}` : `no open line; ${hookLines.length} hook line(s) total`,
});
// The measurement is only about the tab's settings if the tab's settings were in force when
// it happened. The hook waits for its sentinel and says so; a run that measured before the
// remote layer landed is INCONCLUSIVE, not contained.
checks.push({
	vector: 'hook', name: "the tab's remote settings were in force when the page was opened", ok: hookLines.some(l => l.includes('ready=yes')),
	detail: hookLines.filter(l => l.includes('ready=')).slice(-1)[0]?.slice(-80) ?? 'no readiness line',
});

// Fact 1: the host beacon. Reachable only from the host side.
const beaconHits = fs.existsSync(beaconLog) ? fs.readFileSync(beaconLog, 'utf8').trim().split('\n').filter(Boolean) : [];
const probeHits = beaconHits.filter(l => l.includes(`browser-probe-${facts.arm}`));

if (facts.build === 'u') {
	checks.push({
		vector: 'U', name: "VULNERABLE: the tab's settings put the page on the HOST network", ok: resolvedNetwork === 'none',
		detail: `resolved network=${resolvedNetwork} (the tab asked for enableRemoteProxy=false, dataStorage=global)`,
	});
	checks.push({
		vector: 'U', name: 'and the host beacon saw the fetch', ok: probeHits.length > 0,
		detail: `${probeHits.length} hit(s) for this run's probe URL`,
	});
} else {
	checks.push({
		vector: 'F', name: "CONTAINED: the page resolved to the TAB's network despite the tab's settings", ok: resolvedNetwork === `seclab+${facts.tabId}`,
		detail: `resolved network=${resolvedNetwork}, expected seclab+${facts.tabId}`,
	});
	checks.push({
		vector: 'F', name: 'and the host beacon saw nothing', ok: probeHits.length === 0,
		detail: `${probeHits.length} hit(s); total beacon hits ${beaconHits.length}`,
	});
	// The pair is one control: the proxy keeps the network, the storage scope stops the tab
	// removing it. `global` would have dropped the network even with the proxy on.
	checks.push({
		vector: 'F', name: "the tab's `dataStorage: global` did not take the network away", ok: resolvedNetwork !== 'none',
		detail: `the tab wrote global; resolved network=${resolvedNetwork}`,
	});
}
if (phase === 'restore') {
	checks.push({
		vector: 'restore', name: 'the restored window resolved the same network as the first launch', ok: facts.build === 'u' ? resolvedNetwork === 'none' : resolvedNetwork === `seclab+${facts.tabId}`,
		detail: `restored: resolved network=${resolvedNetwork}, host hits ${probeHits.length}`,
	});
}

const ok = report(checks);
fs.writeFileSync(path.join(base, `verdict-${phase}.json`), JSON.stringify({
	build: facts.build, phase, ok, resolvedNetwork, probeHits: probeHits.length, beaconHits: beaconHits.length, hookLines: hookLines.length,
}, null, '\t'));
// The first phase leaves the run up so the restore phase can relaunch the same profile.
if (phase === 'restore') {
	fs.rmSync(armDir, { recursive: true, force: true });
	// Evaluated FIRST and on its own line: `ok && teardownGate(base)` short-circuits, so a
	// failing verdict skipped teardown entirely and left an editor running (observed, and
	// exactly the hard rule teardown exists for).
	const clean = teardownGate(base);
	process.exit(ok && clean ? 0 : 1);
}
process.exit(ok ? 0 : 1);
