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
import { browserProbeChecks } from './verdict.ts';
import { beaconPort, beaconSelfHit, checkIsolatedProfile, checkUserDataDir, editorLaunchCommand, lockRun, privateHostAddress, repoRoot } from '../../harness.ts';
import { report } from '../../containment/assert.ts';
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
	console.error('usage: run.ts prepare|switch-build|check <user-data-dir> [--build u|f] [--probe proxy|storage]\n       [--to u|f] [--driver sbx|oci] [--phase first|restore]');
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

/**
 * Every `.log` file under the profile, with its current size. The unit of attribution.
 */
function logFileSizes(dir: string): Record<string, number> {
	const out: Record<string, number> = {};
	const logs = path.join(dir, 'logs');
	const stack = fs.existsSync(logs) ? [logs] : [];
	while (stack.length) {
		const d = stack.pop()!;
		for (const e of fs.readdirSync(d, { withFileTypes: true })) {
			const p = path.join(d, e.name);
			if (e.isDirectory()) {
				stack.push(p);
			} else if (e.name.endsWith('.log')) {
				out[p] = fs.statSync(p).size;
			}
		}
	}
	return out;
}

/**
 * Lines written to the profile's logs SINCE `since`, i.e. by this launch and no other.
 *
 * The first version of this read every log in the profile and took the last matching line,
 * which is how the restore phase came to measure nothing: the relaunched window produced no
 * hook output at all, so the check silently re-read the FIRST launch's lines and passed
 * (security review round 8, finding 1). Attribution cannot rest on "the last line in the
 * directory", because nothing ties that line to the window that is supposed to have written
 * it. Here a phase declares the byte offsets it starts from, and sees only what was appended
 * past them; a file that did not exist at the snapshot is read whole. A phase that produced
 * nothing therefore reads as nothing, and its checks fail, which is the point.
 */
function linesSince(dir: string, since: Record<string, number>): string[] {
	const out: string[] = [];
	for (const [file, size] of Object.entries(logFileSizes(dir))) {
		const from = since[file] ?? 0;
		if (size <= from) {
			continue;
		}
		const fd = fs.openSync(file, 'r');
		try {
			const buf = Buffer.alloc(size - from);
			fs.readSync(fd, buf, 0, buf.length, from);
			out.push(...buf.toString('utf8').split('\n'));
		} finally {
			fs.closeSync(fd);
		}
	}
	return out;
}

// Point the SAME profile at the other build, for the cross-build restore phase. Nothing in
// the profile is touched: that is the whole point, since the persisted browser editor state
// written by launch 1 has to reach the relaunch byte-for-byte, so that the only difference
// between the two observations is the patch under test.
if (mode === 'switch-build') {
	const to = (opt('to') ?? '') as 'u' | 'f';
	if (to !== 'u' && to !== 'f') {
		console.error('switch-build needs --to u|f');
		process.exit(2);
	}
	const app = APPS[to];
	const buildInfo = path.join(path.dirname(app), 'build-info-app.json');
	if (!fs.existsSync(app) || !fs.existsSync(buildInfo)) {
		console.error(`no app or build-info-app.json for build ${to} at ${app}`);
		process.exit(2);
	}
	const facts0 = JSON.parse(fs.readFileSync(runFacts, 'utf8'));
	if (facts0.build === to) {
		console.error(`switch-build: the run is already on build ${to}; the restore phase must read the OTHER build.`);
		process.exit(2);
	}
	fs.writeFileSync(runFacts, JSON.stringify({ ...facts0, build: to, seededBy: facts0.build }, null, '\t'));
	fs.writeFileSync(path.join(userData, 'seclab-run-build.json'), JSON.stringify({ build: to, app, buildInfo: JSON.parse(fs.readFileSync(buildInfo, 'utf8')) }, null, '\t'));
	const folderUri = `vscode-remote://seclab+${facts0.tabId}${ws}`;
	console.log(`switched the run to build ${to} (${app}); the profile is untouched.\n`);
	console.log('relaunch the SAME profile in the BACKGROUND:\n');
	console.log(`  ${editorLaunchCommand(userData, folderUri, {}, app)}\n`);
	console.log(`then:  node test/agentic/browser/run.ts check ${userData} --phase restore`);
	process.exit(0);
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
	// Created BEFORE the snapshot, parent included: both live under the user's home, so a
	// directory made after the baseline makes teardown report `~/` as changed. The arming
	// file cannot move into the run directory, because that is the workspace the tab mounts.
	fs.mkdirSync(path.dirname(armDir), { recursive: true });
	fs.rmSync(armDir, { recursive: true, force: true });
	fs.mkdirSync(armDir, { recursive: true, mode: 0o700 });
	const port = await beaconPort();
	const beaconAddress = privateHostAddress();
	if (!beaconAddress) {
		console.error('prepare: this host has no private IPv4 address, so the beacon cannot be\n' +
			'distinguished from the tab\'s own loopback. Refusing to run a probe that could not fail.');
		process.exit(2);
	}
	const beacon = beaconSpawn(repoRoot, beaconLog, port, beaconAddress);
	spawn(process.execPath, beacon.argv, { detached: true, stdio: 'ignore' }).unref();
	// LIVENESS, opening half. Without it a beacon that never bound produces exactly the
	// evidence a contained build produces, so "no hit" would prove nothing (security review
	// round 8, finding 4). The check phase closes the bracket, so the measurement happens
	// between two confirmed-live observations.
	let live = false;
	for (let i = 0; i < 40 && !live; i++) {
		live = await beaconSelfHit(beaconAddress, port, `/beacon-live-prepare-${arm}`);
		if (!live) {
			await new Promise(res => setTimeout(res, 250));
		}
	}
	if (!live) {
		console.error(`prepare: the beacon never answered on ${beaconAddress}:${port}; refusing to measure.`);
		process.exit(1);
	}
	console.log(`prepare: beacon live on ${beaconAddress}:${port}`);
	writeSnapshot(base);
	writeManifest(base, { driver, userDataDir: userData, stateDirs: [stateDir], commandMarks: [beacon.mark] });

	// The probe URL. A PRIVATE address this host holds, never loopback, and unique to this
	// run so a hit cannot be anything else. Loopback is useless here: inside the tab
	// `127.0.0.1` is the GUEST's loopback, so a quiet beacon would be ambiguous between
	// "the fence contained it" and "that address never meant this host" (security review
	// round 8, finding 5). A private host address is reachable from the host side and denied
	// by the tab's fence, which allows the broker port alone. It is also what takes the probe
	// INSIDE the hook's reviewed validity envelope, which covers non-localhost targets only.
	const probeUrl = `http://${beaconAddress}:${port}/browser-probe-${arm}`;
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
	// The sentinel is a neutral key that 0017 does NOT fix, so it becomes visible on both
	// builds once the tab's remote layer is applied. The hook waits for it before measuring:
	// without that wait the hook ran before the remote configuration had loaded, read the
	// registered default, and reported the tab's network on a build that would have obeyed
	// the tab a second later. U looked contained, which is the false-negative this whole
	// runner exists to prevent.
	//
	// It must be WINDOW scope. The first attempt used `workbench.browser.maxHistoryEntries`,
	// which is APPLICATION, i.e. exactly the one scope `REMOTE_MACHINE_SCOPES` withholds from
	// a tab, so it could never arrive and every run was inconclusive. `newTabPlacement` is
	// WINDOW, like the two keys under test.
	const sentinel = 'sideGroup';
	// WHICH SETTING THIS RUN IS ABOUT. The two keys are fixed for different reasons and
	// fail in different places, so a run that writes BOTH cannot tell which one did the
	// work: with the proxy off the network is dropped before the storage scope is even
	// consulted, so the storage check rides along on the proxy result and cannot fail on
	// its own (security review round 8, finding 2). Each probe therefore writes the hostile
	// value for ONE key and the contained value for the other, so exactly one check decides.
	//
	//  proxy   : proxy OFF, storage ephemeral -> upstream drops the view's NETWORK.
	//  storage : proxy ON,  storage GLOBAL    -> upstream keeps the network but gives the
	//            view the GLOBAL session, which upstream documents as always using the
	//            local network ("Browsers using global storage always use the local
	//            network"), and `toBrowserViewSessionOptions` returns `{ scope }` with no
	//            network for it. So the evidence here is the resolved SCOPE.
	//
	// `enableRemoteProxy` is written explicitly in both, never left at its default: that
	// default is `product.quality !== 'stable'`, so leaving it out would make the storage
	// probe depend on how the variant happened to be branded.
	const probe = opt('probe', 'proxy') as 'proxy' | 'storage';
	if (probe !== 'proxy' && probe !== 'storage') {
		console.error('prepare: --probe must be proxy or storage');
		process.exit(2);
	}
	const remoteSettings = JSON.stringify({
		'workbench.browser.enableRemoteProxy': probe !== 'proxy',
		'workbench.browser.dataStorage': probe === 'storage' ? 'global' : 'ephemeral',
		'workbench.browser.newTabPlacement': sentinel,
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

	fs.writeFileSync(runFacts, JSON.stringify({ build, tabId, arm, probeUrl, beaconPort: port, beaconAddress, sentinel, probe }, null, '\t'));
	// This phase starts from an empty profile, but record the offsets anyway so every phase
	// reads its own lines by the same rule.
	fs.writeFileSync(path.join(base, 'offsets-first.json'), JSON.stringify(logFileSizes(userData)));
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
	beaconAddress: string; sentinel: string; probe: 'proxy' | 'storage';
};
const phase = opt('phase', 'first')!;

const recorded = JSON.parse(fs.readFileSync(path.join(userData, 'seclab-run-build.json'), 'utf8')) as { build: string; buildInfo: { repoSha: string } };

// Read ONLY the lines this phase's launch appended, so a phase that produced nothing cannot
// borrow an earlier launch's evidence (security review round 8, finding 1).
const offsetsFile = path.join(base, `offsets-${phase}.json`);
if (!fs.existsSync(offsetsFile)) {
	console.error(`check: no ${path.basename(offsetsFile)}; run the previous phase first.`);
	process.exit(2);
}
const phaseLines = linesSince(userData, JSON.parse(fs.readFileSync(offsetsFile, 'utf8')));
const hookLines = phaseLines.filter(l => l.includes('SECLAB_TEST_ONLY:browser-drive-hook'));

const beaconHits = fs.existsSync(beaconLog) ? fs.readFileSync(beaconLog, 'utf8').trim().split('\n').filter(Boolean) : [];
const probeHits = beaconHits.filter(l => l.includes(`browser-probe-${facts.arm}`));

// LIVENESS, closing half: the beacon answered the HOST after the measurement, so a quiet
// beacon is a statement about the page and not about a dead listener.
const beaconLiveAfter = await beaconSelfHit(facts.beaconAddress, facts.beaconPort, `/beacon-live-check-${facts.arm}-${phase}`);

// The verdict itself is a pure function with its own defect-injection test, which asserts
// that each check below can go red ON ITS OWN. Keeping it there rather than inline is what
// makes that test a test of the shipped logic instead of a copy of it.
const checks = browserProbeChecks({
	build: facts.build, phase: phase as 'first' | 'restore', probe: facts.probe, tabId: facts.tabId,
	hookLines, phaseLines: phaseLines.length,
	probeHits: probeHits.length, beaconHits: beaconHits.length, beaconLiveAfter,
	buildMatches: recorded.build === facts.build,
	buildDetail: `${recorded.build} (repo ${recorded.buildInfo.repoSha.slice(0, 7)})`,
});
const lastResolved = hookLines.filter(l => l.includes(' resolved ')).slice(-1)[0] ?? '';
const resolvedNetwork = /\bnetwork=(\S+)/.exec(lastResolved)?.[1];
const resolvedScope = /\bscope=(\S+)/.exec(lastResolved)?.[1];

const ok = report(checks);
fs.writeFileSync(path.join(base, `verdict-${phase}.json`), JSON.stringify({
	build: facts.build, phase, probe: facts.probe, ok, resolvedScope, resolvedNetwork,
	probeHits: probeHits.length, beaconHits: beaconHits.length,
	hookLines: hookLines.length, phaseLines: phaseLines.length,
}, null, '\t'));
// Hand the next phase its starting offsets, so it can only ever read its own launch's lines.
fs.writeFileSync(path.join(base, 'offsets-restore.json'), JSON.stringify(logFileSizes(userData)));

// The arming file is removed on EVERY check, not only the last one: a run stopped after the
// first phase used to leave it armed until its ten-minute expiry (security review round 8,
// finding 6). Re-arming is a `prepare` away, so there is no cost to removing it early.
fs.rmSync(armDir, { recursive: true, force: true });

// The first phase leaves the run up so the restore phase can relaunch the same profile.
if (phase === 'restore') {
	// Evaluated FIRST and on its own line: `ok && teardownGate(base)` short-circuits, so a
	// failing verdict skipped teardown entirely and left an editor running (observed, and
	// exactly the hard rule teardown exists for).
	const clean = teardownGate(base);
	process.exit(ok && clean ? 0 : 1);
}
process.exit(ok ? 0 : 1);
