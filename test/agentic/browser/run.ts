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
import { beaconPort, beaconSelfHit, editorPid, checkIsolatedProfile, checkUserDataDir, editorLaunchCommand, lockRun, repoRoot } from '../../harness.ts';
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
if ((mode !== 'prepare' && mode !== 'arm' && mode !== 'switch-build' && mode !== 'check') || !userDataArg) {
	console.error('usage: run.ts prepare|arm|switch-build|check <user-data-dir> [--build u|f] [--probe proxy|storage]\n       [--to u|f] [--driver sbx|oci] [--phase first|restore]');
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
	for (const [file, size] of Object.entries(logFileSizes(dir)).sort(([a], [b]) => a < b ? -1 : 1)) {
		const from = since[file] ?? 0;
		if (size < from) {
			// Rotated or truncated. Skipping it would drop a phase's evidence silently, so
			// this is a hard error for the phase instead.
			throw new Error(`log ${file} shrank from ${from} to ${size}: this phase's evidence is incomplete`);
		}
		if (size === from) {
			continue;
		}
		const fd = fs.openSync(file, 'r');
		try {
			const buf = Buffer.alloc(size - from);
			fs.readSync(fd, buf, 0, buf.length, from);
			let text = buf.toString('utf8');
			if (from > 0) {
				// The offset can land mid-line, so drop the leading fragment rather than
				// letting half a line parse as a whole one.
				const nl = text.indexOf('\n');
				text = nl < 0 ? '' : text.slice(nl + 1);
			}
			out.push(...text.split('\n'));
		} finally {
			fs.closeSync(fd);
		}
	}
	// CHRONOLOGICAL, not directory order. The lines come from several files, and
	// `readdir` order is not time order, so taking "the last resolution" off an
	// unsorted concatenation could pair one launch's scope with another's saved scope.
	// Every line this hook writes is prefixed by the log service with an ISO timestamp,
	// which sorts lexicographically; lines without one keep their relative position by
	// virtue of a stable sort.
	const stamp = (l: string) => /^\[?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\.\d+)/.exec(l)?.[1] ?? '';
	return out.map((line, i) => ({ line, i, t: stamp(line) }))
		.sort((a, b) => (a.t && b.t && a.t !== b.t) ? (a.t < b.t ? -1 : 1) : a.i - b.i)
		.map(x => x.line);
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
	// The offsets for the restore phase are taken HERE, not at the end of the first check,
	// and only once launch 1 is gone. Taken earlier they were snapshotted while that window
	// was still alive, so everything it wrote afterwards (its shutdown, any further
	// resolutions) was appended past them and attributed to the relaunch -- carrying exactly
	// the `savedScope=global` lines the relaunch cannot produce itself. That would have been
	// round 8's finding reintroduced from the other side.
	const stillRunning = editorPid(userData);
	if (stillRunning) {
		console.error(`switch-build: the first launch is still running (pid ${stillRunning}).\n` +
			'Close it before switching, or the relaunch inherits its log lines.');
		process.exit(1);
	}
	fs.writeFileSync(path.join(base, 'offsets-restore.json'), JSON.stringify(logFileSizes(userData)));
	fs.writeFileSync(runFacts, JSON.stringify({ ...facts0, build: to, seededBy: facts0.build }, null, '\t'));
	fs.writeFileSync(path.join(userData, 'seclab-run-build.json'), JSON.stringify({ build: to, app, buildInfo: JSON.parse(fs.readFileSync(buildInfo, 'utf8')) }, null, '\t'));
	const folderUri = `vscode-remote://seclab+${facts0.tabId}${ws}`;
	console.log(`switched the run to build ${to} (${app}); the profile is untouched.\n`);
	console.log('relaunch the SAME profile in the BACKGROUND:\n');
	console.log(`  ${editorLaunchCommand(userData, folderUri, {}, app)}\n`);
	console.log(`then:  node test/agentic/browser/run.ts check ${userData} --phase restore`);
	process.exit(0);
}

// Start the tab-side listener and only THEN arm the hook. Ordering is the point: `prepare`
// stops the tab so the editor can take it over, which kills anything running inside it, and
// the hook polls for the arming file once a second. Arming last means the page is never
// fetched before both listeners are confirmed live, so "the tab saw nothing" can only mean
// the page did not go there.
if (mode === 'arm') {
	const facts0 = JSON.parse(fs.readFileSync(runFacts, 'utf8'));
	let up = '';
	for (let i = 0; i < 60 && !/^[1-9]/.test(up); i++) {
		const r = tabExec(facts0.tabId, ['sh', '-c',
			`cd ${ws} && (setsid /opt/seclab-reh/node .seclab-tab-beacon.mjs ${facts0.tabBeaconLog} ${facts0.beaconPort} ${facts0.arm} >> .seclab-tab-beacon.out 2>&1 &) ; ` +
			`for j in $(seq 1 12); do curl -sS -m 2 -o /dev/null http://127.0.0.1:${facts0.beaconPort}/tab-live-arm-${facts0.arm} && break; sleep 0.25; done; ` +
			`grep -c tab-live-arm-${facts0.arm} ${facts0.tabBeaconLog} 2>/dev/null || true`]);
		up = r.stdout.trim();
		if (!/^[1-9]/.test(up)) {
			await new Promise(res => setTimeout(res, 2000));
		}
	}
	if (!/^[1-9]/.test(up)) {
		console.error('arm: the tab-side listener never answered inside the tab; refusing to arm.');
		process.exit(1);
	}
	if (!await beaconSelfHit('127.0.0.1', facts0.beaconPort, `/beacon-live-arm-${facts0.arm}`)) {
		console.error('arm: the host beacon stopped answering; refusing to arm.');
		process.exit(1);
	}
	fs.mkdirSync(armDir, { recursive: true, mode: 0o700 });
	fs.writeFileSync(path.join(armDir, 'targets'),
		`arm=${facts0.arm}\nurl=${facts0.probeUrl}\nready=${facts0.sentinel}\nuntil=${Date.now() + 10 * 60_000}\n`, { mode: 0o600 });
	console.log('arm: both listeners live, hook armed.');
	console.log(`then, after about 45s:  node test/agentic/browser/run.ts check ${userData}`);
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
	const beacon = beaconSpawn(repoRoot, beaconLog, port);
	// RECORDED BEFORE IT IS SPAWNED. A helper that exists but is not in the manifest is
	// invisible to teardown and to clean-host, and this is exactly how a beacon was once
	// left running on the user's machine: it was spawned here, its liveness probe below
	// failed, and the runner exited on that failure before the manifest was written. The
	// snapshot and the rest of the manifest follow, but the mark goes down first.
	writeSnapshot(base);
	writeManifest(base, { driver, userDataDir: userData, stateDirs: [stateDir], commandMarks: [beacon.mark] });
	spawn(process.execPath, beacon.argv, { detached: true, stdio: 'ignore' }).unref();
	// LIVENESS, opening half. Without it a beacon that never bound produces exactly the
	// evidence a contained build produces, so "no hit" would prove nothing.
	let live = false;
	for (let i = 0; i < 40 && !live; i++) {
		live = await beaconSelfHit('127.0.0.1', port, `/beacon-live-prepare-${arm}`);
		if (!live) {
			await new Promise(res => setTimeout(res, 250));
		}
	}
	if (!live) {
		console.error(`prepare: the host beacon never answered on 127.0.0.1:${port}; refusing to measure.`);
		// Stop what we started before giving up: this exact path leaked a listener once.
		teardownGate(base);
		process.exit(1);
	}
	console.log(`prepare: host beacon live on 127.0.0.1:${port}`);

	// The probe URL. Loopback, and unique to this run so a hit cannot be anything else.
	// `127.0.0.1` resolves to a DIFFERENT machine depending on who fetches it: the host's
	// loopback for a page on the host network, the guest's for a page inside the tab. That
	// was the ambiguity behind round 8's finding 5, and it is resolved by listening on BOTH
	// sides and requiring exactly one of them to have been hit, rather than by trying to
	// find an address only the host can reach.
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

	// The tab-side listener is NOT started here. `prepare` stops the tab (the editor restarts
	// it), which kills anything running inside, so a listener started now is dead by the time
	// the page is fetched -- observed, and caught only because its liveness check can fail.
	// It is started by `arm`, after the editor has the tab up.
	const tabBeaconLog = path.join(ws, '.seclab-tab-beacon.log');
	fs.copyFileSync(path.join(repoRoot, 'test', 'agentic', 'browser', 'tab-beacon.mjs'), path.join(ws, '.seclab-tab-beacon.mjs'));

	fs.writeFileSync(runFacts, JSON.stringify({ build, tabId, arm, probeUrl, beaconPort: port, sentinel, probe, tabBeaconLog }, null, '\t'));
	// This phase starts from an empty profile, but record the offsets anyway so every phase
	// reads its own lines by the same rule.
	fs.writeFileSync(path.join(base, 'offsets-first.json'), JSON.stringify(logFileSizes(userData)));
	client.dispose(); // stops the tab; the editor restarts it
	await new Promise(res => client.once('exit', res));

	const folderUri = `vscode-remote://seclab+${tabId}${ws}`;
	console.log(`\nprepared tab ${tabId} for build ${build} (${app})\n`);
	console.log('now launch the window in the BACKGROUND (never activated; AGENTS.md):\n');
	console.log(`  ${editorLaunchCommand(userData, folderUri, {}, app)}\n`);
	console.log(`then, once the window is up:  node test/agentic/browser/run.ts arm ${userData}`);
	process.exit(0);
}

// ---- check ---------------------------------------------------------------------------

const facts = JSON.parse(fs.readFileSync(runFacts, 'utf8')) as {
	build: 'u' | 'f'; tabId: string; arm: string; probeUrl: string; beaconPort: number;
	sentinel: string; probe: 'proxy' | 'storage'; tabBeaconLog: string;
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

const readBeacon = () => fs.existsSync(beaconLog) ? fs.readFileSync(beaconLog, 'utf8').trim().split('\n').filter(Boolean) : [];
const beaconHits = readBeacon();
const probeHits = beaconHits.filter(l => l.includes(`browser-probe-${facts.arm}`));

// LIVENESS, closing half: the beacon answered the HOST after the measurement, so a quiet
// beacon is a statement about the page and not about a dead listener.
const beaconLiveAfter = await beaconSelfHit('127.0.0.1', facts.beaconPort, `/beacon-live-check-${facts.arm}-${phase}`);

// THE TAB SIDE. Its log lives in the workspace, which the sandbox mounts at the same
// absolute path, so it is read directly. Liveness is confirmed the same way as the host's:
// by a request made from the tab itself, so a listener that died mid-run cannot pass itself
// off as containment.
const tabBeaconLines = fs.existsSync(facts.tabBeaconLog)
	? fs.readFileSync(facts.tabBeaconLog, 'utf8').trim().split('\n').filter(Boolean) : [];
const tabProbeHits = tabBeaconLines.filter(l => l.includes(`browser-probe-${facts.arm}`)).length;
const tabLive = tabExec(facts.tabId, ['sh', '-c',
	`curl -sS -m 3 -o /dev/null http://127.0.0.1:${facts.beaconPort}/tab-live-check-${facts.arm}-${phase} && echo OK`]);
const tabBeaconLiveAfter = /OK/.test(tabLive.stdout);

// The verdict itself is a pure function with its own defect-injection test, which asserts
// that each check below can go red ON ITS OWN. Keeping it there rather than inline is what
// makes that test a test of the shipped logic instead of a copy of it.
// The commit the RUNNING BINARY stamped into its own lines, not the harness's bookkeeping.
const loggedCommit = /\bbuild=(\S+)/.exec(hookLines.filter(l => /\bbuild=/.test(l)).slice(-1)[0] ?? '')?.[1];
const checks = browserProbeChecks({
	build: facts.build, phase: phase as 'first' | 'restore', probe: facts.probe, tabId: facts.tabId,
	hookLines, phaseLines: phaseLines.length,
	probeHits: probeHits.length, beaconHits: beaconHits.length, beaconLiveAfter,
	tabProbeHits, tabBeaconLiveAfter,
	loggedCommit, expectedCommit: recorded.buildInfo.repoSha,
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
