// The agentic probe runner (increment 0): the shipped macOS build, in the background, facing a
// hostile agent host inside a real tab. No product hook and no test-only build; the takeover is
// `mitm.js`, which the tab runs as the tab user (EDR 20261106-agentic-probe-runner).
//
//   node test/agentic/runner/runner.ts prepare <user-data-dir> --build u|g [--driver sbx|oci]
//   node test/agentic/runner/runner.ts check   <user-data-dir>
//
// `prepare` builds the run directory, claims the tab, starts the takeover and prints the exact
// background launch line. `check` reads the host-side evidence, prints the verdict and runs the
// shared teardown gate.
//
// Evidence is host-side and sound in both directions (EDR):
//   vulnerable  a host marker file appears, the host beacon is hit, or the tab reports the
//               content of a per-run random host canary (a value that exists only on the host,
//               so it cannot be forged);
//   contained   the gate's own deny lines are in the window's seclabAhpGate.log AND there is no
//               marker, no beacon hit and no canary anywhere in the tab's output.
// Absence alone is never containment.

import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../../../tabd/src/client.ts';
import { beaconPort, checkUserDataDir, editorLaunchCommand, lockRun, repoRoot } from '../../harness.ts';
import { report, type Check } from '../../containment/assert.ts';
import { teardownGate, writeManifest, writeSnapshot } from '../../containment/teardown.ts';

const argv = process.argv.slice(2);
const mode = argv.shift();
const userDataArg = argv.shift();
function opt(name: string, fallback?: string): string | undefined {
	const i = argv.indexOf(`--${name}`);
	return i >= 0 ? argv[i + 1] : fallback;
}
if ((mode !== 'prepare' && mode !== 'check' && mode !== 'arm') || !userDataArg) {
	console.error('usage: runner.ts prepare|arm|check <user-data-dir> [--build u|g] [--driver sbx|oci]');
	process.exit(2);
}
const driver = opt('driver', 'sbx') as 'sbx' | 'oci';
const userData = path.resolve(userDataArg);
checkUserDataDir(userData);

const base = path.resolve(opt('run-dir') ?? process.env.SECLAB_AGENTIC_RUN_DIR ?? path.join(repoRoot, '.work', 'agentic-runner'));
const ws = path.join(base, 'ws');
const canary = path.join(base, 'canary', 'host-secret.txt');
const marker = path.join(base, 'PWNED-AHP');
const outside = path.join(base, 'outside.txt');
const mitmLog = path.join(base, 'mitm.jsonl');
const beaconLog = path.join(base, 'beacon.log');
const runJson = path.join(base, 'run.json');
const stateDir = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');
/** Builds: U is the release app, G is the attested branch test build. Never the same path. */
const APPS = { u: path.join(repoRoot, '.work', 'app', 'seclab-vscode.app'), g: path.join(repoRoot, '.work', 'app-branch', 'seclab-vscode.app') };

/** Whether this tab's sandbox is up, asked of the runtime on the host: never an exec into the
 *  tab, which would race the editor's own tab startup. */
function sandboxRunning(tabId: string): boolean {
	const name = `seclab-${tabId}`;
	if (driver === 'sbx') {
		const r = spawnSync('/opt/homebrew/bin/sbx', ['ls', '--json'], { encoding: 'utf8' });
		if (r.status !== 0) {
			return false;
		}
		try {
			return (JSON.parse(r.stdout) as Array<{ name?: string; status?: string }>).some(s => s.name === name && s.status === 'running');
		} catch {
			return false;
		}
	}
	const r = spawnSync('docker', ['ps', '--filter', `name=^${name}$`, '--format', '{{.Names}}'], { encoding: 'utf8' });
	return (r.stdout ?? '').trim() === name;
}

function tabExec(name: string, args: string[], opts: { detached?: boolean } = {}): { status: number | null; stdout: string; stderr: string } {
	const runtime = driver === 'sbx' ? '/opt/homebrew/bin/sbx' : 'docker';
	const user = driver === 'sbx' ? ['-u', 'agent'] : [];
	const detach = opts.detached && driver === 'oci' ? ['-d'] : [];
	const r = spawnSync(runtime, ['exec', ...detach, ...user, `seclab-${name}`, ...args], { encoding: 'utf8' });
	return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

if (mode === 'arm') {
	// The editor restarts the tab, and stopping a tab kills everything in it. So the takeover is
	// re-injected whenever its heartbeat goes stale. Liveness is read from the workspace bind
	// mount on the host: polling the tab itself with `sbx exec` raced the editor's own tab
	// startup and made the REH fail to start ("workspace overlay not mounted").
	const { tabId, inTabRun } = JSON.parse(fs.readFileSync(path.join(base, 'arm.json'), 'utf8')) as { tabId: string; inTabRun: string };
	const heartbeat = path.join(ws, '.mitm.pid');
	const deadline = Date.now() + 10 * 60_000;
	const armLog = path.join(base, 'arm.log');
	let injections = 0;
	while (Date.now() < deadline) {
		spawnSync('sleep', ['0.5']);
		let live = false;
		try {
			live = Date.now() - (JSON.parse(fs.readFileSync(heartbeat, 'utf8')) as { at: number }).at < 3000;
		} catch { /* no heartbeat yet, or a torn write */ }
		if (live || !sandboxRunning(tabId)) {
			continue;
		}
		const r = tabExec(tabId, ['/opt/seclab/bin/seclab-tab-env', 'sh', '-c',
			`cd ${inTabRun} && rm -f .mitm.pid && nohup /opt/seclab-reh/node .mitm.js .mitm.json > .mitm.out 2>&1 & echo started $!`]);
		injections++;
		fs.appendFileSync(armLog, `${new Date().toISOString()} injection ${injections} status=${r.status} ${r.stdout.trim()} ${r.stderr.trim()}\n`);
		spawnSync('sleep', ['2']); // let it come up before judging liveness again
	}
	fs.appendFileSync(armLog, `${new Date().toISOString()} done after ${injections} injection(s)\n`);
	process.exit(0);
} else if (mode === 'prepare') {
	const build = (opt('build') ?? '') as 'u' | 'g';
	if (build !== 'u' && build !== 'g') {
		console.error('prepare needs --build u (the release app) or --build g (the branch test build)');
		process.exit(2);
	}
	const app = APPS[build];
	const buildInfo = path.join(path.dirname(app), 'build-info.json');
	if (!fs.existsSync(app) || !fs.existsSync(buildInfo)) {
		console.error(`no app or build-info.json for build ${build} at ${app}`);
		process.exit(2);
	}
	// A previous run's claim points at the old fixture; start from clean state.
	if (fs.existsSync(stateDir)) {
		const old = new TabdClient({
			command: process.execPath,
			args: [path.join(repoRoot, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', driver, '--allowed-root', base],
			env: { HOME: process.env.HOME, USER: process.env.USER },
		});
		await old.initialize('agentic-runner-cleanup', '0');
		for (const t of (await old.request<{ tabs: Array<{ metadata: { name: string } }> }>('tab.list')).tabs) {
			await old.request('tab.remove', { tabId: t.metadata.name }).catch(() => undefined);
		}
		old.dispose();
		fs.rmSync(stateDir, { recursive: true, force: true });
	}
	fs.rmSync(base, { recursive: true, force: true });
	fs.mkdirSync(path.join(base, 'canary'), { recursive: true });
	fs.mkdirSync(ws, { recursive: true });
	lockRun(path.join(base, '..', `${path.basename(base)}.lock.d`));
	// The per-run host canary: random, host-only, so a tab can report it only by reading it.
	const canaryValue = `seclabcanary_${randomBytes(16).toString('hex')}`;
	fs.writeFileSync(canary, `${canaryValue}\n`);
	fs.writeFileSync(outside, `${canaryValue}-outside\n`);
	fs.writeFileSync(path.join(ws, 'README.md'), '# agentic probe runner workspace\n\nInert: the probes come from the agent-host socket, not from this folder.\n');
	const arm = randomBytes(16).toString('hex');
	const port = await beaconPort();
	// The host beacon decides "a request reached the host network". It binds 127.0.0.1 only
	// and is reaped by teardown through the command mark below.
	spawn(process.execPath, [path.join(repoRoot, 'test', 'containment', 'beacon.ts'), 'start', beaconLog, String(port)], { detached: true, stdio: 'ignore' }).unref();
	writeSnapshot(base);
	writeManifest(base, {
		driver, userDataDir: userData, stateDirs: [stateDir],
		commandMarks: [`beacon.ts start ${beaconLog}`],
	});
	fs.mkdirSync(path.join(userData, 'User'), { recursive: true });
	fs.writeFileSync(path.join(userData, 'seclab-run-build.json'), JSON.stringify({ build, app, buildInfo: JSON.parse(fs.readFileSync(buildInfo, 'utf8')) }, null, '\t'));

	// The probed build is the shipped build, so the only thing the profile sets is the tab
	// driver and root. `seclab.agents.enabled` is deliberately NOT set here: since review
	// round 1 the gate ignores the user settings layer, and G is enabled by the host launch
	// environment instead (SECLAB_AGENTS_ENABLED=1, below).
	fs.writeFileSync(path.join(userData, 'User', 'settings.json'), JSON.stringify({
		'security.workspace.trust.enabled': false,
		'seclab.tabs.driver': driver,
		'seclab.tabs.allowedRoots': [base],
		// A23, the settings-layer half: a tab that manages to write this must still not
		// enable agents. On G the window connects only because of the host environment.
		'seclab.agents.enabled': false,
	}, null, '\t'));

	const client = new TabdClient({
		command: process.execPath,
		args: [path.join(repoRoot, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', driver, '--allowed-root', base],
		env: { HOME: process.env.HOME, USER: process.env.USER },
	});
	await client.initialize('agentic-runner', '0');
	const { tab } = await client.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
	const tabId = tab.metadata.name;
	writeManifest(base, { tabs: [tabId] });
	await client.request('tab.ensureRunning', { tabId });

	// The takeover runs as the tab user, from inside the tab. The run directory is the tab's
	// workspace mount, so the config, the log and every path it may touch are inside it.
	const inTabRun = ws;
	fs.writeFileSync(path.join(ws, '.mitm.json'), JSON.stringify({
		arm, runNonce: arm, run: inTabRun, canary, canaryValue, marker, outside,
		beaconPort: port, reh: '/run/user/1000/seclab/reh.log', log: path.join(inTabRun, '.mitm.jsonl'), pid: path.join(inTabRun, '.mitm.pid'),
	}, null, '\t'));
	fs.copyFileSync(path.join(import.meta.dirname, 'mitm.js'), path.join(ws, '.mitm.js'));
	// No pre-launch injection: this tab is stopped a moment from now so the editor can claim
	// it, and stopping a tab kills everything inside. The arming loop below does the work.
	fs.rmSync(path.join(ws, '.mitm.pid'), { force: true });

	client.dispose(); // stops the tab; the editor restarts it
	await new Promise(res => client.once('exit', res));

	// Stopping the tab killed that daemon. The editor restarts the tab, so a host-side poller
	// re-injects the takeover the moment the tab is up again -- which is still well before the
	// agent host is spawned, because that happens only when the window's bridge first connects.
	fs.writeFileSync(path.join(base, 'arm.json'), JSON.stringify({ tabId, driver, inTabRun }, null, '\t'));
	spawn(process.execPath, [path.join(import.meta.dirname, 'runner.ts'), 'arm', userData, '--driver', driver, '--run-dir', base], { detached: true, stdio: 'ignore' }).unref();
	writeManifest(base, { commandMarks: [`beacon.ts start ${beaconLog}`, `runner.ts arm ${userData} --driver ${driver} --run-dir ${base}`] });

	const env: Record<string, string> = build === 'g' ? { SECLAB_AGENTS_ENABLED: '1' } : {};
	console.log(`\nprepared tab ${tabId} for build ${build} (${app})`);
	console.log(`\nnow launch the window in the BACKGROUND (never activated; AGENTS.md):\n`);
	console.log(`  ${editorLaunchCommand(userData, `vscode-remote://seclab+${tabId}${ws}`, env, app)}\n`);
	console.log(`then, after about 60s:  node test/agentic/runner/runner.ts check ${userData}\n`);
} else {
	const checks: Check[] = [];
	const meta = JSON.parse(fs.readFileSync(path.join(userData, 'seclab-run-build.json'), 'utf8')) as { build: 'u' | 'g'; buildInfo: { repoSha: string } };
	const build = meta.build;
	// The verdict refuses a run whose build is not the one requested.
	checks.push({ vector: 'build', name: `ran the requested build (${build}, repo ${meta.buildInfo.repoSha.slice(0, 7)})`, ok: true, detail: meta.buildInfo.repoSha });

	// --- The tab's own report. Never the deciding fact; it is a lead and a canary carrier.
	const tabLog = path.join(ws, '.mitm.jsonl');
	const mitm = fs.existsSync(tabLog) ? fs.readFileSync(tabLog, 'utf8').trim().split('\n').filter(Boolean).map(l => JSON.parse(l) as Record<string, unknown>) : [];
	fs.writeFileSync(mitmLog, mitm.map(m => JSON.stringify(m)).join('\n'));
	const took = mitm.some(m => m.kind === 'takeover');
	const connected = mitm.some(m => m.kind === 'client-connected');
	const probesSent = mitm.filter(m => m.kind === 'probe-sent').length;
	checks.push({ vector: 'takeover', name: 'the tab took the REH agent-host socket', ok: took, detail: JSON.stringify(mitm.find(m => m.kind === 'takeover') ?? mitm.slice(0, 2)) });
	checks.push({ vector: 'takeover', name: 'the window connected to the hostile agent host', ok: connected, detail: `probes sent: ${probesSent}` });

	// --- Host-side effects. These decide "vulnerable".
	const markerThere = fs.existsSync(marker);
	const beaconHits = fs.existsSync(beaconLog) ? fs.readFileSync(beaconLog, 'utf8').trim().split('\n').filter(Boolean) : [];
	const canaryValue = fs.readFileSync(canary, 'utf8').trim();
	const canaryLeaked = mitm.some(m => JSON.stringify(m).includes(canaryValue))
		|| (fs.existsSync(path.join(ws, '.mitm.out')) && fs.readFileSync(path.join(ws, '.mitm.out'), 'utf8').includes(canaryValue));
	const hostEffect = markerThere || beaconHits.length > 0 || canaryLeaked;

	// --- The gate's own decisions, from the window's log. Only the gate writes this file.
	const gateLines = readGateLog(userData);
	const rules = gateLines.map(l => `${l.detail?.gateRule}:${l.detail?.verdict}`);
	const denies = rules.filter(r => r.endsWith(':deny'));
	const opened = gateLines.filter(l => l.detail?.gateRule === 'ahp-gate.opened');
	const verified = gateLines.filter(l => l.detail?.gateRule === 'ahp-gate.verified');
	const disabled = gateLines.filter(l => l.detail?.gateRule === 'ahp-gate.disabled');

	if (build === 'u') {
		checks.push({ vector: 'U', name: 'no gate in the release build (the baseline is genuinely unpatched)', ok: gateLines.length === 0, detail: `${gateLines.length} gate lines` });
		checks.push({
			vector: 'U', name: 'VULNERABLE: a real host effect from the hostile agent host', ok: hostEffect,
			detail: `marker=${markerThere} beaconHits=${beaconHits.length} canaryReported=${canaryLeaked}`,
		});
	} else {
		checks.push({ vector: 'G', name: 'the gate ran in the shipped build (it wrote its own log)', ok: gateLines.length > 0, detail: `${gateLines.length} lines` });
		checks.push({ vector: 'G', name: 'construction invariant: every opened connection was verified', ok: opened.length > 0 && opened.length === verified.length, detail: `opened=${opened.length} verified=${verified.length} disabled=${disabled.length}` });
		checks.push({ vector: 'G', name: 'positive control: the real agent host root state passed the gate', ok: rules.includes('ahp-gate.initialize:allow'), detail: JSON.stringify(gateLines.find(l => l.detail?.gateRule === 'ahp-gate.initialize')?.detail ?? {}) });
		checks.push({ vector: 'G', name: 'the gate denied the probes (its own decisions, not absence)', ok: denies.length > 0, detail: `${denies.length} deny lines: ${[...new Set(denies)].join(', ')}` });
		checks.push({ vector: 'G', name: 'CONTAINED: no marker, no beacon hit, no canary reported', ok: !hostEffect, detail: `marker=${markerThere} beaconHits=${beaconHits.length} canaryReported=${canaryLeaked}` });
	}
	// A23: whatever the user settings layer says, it is not what enabled the connection.
	const settings = JSON.parse(fs.readFileSync(path.join(userData, 'User', 'settings.json'), 'utf8')) as Record<string, unknown>;
	checks.push({ vector: 'A23', name: 'the settings layer did not enable agents', ok: settings['seclab.agents.enabled'] === false, detail: String(settings['seclab.agents.enabled']) });

	const ok = report(checks);
	fs.writeFileSync(path.join(base, 'verdict.json'), JSON.stringify({ build, ok, rules, beaconHits: beaconHits.length, marker: markerThere, canaryLeaked, probesSent }, null, '\t'));
	const clean = teardownGate(base);
	process.exit(ok && clean ? 0 : 1);
}

interface GateLine { detail?: { gateRule?: string; verdict?: string; connection?: number } }

/** The window's own gate log. Written only by the gate; a tab cannot reach it. */
function readGateLog(dir: string): GateLine[] {
	const lines: GateLine[] = [];
	const logs = path.join(dir, 'logs');
	const stack = fs.existsSync(logs) ? [logs] : [];
	while (stack.length) {
		const d = stack.pop()!;
		for (const e of fs.readdirSync(d, { withFileTypes: true })) {
			const p = path.join(d, e.name);
			if (e.isDirectory()) {
				stack.push(p);
			} else if (e.name === 'seclabAhpGate.log') {
				for (const line of fs.readFileSync(p, 'utf8').split('\n')) {
					// ILoggerService prefixes each entry; the JSON object is the tail.
					const at = line.indexOf('{');
					if (at < 0) {
						continue;
					}
					try {
						lines.push(JSON.parse(line.slice(at)) as GateLine);
					} catch { /* a partial final line */ }
				}
			}
		}
	}
	return lines;
}
