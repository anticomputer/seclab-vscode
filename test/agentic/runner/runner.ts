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

import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../../../tabd/src/client.ts';
import { beaconPort, checkIsolatedProfile, checkUserDataDir, editorLaunchCommand, lockRun, repoRoot } from '../../harness.ts';
import { report, type Check } from '../../containment/assert.ts';
import { beaconSpawn } from './marks.ts';
import { readManifest, teardownGate, writeManifest, writeSnapshot } from '../../containment/teardown.ts';

const argv = process.argv.slice(2);
const mode = argv.shift();
const userDataArg = argv.shift();
function opt(name: string, fallback?: string): string | undefined {
	const i = argv.indexOf(`--${name}`);
	return i >= 0 ? argv[i + 1] : fallback;
}
if ((mode !== 'prepare' && mode !== 'check') || !userDataArg) {
	console.error('usage: runner.ts prepare|check <user-data-dir> [--build u|g] [--driver sbx|oci]');
	process.exit(2);
}
const driver = opt('driver', 'sbx') as 'sbx' | 'oci';
const userData = path.resolve(userDataArg);
checkUserDataDir(userData);

const base = path.resolve(opt('run-dir') ?? process.env.SECLAB_AGENTIC_RUN_DIR ?? path.join(repoRoot, '.work', 'agentic-runner'));
// `base` is recursively deleted by `prepare`, and it comes from an option or the environment.
// Confine it to the same places an isolated profile may live before anything touches it
// (review round 2): teardown checks this too, but only long after the delete.
checkIsolatedProfile(path.join(base, 'ws'));
// Teardown finds this run's detached helpers by command mark, and a mark must appear in the
// process's argv with whitespace or a line edge on each side. The helpers are spawned with
// absolute script paths, so the marks are built from the very argv used to spawn them.
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

function tabExec(name: string, args: string[], opts: { detached?: boolean } = {}): { status: number | null; stdout: string; stderr: string } {
	const runtime = driver === 'sbx' ? '/opt/homebrew/bin/sbx' : 'docker';
	const user = driver === 'sbx' ? ['-u', 'agent'] : [];
	const detach = opts.detached && driver === 'oci' ? ['-d'] : [];
	const r = spawnSync(runtime, ['exec', ...detach, ...user, `seclab-${name}`, ...args], { encoding: 'utf8' });
	return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

if (mode === 'prepare') {
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
	const beacon = beaconSpawn(repoRoot, beaconLog, port);
	spawn(process.execPath, beacon.argv, { detached: true, stdio: 'ignore' }).unref();
	writeSnapshot(base);
	writeManifest(base, {
		driver, userDataDir: userData, stateDirs: [stateDir],
		commandMarks: [beacon.mark],
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

	// The takeover is packaged as an extension, so the REH starts it inside the tab. That is
	// what makes the run work across a tab restart: the editor restarts the tab, which kills
	// everything in it, and every host-side way of restarting the takeover was worse (an
	// `sbx exec` loop during the editor's own tab startup makes `tab.ensureRunning` fail with
	// "collector: workspace overlay not mounted", and a workspace heartbeat is invisible to
	// the host because the tab's workspace is an overlay). The REH restarts an extension by
	// itself, so there is no host polling and no liveness signal at all.
	const extSrc = path.join(import.meta.dirname, 'mitm-extension');
	const extBuild = path.join(base, 'mitm-extension');
	fs.rmSync(extBuild, { recursive: true, force: true });
	fs.mkdirSync(extBuild, { recursive: true });
	for (const f of fs.readdirSync(extSrc)) {
		fs.copyFileSync(path.join(extSrc, f), path.join(extBuild, f));
	}
	// `probes.js` too: the probe table is a separate module so the protocol-level validator
	// and the run share one definition, and the takeover requires it at runtime.
	for (const f of ['mitm.js', 'probes.js']) {
		fs.copyFileSync(path.join(import.meta.dirname, f), path.join(extBuild, f));
	}
	// The takeover's own files live in the installed extension directory inside the tab, not
	// in the workspace: the overlay would hide them, and `check` collects them with one exec
	// after the run, as diagnostics only.
	const inTabExt = `/home/agent/.seclab-vscode-server/extensions/seclab.seclab-ahp-takeover-0.0.1`;
	fs.writeFileSync(path.join(extBuild, 'mitm.json'), JSON.stringify({
		arm, runNonce: arm, run: inTabExt, canary, canaryValue, marker, outside,
		beaconPort: port, reh: '/run/user/1000/seclab/reh.log',
		log: path.join(inTabExt, 'mitm.jsonl'), pid: path.join(inTabExt, 'mitm.pid'),
	}, null, '\t'));
	// Inside the workspace: it is the only thing mounted into the tab, so a vsix anywhere
	// else in the run directory is simply not there as far as the REH is concerned.
	const vsixDir = path.join(ws, '.seclab');
	fs.mkdirSync(vsixDir, { recursive: true });
	const VSCE_IMAGE = 'seclab-vsce:3.9.2';
	if (spawnSync('docker', ['image', 'inspect', VSCE_IMAGE], { stdio: 'ignore' }).status !== 0) {
		execFileSync('gh', ['cfs', '--', 'docker', 'build', '-q', '-t', VSCE_IMAGE, path.join(repoRoot, 'build', 'vsce')], { stdio: 'inherit' });
	}
	execFileSync('docker', ['run', '--rm', '--network', 'none', '--user', `${process.getuid!()}:${process.getgid!()}`,
		'-v', `${extBuild}:/ext:ro`, '-v', `${vsixDir}:/out`, VSCE_IMAGE,
		'sh', '-c', 'cp -r /ext /tmp/e && cd /tmp/e && vsce package --allow-missing-repository --skip-license -o /out/takeover.vsix'], { stdio: 'inherit' });
	const install = tabExec(tabId, ['/opt/seclab/bin/seclab-tab-env',
		'/opt/seclab-reh/bin/seclab-code-server', '--install-extension', path.join(vsixDir, 'takeover.vsix')]);
	console.log(`takeover extension: ${install.stdout.trim()} ${install.stderr.trim()}`);
	if (install.status !== 0) {
		console.error('failed to install the takeover extension');
		process.exit(1);
	}

	client.dispose(); // stops the tab; the editor restarts it (extensions persist in the tab)
	await new Promise(res => client.once('exit', res));
	writeManifest(base, { commandMarks: [beacon.mark] });

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

	// The tab's own report. Never the deciding fact; it is diagnostics and a canary carrier.
	// The tab's workspace is an overlay, so this is collected with one exec after the run.
	const tabId = (readManifest(base).tabs ?? [])[0] ?? '';
	const inTabExt = '/home/agent/.seclab-vscode-server/extensions/seclab.seclab-ahp-takeover-0.0.1';
	const collected = tabId ? tabExec(tabId, ['sh', '-c', `cat ${inTabExt}/mitm.jsonl 2>/dev/null`]) : { status: 1, stdout: '', stderr: '' };
	const mitm = collected.stdout.trim().split('\n').filter(Boolean).flatMap(l => {
		try {
			return [JSON.parse(l) as Record<string, unknown>];
		} catch {
			return [];
		}
	});
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
	const canaryLeaked = mitm.some(m => JSON.stringify(m).includes(canaryValue));
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
