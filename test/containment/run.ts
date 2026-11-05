// Containment suite, level A (automated, no UI): create real tabs through seclab-tabd,
// trigger each malicious-workspace vector inside the tab exactly as the editor's REH would
// (same clean environment via /opt/seclab/bin/seclab-tab-env, workspace as cwd), then
// assert where the code ran and what it could reach.
//   node test/containment/run.ts [sbx|oci]
// Level B (editor-driven, rogue extension) is check-evidence.ts.

import { execFileSync, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import { beaconPort, lockRun, NGINX_IMAGE, worktreeId } from '../harness.ts';
import { checkEvidence, readEvidence, report, type Check } from './assert.ts';
import { armCampaignTab, disarmCampaign, runCampaign, setupCampaign } from './campaign.ts';
import { exitedOrTimeout, teardownGate, verifyTeardown, writeManifest, writeSnapshot } from './teardown.ts';

const driver = process.argv[2] ?? 'sbx';
if (driver !== 'sbx' && driver !== 'oci') {
	throw new Error('usage: run.ts [sbx|oci]');
}
const repo = path.resolve(import.meta.dirname, '../..');
const fixture = path.join(import.meta.dirname, 'fixtures', 'malicious-workspace');
const work = path.join(repo, '.work', 'containment', driver);
const runtime = driver === 'sbx' ? '/opt/homebrew/bin/sbx' : 'docker';
lockRun(path.join(repo, '.work', 'containment-lock', driver));
const LOOPBACK_PORT = await beaconPort();
const LOOPBACK_NAME = `seclab-containment-hostsvc-${driver}-${worktreeId}`;
// Per-run arming nonce: fixtures are inert anywhere else (EDR fixture-safety).
const ARM = randomBytes(16).toString('hex');

fs.rmSync(work, { recursive: true, force: true });
writeSnapshot(work);
// Everything this run starts, recorded before it starts (teardown.ts).
writeManifest(work, { driver, stateDirs: [path.join(work, 'state')], containers: [LOOPBACK_NAME] });
fs.mkdirSync(path.join(work, 'canary'), { recursive: true });
const canary = path.join(work, 'canary', 'secret.txt');
fs.writeFileSync(canary, 'HOST-SECRET-CANARY\n');
const marker = path.join(work, 'PWNED');

function makeWorkspace(name: string, othertab: string): string {
	const ws = path.join(work, 'tabs', name);
	fs.cpSync(fixture, ws, { recursive: true });
	fs.chmodSync(path.join(ws, '.seclab', 'probe.sh'), 0o755);
	fs.chmodSync(path.join(ws, '.seclab', 'fake-python'), 0o755);
	fs.writeFileSync(path.join(ws, '.seclab', 'targets'),
		`canary=${canary}\nothertab=${othertab}\nmarker=${marker}\nloopback=${LOOPBACK_PORT}\narm=${ARM}\nrun=${work}\nuntil=${Math.floor(Date.now() / 1000) + 3600}\n`);
	return ws;
}
const wsB = makeWorkspace('ws-b', '');
fs.writeFileSync(path.join(wsB, 'tab-b-secret.txt'), 'TAB-B-SECRET\n');
const wsA = makeWorkspace('ws-a', path.join(wsB, 'tab-b-secret.txt'));
const campaign = setupCampaign(work, ARM, LOOPBACK_PORT, marker);

// A host-loopback service: stands in for another tab's broker or any localhost service.
spawnSync('docker', ['rm', '-f', LOOPBACK_NAME], { stdio: 'ignore' });
execFileSync('docker', ['run', '-d', '--rm', '--name', LOOPBACK_NAME, '-p', `127.0.0.1:${LOOPBACK_PORT}:80`, NGINX_IMAGE], { stdio: 'ignore' });

const client = new TabdClient({
	command: process.execPath,
	args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', path.join(work, 'state'), '--driver', driver, '--allowed-root', path.join(work, 'tabs')],
	env: { HOME: process.env.HOME, USER: process.env.USER },
});
client.on('stderr', (s: string) => process.stderr.write(`[tabd] ${s}`));
const tabdExit = new Promise(res => client.once('exit', res));

interface Tab { metadata: { name: string } }
const tabs: Record<string, string> = {};
async function cleanup(): Promise<void> {
	if (process.env.KEEP !== '1') {
		for (const t of Object.values(tabs)) {
			await client.request('tab.remove', { tabId: t }).catch(e => console.log(`remove ${t}: ${(e as Error).message}`));
		}
		// Disarm the hostile git config left in the host work dir.
		fs.rmSync(path.join(wsA, '.git'), { recursive: true, force: true });
	}
	// Planted (inert) host-executed files never outlive the run, even with KEEP=1.
	disarmCampaign(campaign);
	spawnSync('docker', ['rm', '-f', LOOPBACK_NAME], { stdio: 'ignore' });
	client.dispose();
	await exitedOrTimeout(tabdExit);
}
/** Teardown gate: a run that leaves a process, sandbox or container behind fails. */
function teardownChecks(): Check[] {
	if (process.env.KEEP === '1') {
		teardownGate(work); // prints the verify command
		return [{ vector: 'teardown', name: 'teardown verified (KEEP=1 skips it: not a pass)', ok: false, detail: '' }];
	}
	return verifyTeardown(work).map(c => ({ vector: 'teardown', name: c.name, ok: c.ok, detail: c.detail }));
}
process.on('uncaughtException', e => {
	console.error(e);
	void cleanup().finally(() => {
		teardownChecks();
		process.exit(2);
	});
});
process.on('unhandledRejection', e => {
	console.error(e);
	void cleanup().finally(() => {
		teardownChecks();
		process.exit(2);
	});
});
await client.initialize('containment', '0');
for (const [k, ws] of [['a', wsA], ['b', wsB], ['c', campaign.ws]] as const) {
	const { tab } = await client.request<{ tab: Tab }>('tab.claim', { workspace: { hostPath: ws } });
	tabs[k] = tab.metadata.name;
	writeManifest(work, { tabs: [tab.metadata.name] });
	await client.request('tab.ensureRunning', { tabId: tab.metadata.name });
	console.log(`tab ${k}: ${tab.metadata.name} running`);
}
armCampaignTab(campaign, tabs.c);
const tabA = tabs.a;
const containerA = `seclab-${tabA}`;
const expectHostname = driver === 'sbx' ? containerA : 'tab';

/** Run argv inside tab A as the tab user, with the REH's environment and the workspace as cwd. */
function inTab(argv: string[]): void {
	// sbx: the kit user; OCI: the container's own user (the workspace owner on a Linux host).
	const user = driver === 'sbx' ? ['-u', 'agent'] : [];
	const r = spawnSync(runtime, ['exec', ...user, '-w', wsA, containerA, '/opt/seclab/bin/seclab-tab-env', ...argv],
		{ encoding: 'utf8', timeout: 120_000 });
	if (r.status !== 0) {
		console.log(`  (trigger exit ${r.status}: ${(r.stderr || '').trim().slice(-200)})`);
	}
}

// Vectors, triggered the way the editor/extension would trigger them.
const tasks = JSON.parse(fs.readFileSync(path.join(wsA, '.vscode', 'tasks.json'), 'utf8'));
const folderOpen = tasks.tasks.find((t: { runOptions?: { runOn?: string } }) => t.runOptions?.runOn === 'folderOpen');
const settings = JSON.parse(fs.readFileSync(path.join(wsA, '.vscode', 'settings.json'), 'utf8'));
const interp = String(settings['python.defaultInterpreterPath']).replace('${workspaceFolder}', wsA);
const mcp = JSON.parse(fs.readFileSync(path.join(wsA, '.vscode', 'mcp.json'), 'utf8')).servers['helpful-tools'];

const vectors: Array<[string, string[]]> = [
	['task', ['sh', '-c', folderOpen.command]], // task system: shell task, runOn folderOpen
	['fsmonitor', ['sh', '-c', 'git init -q . && git config core.fsmonitor "sh .seclab/probe.sh fsmonitor" && git status --porcelain >/dev/null']], // git extension's status poll
	['eslint-config', ['/opt/seclab-reh/node', '-e', 'require(process.cwd() + "/eslint.config.js")']], // ESLint server loading config-as-code on the REH's node
	['interpreter-path', [interp, '--version']], // python/php extension executing the configured interpreter
	['mcp-stdio', [mcp.command, ...mcp.args]], // .vscode/mcp.json stdio server
];
const checks: Check[] = [];
// Read workspace files as the tab sees them (sbx: through the write-back overlay).
const readInTab = (p: string): string | undefined => {
	const user = driver === 'sbx' ? ['-u', 'agent'] : [];
	const r = spawnSync(runtime, ['exec', ...user, containerA, 'cat', p], { encoding: 'utf8', timeout: 30_000 });
	return r.status === 0 ? r.stdout : undefined;
};
for (const [vector, argv] of vectors) {
	console.log(`trigger ${vector}`);
	inTab(argv);
	checks.push(...checkEvidence(readEvidence(wsA, vector, readInTab), vector, { marker, expectHostname }));
	if (driver === 'sbx') {
		// Write-back gate (ADR write-back-gate): the tab's write stays in its overlay; nothing
		// reaches the host checkout until tabd reviews it (sync lands in increment 2b).
		checks.push({ vector, name: 'write-back gate: the tab\'s evidence file is not in the host checkout', ok: readEvidence(wsA, vector) === undefined, detail: '' });
	}
}
if (driver === 'sbx') {
	// Review JJ-1: no tab process may keep a reference to the host share under the overlay.
	// Write through every agent process's /proc/<pid>/cwd (the REH, its extension host…) and
	// via a relative path from a child of the REH's own cwd; none may land on the host.
	const probe = '.seclab-jj1-probe';
	const script = `for p in /proc/[0-9]*; do [ -O "$p" ] || continue; printf x > "$p/cwd/${probe}" 2>/dev/null; `
		+ `(cd "$p/cwd" 2>/dev/null && printf x > ${probe}-rel) 2>/dev/null; done; true`;
	spawnSync(runtime, ['exec', '-u', 'agent', '-w', '/', containerA, 'sh', '-c', script], { encoding: 'utf8', timeout: 60_000 });
	const leaked = [probe, `${probe}-rel`].filter(f => fs.existsSync(path.join(wsA, f)));
	checks.push({ vector: 'write-back', name: 'no tab process reaches the host checkout through an inherited cwd (JJ-1)', ok: leaked.length === 0, detail: leaked.join(', ') });
	// Review JJ-2: tab code (every REH descendant runs under seclab-obs-guard) can't create user
	// or mount namespaces. Harness exec sessions aren't REH descendants, so run the guard itself.
	const us = spawnSync(runtime, ['exec', '-u', 'agent', '-w', '/', containerA, '/opt/seclab/bin/seclab-obs-guard', '/usr/bin/unshare', '-Urm', 'true'], { encoding: 'utf8', timeout: 30_000 });
	const usCtl = spawnSync(runtime, ['exec', '-u', 'agent', '-w', '/', containerA, '/opt/seclab/bin/seclab-obs-guard', '/usr/bin/true'], { encoding: 'utf8', timeout: 30_000 });
	checks.push({ vector: 'write-back', name: 'tab code cannot create a user or mount namespace (JJ-2)', ok: us.status !== 0 && usCtl.status === 0, detail: `unshare exit ${us.status}, control exit ${usCtl.status}` });
	// Review KK-1: tab code can't write the memory of, or signal, sbx's own unguarded agent-uid
	// processes (PID 1, sleep, clipboard-bridge): a Landlock domain scopes ptrace and signals.
	const kk = (inner: string) => spawnSync(runtime, ['exec', '-u', 'agent', '-w', '/', containerA, '/opt/seclab/bin/seclab-obs-guard', '/bin/sh', '-c', inner], { encoding: 'utf8', timeout: 30_000 }).status;
	const memOutside = spawnSync(runtime, ['exec', '-u', 'agent', '-w', '/', containerA, '/bin/sh', '-c', 'exec 3<>/proc/1/mem'], { encoding: 'utf8', timeout: 30_000 }).status;
	checks.push({ vector: 'write-back', name: 'tab code cannot write /proc/1/mem or signal PID 1 (KK-1)', ok: memOutside === 0 && kk('exec 3<>/proc/1/mem') !== 0 && kk('kill -0 1') !== 0 && kk('kill -0 $$') === 0,
		detail: `control (unguarded) mem open exit ${memOutside}` });
}

// Fence-level checks via the runtime's own policy evaluator (sbx only).
if (driver === 'sbx') {
	const pc = (target: string) => {
		// `sbx policy check` exits 1 when denied; the JSON verdict is on stdout either way.
		const r = spawnSync(runtime, ['policy', 'check', 'network', '--sandbox', containerA, '--json', target], { encoding: 'utf8' });
		return JSON.parse(r.stdout).allowed;
	};
	checks.push({ vector: 'fence', name: `host loopback localhost:${LOOPBACK_PORT} denied by policy`, ok: pc(`localhost:${LOOPBACK_PORT}`) === false, detail: '' });
	checks.push({ vector: 'fence', name: 'global allow api.anthropic.com:443 denied for the tab', ok: pc('api.anthropic.com:443') === false, detail: '' });
	const ls = JSON.parse(execFileSync(runtime, ['ls', '--json'], { encoding: 'utf8' })) as Array<{ name: string; workspaces?: string[] }>;
	const a = ls.find(e => e.name === containerA);
	checks.push({ vector: 'mount', name: 'only the workspace is mounted', ok: JSON.stringify(a?.workspaces) === JSON.stringify([wsA]), detail: JSON.stringify(a?.workspaces) });
}
checks.push({ vector: 'host', name: 'canary still intact on host', ok: fs.readFileSync(canary, 'utf8') === 'HOST-SECRET-CANARY\n', detail: '' });

// Contagious-Interview worked example (its own tab, as opening a new repo would be).
console.log('trigger contagious-interview loader');
const containerC = `seclab-${tabs.c}`;
checks.push(...await runCampaign(campaign, {
	exec: argv => {
		const user = driver === 'sbx' ? ['-u', 'agent'] : [];
		const r = spawnSync(runtime, ['exec', ...user, '-w', campaign.ws, containerC, '/opt/seclab/bin/seclab-tab-env', ...argv], { encoding: 'utf8', timeout: 120_000 });
		return { status: r.status, stdout: r.stdout ?? '' };
	},
	stop: async () => {
		await client.request('tab.stop', { tabId: tabs.c });
	},
	start: async () => {
		await client.request('tab.ensureRunning', { tabId: tabs.c });
	},
	reset: async () => {
		await client.request('tab.reset', { tabId: tabs.c });
		await client.request('tab.ensureRunning', { tabId: tabs.c });
	},
	expectHostname: driver === 'sbx' ? containerC : 'tab',
	// sbx tabs write through the write-back overlay; OCI on Docker Desktop is ungated (ADR).
	gated: driver === 'sbx',
}, marker));

await cleanup();
checks.push(...teardownChecks());
const ok = report(checks);
process.exit(ok ? 0 : 1);
