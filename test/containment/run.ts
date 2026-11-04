// Containment suite, level A (automated, no UI): create real tabs through seclab-tabd,
// trigger each malicious-workspace vector inside the tab exactly as the editor's REH would
// (same clean environment via /opt/seclab/bin/seclab-tab-env, workspace as cwd), then
// assert where the code ran and what it could reach.
//   node test/containment/run.ts [sbx|oci]
// Level B (editor-driven, rogue extension) is check-evidence.ts.

import { execFileSync, spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import { checkEvidence, readEvidence, report, type Check } from './assert.ts';

const driver = process.argv[2] ?? 'sbx';
if (driver !== 'sbx' && driver !== 'oci') {
	throw new Error('usage: run.ts [sbx|oci]');
}
const repo = path.resolve(import.meta.dirname, '../..');
const fixture = path.join(import.meta.dirname, 'fixtures', 'malicious-workspace');
const work = path.join(repo, '.work', 'containment', driver);
const runtime = driver === 'sbx' ? '/opt/homebrew/bin/sbx' : 'docker';
const LOOPBACK_PORT = 18099;
const LOOPBACK_NAME = `seclab-containment-hostsvc-${driver}`;

fs.rmSync(work, { recursive: true, force: true });
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
		`canary=${canary}\nothertab=${othertab}\nmarker=${marker}\nloopback=${LOOPBACK_PORT}\n`);
	return ws;
}
const wsB = makeWorkspace('ws-b', '');
fs.writeFileSync(path.join(wsB, 'tab-b-secret.txt'), 'TAB-B-SECRET\n');
const wsA = makeWorkspace('ws-a', path.join(wsB, 'tab-b-secret.txt'));

// A host-loopback service: stands in for another tab's broker or any localhost service.
spawnSync('docker', ['rm', '-f', LOOPBACK_NAME], { stdio: 'ignore' });
execFileSync('docker', ['run', '-d', '--rm', '--name', LOOPBACK_NAME, '-p', `127.0.0.1:${LOOPBACK_PORT}:80`, 'nginx:alpine'], { stdio: 'ignore' });

const client = new TabdClient({
	command: process.execPath,
	args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', path.join(work, 'state'), '--driver', driver, '--allowed-root', path.join(work, 'tabs')],
	env: { HOME: process.env.HOME, USER: process.env.USER },
});
client.on('stderr', (s: string) => process.stderr.write(`[tabd] ${s}`));

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
	spawnSync('docker', ['rm', '-f', LOOPBACK_NAME], { stdio: 'ignore' });
	client.dispose();
}
process.on('uncaughtException', e => {
	console.error(e);
	void cleanup().finally(() => process.exit(2));
});
process.on('unhandledRejection', e => {
	console.error(e);
	void cleanup().finally(() => process.exit(2));
});
await client.initialize('containment', '0');
for (const [k, ws] of [['a', wsA], ['b', wsB]] as const) {
	const { tab } = await client.request<{ tab: Tab }>('tab.claim', { workspace: { hostPath: ws } });
	tabs[k] = tab.metadata.name;
	await client.request('tab.ensureRunning', { tabId: tab.metadata.name });
	console.log(`tab ${k}: ${tab.metadata.name} running`);
}
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
for (const [vector, argv] of vectors) {
	console.log(`trigger ${vector}`);
	inTab(argv);
	checks.push(...checkEvidence(readEvidence(wsA, vector), vector, { marker, expectHostname }));
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

const ok = report(checks);
await cleanup();
process.exit(ok ? 0 : 1);
