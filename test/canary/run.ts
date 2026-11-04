// Canary acceptance test, level A (automated, no UI). Seeds canaries into the host-side
// stores reachable without the editor, runs a real tab, and scans everything inside the
// tab (as root, i.e. stronger than the attacker) plus supervisor logs for any canary in
// any encoding.
//   node test/canary/run.ts [sbx|oci]
// Level B (editor-side stores: user settings, clipboard, SecretStorage, auth sessions,
// MCP inputs; RPC results seen by the rogue extension) is test/canary/editor.ts.

import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import { mintCanary, scan, serialize, StreamScanner, type Canary, type Hit } from './canary.ts';
import { exitedOrTimeout, teardownGate, writeManifest, writeSnapshot } from '../containment/teardown.ts';

const driver = process.argv[2] ?? 'sbx';
const repo = path.resolve(import.meta.dirname, '../..');
const work = path.join(repo, '.work', 'canary', driver);
const runtime = driver === 'sbx' ? '/opt/homebrew/bin/sbx' : 'docker';
fs.rmSync(work, { recursive: true, force: true });
writeSnapshot(work);
writeManifest(work, { driver: driver as 'sbx' | 'oci', stateDirs: [path.join(work, 'state')] });
const ws = path.join(work, 'tabs', 'ws');
fs.mkdirSync(ws, { recursive: true });
fs.writeFileSync(path.join(ws, 'README.md'), 'canary workspace\n');

// ---- seed ------------------------------------------------------------------------------
const canaries: Canary[] = [];
const seed = (store: string) => { const c = mintCanary(store); canaries.push(c); return c.value; };

// Editor/supervisor process environment: the kinds of variables a login shell exports.
const leakyEnv: Record<string, string> = {
	GITHUB_TOKEN: seed('env-github-token'),
	GH_TOKEN: seed('env-gh-token'),
	ANTHROPIC_API_KEY: seed('env-anthropic-key'),
	OPENAI_API_KEY: seed('env-openai-key'),
	AWS_SECRET_ACCESS_KEY: seed('env-aws-secret'),
	NPM_TOKEN: seed('env-npm-token'),
	SSH_AUTH_SOCK: `/private/tmp/${seed('env-ssh-auth-sock')}/agent.sock`,
	VSCODE_GIT_IPC_HANDLE: seed('env-git-ipc'),
	HTTPS_PROXY: `http://user:${seed('env-proxy-auth')}@proxy.invalid:3128`,
	SECLAB_CANARY: seed('env-generic'),
};
// A host file outside the workspace (credential-file stand-in).
const hostFile = path.join(work, 'host-credentials');
fs.writeFileSync(hostFile, `token=${seed('host-file')}\n`);
fs.writeFileSync(path.join(work, 'canaries.json'), serialize(canaries));

// ---- run a tab -------------------------------------------------------------------------
const stateDir = path.join(work, 'state');
const stderrLog: string[] = [];
const client = new TabdClient({
	command: process.execPath,
	args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', driver, '--allowed-root', path.join(work, 'tabs')],
	// Deliberately leaky: the supervisor must scrub all of this before any runtime call.
	env: { ...leakyEnv, HOME: process.env.HOME, USER: process.env.USER },
});
client.on('stderr', (s: string) => stderrLog.push(s));
const tabdExit = new Promise(res => client.once('exit', res));
const notifications: string[] = [];
client.on('notification', (m: string, p: unknown) => notifications.push(JSON.stringify({ m, p })));

let tabId = '';
let exitCode = 1;
try {
	await client.initialize('canary', '0');
	tabId = (await client.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } })).tab.metadata.name;
	writeManifest(work, { tabs: [tabId] });
	await client.request('tab.ensureRunning', { tabId });
	// Exercise the REH transport so its process tree is live.
	const { channel } = await client.connect(tabId);
	channel.write(Buffer.from(`GET ws://localhost/?reconnectionToken=${randomBytes(8).toString('hex')}&reconnection=false&skipWebSocketFrames=true HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: ${randomBytes(16).toString('base64')}\r\n\r\n`));
	await new Promise(r => setTimeout(r, 1500));
	channel.close();

	// ---- observe (as root inside the tab: stronger than the attacker) ------------------
	const name = `seclab-${tabId}`;
	const tabScanner = new StreamScanner(canaries, 'tab: process environ/cmdline + filesystem (root view)');
	// Positive controls go through the very same pipeline: a separate control canary is
	// planted (base64, odd alignment) in the tab user's home volume and in the /tmp tmpfs,
	// i.e. on other mounts than /. It must be found; the seeded canaries must not.
	const controlCanary = mintCanary('positive-control');
	const planted = `xx${Buffer.from(`y${controlCanary.value}z`).toString('base64')}xx`;
	const control = new StreamScanner([controlCanary], 'positive control');
	const dumpStatus = await new Promise<number | null>(resolve => {
		const p = spawn(runtime, ['exec', '-i', '-u', '0', name, 'sh', '-c', [
			'IFS= read -r PLANT; for d in /home/agent /tmp; do printf %s "$PLANT" > "$d/.seclab-positive-control"; done',
			'for p in /proc/[0-9]*; do cat "$p/environ" "$p/cmdline" 2>/dev/null; echo; done',
			// Whole VM filesystem across all mounts, except pseudo filesystems and the workspace.
			`find / \\( -path /proc -o -path /sys -o -path /dev -o -path '${ws}' \\) -prune -o -type f -size -5M -print0 2>/dev/null | xargs -0 cat 2>/dev/null`,
			'rm -f /home/agent/.seclab-positive-control /tmp/.seclab-positive-control; true',
		].join('; ')], { stdio: ['pipe', 'pipe', 'ignore'] });
		p.stdout.on('data', (d: Buffer) => { tabScanner.push(d); control.push(d); });
		p.on('close', resolve);
		p.stdin.end(`${planted}\n`);
	});
	const controlOk = control.hits.size > 0;
	const observed: Array<[string, Buffer | string]> = [
		['tabd: audit.log', fs.readFileSync(path.join(stateDir, 'audit.log'))],
		['tabd: stderr', stderrLog.join('')],
		['tabd: protocol notifications', notifications.join('\n')],
	];
	for (const f of fs.readdirSync(path.join(stateDir, 'tabs'))) {
		observed.push([`tabd state: ${f}`, fs.readFileSync(path.join(stateDir, 'tabs', f))]);
	}
	const hits: Hit[] = [...tabScanner.hits.values()];
	for (const [source, data] of observed) {
		hits.push(...scan(canaries, source, data));
	}
	console.log(`observed ${(tabScanner.bytes / 1e6).toFixed(0)} MB inside the tab + supervisor logs; ${canaries.length} canaries`);
	for (const h of hits) {
		console.log(`FAIL  canary from ${h.store} found (${h.encoding}) in ${h.source}`);
	}
	// Sanity: the scanner must find canaries where they legitimately are (host side).
	const selfTest = scan(canaries, 'self-test', fs.readFileSync(path.join(work, 'canaries.json'))).length;
	console.log(`${controlOk ? 'PASS' : 'FAIL'}  positive control: base64 canary planted in /home/agent and /tmp is found by the same find pipeline`);
	const ok = hits.length === 0 && dumpStatus === 0 && tabScanner.bytes > 1e6 && selfTest >= canaries.length && controlOk;
	console.log(ok ? `PASS  no canary in anything the tab can observe or in supervisor logs (scanner self-test ${selfTest} hits)` : `FAIL  (dump status ${dumpStatus}, self-test ${selfTest})`);
	exitCode = ok ? 0 : 1;
} finally {
	if (tabId && process.env.KEEP !== '1') {
		await client.request('tab.remove', { tabId }).catch(() => undefined);
	}
	client.dispose();
	await exitedOrTimeout(tabdExit);
	if (!teardownGate(work)) {
		exitCode = 1;
	}
}
process.exit(exitCode);
