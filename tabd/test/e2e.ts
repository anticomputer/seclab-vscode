// End-to-end smoke test of seclab-tabd against a real runtime (local only; needs sbx or docker).
// Usage: node tabd/test/e2e.ts [sbx|oci]
// Proves: claim -> ensureRunning (fence applied + verified) -> REH reachable over exec stdio.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../src/client.ts';
import { teardownGate, writeManifest, writeSnapshot } from '../../test/containment/teardown.ts';

const driver = process.argv[2] ?? 'sbx';
const repo = path.resolve(import.meta.dirname, '../..');
const work = path.join(repo, '.work', `e2e-${driver}`);
const ws = path.join(work, 'tabs', 'ws1');
fs.mkdirSync(ws, { recursive: true });
writeSnapshot(work);
writeManifest(work, { driver: driver as 'sbx' | 'oci', stateDirs: [path.join(work, 'state')] });
// Teardown gate on every exit path, assertion failures included (it is synchronous).
process.on('exit', code => {
	if (!teardownGate(work) && code === 0) {
		process.exitCode = 1;
	}
});

const client = new TabdClient({
	command: process.execPath,
	args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', path.join(work, 'state'), '--driver', driver, '--allowed-root', path.join(work, 'tabs')],
	env: { HOME: process.env.HOME, USER: process.env.USER, PATH: '/usr/bin:/bin' },
});
client.on('stderr', (s: string) => process.stderr.write(`[tabd] ${s}`));
client.on('notification', (m: string, p: { action?: string; outcome?: string; tabId?: string; phase?: string }) => {
	if (m === 'tab.status') {
		console.log(`status ${p.tabId} ${p.phase}`);
	} else if (m === 'audit' && p.action !== 'spawn') {
		console.log(`audit ${p.action} ${p.outcome}`);
	}
});

const t0 = Date.now();
const init = await client.initialize('e2e', '0');
console.log('drivers', JSON.stringify(init.drivers));
const { tab } = await client.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
const tabId = tab.metadata.name;
writeManifest(work, { tabs: [tabId] });
console.log('claimed', tabId);
await client.request('tab.ensureRunning', { tabId });
console.log(`running after ${Date.now() - t0} ms`);

async function handshake(): Promise<string> {
	const t = Date.now();
	const { channel } = await client.connect(tabId);
	const got: Buffer[] = [];
	const done = new Promise<string>((resolve, reject) => {
		channel.onData(d => {
			got.push(d);
			const s = Buffer.concat(got).toString('latin1');
			if (s.includes('\r\n\r\n')) {
				resolve(s.split('\r\n')[0]);
			}
		});
		channel.onClose(e => reject(new Error(`closed: ${e}`)));
	});
	// Exactly what VS Code's managed socket sends (managedSocket.ts makeRawSocketHeaders).
	const nonce = randomBytes(16).toString('base64');
	channel.write(Buffer.from([
		`GET ws://localhost/?reconnectionToken=${randomBytes(8).toString('hex')}&reconnection=false&skipWebSocketFrames=true HTTP/1.1`,
		'Connection: Upgrade', 'Upgrade: websocket', `Sec-WebSocket-Key: ${nonce}`, '', ''].join('\r\n')));
	const line = await done;
	channel.close();
	console.log(`handshake in ${Date.now() - t} ms: ${line}`);
	return line;
}

assert.match(await handshake(), /^HTTP\/1\.1 101/);
assert.match(await handshake(), /^HTTP\/1\.1 101/, 'second connection to the same REH');

const name = `seclab-${tabId}`;
// The OCI driver runs the REH as the workspace owner on Linux (tabUser in drivers/oci.ts), else 1000:1000.
const st = fs.statSync(ws);
const ociUser = process.platform === 'linux' ? `${st.uid}:${st.gid}` : '1000:1000';
const inTab = (script: string) => driver === 'sbx'
	? spawnSync('/opt/homebrew/bin/sbx', ['exec', '-u', 'agent', name, 'sh', '-c', script], { encoding: 'utf8' })
	: spawnSync('docker', ['exec', '-u', ociUser, '--', name, 'sh', '-c', script], { encoding: 'utf8' });
const rehPid = () => inTab('cat "/run/user/$(id -u)/seclab/reh.pid"').stdout.trim();

// B3c: tab.ensureRunning on a running tab with a live REH leaves it alone (the Tab Manager calls
// it before each new connection; on sbx, a second start used to replace the REH every time).
const pidBefore = rehPid();
assert.match(pidBefore, /^\d+$/);
const before = (await client.request<{ connectionToken: string }>('tab.ensureRunning', { tabId })).connectionToken;
assert.equal(rehPid(), pidBefore, 'ensureRunning on a running tab keeps its REH');
assert.match(await handshake(), /^HTTP\/1\.1 101/, 'the same REH still answers');

// B3c: the server dies; tab.ensureRunning (what the Tab Manager's reconnect does first) brings it
// back under the same connection token, so the window's reload lands on a running tab.
// Fails unless at least one REH process was killed, so a kill as the wrong user cannot pass silently.
const killReh = 'n=0; for p in /proc/[0-9]*; do tr "\\0" " " < "$p/cmdline" 2>/dev/null | grep -q "^/opt/seclab-reh/" && kill -9 "${p#/proc/}" 2>/dev/null && n=$((n+1)); done; echo "killed $n"; [ "$n" -gt 0 ]';
const k = inTab(killReh);
assert.equal(k.status, 0, `killing the REH: ${k.stdout}${k.stderr}`);
await new Promise(r => setTimeout(r, 1000));
await assert.rejects(handshake(), /closed/, 'no server: the connection closes');
const after = (await client.request<{ connectionToken: string }>('tab.ensureRunning', { tabId })).connectionToken;
assert.equal(after, before, 'same connection token after the restart');
assert.match(await handshake(), /^HTTP\/1\.1 101/, 'the server is back: the window can reconnect');
console.log('server restart: reconnect works with the same token');

const list = await client.request<{ tabs: unknown[] }>('tab.list');
assert.equal(list.tabs.length, 1);
if (process.env.KEEP !== '1') {
	await client.request('tab.remove', { tabId });
	console.log('removed');
}
client.dispose();
console.log('E2E OK');
