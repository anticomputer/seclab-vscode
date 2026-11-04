// End-to-end smoke test of seclab-tabd against a real runtime (local only; needs sbx or docker).
// Usage: node tabd/test/e2e.ts [sbx|oci]
// Proves: claim -> ensureRunning (fence applied + verified) -> REH reachable over exec stdio.

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../src/client.ts';

const driver = process.argv[2] ?? 'sbx';
const repo = path.resolve(import.meta.dirname, '../..');
const work = path.join(repo, '.work', `e2e-${driver}`);
const ws = path.join(work, 'tabs', 'ws1');
fs.mkdirSync(ws, { recursive: true });

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

const list = await client.request<{ tabs: unknown[] }>('tab.list');
assert.equal(list.tabs.length, 1);
if (process.env.KEEP !== '1') {
	await client.request('tab.remove', { tabId });
	console.log('removed');
}
client.dispose();
console.log('E2E OK');
