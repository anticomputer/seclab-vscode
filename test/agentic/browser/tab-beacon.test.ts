// R10-1: the tab-side listener must never destroy the evidence it exists to collect.
//
// The defect: `tab-beacon.mjs` truncated its log at startup, and the `listen` watcher
// respawned it unconditionally every 1.5 seconds. So every probe line the live instance
// recorded was erased within a second or two, and the restore phase's network check could
// never pass, whatever the build did. It was recorded as a build limitation before the cause
// was found.
//
// Both halves are pinned here: the log is append-only, and a second instance on the same port
// exits without touching it. Loopback only, no editor, no tab.

import { strict as assert } from 'node:assert';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const BEACON = fileURLToPath(new URL('./tab-beacon.mjs', import.meta.url));
// Generated, not a literal: the listener requires a hex nonce, and a committed hex string
// of that shape reads like an identifier to the publish gate.
const NONCE = randomBytes(8).toString('hex');

/** A free loopback port. */
async function freePort(): Promise<number> {
	const net = await import('node:net');
	return new Promise((resolve, reject) => {
		const s = net.createServer();
		s.once('error', reject);
		s.listen(0, '127.0.0.1', () => {
			const p = (s.address() as { port: number }).port;
			s.close(() => resolve(p));
		});
	});
}

function start(log: string, port: number) {
	const c = spawn(process.execPath, [BEACON, log, String(port), NONCE], { stdio: 'ignore' });
	c.unref();
	return c;
}

async function waitFor(fn: () => boolean, ms = 8000): Promise<boolean> {
	const until = Date.now() + ms;
	while (Date.now() < until) {
		if (fn()) {
			return true;
		}
		await new Promise(r => setTimeout(r, 150));
	}
	return fn();
}

const lines = (f: string): string[] =>
	fs.existsSync(f) ? fs.readFileSync(f, 'utf8').split('\n').filter(Boolean) : [];

test('R10-1: the tab listener appends, and a duplicate cannot erase its evidence', async () => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'seclab-tabbeacon-'));
	const log = path.join(dir, 'tab-beacon.log');
	const port = await freePort();
	const first = start(log, port);
	try {
		assert.ok(await waitFor(() => lines(log).some(l => l.includes('"heartbeat"'))), 'the listener never beat');

		// A probe hit, which is the evidence that used to be destroyed.
		await fetch(`http://127.0.0.1:${port}/browser-probe-${NONCE}`).catch(() => undefined);
		assert.ok(await waitFor(() => lines(log).some(l => l.includes(`browser-probe-${NONCE}`))), 'the probe hit was not recorded');
		const afterHit = lines(log).length;

		// THE REGRESSION: a second instance, exactly as the watcher used to spawn one.
		const dup = start(log, port);
		await new Promise(r => setTimeout(r, 2500));
		assert.equal(dup.exitCode !== null || dup.killed, true, 'the duplicate should have exited on EADDRINUSE');

		const now = lines(log);
		assert.ok(now.some(l => l.includes(`browser-probe-${NONCE}`)),
			'the duplicate erased the probe hit: the log was truncated, which is R10-1');
		assert.ok(now.length >= afterHit, `the log shrank from ${afterHit} to ${now.length} lines`);

		// ...and the original is still serving, not displaced by the duplicate.
		const res = await fetch(`http://127.0.0.1:${port}/tab-live-${NONCE}`).catch(() => undefined);
		assert.ok(res?.ok, 'the original listener stopped serving after a duplicate started');
	} finally {
		try { first.kill('SIGKILL'); } catch { /* gone */ }
		fs.rmSync(dir, { recursive: true, force: true });
	}
});
