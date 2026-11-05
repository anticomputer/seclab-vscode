// Broker control client (docs/broker-protocol.md §1) against a fake `seclab-broker control`.
import assert from 'node:assert/strict';
import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { test } from 'node:test';
import { BROKER_POLICY_SCHEMA, BROKER_PROTOCOL } from '../src/broker.ts';
import { BrokerControl, BrokerControlError, connectBroker, MAX_LINE } from '../src/broker-control.ts';

/** A fake control process: `reply(req)` returns the lines the broker would print for a request. */
function fakeBroker(reply: (req: { id: number; method: string; params?: Record<string, unknown> }) => string[]) {
	const proc = new EventEmitter() as unknown as ChildProcessWithoutNullStreams & { sent: string[] };
	const stdin = new PassThrough();
	const stdout = new PassThrough();
	Object.assign(proc, { stdin, stdout, stderr: new PassThrough(), kill: () => proc.emit('exit', null), sent: [] as string[] });
	let buf = '';
	stdin.on('data', (c: Buffer) => {
		buf += c.toString();
		let nl: number;
		while ((nl = buf.indexOf('\n')) >= 0) {
			const line = buf.slice(0, nl);
			buf = buf.slice(nl + 1);
			proc.sent.push(line);
			for (const out of reply(JSON.parse(line))) {
				stdout.write(out + '\n');
			}
		}
	});
	return proc;
}
const hello = (tabId: string) => ({ protocol: BROKER_PROTOCOL, version: '0.3.0', tabId, engine: 'mitmproxy', engineVersion: '12', policySchema: { ...BROKER_POLICY_SCHEMA }, capabilities: {} });
const ok = (id: number, result: unknown = {}) => JSON.stringify({ jsonrpc: '2.0', id, result });

test('broker control: requests, results, errors and notifications', async () => {
	const proc = fakeBroker(req => req.method === 'health'
		? [JSON.stringify({ jsonrpc: '2.0', method: 'audit.event', params: { seq: 1, type: 'x' } }), ok(req.id, { status: 'ok' })]
		: [JSON.stringify({ jsonrpc: '2.0', id: req.id, error: { code: -32602, message: 'bad params' } })]);
	const c = new BrokerControl(proc);
	const notes: string[] = [];
	c.onNotification(n => notes.push(n.method));
	assert.deepEqual(await c.request('health'), { status: 'ok' });
	assert.deepEqual(notes, ['audit.event']);
	await assert.rejects(c.request('policy.load', { policy: {} }), (e: BrokerControlError) => e.code === -32602 && /^policy\.load: bad params$/.test(e.message));
	c.close();
	await assert.rejects(c.request('health'), /closed/);
});

test('broker control: a secret in params is never in an error message', async () => {
	const secret = 'example_only_password_xxxxxxxxxxxx';
	const c = new BrokerControl(fakeBroker(req => [JSON.stringify({ jsonrpc: '2.0', id: req.id, error: { code: -32602, message: 'rejected' } })]));
	const err = await c.request('proxy.auth.set', { username: 'seclab', password: secret }).catch(e => e as Error);
	assert.ok(err instanceof Error && !err.message.includes(secret));
	c.close();
});

test('broker control: fails closed on garbage, oversize lines and timeouts', async () => {
	const garbage = new BrokerControl(fakeBroker(() => ['not json']));
	await assert.rejects(garbage.request('health'), /not JSON/);
	const huge = new BrokerControl(fakeBroker(() => ['x'.repeat(MAX_LINE + 10)]));
	await assert.rejects(huge.request('health'), /over 1 MiB|not JSON/);
	const silent = new BrokerControl(fakeBroker(() => []), 50);
	await assert.rejects(silent.request('health'), /no reply/);
	silent.close();
	const tooBig = new BrokerControl(fakeBroker(() => []));
	await assert.rejects(tooBig.request('policy.load', { policy: 'x'.repeat(MAX_LINE) }), /too large/);
	tooBig.close();
});

test('connectBroker: retries while the socket is not up, then checks hello (fail closed)', async () => {
	let spawns = 0;
	const c = await connectBroker(() => {
		spawns++;
		return spawns < 3
			? fakeBroker(() => [JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32002, message: 'control socket not up' } })])
			: fakeBroker(req => [ok(req.id, hello('tab-1'))]);
	}, 'tab-1', { delayMs: 1 });
	assert.equal(spawns, 3);
	c.close();
	await assert.rejects(connectBroker(() => fakeBroker(req => [ok(req.id, hello('other-tab'))]), 'tab-1', { delayMs: 1 }), /not tab-1/);
	await assert.rejects(connectBroker(() => fakeBroker(req => [ok(req.id, { ...hello('tab-1'), policySchema: { version: 1, revision: 1 } })]), 'tab-1', { delayMs: 1 }), /policy schema/);
	// XX-2: a broker that never comes up stops retrying at the deadline.
	const t0 = Date.now();
	await assert.rejects(connectBroker(() => fakeBroker(() => [JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32002, message: 'not up' } })]), 'tab-1', { delayMs: 10, deadline: Date.now() + 200 }), /not up/);
	assert.ok(Date.now() - t0 < 2_000, 'gave up at the deadline');
	// A broker that never answers is cut off at the deadline, not after 15 s.
	const t1 = Date.now();
	await assert.rejects(connectBroker(() => fakeBroker(() => []), 'tab-1', { deadline: Date.now() + 200 }), /no reply/);
	assert.ok(Date.now() - t1 < 2_000);
});
