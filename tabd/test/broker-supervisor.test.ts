// Supervisor broker bring-up (plan tabd-broker-wiring B1) against a fake driver and a fake
// `seclab-broker control`: request order, CA check, policy errors fail the start, the proxy
// password never reaches the audit log, and the broker is shut down on stop.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { PassThrough } from 'node:stream';
import { test } from 'node:test';
import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import { encodeJson, FrameDecoder } from '../src/frames.ts';
import { TabStore } from '../src/state.ts';
import { Supervisor } from '../src/supervisor.ts';
import { BROKER_POLICY_SCHEMA, BROKER_PROTOCOL } from '../src/broker.ts';
import type { BrokerHooks, BrokerSetup, Driver, FenceReport, SensorHooks, TabRuntimeSpec, TabTemplate } from '../src/drivers/types.ts';
import { defaultPolicy, tabPolicy, USER_POLICY_FILE } from '../src/broker-policy.ts';

const SCRATCH = path.resolve(import.meta.dirname, '../../.work/test-scratch/broker-supervisor');
const PEM = '-----BEGIN CERTIFICATE-----\nZXhhbXBsZSBvbmx5\n-----END CERTIFICATE-----\n';

/** Fake broker: records methods and params, answers like the real one. */
function fakeBroker(tabId: string, log: Array<{ method: string; params?: Record<string, unknown> }>, opts: { badCa?: boolean; rejectPolicy?: boolean } = {}) {
	const proc = new EventEmitter() as unknown as ChildProcessWithoutNullStreams;
	const stdin = new PassThrough(), stdout = new PassThrough();
	Object.assign(proc, { stdin, stdout, stderr: new PassThrough(), kill: () => proc.emit('exit', null) });
	let buf = '';
	stdin.on('data', (c: Buffer) => {
		buf += c.toString();
		let nl: number;
		while ((nl = buf.indexOf('\n')) >= 0) {
			const req = JSON.parse(buf.slice(0, nl));
			buf = buf.slice(nl + 1);
			log.push({ method: req.method, params: req.params });
			const reply = (result: unknown) => stdout.write(JSON.stringify({ jsonrpc: '2.0', id: req.id, result }) + '\n');
			switch (req.method) {
				case 'broker.hello': reply({ protocol: BROKER_PROTOCOL, version: '0.3.0', tabId, engine: 'x', engineVersion: '1', policySchema: { ...BROKER_POLICY_SCHEMA }, capabilities: {} }); break;
				case 'health': reply({ status: 'ok' }); break;
				case 'policy.load':
					if (opts.rejectPolicy) {
						stdout.write(JSON.stringify({ jsonrpc: '2.0', id: req.id, error: { code: -32602, message: 'policy: /allow/0/host: bad host' } }) + '\n');
					} else {
						reply({ revision: 1, sentinels: {} });
					}
					break;
				case 'ca.get': reply({ certPem: PEM, pemSha256: opts.badCa ? '0'.repeat(64) : createHash('sha256').update(PEM).digest('hex') }); break;
				default: reply({});
			}
		}
	});
	return proc;
}

class BrokerDriver implements Driver {
	readonly name = 'fake';
	running = new Set<string>();
	setup: BrokerSetup | undefined;
	brokerLog: Array<{ method: string; params?: Record<string, unknown> }> = [];
	opts: { badCa?: boolean; rejectPolicy?: boolean } = {};
	async probe() {
		return { name: 'fake', available: true, capabilities: { isolationClass: 'namespaces', networkFence: 'internal-network', liveMounts: false, holdAndResume: false, fileWatch: 'native', sameAbsolutePathMount: true, writeBack: 'ungated' } as const };
	}
	async ensureRunning(spec: TabRuntimeSpec, _token: string, _sensor?: SensorHooks, broker?: BrokerHooks) {
		assert.ok(broker, 'broker hooks supplied for a broker: required template');
		this.setup = await broker.configure(() => fakeBroker(spec.tabId, this.brokerLog, this.opts));
		this.running.add(spec.sandboxName);
	}
	async verifyFence(): Promise<FenceReport> { return { ok: true, problems: [], checkedAt: '' }; }
	async quarantine(spec: TabRuntimeSpec) { this.running.delete(spec.sandboxName); }
	async runningSandboxes() { return new Set(this.running); }
	connectReh(): ChildProcessWithoutNullStreams { throw new Error('unused'); }
	async stop(spec: TabRuntimeSpec) { this.running.delete(spec.sandboxName); }
	async remove() { /* */ }
}

function setup(name: string, policy?: (tabId: string) => Record<string, unknown>) {
	const dir = path.join(SCRATCH, name);
	fs.rmSync(dir, { recursive: true, force: true });
	const ws = path.join(dir, 'home', 'src', 'proj');
	fs.mkdirSync(ws, { recursive: true });
	const driver = new BrokerDriver();
	const template: TabTemplate = { kind: 'TabTemplate', metadata: { name: 'default' }, spec: { driver: 'fake', image: 'img', envVarsInjectionPolicy: 'Disallowed', fence: 'required', broker: 'required' } };
	const out: Array<{ channel: number; payload: Buffer }> = [];
	const audit: string[] = [];
	const dec = new FrameDecoder();
	const sup = new Supervisor({
		drivers: new Map([['fake', driver]]), templates: new Map([['default', template]]),
		store: new TabStore(path.join(dir, 'state')), write: b => out.push(...dec.push(b)), onFatal: () => { /* */ },
		audit: e => audit.push(JSON.stringify(e)), fenceReverifyMs: 60_000,
		pathPolicy: { home: path.join(dir, 'home'), allowedRoots: [path.join(dir, 'home', 'src')] },
		scan: async () => ({ complete: true, findings: [], secrets: new Map() }), brokerPolicy: policy,
	});
	let id = 1;
	const call = async (method: string, params: unknown = {}) => {
		const myId = id++;
		sup.receive(encodeJson({ jsonrpc: '2.0', id: myId, method, params }));
		for (let i = 0; i < 400; i++) {
			const m = out.filter(f => f.channel === 0).map(f => JSON.parse(f.payload.toString())).find(x => x.id === myId);
			if (m) {
				if (m.error) {
					throw new Error(m.error.message);
				}
				return m.result;
			}
			await new Promise(r => setTimeout(r, 5));
		}
		throw new Error('timeout');
	};
	return { sup, driver, call, ws, audit };
}

test('broker bring-up: hello, health, proxy auth, policy, CA; password never audited; shutdown on stop', async () => {
	const { sup, driver, call, ws, audit } = setup('ok');
	await call('initialize', { protocolVersion: 'seclab-tabd/0.1', client: { name: 't', version: '0' } });
	const tabId = (await call('tab.claim', { workspace: { hostPath: ws } })).tab.metadata.name;
	await call('tab.ensureRunning', { tabId });
	assert.deepEqual(driver.brokerLog.map(l => l.method), ['broker.hello', 'health', 'proxy.auth.set', 'policy.load', 'ca.get']);
	const pw = driver.setup!.proxyPassword;
	assert.match(pw, /^[A-Za-z0-9_-]{32}$/);
	assert.equal(driver.brokerLog[2].params!.password, pw);
	const policy = driver.brokerLog[3].params!.policy as Record<string, unknown>;
	assert.equal(policy.tabId, tabId);
	assert.deepEqual(policy.allow, [], 'default policy is deny-all');
	assert.equal(driver.setup!.caPem, PEM);
	assert.ok(!audit.join('\n').includes(pw), 'the proxy password is not in the audit log');
	await call('tab.stop', { tabId });
	assert.equal(driver.brokerLog.at(-1)!.method, 'broker.shutdown');
	sup.shutdown();
});

test('broker bring-up fails closed: CA hash mismatch, policy rejected by the broker, invalid user policy', async () => {
	for (const [name, opts, policy, re] of [
		['badca', { badCa: true }, undefined, /does not match its sha256/],
		['rejected', { rejectPolicy: true }, undefined, /policy\.load: policy: \/allow\/0\/host/],
		['userpolicy', {}, () => { throw new Error('broker-policy.json: not JSON'); }, /broker-policy\.json: not JSON/],
	] as const) {
		const { sup, driver, call, ws } = setup(name, policy as ((t: string) => Record<string, unknown>) | undefined);
		driver.opts = opts;
		await call('initialize', { protocolVersion: 'seclab-tabd/0.1', client: { name: 't', version: '0' } });
		const tabId = (await call('tab.claim', { workspace: { hostPath: ws } })).tab.metadata.name;
		await assert.rejects(call('tab.ensureRunning', { tabId }), re, name);
		assert.equal(driver.running.size, 0, `${name}: tab not started`);
		sup.shutdown();
	}
});

test('tabPolicy: default deny-all; the user policy is a private regular file, version 1, for this tab', () => {
	const dir = path.join(SCRATCH, 'policy');
	fs.rmSync(dir, { recursive: true, force: true });
	fs.mkdirSync(dir, { recursive: true });
	const f = path.join(dir, USER_POLICY_FILE);
	assert.deepEqual(tabPolicy(dir, 't-1'), defaultPolicy('t-1'));
	fs.writeFileSync(f, JSON.stringify({ version: 1, allow: [{ host: 'example.com' }] }), { mode: 0o600 });
	assert.deepEqual(tabPolicy(dir, 't-1'), { version: 1, allow: [{ host: 'example.com' }], tabId: 't-1' });
	fs.chmodSync(f, 0o666);
	assert.throws(() => tabPolicy(dir, 't-1'), /writable by group or others/);
	fs.chmodSync(f, 0o600);
	fs.writeFileSync(f, JSON.stringify({ version: 1, tabId: 't-2' }));
	assert.throws(() => tabPolicy(dir, 't-1'), /names tab/);
	fs.writeFileSync(f, JSON.stringify({ version: 2 }));
	assert.throws(() => tabPolicy(dir, 't-1'), /version 1/);
	fs.writeFileSync(f, '{');
	assert.throws(() => tabPolicy(dir, 't-1'), /not JSON/);
	fs.rmSync(f);
	fs.symlinkSync('/etc/hosts', f);
	assert.throws(() => tabPolicy(dir, 't-1'), /not a regular file/);
	fs.rmSync(dir, { recursive: true, force: true });
});
