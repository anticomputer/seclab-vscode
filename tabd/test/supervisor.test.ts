// Supervisor behaviour against a fake driver: fail-closed fence lifecycle, ownership,
// channel handling. No runtime needed.

import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { PassThrough } from 'node:stream';
import { test } from 'node:test';
import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import { encodeJson, FrameDecoder } from '../src/frames.ts';
import { TabStore } from '../src/state.ts';
import { Supervisor } from '../src/supervisor.ts';
import type { Driver, FenceReport, TabRuntimeSpec, TabTemplate } from '../src/drivers/types.ts';
import type { ScanResult } from '../src/scan.ts';

const SCRATCH = path.resolve(import.meta.dirname, '../../.work/test-tabd-supervisor');

class FakeDriver implements Driver {
	readonly name = 'fake';
	fenceOk = true;
	running = new Set<string>();
	calls: string[] = [];
	async probe() {
		return { name: 'fake', available: true, capabilities: { isolationClass: 'namespaces', networkFence: 'none', liveMounts: false, holdAndResume: false, fileWatch: 'native', sameAbsolutePathMount: true } as const };
	}
	async ensureRunning(spec: TabRuntimeSpec) { this.calls.push(`start ${spec.tabId}`); this.running.add(spec.sandboxName); }
	async verifyFence(): Promise<FenceReport> { return { ok: this.fenceOk, problems: this.fenceOk ? [] : ['drift'], checkedAt: '' }; }
	async quarantine(spec: TabRuntimeSpec) { this.calls.push(`quarantine ${spec.tabId}`); this.running.delete(spec.sandboxName); }
	async runningSandboxes() { return new Set(this.running); }
	connectReh(): ChildProcessWithoutNullStreams {
		const child = new EventEmitter() as unknown as ChildProcessWithoutNullStreams;
		const stdin = new PassThrough(), stdout = new PassThrough(), stderr = new PassThrough();
		Object.assign(child, { stdin, stdout, stderr, kill: () => { stdout.end(); (child as unknown as EventEmitter).emit('close', 0); return true; } });
		stdin.on('data', d => stdout.write(Buffer.concat([Buffer.from('echo:'), d]))); // fake REH: echo
		return child;
	}
	async stop(spec: TabRuntimeSpec) { this.calls.push(`stop ${spec.tabId}`); this.running.delete(spec.sandboxName); }
	async remove(spec: TabRuntimeSpec) { this.calls.push(`remove ${spec.tabId}`); }
}

const noFindings = async (): Promise<ScanResult> => ({ complete: true, findings: [], secrets: new Map() });

function setup(name: string, scanArg: ((p: string) => Promise<ScanResult>) | null = noFindings) {
	const scan = scanArg ?? undefined;
	const dir = path.join(SCRATCH, name);
	fs.rmSync(dir, { recursive: true, force: true });
	const ws = path.join(dir, 'home', 'src', 'proj');
	fs.mkdirSync(ws, { recursive: true });
	const driver = new FakeDriver();
	const template: TabTemplate = { kind: 'TabTemplate', metadata: { name: 'default' }, spec: { driver: 'fake', image: 'img', envVarsInjectionPolicy: 'Disallowed', fence: 'required', broker: 'none' } };
	const out: Array<{ channel: number; payload: Buffer }> = [];
	const dec = new FrameDecoder();
	let fatal: string | undefined;
	const sup = new Supervisor({
		drivers: new Map([['fake', driver]]), templates: new Map([['default', template]]),
		store: new TabStore(path.join(dir, 'state')),
		write: b => out.push(...dec.push(b)), onFatal: r => { fatal = r; },
		fenceReverifyMs: 20, pathPolicy: { home: path.join(dir, 'home'), allowedRoots: [path.join(dir, 'home', 'src')] }, scan,
	});
	let id = 1;
	const call = async (method: string, params: unknown = {}) => {
		const myId = id++;
		sup.receive(encodeJson({ jsonrpc: '2.0', id: myId, method, params }));
		for (let i = 0; i < 200; i++) {
			const m = out.filter(f => f.channel === 0).map(f => JSON.parse(f.payload.toString())).find(x => x.id === myId);
			if (m) {
				if (m.error) {
					throw Object.assign(new Error(m.error.message), { code: m.error.code, data: m.error.data });
				}
				return m.result;
			}
			await new Promise(r => setTimeout(r, 5));
		}
		throw new Error('timeout');
	};
	return { sup, driver, call, out, ws, getFatal: () => fatal };
}

test('supervisor: requires initialize; unknown tab ids are refused', async () => {
	const { call } = setup('init');
	await assert.rejects(call('tab.list'), /not initialized/);
	await call('initialize', { protocolVersion: 'seclab-tabd/0.1', client: { name: 't', version: '0' } });
	await assert.rejects(call('tab.get', { tabId: 't-aaaaaaaaaaaaaaaaaaaaaaaaaa' }), /unknown tab/);
	await assert.rejects(call('tab.get', { tabId: '../etc' }), /invalid tab id/);
});

test('supervisor: connect requires a running sandbox; echo over a channel; drift quarantines', async () => {
	const { call, driver, out, ws, sup } = setup('lifecycle');
	await call('initialize', { protocolVersion: 'seclab-tabd/0.1', client: { name: 't', version: '0' } });
	const { tab } = await call('tab.claim', { workspace: { hostPath: ws } });
	const tabId = tab.metadata.name;
	await assert.rejects(call('tab.connect', { tabId }), /not running/);
	const er = await call('tab.ensureRunning', { tabId });
	assert.match(er.connectionToken, /^[0-9a-f]{64}$/);
	const { channel } = await call('tab.connect', { tabId });
	sup.receive(Buffer.concat([Buffer.from([0, 0, 0, 2, 0, 0, 0, channel]), Buffer.from('hi')]));
	await new Promise(r => setTimeout(r, 20));
	assert.ok(out.some(f => f.channel === channel && f.payload.toString() === 'echo:hi'));
	// Drift: fence starts failing while running -> quarantined by the monitor.
	driver.fenceOk = false;
	await new Promise(r => setTimeout(r, 120));
	assert.ok(driver.calls.includes(`quarantine ${tabId}`), driver.calls.join());
	sup.shutdown();
});

test('supervisor: client gone stops owned tabs even if never connected', async () => {
	const { call, driver, ws, sup } = setup('gone');
	await call('initialize', { protocolVersion: 'seclab-tabd/0.1', client: { name: 't', version: '0' } });
	const { tab } = await call('tab.claim', { workspace: { hostPath: ws } });
	await call('tab.ensureRunning', { tabId: tab.metadata.name });
	await sup.clientGone();
	assert.ok(driver.calls.includes(`stop ${tab.metadata.name}`));
});

test('supervisor: data for a never-opened channel is fatal', async () => {
	const { sup, getFatal } = setup('fatal');
	sup.receive(Buffer.concat([Buffer.from([0, 0, 0, 1, 0, 0, 0, 9]), Buffer.from('x')]));
	assert.match(getFatal() ?? '', /unopened channel/);
});

test('supervisor: secrets block the mount; accept records an exception; move rewrites and restores', async () => {
	const secret = 'seclabcanary_TEST_0123456789abcdef0123456789abcdef';
	let wsPath = '';
	const scan = async (p: string): Promise<ScanResult> => {
		const has = fs.readFileSync(path.join(p, 'config.env'), 'utf8').includes(secret);
		return has
			? { complete: true, findings: [{ id: 'f1', source: 'worktree', file: 'config.env', line: 2, rule: 'seclab-canary', movable: true }], secrets: new Map([['f1', secret]]) }
			: { complete: true, findings: [], secrets: new Map() };
	};
	const { call, driver, ws } = setup('secrets', scan);
	wsPath = ws;
	fs.writeFileSync(path.join(wsPath, 'config.env'), `A=1\nTOKEN=${secret}\n`);
	await call('initialize', { protocolVersion: 'seclab-tabd/0.1', client: { name: 't', version: '0' } });
	const { tab } = await call('tab.claim', { workspace: { hostPath: wsPath } });
	const tabId = tab.metadata.name;
	await assert.rejects(call('tab.ensureRunning', { tabId }), (e: Error & { code?: number }) => e.code === -32020);
	assert.equal(driver.calls.filter(c => c.startsWith('start')).length, 0, 'nothing mounted while secrets are unresolved');
	// Move to broker: file now holds a sentinel; the secret only exists in the host vault.
	await call('tab.scan', { tabId });
	await assert.rejects(call('tab.moveSecrets', { tabId, moves: [{ id: 'f1', bind: { host: 'evil host' } }] }), /invalid credential binding/);
	const { moved } = await call('tab.moveSecrets', { tabId, moves: [{ id: 'f1', bind: { host: 'api.example.com', path: '/v1/**' } }] });
	const content = fs.readFileSync(path.join(wsPath, 'config.env'), 'utf8');
	assert.ok(!content.includes(secret) && content.includes(moved[0].sentinel));
	await call('tab.ensureRunning', { tabId });
	assert.equal(driver.calls.filter(c => c.startsWith('start')).length, 1);
	// Restore (tab must be stopped).
	await call('tab.stop', { tabId });
	const { restored } = await call('tab.restoreSecrets', { tabId });
	assert.deepEqual(restored, ['config.env:2']);
	assert.ok(fs.readFileSync(path.join(wsPath, 'config.env'), 'utf8').includes(secret));
	// Open anyway: accepted finding ids are recorded as an exception.
	await call('tab.ensureRunning', { tabId, acceptFindings: ['f1'] });
	assert.equal(driver.calls.filter(c => c.startsWith('start')).length, 2);
});

test('supervisor: no scanner = fail closed', async () => {
	const { call, ws } = setup('noscan', null);
	await call('initialize', { protocolVersion: 'seclab-tabd/0.1', client: { name: 't', version: '0' } });
	const { tab } = await call('tab.claim', { workspace: { hostPath: ws } });
	await assert.rejects(call('tab.ensureRunning', { tabId: tab.metadata.name }), (e: Error & { code?: number }) => e.code === -32021);
	await call('tab.ensureRunning', { tabId: tab.metadata.name, acceptFindings: ['scan-incomplete'] });
});

test('supervisor: an incomplete scan still reports its findings first; both must be accepted (S1)', async () => {
	const scan = async (): Promise<ScanResult> => ({
		complete: false, overflow: true, error: 'secret scan incomplete: scanner report too large to review',
		findings: [{ id: 'f1', source: 'worktree', file: '.env', line: 1, rule: 'generic-api-key', movable: true }], secrets: new Map([['f1', 'REAL_TOKEN_ABCDEF']]),
	});
	const { call, driver, ws } = setup('partial', scan);
	await call('initialize', { protocolVersion: 'seclab-tabd/0.1', client: { name: 't', version: '0' } });
	const tabId = (await call('tab.claim', { workspace: { hostPath: ws } })).tab.metadata.name;
	await assert.rejects(call('tab.ensureRunning', { tabId }), (e: Error & { code?: number; data?: { findings: unknown[]; overflow: boolean } }) =>
		e.code === -32020 && e.data?.findings.length === 1 && e.data.overflow === true);
	await assert.rejects(call('tab.ensureRunning', { tabId, acceptFindings: ['scan-incomplete'] }), (e: Error & { code?: number }) => e.code === -32020);
	await assert.rejects(call('tab.ensureRunning', { tabId, acceptFindings: ['f1'] }), (e: Error & { code?: number }) => e.code === -32021);
	assert.equal(driver.calls.filter(c => c.startsWith('start')).length, 0);
	await call('tab.ensureRunning', { tabId, acceptFindings: ['f1', 'scan-incomplete'] });
	assert.equal(driver.calls.filter(c => c.startsWith('start')).length, 1);
});
