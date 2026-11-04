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

function setup(name: string) {
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
		fenceReverifyMs: 20, pathPolicy: { home: path.join(dir, 'home'), allowedRoots: [path.join(dir, 'home', 'src')] },
	});
	let id = 1;
	const call = async (method: string, params: unknown = {}) => {
		const myId = id++;
		sup.receive(encodeJson({ jsonrpc: '2.0', id: myId, method, params }));
		for (let i = 0; i < 200; i++) {
			const m = out.filter(f => f.channel === 0).map(f => JSON.parse(f.payload.toString())).find(x => x.id === myId);
			if (m) {
				if (m.error) {
					throw Object.assign(new Error(m.error.message), { code: m.error.code });
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
