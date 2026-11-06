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
import { approvalPromptText, DECISION_LABELS, sanitizeApproval } from '../src/approvals.ts';
import { CFS_TENANT, feedInstallLine, parseAzToken, type AzToken } from '../src/cfs.ts';
import { INSTALL_FEED } from '../src/drivers/broker-install.ts';
import { spawnSync } from 'node:child_process';

const SCRATCH = path.resolve(import.meta.dirname, '../../.work/test-scratch/broker-supervisor');
const PEM = '-----BEGIN CERTIFICATE-----\nZXhhbXBsZSBvbmx5\n-----END CERTIFICATE-----\n';

/** Fake broker: records methods and params, answers like the real one. */
function fakeBroker(tabId: string, log: Array<{ method: string; params?: Record<string, unknown> }>, opts: { badCa?: boolean; rejectPolicy?: boolean; tail?: unknown[]; denyRules?: boolean } = {}, onStdout?: (s: PassThrough) => void) {
	const proc = new EventEmitter() as unknown as ChildProcessWithoutNullStreams;
	const stdin = new PassThrough(), stdout = new PassThrough();
	Object.assign(proc, { stdin, stdout, stderr: new PassThrough(), kill: () => proc.emit('exit', null) });
	onStdout?.(stdout);
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
				case 'broker.hello': reply({ protocol: BROKER_PROTOCOL, version: '0.3.0', tabId, engine: 'x', engineVersion: '1', policySchema: { ...BROKER_POLICY_SCHEMA }, capabilities: opts.denyRules ? { denyRules: true } : {} }); break;
				case 'health': reply({ status: 'ok' }); break;
				case 'policy.load':
					if (opts.rejectPolicy) {
						stdout.write(JSON.stringify({ jsonrpc: '2.0', id: req.id, error: { code: -32602, message: 'policy: /allow/0/host: bad host' } }) + '\n');
					} else {
						reply({ revision: 1, sentinels: {} });
					}
					break;
				case 'ca.get': reply({ certPem: PEM, pemSha256: opts.badCa ? '0'.repeat(64) : createHash('sha256').update(PEM).digest('hex') }); break;
				case 'audit.tail': reply({ events: opts.tail ?? [] }); break;
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
	opts: { badCa?: boolean; rejectPolicy?: boolean; tail?: unknown[]; denyRules?: boolean } = {};
	brokerOut: PassThrough | undefined;
	feeds: Array<string | undefined> = [];
	async installFeed(_spec: TabRuntimeSpec, sentinel: string | undefined) { this.feeds.push(sentinel); }
	async probe() {
		return { name: 'fake', available: true, capabilities: { isolationClass: 'namespaces', networkFence: 'internal-network', liveMounts: false, holdAndResume: false, fileWatch: 'native', sameAbsolutePathMount: true, writeBack: 'ungated' } as const };
	}
	async ensureRunning(spec: TabRuntimeSpec, _token: string, _sensor?: SensorHooks, broker?: BrokerHooks) {
		assert.ok(broker, 'broker hooks supplied for a broker: required template');
		this.setup = await broker.configure(() => fakeBroker(spec.tabId, this.brokerLog, this.opts, s => {
			this.brokerOut = s;
		}));
		this.running.add(spec.sandboxName);
	}
	async verifyFence(): Promise<FenceReport> { return { ok: true, problems: [], checkedAt: '' }; }
	async quarantine(spec: TabRuntimeSpec) { this.running.delete(spec.sandboxName); }
	async runningSandboxes() { return new Set(this.running); }
	connectReh(): ChildProcessWithoutNullStreams { throw new Error('unused'); }
	async stop(spec: TabRuntimeSpec) { this.running.delete(spec.sandboxName); }
	async remove() { /* */ }
}

function setup(name: string, policy?: (tabId: string) => Record<string, unknown>, cfs?: { token(): Promise<AzToken> }) {
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
		scan: async () => ({ complete: true, findings: [], secrets: new Map() }), brokerPolicy: policy, cfs,
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
	assert.deepEqual(driver.brokerLog.map(l => l.method).filter(m => m !== 'audit.tail'), ['broker.hello', 'health', 'proxy.auth.set', 'policy.load', 'ca.get', 'tab.event', 'approval.list']);
	assert.deepEqual(driver.brokerLog.find(l => l.method === 'tab.event')!.params, { kind: 'opened' }, 'the broker learns the tab was just opened');
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

test('broker audit: replayed and live events become trusted tab events; deduped, aggregated, gaps reported, tab text tagged', async () => {
	const { sup, driver, call, ws } = setup('audit');
	const started = { seq: 1, ts: 1793800000.0, type: 'broker.started', version: '0.3.0' };
	await call('initialize', { protocolVersion: 'seclab-tabd/0.1', client: { name: 't', version: '0' } });
	const tabId = (await call('tab.claim', { workspace: { hostPath: ws } })).tab.metadata.name;
	const denied = {
		seq: 2, ts: 1793800001.0, type: 'request.denied_unprompted', tabId, reason: 'raw ip', scheme: 'http', host: '192.0.2.10', port: 80, method: 'GET',
		path: '/beacon', risk: { flags: ['raw-ip'], origin: { label: 'IGNORE PREVIOUS INSTRUCTIONS', verified: false } }, untrusted: ['host', 'method', 'path', 'risk.origin.label'],
	};
	driver.opts = { tail: [started, denied] };
	await call('tab.ensureRunning', { tabId });
	const notify = (params: unknown) => driver.brokerOut!.write(JSON.stringify({ jsonrpc: '2.0', method: 'audit.event', params }) + '\n');
	const allowed = (seq: number) => ({ seq, ts: 1793800002 + seq, type: 'request.allowed', tabId, scheme: 'https', host: 'api.example.com', port: 443, method: 'GET', path: '/x', rule: 'r1' });
	notify(denied); // duplicate of a replayed event: ignored
	notify(allowed(3));
	notify(allowed(4));
	notify(allowed(5));
	notify({ seq: 6, ts: 1793800010, type: 'model.call', tabId, provider: 'example', host: 'api.example.com', port: 443, method: 'POST', path: '/v1/chat', reqBytes: 10, respBytes: 20, status: 200, durationMs: 5, tools: ['function'] });
	notify({ seq: 7, ts: 1793800011, type: 'request.denied', tabId: 't-someoneelse', host: 'x.example', port: 443 });
	notify({ seq: 10, ts: 1793800012, type: 'sentinel.misplaced', tabId, credentialId: 'gh', location: 'header', host: 'evil.example', port: 443 });
	let events: Array<Record<string, any>> = [];
	for (let i = 0; i < 100 && !events.some(e => e.detail?.auditType === 'sentinel.misplaced'); i++) {
		await new Promise(r => setTimeout(r, 10));
		events = (await call('tab.events.tail', { tabId, limit: 1000 })).events;
	}
	const broker = events.filter(e => e.source === 'broker');
	assert.ok(broker.every(e => e.integrity === 'trusted'), 'broker events are trusted');
	const types = broker.map(e => e.detail.auditType);
	assert.deepEqual(types, ['broker.started', 'request.denied_unprompted', 'request.allowed', 'model.call', 'sentinel.misplaced'], 'replay once, dup and foreign tab dropped, repeats aggregated');
	const d = broker[1];
	assert.equal(d.class, 'egress.request');
	assert.deepEqual(d.net, { addr: '192.0.2.10', port: 80 });
	assert.equal(d.detail.originVerified, false);
	for (const f of ['summary', 'net.addr', 'detail.method', 'detail.path', 'detail.originLabel', 'detail.reason']) {
		assert.ok(d.untrusted.includes(f), `${f} tagged untrusted`);
	}
	assert.ok(!d.untrusted.includes('detail.auditType'), 'our vocabulary is not tagged');
	const m = broker[3];
	assert.equal(m.class, 'model.call');
	assert.equal(m.detail.reqBytes, 10);
	assert.equal(broker[4].priority, 'critical');
	assert.ok(events.some(e => e.source === 'tabd' && e.detail?.status === 'broker-audit-gap' && e.detail.missed === 2), 'seq 8-9 missing: gap reported');
	assert.ok(events.some(e => e.source === 'tabd' && e.detail?.status === 'broker-audit-drop'), 'foreign tab id dropped and reported');
	// Stopping flushes the aggregate: 2 more allowed requests to the same destination.
	await call('tab.stop', { tabId });
	const after = (await call('tab.events.tail', { tabId, limit: 1000 })).events as Array<Record<string, any>>;
	const agg = after.find(e => e.detail?.auditType === 'request.allowed' && e.detail.count === 2);
	assert.ok(agg, 'aggregate emitted with count');
	assert.match(agg.summary, /×2 more/);
	sup.shutdown();
});

test('tab.egress.block: refused without broker deny rules; with them, a deny rule now and on every later start; input checked', async () => {
	const { sup, driver, call, ws, audit } = setup('block');
	await call('initialize', { protocolVersion: 'seclab-tabd/0.1', client: { name: 't', version: '0' } });
	const tabId = (await call('tab.claim', { workspace: { hostPath: ws } })).tab.metadata.name;
	await call('tab.ensureRunning', { tabId });
	assert.equal((await call('tab.get', { tabId })).tab.status.brokerCapabilities.denyRules, undefined);
	await assert.rejects(call('tab.egress.block', { tabId, host: 'c2.example', port: 443 }), /cannot block destinations/, 'no button that does nothing');
	await call('tab.stop', { tabId });
	driver.opts = { denyRules: true };
	await call('tab.ensureRunning', { tabId });
	assert.equal((await call('tab.get', { tabId })).tab.status.brokerCapabilities.denyRules, true);
	for (const host of ['c2.example/x', 'a b', '*.example', 'x'.repeat(260), '[evil](command:x)']) {
		await assert.rejects(call('tab.egress.block', { tabId, host }), /exact host/, host);
	}
	await assert.rejects(call('tab.egress.block', { tabId, host: 'c2.example', port: 70000 }), /port/);
	const r = await call('tab.egress.block', { tabId, host: 'C2.Example', port: 443 });
	assert.match(r.rule, /^user-block-[0-9a-f]{16}$/);
	const upd = driver.brokerLog.find(l => l.method === 'policy.update')!;
	assert.deepEqual(upd.params, { addDeny: [{ id: r.rule, host: 'c2.example', ports: [443] }] });
	await call('tab.egress.block', { tabId, host: 'c2.example', port: 443 });
	assert.equal(driver.brokerLog.filter(l => l.method === 'policy.update').length, 1, 'idempotent');
	assert.ok(audit.some(a => a.includes('"tab.egress.block"')));
	// The next start carries the block in the policy itself.
	await call('tab.stop', { tabId });
	await call('tab.ensureRunning', { tabId });
	const loads = driver.brokerLog.filter(l => l.method === 'policy.load');
	assert.deepEqual((loads.at(-1)!.params!.policy as Record<string, unknown>).deny, [{ id: r.rule, host: 'c2.example', ports: [443] }]);
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
	assert.deepEqual(tabPolicy(dir, 't-1'), { version: 1, allow: [{ host: 'example.com' }], tabId: 't-1', prompt: { enabled: false } });
	assert.deepEqual(tabPolicy(dir, 't-1', true).prompt, { enabled: true });
	fs.writeFileSync(f, JSON.stringify({ version: 1, allow: [], prompt: { enabled: true, timeoutSeconds: 30 } }), { mode: 0o600 });
	assert.deepEqual(tabPolicy(dir, 't-1', false).prompt, { enabled: false, timeoutSeconds: 30 }, 'no client to answer: prompts off');
	assert.deepEqual(tabPolicy(dir, 't-1', true).prompt, { enabled: true, timeoutSeconds: 30 });
	fs.writeFileSync(f, JSON.stringify({ version: 1, allow: [], prompt: { enabled: false } }), { mode: 0o600 });
	assert.deepEqual(tabPolicy(dir, 't-1', true).prompt, { enabled: false }, 'the user turned prompts off');
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

test('B3 prompts: approvals reach the client sanitised; only offered decisions, for this tab, are relayed; userAction is rate-limited', async () => {
	const { sup, driver, call, ws, audit } = setup('approvals');
	const notes: Array<{ method: string; params: Record<string, unknown> }> = [];
	const origNotify = (sup as unknown as { notify: (m: string, p: unknown) => void }).notify.bind(sup);
	(sup as unknown as { notify: (m: string, p: unknown) => void }).notify = (m, p) => {
		notes.push({ method: m, params: p as Record<string, unknown> });
		origNotify(m, p);
	};
	await call('initialize', { protocolVersion: 'seclab-tabd/0.1', client: { name: 't', version: '0' } });
	const tabId = (await call('tab.claim', { workspace: { hostPath: ws } })).tab.metadata.name;
	await call('tab.ensureRunning', { tabId });
	const send = (method: string, params: unknown) => driver.brokerOut!.write(JSON.stringify({ jsonrpc: '2.0', method, params }) + '\n');
	const approval = {
		approvalId: 'a1b2c3', kind: 'egress', request: { scheme: 'https', host: 'evil.example', port: 443, method: 'GET', path: '/' + 'x'.repeat(400) },
		createdAt: 1, expiresAt: Date.now() / 1000 + 60, waiting: 1, decisions: ['allow-once', 'deny', 'bogus'],
		risk: { flags: ['early-after-open'], origin: { label: 'task.env\u001b[31m', verified: false }, userActionSeen: false }, untrusted: {},
	};
	send('approval.requested', approval);
	send('approval.requested', { ...approval, approvalId: 'bad id!' });
	for (let i = 0; i < 100 && !notes.some(n => n.method === 'tab.approval'); i++) {
		await new Promise(r => setTimeout(r, 5));
	}
	const shown = notes.filter(n => n.method === 'tab.approval');
	assert.equal(shown.length, 1, 'malformed approvals are dropped');
	const a = shown[0].params.approval as { decisions: string[]; request: { path: string } };
	assert.equal(shown[0].params.tabId, tabId);
	assert.deepEqual(a.decisions, ['allow-once', 'deny'], 'only known decisions');
	assert.equal(a.request.path.length, 256, 'tab-influenced text is capped');
	assert.ok('lineage' in shown[0].params);
	assert.deepEqual((await call('tab.approval.list', { tabId })).approvals.map((x: { approvalId: string }) => x.approvalId), ['a1b2c3']);
	await assert.rejects(call('tab.approval.decide', { tabId, approvalId: 'a1b2c3', decision: 'allow-tab' }), /one of allow-once, deny/, 'a decision the approval did not offer is refused');
	await assert.rejects(call('tab.approval.decide', { tabId, approvalId: 'nope', decision: 'deny' }), /no such pending approval/);
	// Another tab can't answer this one (decision 3: an approval never grants another tab).
	const ws2 = path.join(path.dirname(ws), 'other');
	fs.mkdirSync(ws2);
	const tab2 = (await call('tab.claim', { workspace: { hostPath: ws2 } })).tab.metadata.name;
	await assert.rejects(call('tab.approval.decide', { tabId: tab2, approvalId: 'a1b2c3', decision: 'deny' }), /no such pending approval/);
	await call('tab.approval.decide', { tabId, approvalId: 'a1b2c3', decision: 'deny' });
	assert.deepEqual(driver.brokerLog.filter(l => l.method === 'approval.decide').map(l => l.params), [{ approvalId: 'a1b2c3', decision: 'deny' }]);
	assert.deepEqual((await call('tab.approval.list', { tabId })).approvals, []);
	// A broker-side resolution (timeout) dismisses the client's prompt.
	send('approval.requested', { ...approval, approvalId: 'd4e5f6' });
	for (let i = 0; i < 100 && (await call('tab.approval.list', { tabId })).approvals.length === 0; i++) {
		await new Promise(r => setTimeout(r, 5));
	}
	send('approval.resolved', { approvalId: 'd4e5f6', decision: 'deny', by: 'timeout' });
	for (let i = 0; i < 100 && !notes.some(n => n.method === 'tab.approval.resolved'); i++) {
		await new Promise(r => setTimeout(r, 5));
	}
	assert.deepEqual(notes.find(n => n.method === 'tab.approval.resolved')!.params, { tabId, approvalId: 'd4e5f6', decision: 'deny', by: 'timeout' });
	// userAction: relayed, at most once a second.
	await call('tab.userAction', { tabId });
	await call('tab.userAction', { tabId });
	assert.deepEqual(driver.brokerLog.filter(l => l.method === 'tab.event').map(l => l.params), [{ kind: 'opened' }, { kind: 'userAction' }]);
	assert.ok(audit.some(e => e.includes('"decided"')) && !audit.some(e => e.includes('\u001b')));
});

test('B3 prompts: the default policy holds for a prompt only when the client shows prompts', async () => {
	for (const shows of [false, true]) {
		const { driver, call, ws } = setup(`prompts-${shows}`);
		await call('initialize', { protocolVersion: 'seclab-tabd/0.1', client: { name: 't', version: '0', ...(shows ? { capabilities: { approvals: true } } : {}) } });
		const tabId = (await call('tab.claim', { workspace: { hostPath: ws } })).tab.metadata.name;
		await call('tab.ensureRunning', { tabId });
		const policy = driver.brokerLog.find(l => l.method === 'policy.load')!.params!.policy as { prompt: { enabled: boolean } };
		assert.equal(policy.prompt.enabled, shows);
	}
});

test('B3 prompt text: tab named first, tab text quoted (no links, icons, bidi), deny first, lineage only as data', () => {
	const raw = {
		approvalId: 'a1', kind: 'egress', decisions: ['allow-tab', 'allow-once', 'deny'], expiresAt: 1,
		request: { scheme: 'https', host: 'evil.example', port: 8443, method: 'POST', path: '/[x](command:workbench.action.reloadWindow)' },
		risk: { flags: ['no-user-action-yet', 'risky-destination:paste$(zap)'], origin: { label: 'npm \u202e[click](https://x)', verified: false } },
	};
	const a = sanitizeApproval(raw)!;
	const text = approvalPromptText('my repo', a, { confidence: 'ambiguous', chain: 'sh → curl [x](https://y)', integrity: 'tab-vm-root' });
	assert.ok(text.startsWith('Tab “my repo” wants to connect to “evil.example”:8443'), text);
	assert.match(text, /before you did anything in this tab/);
	assert.match(text, /ambiguous, may be another process/);
	assert.match(text, /root in the tab could fake it/);
	assert.match(text, /Ignoring this denies it\.$/);
	for (const bad of ['[', ']', '$(', '://', 'command:', 'https:', '\u202e']) {
		assert.ok(!text.includes(bad), `${JSON.stringify(bad)} in ${text}`);
	}
	assert.doesNotMatch(approvalPromptText('t', a, { confidence: 'none', chain: 'sh', integrity: 'trusted' }), /Process:/);
	assert.doesNotMatch(approvalPromptText('t', a, { confidence: 'single', chain: 'sh', integrity: 'bogus' as never }), /Process:/);
	const cred = approvalPromptText('t', { ...a, kind: 'credential-binding', credentialId: 'cfs' }, undefined);
	assert.match(cred, /wants to send credential “cfs” to “evil\.example”:8443/);
	assert.deepEqual(DECISION_LABELS.map(([d]) => d), ['deny', 'deny-new-destinations', 'allow-once', 'allow-tab']);
	const long = `api.github.com.${'a'.repeat(60)}.${'b'.repeat(60)}.attacker.example`;
	const longText = approvalPromptText('t', sanitizeApproval({ ...raw, waiting: 3, request: { ...raw.request, host: long } })!, undefined);
	assert.ok(longText.includes(`“${long}”`), 'the whole host, right end included');
	assert.match(longText, /3 requests waiting\)\. Your answer covers every request held for this destination\./);
});

test('B4 CFS feeds: off by default; enabling imports the sentinel credential GET-only with a budget, on a running tab and every start; refresh on credential.needed; disabling revokes', async t => {
	let mints = 0;
	let gate: Promise<void> = Promise.resolve();
	const cfs = { token: async (): Promise<AzToken> => {
		await gate;
		return { value: `tok-${++mints}-0123456789abcdef`, expiresAt: Math.floor(Date.now() / 1000) + 3600 };
	} };
	const { sup, driver, call, ws, audit } = setup('cfs', undefined, cfs);
	await call('initialize', { protocolVersion: 'seclab-tabd/0.1', client: { name: 't', version: '0' } });
	const tabId = (await call('tab.claim', { workspace: { hostPath: ws } })).tab.metadata.name;
	if ((BROKER_POLICY_SCHEMA.revision as number) < 7) {
		// Review EEE-1: a broker whose credential.import drops `budget` is never given the token.
		await assert.rejects(call('tab.packages.set', { tabId, cfs: true }), /revision 7/);
		assert.deepEqual(await call('tab.packages.get', { tabId }), { cfs: false });
		sup.shutdown();
		t.skip('the import path needs broker policy schema revision 7');
		return;
	}
	// A stopped tab: the setting is persisted only, nothing runs in the sandbox (review EEE-4).
	assert.deepEqual(await call('tab.packages.set', { tabId, cfs: true }), { cfs: true, applied: false });
	assert.equal(driver.feeds.length, 0);
	await call('tab.packages.set', { tabId, cfs: false });
	await call('tab.ensureRunning', { tabId });
	assert.equal(driver.setup!.feedSentinel, undefined, 'off by default: no feed config');
	assert.ok(!driver.brokerLog.some(l => l.method === 'credential.import'));
	assert.deepEqual(await call('tab.packages.get', { tabId }), { cfs: false });
	await assert.rejects(call('tab.packages.set', { tabId, cfs: 'yes' }), /true or false/);

	const wait = async (pred: () => boolean) => {
		for (let i = 0; i < 200 && !pred(); i++) {
			await new Promise(r => setTimeout(r, 5));
		}
		assert.ok(pred());
	};
	// Enable on the running tab: import, allow the two feed paths, write the tab's config.
	assert.deepEqual(await call('tab.packages.set', { tabId, cfs: true }), { cfs: true, applied: true });
	await wait(() => driver.brokerLog.some(l => l.method === 'policy.update' && Array.isArray(l.params?.addAllow)));
	const imp = driver.brokerLog.find(l => l.method === 'credential.import')!.params!;
	const sentinel = imp.sentinel as string;
	assert.match(sentinel, /^seclab_cfs_[A-Za-z0-9_-]{43}$/);
	assert.equal(imp.id, 'cfs');
	assert.equal(imp.value, 'tok-1-0123456789abcdef');
	assert.equal(imp.provider, 'azure-devops');
	assert.deepEqual(imp.inject, { header: 'Authorization', fmt: 'Basic {base64:cfs:{value}}' });
	assert.deepEqual(imp.budget, { requests: 5000, bytes: 2147483648 });
	for (const b of imp.bind as Array<{ host: string; path: string; methods: string[] }>) {
		assert.equal(b.host, 'pkgs.dev.azure.com');
		assert.deepEqual(b.methods, ['GET'], 'GET only');
		assert.match(b.path, /^\/example-org\/(ExampleProject\/_packaging\/example-(npm-feed\/npm\/registry|pypi-feed\/pypi)|00000000-0000-0000-0000-000000000001\/_packaging\/00000000-0000-0000-0000-000000000002\/pypi\/download)\/\*\*$/);
	}
	assert.deepEqual((driver.brokerLog.find(l => Array.isArray(l.params?.addAllow))!.params!.addAllow as Array<{ id: string }>).map(r => r.id), ['cfs-npm', 'cfs-pypi', 'cfs-pypi-files']);
	await wait(() => driver.feeds.length === 1);
	assert.deepEqual(driver.feeds, [sentinel], 'the running tab gets its npm/pip config with the sentinel');
	assert.deepEqual(await call('tab.packages.get', { tabId }), { cfs: true });

	// credential.needed for cfs: a fresh token, provided just in time; another id is ignored.
	driver.brokerOut!.write(JSON.stringify({ jsonrpc: '2.0', method: 'credential.needed', params: { id: 'other' } }) + '\n');
	driver.brokerOut!.write(JSON.stringify({ jsonrpc: '2.0', method: 'credential.needed', params: { id: 'cfs' } }) + '\n');
	await wait(() => driver.brokerLog.some(l => l.method === 'credential.provide'));
	const prov = driver.brokerLog.filter(l => l.method === 'credential.provide');
	assert.equal(prov.length, 1);
	assert.deepEqual(Object.keys(prov[0].params!).sort(), ['expiresAt', 'id', 'value']);
	assert.equal(prov[0].params!.id, 'cfs');

	// Every start: the same sentinel in the tab's config, and the credential imported again.
	await call('tab.stop', { tabId });
	driver.brokerLog.length = 0;
	await call('tab.ensureRunning', { tabId });
	assert.equal(driver.setup!.feedSentinel, sentinel, 'the persisted sentinel: the tab config stays valid');
	await wait(() => driver.brokerLog.some(l => l.method === 'credential.import'));
	assert.equal(driver.brokerLog.find(l => l.method === 'credential.import')!.params!.sentinel, sentinel);

	// Disable: allow rules removed, the credential revoked (sentinel rotated), the config removed.
	assert.deepEqual(await call('tab.packages.set', { tabId, cfs: false }), { cfs: false, applied: true });
	assert.ok(driver.brokerLog.some(l => l.method === 'policy.update' && JSON.stringify(l.params?.removeAllow) === '["cfs-npm","cfs-pypi","cfs-pypi-files"]'));
	assert.deepEqual(driver.brokerLog.find(l => l.method === 'credential.revoke')!.params, { id: 'cfs', rotateSentinel: true });
	assert.equal(driver.feeds.at(-1), undefined);
	// Review EEE-2: a start's import still waiting for az when feeds are turned off is undone,
	// never left behind: enable, restart with az held, disable, then let az answer.
	await call('tab.packages.set', { tabId, cfs: true });
	await call('tab.stop', { tabId });
	let release!: () => void;
	gate = new Promise(r => release = r);
	driver.brokerLog.length = 0;
	await call('tab.ensureRunning', { tabId });
	const off = call('tab.packages.set', { tabId, cfs: false });
	release();
	await off;
	await new Promise(r => setTimeout(r, 50));
	const last = driver.brokerLog.filter(l => ['credential.import', 'credential.revoke', 'policy.update'].includes(l.method)).at(-1)!;
	assert.ok(last.method === 'credential.revoke' || (last.method === 'policy.update' && Array.isArray(last.params?.removeAllow)), `ends removed: ${JSON.stringify(driver.brokerLog.map(l => l.method))}`);
	assert.ok(!driver.brokerLog.some((l, i) => l.method === 'policy.update' && Array.isArray(l.params?.addAllow) && !driver.brokerLog.slice(i).some(m => m.method === 'credential.revoke')), 'no allow rule outlives the disable');
	await call('tab.stop', { tabId });
	await call('tab.ensureRunning', { tabId });
	assert.equal(driver.setup!.feedSentinel, undefined);
	// No token ever reaches the audit log.
	assert.ok(!/tok-\d/.test(audit.join('\n')), 'tokens are never audited');
	sup.shutdown();

	// Without a token source, enabling is refused.
	const none = setup('cfs-none');
	await none.call('initialize', { protocolVersion: 'seclab-tabd/0.1', client: { name: 't', version: '0' } });
	const t2 = (await none.call('tab.claim', { workspace: { hostPath: none.ws } })).tab.metadata.name;
	await assert.rejects(none.call('tab.packages.set', { tabId: t2, cfs: true }), /unavailable/);
	none.sup.shutdown();
});

test('B4 CFS token: tenant checked, expiry required; feed line validated; the install script and seclab-tab-env wire npm and pip to the sentinel only', () => {
	const ok = { tenant: CFS_TENANT, accessToken: 'fake-token-for-tests-only', expires_on: 1793900000 };
	assert.deepEqual(parseAzToken(JSON.stringify(ok), 1793800000), { value: ok.accessToken, expiresAt: 1793900000 });
	assert.throws(() => parseAzToken(JSON.stringify({ ...ok, tenant: 'other' }), 1793800000), /another tenant/);
	assert.throws(() => parseAzToken(JSON.stringify(ok), 1793900001), /expired/);
	assert.throws(() => parseAzToken(JSON.stringify({ ...ok, accessToken: '' }), 1793800000), /no usable/);
	assert.throws(() => parseAzToken('not json'), /not JSON/);
	assert.equal(parseAzToken(JSON.stringify({ tenant: CFS_TENANT, accessToken: ok.accessToken, expiresOn: '2026-11-06 20:00:00.000000' }), 0).value, ok.accessToken);
	assert.equal(feedInstallLine(undefined), 'feed -');
	assert.throws(() => feedInstallLine('short'), /format/);
	assert.throws(() => feedInstallLine(`seclab_cfs_${'a'.repeat(40)} rm -rf`), /format/);

	// The shell side, where we can: as root, in the test container (./seclab test unit).
	if (process.getuid?.() !== 0 || !fs.existsSync('/etc/ssl/certs/ca-certificates.crt')) {
		return;
	}
	const s = `seclab_cfs_${'A'.repeat(43)}`;
	const run = (input: string) => spawnSync('sh', ['-c', INSTALL_FEED], { input, encoding: 'utf8' });
	fs.rmSync('/run/seclab-broker', { recursive: true, force: true });
	assert.equal(run(`${feedInstallLine(s)}\n`).status, 0);
	const npmrc = fs.readFileSync('/run/seclab-broker/npmrc', 'utf8');
	assert.match(npmrc, /^registry=https:\/\/pkgs\.dev\.azure\.com\/example-org\/ExampleProject\/_packaging\/example-npm-feed\/npm\/registry\/$/m);
	assert.ok(npmrc.includes(`:_password=${Buffer.from(s).toString('base64')}\n`));
	assert.equal(fs.readFileSync('/run/seclab-broker/pip-index-url', 'utf8'), `https://cfs:${s}@pkgs.dev.azure.com/example-org/ExampleProject/_packaging/example-pypi-feed/pypi/simple/\n`);
	assert.notEqual(run('feed bad;sentinel x\n').status, 0, 'unexpected characters are refused');
	assert.notEqual(run('nope -\n').status, 0);
	// seclab-tab-env exports them only with a configured broker, and only the expected URL.
	fs.writeFileSync('/run/seclab-broker/proxy-url', 'http://seclab:pw@broker:8080\n');
	fs.writeFileSync('/run/seclab-broker/ca.pem', PEM);
	fs.writeFileSync('/run/seclab-broker/bundle.pem', PEM);
	const env = () => spawnSync('sh', [path.resolve(import.meta.dirname, '../../sandbox/rootfs/opt/seclab/bin/seclab-tab-env'), 'env'], { encoding: 'utf8' }).stdout;
	assert.match(env(), /^NPM_CONFIG_GLOBALCONFIG=\/run\/seclab-broker\/npmrc$/m);
	assert.match(env(), new RegExp(`^PIP_INDEX_URL=https://cfs:${s}@pkgs\\.dev\\.azure\\.com/`, 'm'));
	fs.writeFileSync('/run/seclab-broker/pip-index-url', 'https://cfs:x@evil.example/simple/\n');
	assert.doesNotMatch(env(), /PIP_INDEX_URL|NPM_CONFIG_GLOBALCONFIG/, 'an unexpected index URL: no feeds');
	assert.equal(run('feed -\n').status, 0);
	assert.ok(!fs.existsSync('/run/seclab-broker/npmrc') && !fs.existsSync('/run/seclab-broker/pip-index-url'), 'disabled: config removed');
	fs.rmSync('/run/seclab-broker', { recursive: true, force: true });
});
