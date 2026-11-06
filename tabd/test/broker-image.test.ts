// Broker image identity (review XX-6): tabd's pinned expectations equal the broker's own
// sources, and the label check refuses everything that isn't a clean build.sh build.

import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { test } from 'node:test';
import { BROKER_BASE_DIGEST, BROKER_LABELS, BrokerImagePin, brokerImageProblems } from '../src/broker-image.ts';
import { BROKER_POLICY_SCHEMA, BROKER_PROTOCOL, checkBrokerHello } from '../src/broker.ts';
import { AUDIT_KINDS } from '../src/obs/broker-audit.ts';
import type { Runner } from '../src/run.ts';

const repo = path.resolve(import.meta.dirname, '../..');
const ID = 'sha256:' + 'ab'.repeat(32);
const good = (over: Record<string, string> = {}): Record<string, string> => ({
	[BROKER_LABELS.revision]: 'c'.repeat(40),
	[BROKER_LABELS.base]: BROKER_BASE_DIGEST,
	[BROKER_LABELS.version]: '0.3.1',
	[BROKER_LABELS.protocol]: BROKER_PROTOCOL,
	[BROKER_LABELS.policyRevision]: String(BROKER_POLICY_SCHEMA.revision),
	...over,
});

test('broker-image: pinned base digest and protocol equal broker/deps.json and protocol.v1.json', () => {
	const deps = JSON.parse(fs.readFileSync(path.join(repo, 'broker/deps.json'), 'utf8')) as { images: Array<{ name: string; ref: string }> };
	const mitm = deps.images.filter(i => i.name === 'mitmproxy/mitmproxy');
	assert.equal(mitm.length, 1);
	assert.equal(mitm[0].ref.split('@')[1], BROKER_BASE_DIGEST);
	const proto = JSON.parse(fs.readFileSync(path.join(repo, 'broker/schema/protocol.v1.json'), 'utf8')) as { protocol: string; changelog: Array<{ policySchemaRevision: number }> };
	assert.equal(proto.protocol, BROKER_PROTOCOL);
	assert.equal(proto.changelog[0].policySchemaRevision, BROKER_POLICY_SCHEMA.revision);
});

test('broker audit: observability classifies exactly the broker protocol\'s audit types', () => {
	// An unlisted type is demoted to a bare notice with its fields dropped (review 13-5), so a
	// new broker audit type must be classified here in the same change.
	const proto = JSON.parse(fs.readFileSync(path.join(repo, 'broker/schema/protocol.v1.json'), 'utf8')) as { auditTypes: Record<string, string> };
	assert.deepEqual(Object.keys(AUDIT_KINDS).sort(), Object.keys(proto.auditTypes).sort());
});

test('broker-image: a clean build.sh build is accepted; dirty only with --broker-dev', () => {
	assert.deepEqual(brokerImageProblems(ID, good(), { allowDirty: false }), []);
	const dirty = good({ [BROKER_LABELS.revision]: 'c'.repeat(40) + '-dirty' });
	assert.match(brokerImageProblems(ID, dirty, { allowDirty: false }).join(), /uncommitted/);
	assert.deepEqual(brokerImageProblems(ID, dirty, { allowDirty: true }), []);
});

test('broker-image: unlabelled, unknown, mitmproxy-inherited and mismatched images are refused', () => {
	// An image from before the labels inherits mitmproxy's own revision and version: both look valid.
	const inherited = { [BROKER_LABELS.revision]: '5'.repeat(40), [BROKER_LABELS.version]: '12.3.1' };
	const p = brokerImageProblems(ID, inherited, { allowDirty: true }).join();
	assert.match(p, /base/);
	assert.match(p, /protocol/);
	assert.ok(brokerImageProblems(ID, null, { allowDirty: true }).length >= 5);
	const unknown = good(Object.fromEntries([BROKER_LABELS.revision, BROKER_LABELS.base, BROKER_LABELS.version, BROKER_LABELS.policyRevision].map(k => [k, 'unknown'])));
	assert.equal(brokerImageProblems(ID, unknown, { allowDirty: true }).length, 4);
	assert.match(brokerImageProblems(ID, good({ [BROKER_LABELS.base]: 'sha256:' + '0'.repeat(64) }), { allowDirty: false }).join(), /mitmproxy/);
	assert.match(brokerImageProblems(ID, good({ [BROKER_LABELS.policyRevision]: '2' }), { allowDirty: false }).join(), /policy revision.*\.\/seclab image oci/);
	assert.match(brokerImageProblems('seclab-broker:dev', good(), { allowDirty: false }).join(), /not a sha256/);
});

test('broker-image: the pin resolves at every use (a rebuilt image is picked up; ZZ-10)', async () => {
	let calls = 0;
	let labels: Record<string, string> | null = null;
	const runner = { run: async (_cmd: string, args: string[]) => {
		calls++;
		assert.deepEqual(args.slice(0, 2), ['image', 'inspect']);
		return { code: 0, stdout: `${JSON.stringify(ID)}\n${JSON.stringify(labels)}\n`, stderr: '' };
	} } as unknown as Runner;
	const pin = new BrokerImagePin(runner, '/usr/bin/docker', 'seclab-broker:dev');
	await assert.rejects(pin.get(), /refused/);
	labels = good();
	assert.deepEqual(await pin.get(), { id: ID, revision: 'c'.repeat(40), version: '0.3.1' });
	await pin.get();
	assert.equal(calls, 3);
});

test('broker-image: hello must report the version the image declares', () => {
	const hello = { protocol: BROKER_PROTOCOL, tabId: 't', version: '0.3.1', policySchema: { ...BROKER_POLICY_SCHEMA } };
	checkBrokerHello(hello, 't', '0.3.1');
	checkBrokerHello(hello, 't');
	assert.throws(() => checkBrokerHello(hello, 't', '0.3.2'), /image declares 0.3.2/);
});

// ---- driver wiring (review ZZ-11): the sbx broker path against a fake docker ----------------

import { SbxDriver } from '../src/drivers/sbx.ts';
import type { TabRuntimeSpec, TabTemplate } from '../src/drivers/types.ts';

const TAB = 't-' + 'a'.repeat(26);
const SPEC: TabRuntimeSpec = {
	tabId: TAB, sandboxName: `seclab-${TAB}`, hostPath: '/w',
	template: { kind: 'TabTemplate', metadata: { name: 'default' }, spec: { driver: 'sbx', image: 'img', envVarsInjectionPolicy: 'Disallowed', fence: 'required', broker: 'required' } } as TabTemplate,
};
const BROKER = `seclab-${TAB}-broker`;

/** Fake docker: the pinned image, an optional pre-existing broker container; sbx stops the run. */
function fakeDocker(opts: { labels?: Record<string, string> | null; existing?: { image: string; tab: string } }) {
	const calls: string[][] = [];
	let container = opts.existing;
	const runner = {
		run: async (bin: string, args: readonly string[]) => {
			const a = [...args];
			calls.push([bin, ...a]);
			const ok = (stdout = '') => ({ code: 0, stdout, stderr: '' });
			if (bin === '/sbx') {
				throw new Error('stop: sbx reached');
			}
			if (a[0] === 'image' && a[1] === 'inspect') {
				return ok(`${JSON.stringify(ID)}\n${JSON.stringify(opts.labels === undefined ? good() : opts.labels)}\n`);
			}
			if (a[0] === 'container' && a[1] === 'inspect') {
				if (!container) {
					return { code: 1, stdout: '', stderr: `Error response from daemon: No such container: ${BROKER}` };
				}
				return ok(a[3].includes('.Image') ? `${container.image}|${container.tab}` : BROKER);
			}
			if (a[0] === 'rm') {
				container = undefined;
				return ok();
			}
			if (a[0] === 'create') {
				container = { image: a[a.length - 1], tab: TAB };
				return ok();
			}
			if (a[0] === 'port') {
				return ok('127.0.0.1:49999');
			}
			return ok();
		},
		spawnStream: () => { throw new Error('no streams'); },
	} as unknown as Runner;
	const pin = new BrokerImagePin(runner, '/docker', 'seclab-broker:dev');
	return { calls, driver: new SbxDriver('/sbx', runner, { docker: '/docker', brokerPin: pin }) };
}
const start = (d: SbxDriver) => d.ensureRunning(SPEC, 'f'.repeat(64), undefined, { configure: async () => { throw new Error('unreached'); } }).catch((e: Error) => e);

test('sbx driver: the broker is created by the checked image ID, never the tag', async () => {
	const { calls, driver } = fakeDocker({});
	const e = await start(driver);
	assert.match(String(e), /sbx reached/);
	const create = calls.find(c => c[1] === 'create');
	assert.ok(create, 'broker created');
	assert.deepEqual(create!.slice(-2), ['--', ID]);
	assert.ok(!create!.includes('seclab-broker:dev'));
});

test('sbx driver: a broker from another image is removed (with its volume) and recreated', async () => {
	const { calls, driver } = fakeDocker({ existing: { image: 'sha256:' + '0'.repeat(64), tab: TAB } });
	await start(driver);
	const i = calls.findIndex(c => c[1] === 'rm');
	assert.ok(i >= 0);
	assert.deepEqual(calls[i].slice(1), ['rm', '-f', '-v', '--', BROKER]);
	assert.ok(calls.findIndex(c => c[1] === 'create') > i);
});

test('sbx driver: a refused image creates nothing; another tab\'s container is never used or removed', async () => {
	const refused = fakeDocker({ labels: null });
	assert.match(String(await start(refused.driver)), /refused/);
	assert.ok(!refused.calls.some(c => c[1] === 'create' || (c[1] === 'network' && c[2] === 'create')));
	const foreign = fakeDocker({ existing: { image: 'sha256:' + '0'.repeat(64), tab: 'someone-else' } });
	assert.match(String(await start(foreign.driver)), /not this tab's broker/);
	assert.ok(!foreign.calls.some(c => c[1] === 'rm' || c[1] === 'create'));
});

test('sbx driver: quarantine removes the tab\'s stale broker allow instead of denying it (focus probe 2026-11-06)', async () => {
	const sb = `seclab-${TAB}`;
	const allowId = '0123abcd-0000-4000-8000-000000000001';
	let rules = [
		{ id: 'default-deny-all', applies_to: 'all', scope: 'global', decision: 'deny', resource_type: 'network', resources: ['**'], actions: ['net:connect:tcp'], status: 'active' },
		{ id: allowId, applies_to: `sandbox:${sb}`, scope: `sandbox:${sb}`, decision: 'allow', resource_type: 'network', resources: ['localhost:62285'], actions: ['net:connect:tcp'], status: 'active' },
	];
	const calls: string[][] = [];
	const runner = {
		run: async (bin: string, args: readonly string[]) => {
			const a = [...args];
			calls.push([bin, ...a]);
			if (bin === '/sbx' && a[0] === 'policy' && a[1] === 'ls') {
				return { code: 0, stdout: JSON.stringify({ rules }), stderr: '' };
			}
			if (bin === '/sbx' && a[0] === 'policy' && a[1] === 'rm') {
				rules = rules.filter(r => r.id !== a[a.indexOf('--id') + 1]);
			}
			if (bin === '/sbx' && a[0] === 'policy' && a[1] === 'deny' && a.includes('localhost:62285')) {
				return { code: 1, stdout: '', stderr: 'conflicts with existing allow rule' };
			}
			if (bin === '/docker' && a[1] === 'inspect') {
				return { code: 1, stdout: '', stderr: 'Error: No such container' };
			}
			return { code: 0, stdout: '', stderr: '' };
		},
		spawnStream: () => { throw new Error('no streams'); },
	} as unknown as Runner;
	const driver = new SbxDriver('/sbx', runner, { docker: '/docker', brokerPin: new BrokerImagePin(runner, '/docker', 'seclab-broker:dev') });
	await driver.quarantine(SPEC);
	assert.ok(calls.some(c => c[0] === '/sbx' && c[2] === 'rm' && c.includes(allowId)), 'stale broker allow removed');
	assert.ok(!calls.some(c => c[0] === '/sbx' && c[2] === 'deny' && c.includes('localhost:62285')), 'never mirrored as a deny');
	assert.ok(calls.some(c => c[0] === '/sbx' && c[1] === 'stop'), 'sandbox stopped');
});
