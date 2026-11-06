// Broker image identity (review XX-6): tabd's pinned expectations equal the broker's own
// sources, and the label check refuses everything that isn't a clean build.sh build.

import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { test } from 'node:test';
import { BROKER_BASE_DIGEST, BROKER_LABELS, BrokerImagePin, brokerImageProblems } from '../src/broker-image.ts';
import { BROKER_POLICY_SCHEMA, BROKER_PROTOCOL, checkBrokerHello } from '../src/broker.ts';
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
	assert.match(brokerImageProblems(ID, good({ [BROKER_LABELS.policyRevision]: '2' }), { allowDirty: false }).join(), /policy revision/);
	assert.match(brokerImageProblems('seclab-broker:dev', good(), { allowDirty: false }).join(), /not a sha256/);
});

test('broker-image: the pin resolves once, caches success, retries after failure', async () => {
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
	assert.equal(calls, 2);
});

test('broker-image: hello must report the version the image declares', () => {
	const hello = { protocol: BROKER_PROTOCOL, tabId: 't', version: '0.3.1', policySchema: { ...BROKER_POLICY_SCHEMA } };
	checkBrokerHello(hello, 't', '0.3.1');
	checkBrokerHello(hello, 't');
	assert.throws(() => checkBrokerHello(hello, 't', '0.3.2'), /image declares 0.3.2/);
});
