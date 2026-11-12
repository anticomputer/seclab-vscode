// The two 0015 proof rules that only a live U/G run used to witness.
//
// Both were `fixed-untested` in the findings baseline: the fix had been read and believed,
// but nothing failed if it were reverted, and a live run is the one thing that cannot be
// made to run in CI. Each test below injects the defect the rule exists to catch.

import { strict as assert } from 'node:assert';
import { test } from 'node:test';

import { hashCanary, plaintextCanariesIn, proofChecks, takeoverCanaryConfig } from './verdict.ts';
import type { ProofEvidence } from './verdict.ts';

const VALUES = {
	'host-file-canary': 'seclabcanary_file_2f6c1b',
	'host-settings-proxy': 'seclabcanary_proxy_9ad410',
};
// Not hex-shaped: a run's real salt is random hex, and a literal of that shape in a
// committed file reads like an identifier to the publish gate. Any string salts.
const SALT = 'salt-for-this-test';

// ---- the canary salt rule --------------------------------------------------------------

test('the tab is given salted hashes, never a canary value', () => {
	const config = takeoverCanaryConfig(SALT, VALUES);
	assert.deepEqual(plaintextCanariesIn(config, VALUES), []);
	for (const name of Object.keys(VALUES)) {
		assert.match(config.canaryHashes[name], /^[0-9a-f]{64}$/);
	}
});

test('a canary path may ship, because a path is not its content', () => {
	// The read probe asks the window to fetch a host PATH; that is the probe, not the secret.
	const payload = { ...takeoverCanaryConfig(SALT, VALUES), canary: '.work/example-run/canary.txt' };
	assert.deepEqual(plaintextCanariesIn(payload, VALUES), []);
});

test('defect: a plaintext canary added anywhere in the config is caught', () => {
	// The failure this rule exists for: the config ships into the tab inside the vsix, so a
	// plaintext value is something in-tab code could echo back without the window ever
	// having sent it, and the verdict could not tell a replay from a real leak.
	const leaky = { ...takeoverCanaryConfig(SALT, VALUES), debugExpected: VALUES['host-file-canary'] };
	assert.deepEqual(plaintextCanariesIn(leaky, VALUES), ['host-file-canary']);
	// Nested just as well, since the check is on the serialised payload.
	const nested = { ...takeoverCanaryConfig(SALT, VALUES), extra: { deep: [{ v: VALUES['host-settings-proxy'] }] } };
	assert.deepEqual(plaintextCanariesIn(nested, VALUES), ['host-settings-proxy']);
});

test('the salt actually salts: the same value hashes differently per run', () => {
	assert.notEqual(hashCanary(SALT, VALUES['host-file-canary']), hashCanary('ffffffffffffffff', VALUES['host-file-canary']));
	// ...and a hash cannot be matched without the run's salt, which is what makes a hash
	// useless to anything outside this run.
	assert.notEqual(hashCanary(SALT, VALUES['host-file-canary']), hashCanary(SALT, VALUES['host-settings-proxy']));
});

// ---- the G-side assertions -------------------------------------------------------------

/** A clean G run: the gate ran, denied the probes, stripped the mirror, nothing leaked. */
function gEvidence(over: Partial<ProofEvidence> = {}): ProofEvidence {
	return {
		build: 'g',
		rules: [
			'ahp-gate.opened:allow', 'ahp-gate.verified:allow', 'ahp-gate.initialize:allow',
			'ahp-gate.root-config:strip', 'ahp-gate.resourceRead:deny', 'ahp-gate.createTcpConnection:deny',
		],
		planted: { ...VALUES },
		armed: { 'host-file-canary': true, 'host-settings-proxy': true },
		leaked: [], markerThere: false, beaconHits: 0,
		...over,
	};
}

const red = (e: ProofEvidence): string[] => proofChecks(e).filter(c => !c.ok).map(c => c.name);

test('a clean G run is all green, and a clean U run is too', () => {
	assert.deepEqual(red(gEvidence()), []);
	assert.deepEqual(red({
		...gEvidence(), build: 'u', rules: [], leaked: ['host-settings-proxy'],
	}), []);
});

test('defect: the gate stops stripping the configuration mirror -> only that check goes red', () => {
	// THE ROUND 5 FINDING. The mirror is the vector that actually leaks on U, and it is
	// recorded as a `strip`, not a `deny`. Counting only `:deny` left "contained" resting on
	// absence, and this evidence passed.
	const e = gEvidence({ rules: gEvidence().rules.filter(r => r !== 'ahp-gate.root-config:strip') });
	assert.deepEqual(red(e), ['the gate stripped the configuration mirror (the vector that leaks on U)']);
});

test('defect: a G run whose canaries were never recorded is not containment', () => {
	// `prepare` failing to record canaries.json leaves nothing planted, so a quiet run
	// proves nothing. It must not read as contained.
	const e = gEvidence({ planted: {}, armed: {} });
	const names = red(e);
	assert.ok(names.includes('the run recorded the canaries it planted'));
	assert.ok(names.includes('every host canary was still planted where the window reads it'));
});

test('defect: a canary that was not armed where the window reads it fails the run', () => {
	const e = gEvidence({ armed: { 'host-file-canary': true, 'host-settings-proxy': false } });
	assert.deepEqual(red(e), ['every host canary was still planted where the window reads it']);
});

test('defect: the gate never ran in the shipped build', () => {
	// The silent pass: no gate lines at all would otherwise look like "nothing happened",
	// which is indistinguishable from containment.
	const names = red(gEvidence({ rules: [] }));
	assert.ok(names.includes('the gate ran in the shipped build (it wrote its own log)'));
	assert.ok(names.includes('the gate denied the probes (its own decisions, not absence)'));
	assert.ok(names.includes('the gate stripped the configuration mirror (the vector that leaks on U)'));
});

test('defect: a connection was opened but never verified', () => {
	const e = gEvidence({ rules: gEvidence().rules.filter(r => r !== 'ahp-gate.verified:allow') });
	assert.deepEqual(red(e), ['construction invariant: every opened connection was verified']);
});

test('defect: the positive control did not pass the gate', () => {
	// Without it, a gate that denied EVERYTHING would look perfect while being useless.
	const e = gEvidence({ rules: gEvidence().rules.map(r => r === 'ahp-gate.initialize:allow' ? 'ahp-gate.initialize:deny' : r) });
	assert.deepEqual(red(e), ['positive control: the real agent host root state passed the gate']);
});

test('defect: a host effect on G is reported, not swallowed', () => {
	assert.deepEqual(red(gEvidence({ leaked: ['host-file-canary'] })), ['CONTAINED: no marker, no beacon hit, no canary reported']);
	assert.deepEqual(red(gEvidence({ beaconHits: 1 })), ['CONTAINED: no marker, no beacon hit, no canary reported']);
	assert.deepEqual(red(gEvidence({ markerThere: true })), ['CONTAINED: no marker, no beacon hit, no canary reported']);
});

test('defect: a U run that shows no host effect is not a baseline', () => {
	// U exists to prove the vector fires. A quiet U makes every G result meaningless.
	const e: ProofEvidence = { ...gEvidence(), build: 'u', rules: [] };
	assert.deepEqual(red(e), ['VULNERABLE: a real host effect from the hostile agent host']);
});

test('defect: the U baseline turns out to contain the gate', () => {
	const e: ProofEvidence = { ...gEvidence(), build: 'u', leaked: ['host-file-canary'] };
	assert.deepEqual(red(e), ['no gate in the release build (the baseline is genuinely unpatched)']);
});
