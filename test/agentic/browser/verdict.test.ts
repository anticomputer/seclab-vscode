// Each check in the increment 2 verdict must be able to fail ON ITS OWN.
//
// Security review round 8 found two that could not: the restore check re-read the first
// launch's log, and the `dataStorage` check was implied by the check above it. Both had been
// green on a real run and both meant nothing. So this test injects, one at a time, each
// defect that patch 0017 is supposed to prevent, and asserts that exactly ONE check goes red.
// A refactor that makes two checks collapse into one, or makes a check unconditionally true,
// fails here rather than on a build nobody re-reads.

import { strict as assert } from 'node:assert';
import { test } from 'node:test';

import { browserProbeChecks } from './verdict.ts';
import type { Evidence } from './verdict.ts';

const TAB = 't-abc123';

function evidence(over: Partial<Evidence> = {}): Evidence {
	return {
		build: 'f', phase: 'first', probe: 'proxy', tabId: TAB,
		hookLines: [
			'[SECLAB_TEST_ONLY:browser-drive-hook] ready=yes',
			`[SECLAB_TEST_ONLY:browser-drive-hook] opening http://192.0.2.10:1/x requestedNetwork=seclab+${TAB}`,
			`[SECLAB_TEST_ONLY:browser-drive-hook] resolved scope=ephemeral network=seclab+${TAB} requestedScope=ephemeral`,
		],
		phaseLines: 40, probeHits: 0, beaconHits: 2, beaconLiveAfter: true,
		buildMatches: true, buildDetail: 'f',
		...over,
	};
}

/** The names of the checks that are red. */
function red(e: Evidence): string[] {
	return browserProbeChecks(e).filter(c => !c.ok).map(c => c.name);
}

/** A resolution line, as the hook emits it. */
function resolved(scope: string, network: string, requestedScope = scope): string {
	return `[SECLAB_TEST_ONLY:browser-drive-hook] resolved scope=${scope} network=${network} requestedScope=${requestedScope}`;
}

test('a clean F run is all green', () => {
	assert.deepEqual(red(evidence()), []);
	assert.deepEqual(red(evidence({ probe: 'storage' })), []);
});

test('a clean U run is all green', () => {
	// U is vulnerable, so for U "all green" means every vulnerability fired.
	assert.deepEqual(red(evidence({
		build: 'u', probe: 'proxy', probeHits: 1,
		hookLines: [...evidence().hookLines.slice(0, 2), resolved('workspace', 'none')],
	})), []);
	assert.deepEqual(red(evidence({
		build: 'u', probe: 'storage', probeHits: 1,
		hookLines: [...evidence().hookLines.slice(0, 2), resolved('global', `seclab+${TAB}`)],
	})), []);
});

// ---- one injected defect, one red check ------------------------------------------------

test('defect: 0017 stops forcing enableRemoteProxy -> only the proxy check goes red', () => {
	const e = evidence({ probe: 'proxy', hookLines: [...evidence().hookLines.slice(0, 2), resolved('ephemeral', 'none')] });
	assert.deepEqual(red(e), ["CONTAINED: 0017 overrode the tab's enableRemoteProxy=false"]);
});

test('defect: 0017 stops scrubbing dataStorage -> only the storage check goes red', () => {
	// The network is untouched here, which is exactly the case the old verdict could not
	// see: it keyed the storage result off the network, so this evidence passed.
	const e = evidence({ probe: 'storage', hookLines: [...evidence().hookLines.slice(0, 2), resolved('global', `seclab+${TAB}`)] });
	assert.deepEqual(red(e), ["CONTAINED: 0017 overrode the tab's dataStorage=global"]);
});

test('defect: 0017 stops dropping the persisted request -> only the restore verdict goes red', () => {
	const e = evidence({
		phase: 'restore', probe: 'storage',
		hookLines: [resolved('global', `seclab+${TAB}`, 'global')],
	});
	assert.deepEqual(red(e), ['CONTAINED: 0017 rebuilt the restored view under the fixed setting']);
});

test('defect: the page escapes to the host network -> only the beacon check goes red', () => {
	assert.deepEqual(red(evidence({ probeHits: 1 })), ['and the host beacon saw nothing']);
});

test('defect: the beacon was not listening -> only the liveness check goes red', () => {
	// The one that makes every "saw nothing" above mean something.
	assert.deepEqual(red(evidence({ beaconLiveAfter: false })), ['the beacon was still listening after the measurement']);
});

test('defect: the launch resolved nothing -> inconclusive, not contained', () => {
	// The round 8 failure mode: a phase whose window produced no output must NOT read as
	// contained. It has no resolution line, so the F verdict cannot be satisfied either.
	const e = evidence({ hookLines: [], phaseLines: 0 });
	const names = red(e);
	assert.ok(names.includes('THIS launch resolved a browser view (otherwise the phase is inconclusive)'));
	assert.ok(names.includes("CONTAINED: 0017 overrode the tab's enableRemoteProxy=false"),
		'a silent launch must not satisfy the containment check');
});

test('defect: the restore phase saw no hostile saved state -> the restore run is not evidence', () => {
	// If U did not actually persist `global`, F restoring cleanly proves nothing, so the
	// attributability check has to fail rather than let the verdict stand.
	const e = evidence({ phase: 'restore', hookLines: [resolved('ephemeral', `seclab+${TAB}`, 'ephemeral')] });
	assert.deepEqual(red(e), ['the restored view really did carry the hostile saved scope']);
});

test('the wrong build cannot be mistaken for a result', () => {
	assert.deepEqual(red(evidence({ buildMatches: false, buildDetail: 'u' })), ['ran the requested build']);
});

test('a restore phase cannot borrow the first launch readiness line', () => {
	// `ready=yes` is only meaningful for a hook-driven open, so the restore phase must not
	// assert it at all; if it did, a relaunch that produced nothing could inherit it.
	const names = browserProbeChecks(evidence({ phase: 'restore' })).map(c => c.name);
	assert.ok(!names.some(n => n.includes('in force when the page was opened')));
});
