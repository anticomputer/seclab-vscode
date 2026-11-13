// Each check in the increment 2 verdict must be able to fail ON ITS OWN.
//
// Security review round 8 found two that could not: the restore check re-read the first
// launch's log, and the `dataStorage` check was implied by the check above it. Both had been
// green on a real run and both meant nothing. So this test injects, one at a time, each
// defect that patch 0017 is supposed to prevent, and asserts that exactly ONE check goes red.
// A refactor that makes two checks collapse into one, or makes a check unconditionally true,
// fails here rather than on a build nobody re-reads.

import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

import { browserProbeChecks, HEARTBEAT_GAP_MS, heartbeatsContinuous } from './verdict.ts';
import type { Evidence } from './verdict.ts';

const TAB = 't-abc123';
const SHA = 'deadbeefcafe0000111122223333444455556666';

function evidence(over: Partial<Evidence> = {}): Evidence {
	return {
		build: 'f', phase: 'first', probe: 'proxy', tabId: TAB,
		hookLines: [
			'[SECLAB_TEST_ONLY:browser-drive-hook] ready=yes',
			`[SECLAB_TEST_ONLY:browser-drive-hook] opening http://192.0.2.10:1/x requestedNetwork=seclab+${TAB} build=${SHA}`,
			resolved('ephemeral', `seclab+${TAB}`),
		],
		phaseLines: 40, probeHits: 0, beaconHits: 2, beaconLiveAfter: true,
		tabProbeHits: 1, tabBeaconLiveAfter: true,
		loggedCommit: SHA, expectedCommit: SHA,
		...over,
	};
}

/** The names of the checks that are red. */
function red(e: Evidence): string[] {
	return browserProbeChecks(e).filter(c => !c.ok).map(c => c.name);
}

/** A resolution line, as the hook emits it. */
function resolved(scope: string, network: string, requestedScope = scope): string {
	const proxy = network === 'none' ? 'false' : 'true';
	return `[SECLAB_TEST_ONLY:browser-drive-hook] resolved scope=${scope} network=${network} requestedScope=${requestedScope} proxySetting=${proxy} storageSetting=${scope === 'global' ? 'global' : 'ephemeral'} build=${SHA}`;
}

/** The saved-scope line, logged before patch 0017 can discard the persisted request. */
function saved(scope: string): string {
	return `[SECLAB_TEST_ONLY:browser-drive-hook] input id=v1 savedScope=${scope} explicitSession=no`;
}

/** A restore phase as a CORRECT F build produces it: 0017 drops the saved `global`. */
function fRestore(over: Partial<Evidence> = {}): Evidence {
	return evidence({
		phase: 'restore', probe: 'storage',
		hookLines: [saved('global'), resolved('ephemeral', `seclab+${TAB}`, 'ephemeral')],
		...over,
	});
}

test('a clean F run is all green', () => {
	assert.deepEqual(red(evidence()), []);
	assert.deepEqual(red(evidence({ probe: 'storage' })), []);
});

test('a clean U run is all green', () => {
	// U is vulnerable, so for U "all green" means every vulnerability fired.
	assert.deepEqual(red(evidence({
		build: 'u', probe: 'proxy', probeHits: 1, tabProbeHits: 0,
		hookLines: [...evidence().hookLines.slice(0, 2), resolved('workspace', 'none')],
	})), []);
	assert.deepEqual(red(evidence({
		build: 'u', probe: 'storage', probeHits: 1, tabProbeHits: 0,
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

test('a clean F RESTORE is all green', () => {
	// The case the previous version of this file never constructed, which is why it did not
	// notice that the attributability check was unsatisfiable on F: 0017 discards the saved
	// request before `requestedScope` is logged, so keying off that line made a CORRECT F
	// run read as inconclusive, and the phase could only go green when lines leaked in from
	// the other launch. `savedScope` is logged earlier, before 0017 can touch it.
	assert.deepEqual(red(fRestore()), []);
});

test('defect: 0017 stops dropping the persisted request -> only the restore verdict goes red', () => {
	const e = fRestore({ hookLines: [saved('global'), resolved('global', `seclab+${TAB}`, 'global')] });
	assert.deepEqual(red(e), ['CONTAINED: 0017 rebuilt the restored view under the fixed setting']);
});

test('the restore attributability check keys off the SAVED scope, not the resolved one', () => {
	// A regression guard for exactly the inversion above: F resolves `ephemeral`, and that
	// must not be read as "there was no hostile saved state".
	const e = fRestore();
	assert.ok(e.hookLines.some(l => l.includes('savedScope=global')));
	assert.ok(!e.hookLines.some(l => l.includes('requestedScope=global')));
	assert.deepEqual(red(e), []);
});

test('defect: the page escaped to the host -> only the side check goes red', () => {
	assert.deepEqual(red(evidence({ probeHits: 1, tabProbeHits: 0 })),
		['and the page was fetched INSIDE THE TAB, and never on the host']);
});

test('inconclusive: neither side saw the page -> the side check cannot pass', () => {
	// The old form read this as containment. It is a page that never loaded, a dead
	// listener, or a broken probe, and it must not be mistaken for evidence.
	const names = red(evidence({ probeHits: 0, tabProbeHits: 0 }));
	assert.ok(names.includes('and the page was fetched INSIDE THE TAB, and never on the host'));
});

test('inconclusive: both sides saw the page -> the side check cannot pass', () => {
	assert.ok(red(evidence({ probeHits: 1, tabProbeHits: 1 }))
		.includes('and the page was fetched INSIDE THE TAB, and never on the host'));
	assert.ok(red(evidence({ build: 'u', probe: 'proxy', probeHits: 1, tabProbeHits: 1,
		hookLines: [...evidence().hookLines.slice(0, 2), resolved('workspace', 'none')] }))
		.includes('and the page was fetched on the HOST, and not inside the tab'));
});

test('defect: the tab-side listener died -> only its liveness check goes red', () => {
	assert.deepEqual(red(evidence({ tabBeaconLiveAfter: false })),
		['the tab-side listener was still listening after the measurement']);
});

test('defect: a different binary produced the lines -> only the build check goes red', () => {
	assert.deepEqual(red(evidence({ loggedCommit: 'f'.repeat(40) })), ['the binary that produced these lines is the requested build']);
	assert.deepEqual(red(evidence({ loggedCommit: undefined })), ['the binary that produced these lines is the requested build']);
});

test('defect: the network was dropped but NOT by the setting -> the U proxy claim does not stand', () => {
	// `network=none` alone is also what a missing resolver produces. The window must have
	// actually read `false` for the claim to mean anything.
	const e = evidence({
		build: 'u', probe: 'proxy', probeHits: 1, tabProbeHits: 0,
		hookLines: [...evidence().hookLines.slice(0, 2),
			`[SECLAB_TEST_ONLY:browser-drive-hook] resolved scope=ephemeral network=none requestedScope=ephemeral proxySetting=true storageSetting=ephemeral build=${SHA}`],
	});
	assert.deepEqual(red(e), ["VULNERABLE: the tab's enableRemoteProxy=false moved the page off the tab"]);
});

test('defect: F reads the fixed value but the view still lost the network -> the F proxy claim does not stand', () => {
	const e = evidence({
		hookLines: [...evidence().hookLines.slice(0, 2),
			`[SECLAB_TEST_ONLY:browser-drive-hook] resolved scope=ephemeral network=none requestedScope=ephemeral proxySetting=true storageSetting=ephemeral build=${SHA}`],
	});
	assert.ok(red(e).includes("CONTAINED: 0017 overrode the tab's enableRemoteProxy=false"));
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

test('a restore phase cannot borrow the first launch readiness line', () => {
	// `ready=yes` is only meaningful for a hook-driven open, so the restore phase must not
	// assert it at all; if it did, a relaunch that produced nothing could inherit it.
	const names = browserProbeChecks(evidence({ phase: 'restore' })).map(c => c.name);
	assert.ok(!names.some(n => n.includes('in force when the page was opened')));
});

// ---- the harness itself ----------------------------------------------------------------

test('every mode the usage line documents actually reaches a handler', () => {
	// Round 9 found `switch-build` was unreachable: it was written, reviewed and recorded in
	// the EDR's procedure, but the argument guard still listed only `prepare` and `check`, so
	// it printed usage and exited. A mode nobody can run is dead code, which is the exact
	// failure this project keeps paying for. This parses the documented modes out of the
	// usage line and checks each one gets past the guard.
	const src = fs.readFileSync(new URL('./run.ts', import.meta.url), 'utf8');
	const documented = /usage: run\.ts ([a-z|-]+) </.exec(src)?.[1]?.split('|') ?? [];
	assert.ok(documented.length >= 3, `expected the usage line to list the modes, got ${documented.join(',')}`);
	for (const mode of documented) {
		const r = spawnSync(process.execPath, [fileURLToPath(new URL('./run.ts', import.meta.url)), mode, '/nonexistent-seclab-probe-dir'], { encoding: 'utf8' });
		assert.ok(!(r.stderr ?? '').startsWith('usage: run.ts'),
			`mode '${mode}' is documented but the argument guard rejects it as unknown`);
	}
});

// ---- R10-2: liveness must be continuity, not two point samples ---------------------------

function beats(...offsetsSec: number[]): string[] {
	const t0 = Date.parse('2026-11-12T10:00:00.000Z');
	return offsetsSec.map((s, i) => JSON.stringify({ at: new Date(t0 + s * 1000).toISOString(), side: 'tab', heartbeat: i + 1, pid: 7 }));
}

test('R10-2: a continuous heartbeat sequence is accepted', () => {
	assert.equal(heartbeatsContinuous(beats(0, 2, 4, 6, 8)), true);
});

test('R10-2 defect: a mid-phase gap is NOT continuity', () => {
	// The failure the rule exists for: the listener died and was resurrected, and the page
	// load it was meant to witness happened in the gap. Two point samples either side would
	// both have passed.
	assert.equal(heartbeatsContinuous(beats(0, 2, 4, 30, 32)), false);
	// A gap just over the threshold still fails: the bound is the rule, not a vibe.
	assert.equal(heartbeatsContinuous(beats(0, 2, 2 + HEARTBEAT_GAP_MS / 1000 + 1)), false);
	assert.equal(heartbeatsContinuous(beats(0, 2, 2 + HEARTBEAT_GAP_MS / 1000)), true);
});

test('R10-2 defect: too few beats cannot establish continuity', () => {
	// One beat says the listener was alive once, which is the point-sample failure again.
	assert.equal(heartbeatsContinuous(beats(0)), false);
	assert.equal(heartbeatsContinuous([]), false);
});

test('R10-2: probe hits and malformed lines are not mistaken for beats', () => {
	const noise = [
		JSON.stringify({ at: '2026-11-12T10:00:01.000Z', side: 'tab', method: 'GET', url: '/browser-probe-x' }),
		'not json at all',
		JSON.stringify({ at: 'not-a-date', side: 'tab', heartbeat: 99, pid: 7 }),
	];
	// Those three carry no usable beat, so on their own they cannot establish continuity...
	assert.equal(heartbeatsContinuous(noise), false);
	// ...and mixed in with real beats they neither break nor pad the sequence.
	assert.equal(heartbeatsContinuous([...noise, ...beats(0, 2, 4)]), true);
});
