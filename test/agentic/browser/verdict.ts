// The increment 2 verdict, as a pure function of the evidence a run collected.
//
// It lives apart from the runner so that each check can be driven directly with synthetic
// evidence. That is not a convenience: security review round 8 found two checks in the first
// version of this proof that could not fail, one because it re-read an earlier launch's log
// and one because it was implied by the check above it. A check that cannot fail is not
// evidence, and the only way to show a check CAN fail is to make it fail on purpose. The
// companion test injects each defect 0017 is supposed to prevent and asserts that exactly
// one check goes red, so "all green" on a real run means something.
//
// Nothing here reads a file, a clock or the network.

// One source of truth for the shape, shared with the containment reporter.
import type { Check } from '../../containment/assert.ts';
export type { Check };

/** What a single launch of a single build produced. */
export type Evidence = {
	/** Which build ran: `u` has no 0017, `f` has it. */
	build: 'u' | 'f';
	/** `first` is a hook-driven open; `restore` is a relaunch reading persisted state. */
	phase: 'first' | 'restore';
	/** Which setting this run is about. */
	probe: 'proxy' | 'storage';
	/** The tab's remote authority, which is the network a contained view must resolve to. */
	tabId: string;
	/** Lines THIS launch appended to the profile's logs, and nothing from any other launch. */
	hookLines: string[];
	/** Total lines this launch appended, used only to describe an inconclusive phase. */
	phaseLines: number;
	/** Hits on this run's unique probe URL, recorded by the host-side beacon. */
	probeHits: number;
	/** Every hit the beacon recorded, used only for context in the detail text. */
	beaconHits: number;
	/** Whether the beacon answered the HOST after the measurement. */
	beaconLiveAfter: boolean;
	/** Hits on this run's probe URL recorded by the listener INSIDE the tab. */
	tabProbeHits: number;
	/** Whether the tab-side listener answered the tab after the measurement. */
	tabBeaconLiveAfter: boolean;
	/** The repo SHA the RUNNING BINARY reported, from its own log line. */
	loggedCommit: string | undefined;
	/** The repo SHA the requested build's `build-info-app.json` records. */
	expectedCommit: string;
};

/**
 * EXACTLY ONE SIDE. The probe URL is loopback, and `127.0.0.1` means a different machine
 * depending on who fetches it, so the two listeners together say where the page ran:
 *
 *   host hit, tab quiet -> fetched on the HOST network
 *   tab hit, host quiet -> fetched INSIDE the tab
 *   both, or neither    -> inconclusive
 *
 * This is what removes absence-based reasoning from the proof. The old form asked only
 * whether the host beacon was quiet, which a dead listener, a page that never loaded or a
 * broken probe satisfies just as well as containment does.
 */
function sideCheck(e: Evidence, expected: 'host' | 'tab'): Check {
	const detail = `host ${e.probeHits} hit(s), tab ${e.tabProbeHits} hit(s)`;
	const exactlyOne = (e.probeHits > 0) !== (e.tabProbeHits > 0);
	const ok = exactlyOne && (expected === 'host' ? e.probeHits > 0 : e.tabProbeHits > 0);
	return {
		vector: 'beacon',
		name: expected === 'host'
			? 'and the page was fetched on the HOST, and not inside the tab'
			: 'and the page was fetched INSIDE THE TAB, and never on the host',
		ok,
		detail: exactlyOne ? detail : `${detail}: ${e.probeHits > 0 ? 'both sides saw it' : 'neither side saw it'}, so this run is inconclusive`,
	};
}

/** Three missed beats at the listener's 2s interval. */
export const HEARTBEAT_GAP_MS = 6_000;

/**
 * Whether the tab-side listener beat continuously across a phase.
 *
 * Liveness used to be two point samples, one before arming and one at check time, so a
 * listener that died and was resurrected mid-phase passed while the page load it was meant to
 * witness happened in the gap (round 10, R10-2). A restart shows up here as a gap, which is
 * exactly what must invalidate the phase. Timestamps come from the listener's own clock only:
 * comparing them against the window log, which is local time while these are UTC, rejected
 * correct runs.
 */
export function heartbeatsContinuous(lines: string[], gapMs: number = HEARTBEAT_GAP_MS): boolean {
	const beats = lines
		.map(l => { try { return JSON.parse(l) as { at?: string; heartbeat?: number }; } catch { return {}; } })
		.filter((b): b is { at: string; heartbeat: number } => b.heartbeat !== undefined && !!b.at)
		.map(b => Date.parse(b.at))
		.filter(t => !Number.isNaN(t))
		.sort((x, y) => x - y);
	return beats.length >= 2 && beats.every((t, i) => i === 0 || t - beats[i - 1] <= gapMs);
}

export function browserProbeChecks(e: Evidence): Check[] {
	const checks: Check[] = [];
	// BUILD IDENTITY FROM THE BINARY. Comparing the harness's two bookkeeping files only
	// ever asserted that the harness agreed with itself, and the whole cross-build restore
	// claim rests on which bundle the operator actually launched. The hook stamps the
	// running product's repo SHA into its own log lines, so this compares what RAN against
	// what was asked for. The product's `commit` is upstream's SHA and is identical in both
	// builds, so it cannot tell them apart; the variant build stamps the repo SHA instead.
	checks.push({
		vector: 'build', name: 'the binary that produced these lines is the requested build',
		ok: !!e.loggedCommit && e.loggedCommit === e.expectedCommit,
		detail: `logged ${e.loggedCommit ?? 'none'}, expected ${e.expectedCommit}`,
	});

	// The AUTHORITATIVE line: what upstream settled on after workspace trust, proxy
	// availability and storage isolation, rather than what the hook asked for.
	const resolvedLines = e.hookLines.filter(l => l.includes(' resolved '));
	const last = resolvedLines[resolvedLines.length - 1] ?? '';
	const network = /\bnetwork=(\S+)/.exec(last)?.[1];
	const scope = /\bscope=(\S+)/.exec(last)?.[1];
	checks.push({
		vector: 'hook', name: 'THIS launch resolved a browser view (otherwise the phase is inconclusive)',
		ok: resolvedLines.length > 0,
		detail: resolvedLines.length
			? `${resolvedLines.length} resolution(s) by this launch; last scope=${scope} network=${network}`
			: `this launch appended ${e.phaseLines} log line(s) and resolved nothing`,
	});
	if (e.phase !== 'restore') {
		checks.push({
			vector: 'hook', name: "the tab's remote settings were in force when the page was opened",
			ok: e.hookLines.some(l => l.includes('ready=yes')),
			detail: e.hookLines.filter(l => l.includes('ready=')).slice(-1)[0]?.slice(-80) ?? 'no readiness line',
		});
	}

	// ONE key decides each run. `proxy` is read off the resolved NETWORK, which upstream
	// drops when the proxy is off. `storage` is read off the resolved SCOPE: a global scope
	// keeps a network value but gives the view the host's shared session, which upstream
	// documents as always using the local network. Writing both hostile values at once is
	// what made the storage check ride along on the proxy result and never fail on its own.
	const wrote = e.probe === 'proxy' ? 'enableRemoteProxy=false' : 'dataStorage=global';
	if (e.phase !== 'restore') {
		// `network=none` on its own is NOT proof the setting caused it: a missing resolver
		// produces the same value. The first attempt at a discriminator required
		// `requestedNetwork=seclab+<tab>` on U, which is UNSATISFIABLE: `resolveNetwork`
		// returns undefined at the proxy gate itself, so with the proxy off there is no
		// requested network to see. (Another check that could not pass; found by running it.)
		// The effective SETTING VALUE, as the window read it, is the discriminator that
		// works: it is the thing 0017 overrides, and it ties cause to effect directly.
		const proxySetting = /\bproxySetting=(\S+)/.exec(last)?.[1];
		const storageSetting = /\bstorageSetting=(\S+)/.exec(last)?.[1];
		const proxyDropped = network === 'none' && proxySetting === 'false';
		if (e.build === 'u') {
			checks.push({
				vector: 'U', name: `VULNERABLE: the tab's ${wrote} moved the page off the tab`,
				ok: e.probe === 'proxy' ? proxyDropped : (scope === 'global' && storageSetting === 'global'),
				detail: `resolved scope=${scope} network=${network}, proxySetting=${proxySetting} storageSetting=${storageSetting}`,
			});
			checks.push(sideCheck(e, 'host'));
		} else {
			checks.push({
				vector: 'F', name: `CONTAINED: 0017 overrode the tab's ${wrote}`,
				// BOTH the override and its effect: the window must have read the fixed value
				// despite the tab writing the hostile one, AND the view must have got the
				// network or scope that value implies.
				ok: e.probe === 'proxy'
					? proxySetting === 'true' && network === `seclab+${e.tabId}`
					: storageSetting === 'ephemeral' && scope === 'ephemeral',
				detail: `resolved scope=${scope} network=${network}, proxySetting=${proxySetting} storageSetting=${storageSetting}`,
			});
			checks.push(sideCheck(e, 'tab'));
		}
	}

	// The restore path. A browser editor restored from a previous window carries its saved
	// session request, and upstream returns it verbatim when it has a scope, without
	// consulting the configured storage. Run cross-build on one profile: U persists `global`,
	// and the relaunch reads byte-for-byte the same state, so the only difference between the
	// two observations is the patch.
	if (e.phase === 'restore') {
		// `savedScope` is logged in `_getOrCreateLazy`, BEFORE `_resolveSessionRequest` runs.
		// It has to be: patch 0017 discards the saved request inside that method, so on a
		// fixed build `requestedScope` has already been rebuilt to `ephemeral` by the time
		// the resolution line is written. Keying this off `requestedScope` made the check
		// unsatisfiable on F, so a correct F run read as inconclusive and the phase could
		// only go green if lines leaked in from the other launch -- green exactly when
		// attribution had been violated.
		checks.push({
			vector: 'restore', name: 'the restored view really did carry the hostile saved scope',
			ok: e.hookLines.some(l => /\bsavedScope=global\b/.test(l)),
			detail: e.hookLines.filter(l => l.includes('savedScope=')).slice(-1)[0]?.slice(-90) ?? 'no savedScope line from this launch',
		});
		checks.push({
			vector: 'restore',
			name: e.build === 'u' ? 'VULNERABLE: the restored view came back global' : 'CONTAINED: 0017 rebuilt the restored view under the fixed setting',
			ok: e.build === 'u' ? scope === 'global' : scope === 'ephemeral',
			detail: `restored scope=${scope} network=${network}, host hits ${e.probeHits}`,
		});
		checks.push(sideCheck(e, e.build === 'u' ? 'host' : 'tab'));
	}

	// Liveness. Without it, a beacon that never bound produces exactly the evidence a
	// contained build produces, so every "no hit" above would prove nothing.
	checks.push({
		vector: 'beacon', name: 'the beacon was still listening after the measurement',
		ok: e.beaconLiveAfter, detail: 'host-side self-hit',
	});
	checks.push({
		vector: 'beacon', name: 'the tab-side listener was still listening after the measurement',
		ok: e.tabBeaconLiveAfter, detail: 'tab-side self-hit',
	});
	return checks;
}
