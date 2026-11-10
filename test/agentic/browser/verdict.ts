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
	/** Whether the recorded build matches the one the run asked for. */
	buildMatches: boolean;
	/** Free text describing the build, for the report only. */
	buildDetail: string;
};

export function browserProbeChecks(e: Evidence): Check[] {
	const checks: Check[] = [];
	checks.push({ vector: 'build', name: 'ran the requested build', ok: e.buildMatches, detail: e.buildDetail });

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
		if (e.build === 'u') {
			checks.push({
				vector: 'U', name: `VULNERABLE: the tab's ${wrote} moved the page off the tab`,
				ok: e.probe === 'proxy' ? network === 'none' : scope === 'global',
				detail: `resolved scope=${scope} network=${network}`,
			});
			checks.push({
				vector: 'U', name: 'and the host beacon saw the fetch', ok: e.probeHits > 0,
				detail: `${e.probeHits} hit(s) for this run's probe URL`,
			});
		} else {
			checks.push({
				vector: 'F', name: `CONTAINED: 0017 overrode the tab's ${wrote}`,
				ok: e.probe === 'proxy' ? network === `seclab+${e.tabId}` : scope === 'ephemeral',
				detail: `resolved scope=${scope} network=${network}, expected ${e.probe === 'proxy' ? `network seclab+${e.tabId}` : 'scope ephemeral'}`,
			});
			checks.push({
				vector: 'F', name: 'and the host beacon saw nothing', ok: e.probeHits === 0,
				detail: `${e.probeHits} hit(s); total beacon hits ${e.beaconHits}`,
			});
		}
	}

	// The restore path. A browser editor restored from a previous window carries its saved
	// session request, and upstream returns it verbatim when it has a scope, without
	// consulting the configured storage. Run cross-build on one profile: U persists `global`,
	// and the relaunch reads byte-for-byte the same state, so the only difference between the
	// two observations is the patch.
	if (e.phase === 'restore') {
		checks.push({
			vector: 'restore', name: 'the restored view really did carry the hostile saved scope',
			ok: e.hookLines.some(l => /requestedScope=global/.test(l)),
			detail: `from ${resolvedLines.length} resolution(s) by this launch`,
		});
		checks.push({
			vector: 'restore',
			name: e.build === 'u' ? 'VULNERABLE: the restored view came back global' : 'CONTAINED: 0017 rebuilt the restored view under the fixed setting',
			ok: e.build === 'u' ? scope === 'global' : scope === 'ephemeral',
			detail: `restored scope=${scope} network=${network}, host hits ${e.probeHits}`,
		});
		checks.push({
			vector: 'restore', name: e.build === 'u' ? 'and the host beacon saw the restored fetch' : 'and the host beacon saw nothing',
			ok: e.build === 'u' ? e.probeHits > 0 : e.probeHits === 0,
			detail: `${e.probeHits} hit(s)`,
		});
	}

	// Liveness. Without it, a beacon that never bound produces exactly the evidence a
	// contained build produces, so every "no hit" above would prove nothing.
	checks.push({
		vector: 'beacon', name: 'the beacon was still listening after the measurement',
		ok: e.beaconLiveAfter, detail: 'host-side self-hit',
	});
	return checks;
}
