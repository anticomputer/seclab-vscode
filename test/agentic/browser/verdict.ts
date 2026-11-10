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
	/** Whether the TAB could reach the beacon address. It must not be able to. */
	beaconReachableFromTab: boolean;
	/** Whether the tab's attempt left a hit, which would mean the address was not fenced. */
	tabControlHits: number;
	/** The repo SHA the RUNNING BINARY reported, from its own log line. */
	loggedCommit: string | undefined;
	/** The repo SHA the requested build's `build-info-app.json` records. */
	expectedCommit: string;
};

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
		// For the proxy probe, `network=none` on its own is NOT the setting's doing: it is
		// also what you get when `resolveNetwork` returned nothing, or the authority reported
		// that it cannot proxy. The hook logs what was REQUESTED, so require that the tab's
		// network was available and then dropped.
		const requestedNetwork = /\brequestedNetwork=(\S+)/.exec(e.hookLines.filter(l => l.includes(' opening ')).slice(-1)[0] ?? '')?.[1];
		const proxyDropped = network === 'none' && requestedNetwork === `seclab+${e.tabId}`;
		if (e.build === 'u') {
			checks.push({
				vector: 'U', name: `VULNERABLE: the tab's ${wrote} moved the page off the tab`,
				ok: e.probe === 'proxy' ? proxyDropped : scope === 'global',
				detail: `resolved scope=${scope} network=${network}, requestedNetwork=${requestedNetwork}`,
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
	// THE FENCE, MEASURED. Every "the beacon saw nothing" above means "the page was not
	// fetched from the host" only if the tab could not have reached that address anyway.
	// That was asserted in three places and measured in none; a beacon bound to a bridge or
	// vmnet gateway IS reachable from the guest, which would reintroduce precisely the
	// ambiguity the non-loopback address was chosen to remove.
	checks.push({
		vector: 'beacon', name: 'the TAB cannot reach the beacon address (so a quiet beacon means the host)',
		ok: !e.beaconReachableFromTab && e.tabControlHits === 0,
		detail: e.beaconReachableFromTab
			? 'the tab reached it: this address is bridged to the guest, and the probe cannot distinguish host from tab'
			: `tab denied, ${e.tabControlHits} hit(s) from the tab`,
	});
	return checks;
}
