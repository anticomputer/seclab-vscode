// The two rules of the 0015 U/G proof that a live run would otherwise be the only witness to.
//
// Both were recorded as `fixed-untested` in the findings baseline: the fix was read and
// believed, but nothing failed if it were reverted. They are pulled out here as pure
// functions so the runner calls exactly what the tests drive, rather than a copy of it.
//
// Nothing here reads a file, a clock or the network.

import { createHash } from 'node:crypto';

/** The salted hash the takeover matches on, so it never holds a canary value. */
export function hashCanary(salt: string, value: string): string {
	return createHash('sha256').update(`${salt}${value}`).digest('hex');
}

/**
 * THE CANARY SALT RULE (security review round 5).
 *
 * The takeover's config ships into the tab inside the vsix, in the mounted workspace. So
 * anything plaintext in it is something in-tab code could echo back without the window ever
 * having sent it, and the verdict could not tell a real leak from a replay. The tab is
 * therefore given a per-run salt and salted hashes, never a canary value.
 *
 * `canaryPath` is deliberately present: it is a host PATH, which is what the read probe asks
 * the window to fetch, not its content.
 */
export function takeoverCanaryConfig(canarySalt: string, values: Record<string, string>): {
	canarySalt: string; canaryHashes: Record<string, string>;
} {
	return {
		canarySalt,
		canaryHashes: Object.fromEntries(Object.entries(values).map(([k, v]) => [k, hashCanary(canarySalt, v)])),
	};
}

/**
 * Every canary value, anywhere in what the tab is given. Must be empty: the check exists so
 * that adding a field to the takeover's config cannot quietly reintroduce a plaintext canary.
 */
export function plaintextCanariesIn(payload: unknown, values: Record<string, string>): string[] {
	const text = JSON.stringify(payload) ?? '';
	return Object.entries(values).filter(([, v]) => v.length > 0 && text.includes(v)).map(([k]) => k);
}

export type GateRule = { gateRule?: string; verdict?: string };

/** What a U or G run observed, reduced to the facts the two rules below turn on. */
export type ProofEvidence = {
	build: 'u' | 'g';
	/** `gateRule:verdict` for every line the gate wrote in the window's own log. */
	rules: string[];
	/** Canary values the run planted, by name. Empty means `prepare` recorded nothing. */
	planted: Record<string, string>;
	/** Whether each planted canary was still armed where the window reads it. */
	armed: Record<string, boolean>;
	/** Canary names found in what the tab reported back. */
	leaked: string[];
	markerThere: boolean;
	beaconHits: number;
};

export type ProofCheck = { vector: string; name: string; ok: boolean; detail: string };

/**
 * The G-side assertions that a silent pass would otherwise slip through (review round 5,
 * and the two `fixed-untested` findings).
 *
 * Two of these are the point:
 *  - a G run must show the gate's OWN `ahp-gate.root-config:strip` decision, because the
 *    configuration mirror is the vector that actually leaks on U. Counting only `:deny`
 *    missed it, so "contained" would have rested on absence;
 *  - a run whose canaries were never planted, or never armed where the window reads them,
 *    proves nothing either way and must not be read as containment.
 */
export function proofChecks(e: ProofEvidence): ProofCheck[] {
	const checks: ProofCheck[] = [];
	const hostEffect = e.markerThere || e.beaconHits > 0 || e.leaked.length > 0;

	// The canaries have to exist and be armed before either verdict means anything.
	const names = Object.keys(e.planted);
	checks.push({
		vector: 'canaries', name: 'the run recorded the canaries it planted',
		ok: names.length > 0 && names.every(n => e.planted[n].length > 0),
		detail: names.length ? names.join(' ') : 'no canaries recorded',
	});
	checks.push({
		vector: 'canaries', name: 'every host canary was still planted where the window reads it',
		ok: names.length > 0 && names.every(n => e.armed[n]),
		detail: names.map(n => `${n}:${e.armed[n] ? 'armed' : 'MISSING'}`).join(' ') || 'none',
	});

	if (e.build === 'u') {
		checks.push({
			vector: 'U', name: 'no gate in the release build (the baseline is genuinely unpatched)',
			ok: e.rules.length === 0, detail: `${e.rules.length} gate lines`,
		});
		checks.push({
			vector: 'U', name: 'VULNERABLE: a real host effect from the hostile agent host', ok: hostEffect,
			detail: `marker=${e.markerThere} beaconHits=${e.beaconHits} canaryReported=${e.leaked.length > 0}`,
		});
		return checks;
	}

	const denies = e.rules.filter(r => r.endsWith(':deny'));
	const opened = e.rules.filter(r => r.startsWith('ahp-gate.opened')).length;
	const verified = e.rules.filter(r => r.startsWith('ahp-gate.verified')).length;
	const configStrips = e.rules.filter(r => r === 'ahp-gate.root-config:strip').length;

	checks.push({ vector: 'G', name: 'the gate ran in the shipped build (it wrote its own log)', ok: e.rules.length > 0, detail: `${e.rules.length} lines` });
	checks.push({ vector: 'G', name: 'construction invariant: every opened connection was verified', ok: opened > 0 && opened === verified, detail: `opened=${opened} verified=${verified}` });
	checks.push({ vector: 'G', name: 'positive control: the real agent host root state passed the gate', ok: e.rules.includes('ahp-gate.initialize:allow'), detail: `${e.rules.filter(r => r.startsWith('ahp-gate.initialize')).join(' ') || 'no initialize decision'}` });
	checks.push({ vector: 'G', name: 'the gate denied the probes (its own decisions, not absence)', ok: denies.length > 0, detail: `${denies.length} deny lines` });
	// THE STRIP ASSERTION. `denies` counts only `:deny`, and this one is a `strip`.
	checks.push({
		vector: 'G', name: 'the gate stripped the configuration mirror (the vector that leaks on U)',
		ok: configStrips > 0, detail: `${configStrips} ahp-gate.root-config:strip decisions`,
	});
	checks.push({
		vector: 'G', name: 'CONTAINED: no marker, no beacon hit, no canary reported', ok: !hostEffect,
		detail: `marker=${e.markerThere} beaconHits=${e.beaconHits} canaryReported=${e.leaked.length > 0}`,
	});
	return checks;
}
