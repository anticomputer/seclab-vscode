// Probe checker: assert the RPC escape probes behaved as the build requires.
//
//   node test/containment/check-probes.ts unpatched <evidence-dir> [beacon-log]
//   node test/containment/check-probes.ts patched   <evidence-dir> [beacon-log]
//
// The two modes are not symmetric, and that asymmetry is the point:
//
//   unpatched  every required probe must SUCCEED. This is what makes the probe
//              set trustworthy. A probe that has never succeeded proves nothing
//              when it later "fails", because it may simply be broken.
//   patched    every required probe must be DENIED, except where expectations
//              name a different patched outcome (a sentinel is still a
//              successful call; a filtered command list is still a list).
//
// It also checks that every probe names a policy entry that actually exists, so
// a probe cannot drift away from the table it is supposed to be testing.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { readHits } from './beacon.ts';
import { report, type Check } from './assert.ts';

const [mode, evidenceArg, beaconArg] = process.argv.slice(2);
if ((mode !== 'unpatched' && mode !== 'patched') || !evidenceArg) {
	console.error('usage: check-probes.ts unpatched|patched <evidence-dir> [beacon-log]');
	process.exit(2);
}
const repo = path.resolve(import.meta.dirname, '../..');
const evidence = path.resolve(evidenceArg);
const expectations = JSON.parse(
	fs.readFileSync(path.join(repo, 'rpc-filter/probes/expectations.json'), 'utf8'));
const coverage = JSON.parse(
	fs.readFileSync(path.join(repo, 'rpc-filter/policy/coverage.json'), 'utf8'));

interface Result { id: string; policyRef: string; outcome: string; detail: string }
interface Spec {
	required?: boolean; policyRef: string; why: string; beacon?: string;
	patchedOutcome?: string; patchedAssertion?: string; needsTestContribution?: boolean;
}

const probeFile = path.join(evidence, 'rpc-probes.json');
const checks: Check[] = [];

if (!fs.existsSync(probeFile)) {
	checks.push({
		vector: 'probes', ok: false, name: 'rogue extension produced rpc-probes.json',
		detail: `missing ${probeFile}; see rpc-probes-error.txt`,
	});
	process.exit(report(checks) ? 0 : 1);
}

const run = JSON.parse(fs.readFileSync(probeFile, 'utf8')) as { results: Result[]; tab: string };
const byId = new Map(run.results.map(r => [r.id, r]));
const specs = expectations.probes as Record<string, Spec>;
const beaconHits = beaconArg ? readHits(path.resolve(beaconArg)) : [];
const beaconPaths = new Set(beaconHits.map(h => h.url.split('?')[0]));

// Every probe must point at a policy entry that exists. Without this a probe
// can keep passing while the table it claims to test has moved underneath it.
for (const [id, spec] of Object.entries(specs)) {
	const known = spec.policyRef in (coverage.mapping as Record<string, string>)
		|| spec.policyRef.startsWith('data:')
		|| spec.needsTestContribution;
	checks.push({
		vector: 'probe-policy-link', ok: known,
		name: `${id} references a real policy entry (${spec.policyRef})`,
		detail: known ? '' : 'not present in coverage.json',
	});
}

for (const [id, spec] of Object.entries(specs)) {
	const result = byId.get(id);
	if (!result) {
		checks.push({
			vector: 'probes', ok: !spec.required, name: `${id} ran`,
			detail: 'no result recorded',
		});
		continue;
	}

	if (mode === 'unpatched') {
		// An ERROR is not a pass. It means the probe is broken, which is exactly
		// what this run exists to catch before the probe is trusted.
		const ok = result.outcome === 'succeeded';
		checks.push({
			vector: 'probes', ok: ok || !spec.required,
			name: `${id} succeeds on the unpatched build (${spec.why})`,
			detail: `${result.outcome}: ${String(result.detail).slice(0, 200)}`,
		});
		if (spec.beacon && spec.required) {
			checks.push({
				vector: 'beacon', ok: beaconPaths.has(spec.beacon),
				name: `${id} actually reached the host network (${spec.beacon})`,
				detail: `beacon paths seen: ${[...beaconPaths].join(', ') || 'none'}`,
			});
		}
	} else {
		const want = spec.patchedOutcome ?? 'denied';
		const ok = want === 'denied'
			? result.outcome === 'denied'
			: result.outcome === want;
		checks.push({
			vector: 'probes', ok: ok || !spec.required,
			name: `${id} is ${want} on the patched build`,
			detail: `${result.outcome}: ${String(result.detail).slice(0, 200)}`
				+ (spec.patchedAssertion ? ` | also assert: ${spec.patchedAssertion}` : ''),
		});
		if (spec.beacon && spec.required) {
			checks.push({
				vector: 'beacon', ok: !beaconPaths.has(spec.beacon),
				name: `${id} did not reach the host network (${spec.beacon})`,
				detail: `beacon paths seen: ${[...beaconPaths].join(', ') || 'none'}`,
			});
		}
	}
}

// A probe result with no expectation is unreviewed, and silently ignoring it is
// how a probe set rots.
for (const id of byId.keys()) {
	if (!(id in specs)) {
		checks.push({
			vector: 'probes', ok: false, name: `${id} has an expectation`,
			detail: 'result recorded but absent from expectations.json',
		});
	}
}

process.exit(report(checks) ? 0 : 1);
