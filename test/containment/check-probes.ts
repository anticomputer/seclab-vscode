// Probe checker: assert the RPC escape probes behaved as the build requires.
//
//   node test/containment/check-probes.ts <mode> <evidence-dir> [options]
//     mode          unpatched | patched
//     --beacon F    beacon log (required in patched mode)
//     --denials F   host-side filter denial log (required in patched mode)
//     --no-reh      the run did not include the rogue-REH fixture
//
// The two modes are not symmetric, and that asymmetry is the point:
//
//   unpatched  every required probe must SUCCEED. This is what makes the probe
//              set trustworthy. A probe that has never succeeded proves nothing
//              when it later "fails", because it may simply be broken.
//   patched    every required probe must be DENIED, except where expectations
//              name a different patched outcome.
//
// Three design points are load-bearing, from the 2026-11-04 review:
//
//  * A probe's own error message is NOT the source of truth for denial. The
//    filter deliberately makes a denial look like an unsupported operation to
//    the tab, so message sniffing cannot separate "denied" from "broken". The
//    host-side denial log is the oracle; the probe's classification is a hint.
//  * Both fixtures are checked. Reading only the extension-side evidence left
//    the whole client-served channel surface with no baseline at all.
//  * A patchedOutcome other than "denied" requires an executable predicate.
//    Free-text "also assert ..." asserts nothing.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { readHits } from './beacon.ts';
import { report, type Check } from './assert.ts';

const argv = process.argv.slice(2);
const mode = argv[0];
const evidenceArg = argv[1];
const opt = (name: string): string | undefined => {
	const i = argv.indexOf(name);
	return i >= 0 ? argv[i + 1] : undefined;
};
const noReh = argv.includes('--no-reh');
if ((mode !== 'unpatched' && mode !== 'patched') || !evidenceArg) {
	console.error('usage: check-probes.ts unpatched|patched <evidence-dir> [--beacon F] [--denials F] [--no-reh]');
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
	patchedOutcome?: string; needsTestContribution?: boolean;
	status?: string; blocked_on?: string;
	hostEffect?: string; hostEffectAbsolute?: string;
}

/**
 * Resolve a declared hostEffect to the file it must produce on the host.
 * "marker" and "marker.<suffix>" map onto the run directory's fixed marker
 * basename, which is what probe-safety.js markerCommand() writes.
 */
function hostEffectPath(effect: string): string | null {
	const runDir = process.env.SECLAB_PROBE_RUNDIR;
	if (!runDir) { return null; }
	if (effect === 'marker') { return path.join(runDir, 'PWNED'); }
	if (effect.startsWith('marker.')) {
		return path.join(runDir, `PWNED${effect.slice('marker'.length)}`);
	}
	if (!HOST_EFFECT_FILENAME.test(effect)) {
		// Not a filename. The previous version joined whatever it was onto the
		// run directory, so an English description of an effect -- "beacon hit
		// from the host, or a marker written outside the tab" -- became a path
		// that could never exist, and the absence of that file was reported as
		// the host being unchanged. A probe that cannot fail is worse than no
		// probe, so an unresolvable effect is an error rather than a pass.
		throw new Error(
			`hostEffect ${JSON.stringify(effect)} is not a filename. Use "marker", `
			+ `"marker.<suffix>", a run-relative path, or hostEffectAbsolute.`);
	}
	return path.join(runDir, effect);
}

/** A plausible run-relative filename: no spaces, no prose. */
const HOST_EFFECT_FILENAME = /^[A-Za-z0-9._\/-]+$/;

const checks: Check[] = [];
const c = (vector: string, ok: boolean, name: string, detail = ''): void => {
	checks.push({ vector, ok, name, detail });
};

/**
 * Resolve a hostEffectAbsolute like "userDataDir:/User/x.txt" against the run
 * manifest. This exists because host-fs-write-userdata is the probe that
 * demonstrates a write genuinely crossing to the host, and scoring it on its
 * return value is exactly the mistake host-fs-write-file-scheme already made.
 */
function hostEffectAbsolutePath(effect: string): string | null {
	const runDir = process.env.SECLAB_PROBE_RUNDIR;
	if (!runDir) { return null; }
	const m = /^userDataDir:(.+)$/.exec(effect);
	if (!m) { return path.resolve(effect); }
	try {
		const manifest = JSON.parse(
			fs.readFileSync(path.join(runDir, 'run.json'), 'utf8')) as { userDataDir?: string };
		return manifest.userDataDir ? path.join(manifest.userDataDir, m[1]) : null;
	} catch {
		return null;
	}
}

/** Both forms, or null when it cannot be resolved (which is a failure, not a pass). */
function effectTarget(spec: { hostEffect?: string; hostEffectAbsolute?: string }): string | null {
	if (spec.hostEffectAbsolute) { return hostEffectAbsolutePath(spec.hostEffectAbsolute); }
	return spec.hostEffect ? hostEffectPath(spec.hostEffect) : null;
}

// ---------------------------------------------------------------- evidence
const results = new Map<string, Result>();
function load(file: string, label: string, required: boolean): void {
	const p = path.join(evidence, file);
	if (!fs.existsSync(p)) {
		c('probes', !required, `${label} evidence present (${file})`, `missing ${p}`);
		return;
	}
	const run = JSON.parse(fs.readFileSync(p, 'utf8')) as { results: Result[] };
	for (const r of run.results) {
		results.set(r.id, r);
	}
	c('probes', true, `${label} evidence present (${file})`, `${run.results.length} results`);
}
load('rpc-probes.json', 'rogue extension', true);
// The REH fixture reaches surfaces the extension host cannot. Skipping it
// silently would leave chan:download, chan:mcpGatewayToolBroker and the raw-RPC
// identity spoof with no baseline, which reads as containment.
load('reh-probes.json', 'rogue REH', !noReh);

const specs: Record<string, Spec> = {
	...(expectations.probes as Record<string, Spec>),
	...(noReh ? {} : (expectations.rehProbes as Record<string, Spec>)),
};
delete (specs as Record<string, unknown>).note;

// ---------------------------------------------------------------- oracles
const beaconFile = opt('--beacon');
const denialFile = opt('--denials');
if (mode === 'patched') {
	// Without these, a forgotten argument silently certifies every egress claim
	// and every denial claim.
	c('oracles', !!beaconFile, 'beacon log supplied (required in patched mode)', beaconFile ?? 'missing');
	c('oracles', !!denialFile, 'denial log supplied (required in patched mode)', denialFile ?? 'missing');
}
const beaconPaths = new Set(
	(beaconFile ? readHits(path.resolve(beaconFile)) : []).map(h => h.url.split('?')[0]));
const denials: Array<{ policyRef?: string }> =
	denialFile && fs.existsSync(path.resolve(denialFile))
		? fs.readFileSync(path.resolve(denialFile), 'utf8').split('\n')
			.filter(l => l.trim()).map(l => JSON.parse(l))
		: [];
const deniedRefs = new Set(denials.map(d => d.policyRef ?? ''));

// ------------------------------------------- executable patched predicates
// Each returns null when satisfied, or the reason it is not. These replace
// free-text "also assert ..." notes, which asserted nothing -- auth-get-session
// in particular would have passed while handing a live token to the tab.
const predicates: Record<string, (r: Result) => string | null> = {
	'auth-get-session': r => {
		if (r.outcome !== 'succeeded') { return null; }
		let v: { tokenLength?: number } | null = null;
		try { v = JSON.parse(r.detail); } catch { return `unparseable detail: ${r.detail}`; }
		if (!v) { return null; }
		const len = Number(v.tokenLength ?? 0);
		const sentinel = Number(process.env.SECLAB_SENTINEL_LEN ?? 64);
		return len > 0 && len !== sentinel ? `accessToken length ${len} is not a sentinel` : null;
	},
	'command-enumeration': r => {
		if (r.outcome !== 'succeeded') { return null; }
		let v: { dangerousVisible?: string[] } | null = null;
		try { v = JSON.parse(r.detail); } catch { return `unparseable detail: ${r.detail}`; }
		const vis = v?.dangerousVisible ?? [];
		return vis.length ? `registry still exposes ${vis.join(', ')}` : null;
	},
	'secret-read-cross-tab': r => {
		if (r.outcome !== 'succeeded') { return null; }
		const other = process.env.SECLAB_OTHER_TAB_ID;
		return other && r.detail.includes(other) ? `read the other tab's value (${other})` : null;
	},
	'webview-egress': () =>
		beaconPaths.has('/webview') ? 'webview still reached the host network' : null,
};

// ---------------------------------------------------------------- checks
for (const [id, spec] of Object.entries(specs)) {
	const mapping = coverage.mapping as Record<string, string>;
	// Surface (e) keys carry pinned attributes after the id --
	// `ai-tool:<id>|host=…`, `ai-setting:<id>|scope=…|unreg=…|tab_writable=…` --
	// so an exact lookup never matches. Match on the id prefix instead: the
	// attributes are what the gate pins, not part of the surface's identity.
	const composite = (ref: string): boolean =>
		(ref.startsWith('ai-tool:') || ref.startsWith('ai-setting:'))
		&& Object.keys(mapping).some(k => k === ref || k.startsWith(`${ref}|`));
	const known = spec.policyRef in mapping
		|| composite(spec.policyRef)
		|| spec.policyRef.startsWith('data:')
		|| spec.policyRef.startsWith('chan:server_initiated')
		|| spec.policyRef.startsWith('push:')
		|| spec.needsTestContribution
		|| spec.policyRef === 'rpc:raw';
	c('probe-policy-link', known, `${id} references a real policy entry (${spec.policyRef})`,
		known ? '' : 'not present in coverage.json');
}

for (const [id, spec] of Object.entries(specs)) {
	if (spec.status === 'not-implemented') {
		// Reported, never silently skipped. These are registered surfaces with
		// no runner yet; counting them as passes would turn an absence of
		// evidence into evidence of containment.
		c('probes-pending', true, `${id} is registered but NOT IMPLEMENTED`,
			spec.blocked_on ?? '');
		continue;
	}
	const r = results.get(id);
	if (!r) {
		c('probes', !spec.required, `${id} ran`, 'no result recorded');
		continue;
	}

	if (mode === 'unpatched') {
		// ERROR is not a pass: that is the whole reason this run exists.
		c('probes', r.outcome === 'succeeded' || !spec.required,
			`${id} succeeds on the unpatched build (${spec.why})`,
			`${r.outcome}: ${String(r.detail).slice(0, 200)}`);
		if (spec.beacon && spec.required) {
			c('beacon', beaconPaths.has(spec.beacon),
				`${id} actually reached the host network (${spec.beacon})`,
				`seen: ${[...beaconPaths].join(', ') || 'none'}`);
		}
		// A return value is not an escape. host-fs-write-file-scheme reported
		// success on 2026-11-04 while writing nothing on the host, because a
		// remote window routes file: writes to the REH's own provider. Without
		// this check it would have been recorded as a proven escape and then
		// "fixed" by a patch that changed nothing.
		if ((spec.hostEffect || spec.hostEffectAbsolute) && spec.required) {
			const target = effectTarget(spec);
			c('host-effect', !!target && fs.existsSync(target),
				`${id} actually changed the host (${spec.hostEffect ?? spec.hostEffectAbsolute})`,
				target ? `${target} ${fs.existsSync(target) ? 'exists' : 'MISSING: the call succeeded but nothing happened on the host'}`
					: 'SECLAB_PROBE_RUNDIR not set, cannot verify');
		}
		continue;
	}

	const want = spec.patchedOutcome ?? 'denied';
	if (want === 'denied') {
		c('probes', r.outcome !== 'succeeded' || !spec.required,
			`${id} did not succeed on the patched build`,
			`${r.outcome}: ${String(r.detail).slice(0, 200)}`);
		// Corroborate with the host-side log rather than the tab-visible error,
		// which is deliberately indistinguishable from an unsupported operation.
		c('denial-log', deniedRefs.has(spec.policyRef) || !spec.required,
			`${id} denial recorded by the filter (${spec.policyRef})`,
			deniedRefs.has(spec.policyRef) ? ''
				: 'no host-side denial entry; the probe may have failed for another reason');
	} else {
		c('probes', r.outcome === want || !spec.required,
			`${id} is ${want} on the patched build`,
			`${r.outcome}: ${String(r.detail).slice(0, 200)}`);
		const pred = predicates[id];
		c('predicate', !!pred, `${id} has an executable patched predicate`,
			pred ? '' : 'patchedOutcome is not "denied" but nothing checks the claim');
		if (pred) {
			const reason = pred(r);
			c('predicate', reason === null, `${id} patched predicate holds`, reason ?? '');
		}
	}
	if (spec.beacon && spec.required) {
		c('beacon', !beaconPaths.has(spec.beacon),
			`${id} did not reach the host network (${spec.beacon})`,
			`seen: ${[...beaconPaths].join(', ') || 'none'}`);
	}
	if ((spec.hostEffect || spec.hostEffectAbsolute) && spec.required) {
		const target = effectTarget(spec);
		// An unresolvable target must fail. Previously `!target || ...` made a
		// forgotten SECLAB_PROBE_RUNDIR certify "did not change the host".
		c('host-effect', !!target && !fs.existsSync(target),
			`${id} did not change the host (${spec.hostEffect ?? spec.hostEffectAbsolute})`,
			target ?? 'cannot resolve the target: SECLAB_PROBE_RUNDIR or run.json missing');
	}
}

// A result with no expectation is unreviewed, and ignoring it is how a probe
// set rots.
for (const id of results.keys()) {
	if (!(id in specs)) {
		c('probes', false, `${id} has an expectation`,
			'result recorded but absent from expectations.json');
	}
}

process.exit(report(checks) ? 0 : 1);
