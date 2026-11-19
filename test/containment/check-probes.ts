// Probe checker: assert the RPC escape probes behaved as the build requires.
//
//   node test/containment/check-probes.ts <mode> <evidence-dir> [options]
//     mode          unpatched | patched
//     --beacon F    beacon log (required in patched mode)
//     --denials F   host-side filter denial log (required in patched mode)
//     --no-reh      the run did not include the rogue-REH fixture
//     --only IDS    judge only these registered probes (comma-separated), for a run that
//                   exercises one surface (test/containment/reh-push.ts); reported as a
//                   selection, never as the whole set
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
import { partitionFindings, stateItems } from './state-db.ts';
import { report, type Check } from './assert.ts';

const argv = process.argv.slice(2);
const mode = argv[0];
const evidenceArg = argv[1];
const opt = (name: string): string | undefined => {
	const i = argv.indexOf(name);
	return i >= 0 ? argv[i + 1] : undefined;
};
const noReh = argv.includes('--no-reh');
const only = opt('--only')?.split(',').filter(Boolean);
if ((mode !== 'unpatched' && mode !== 'patched') || !evidenceArg) {
	console.error('usage: check-probes.ts unpatched|patched <evidence-dir> [--beacon F] [--denials F] [--user-data DIR --tab ID] [--no-reh]');
	process.exit(2);
}

const repo = path.resolve(import.meta.dirname, '../..');
const evidence = path.resolve(evidenceArg);
// --expectations: the self-test (check-probes.test.ts) drives the checker with synthetic
// expectations. Only with SECLAB_PROBE_SELFTEST=1, and the report says so: a proof run always
// reads the registry, and a transcript must show which it was (review round 18).
const syntheticExpectations = opt('--expectations');
if (syntheticExpectations !== undefined && process.env.SECLAB_PROBE_SELFTEST !== '1') {
	console.error('check-probes: --expectations is for the self-test only (SECLAB_PROBE_SELFTEST=1)');
	process.exit(2);
}
if (syntheticExpectations !== undefined) {
	console.log(`SYNTHETIC EXPECTATIONS (self-test): ${syntheticExpectations}; this is not a proof run`);
}
const expectations = JSON.parse(
	fs.readFileSync(syntheticExpectations ? path.resolve(syntheticExpectations) : path.join(repo, 'rpc-filter/probes/expectations.json'), 'utf8'));
const coverage = JSON.parse(
	fs.readFileSync(path.join(repo, 'rpc-filter/policy/coverage.json'), 'utf8'));

/** A probe result as the payloads record it: facts only, never a value (probe-safety.js). */
interface Result { id: string; policyRef: string; outcome: string; facts?: Record<string, unknown> | null; error?: string }
/** What a result says, for a report line: the failure kind, or its facts. */
const said = (r: Result): string => r.error ?? JSON.stringify(r.facts ?? null).slice(0, 200);
const fact = (r: Result, k: string): unknown => (r.facts && typeof r.facts === 'object' ? r.facts[k] : undefined);
const tokens = (r: Result): string[] => { const t = fact(r, 'canaryTokens'); return Array.isArray(t) ? t.map(String) : []; };
interface Spec {
	required?: boolean; policyRef: string; why: string; beacon?: string;
	patchedOutcome?: string; needsTestContribution?: boolean;
	status?: string; blocked_on?: string;
	hostEffect?: string; hostEffectAbsolute?: string;
	/** Run only by this harness's selection (the payload arms it on that path alone). */
	runner?: string;
	/** Why this probe has no unpatched baseline, and what in the patched run stands in for one. */
	noUnpatchedBaseline?: string;
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
/** The one record a registered probe's result may come from (undefined: not registered). */
function recordFor(id: string): string | undefined {
	const probes = expectations.probes as Record<string, { runner?: unknown }>;
	// `harness` is the fault channel every payload may write (never armed, unreadable targets).
	if (id === 'harness' || id === 'note') {
		return undefined;
	}
	if (Object.hasOwn(expectations.rehProbes as object, id)) {
		return 'reh-probes.json';
	}
	if (Object.hasOwn(probes, id)) {
		return typeof probes[id]?.runner === 'string' ? 'harness-probes.json' : 'rpc-probes.json';
	}
	return undefined;
}
function load(file: string, label: string, required: boolean): void {
	const p = path.join(evidence, file);
	if (!fs.existsSync(p)) {
		c('probes', !required, required ? `${label} evidence present (${file})` : `${label} evidence not needed by this selection (${file})`,
			required ? `missing ${p}` : 'absent');
		return;
	}
	const run = JSON.parse(fs.readFileSync(p, 'utf8')) as { results: Result[] };
	for (const r of run.results) {
		// Each record speaks only for its own probes: the tab's REH record can't stand in for a
		// host-measured one, and no id may come from two records (PR review, AID-1).
		const owner = recordFor(r.id);
		if (owner && owner !== file) {
			c('probes', false, `${label} evidence names ${r.id}, which only ${owner} may record`, file);
			continue;
		}
		if (results.has(r.id)) {
			if (r.id !== 'harness') {
				c('probes', false, `${r.id} is recorded twice`, file);
			}
			continue;
		}
		results.set(r.id, r);
	}
	c('probes', true, `${label} evidence present (${file})`, `${run.results.length} results`);
}
// A selection of REH probes only needs the REH evidence; any rogue-extension probe in it
// still needs the rogue extension's.
// A probe a harness measures itself (a `runner` in the rogue-extension section) comes from that
// harness's own record, not the rogue extension's.
const ownRunner = (id: string) => typeof (expectations.probes as Record<string, { runner?: unknown }>)[id]?.runner === 'string';
load('rpc-probes.json', 'rogue extension', !only || only.some(id => id in (expectations.probes as Record<string, unknown>) && !ownRunner(id)));
load('harness-probes.json', 'harness-measured', !!only && only.some(id => id in (expectations.probes as Record<string, unknown>) && ownRunner(id)));
// The restart probe runs last, once, in its own record (it can restart the extension host
// that runs it). An attempt that no new host settled has no outcome: inconclusive, never a pass.
{
	const p = path.join(evidence, 'rpc-probe-restart.json');
	if (fs.existsSync(p)) {
		try {
			const r = JSON.parse(fs.readFileSync(p, 'utf8')) as Result;
			if (r && r.id === 'host-restart-extension-host') {
				results.set(r.id, r.outcome ? r : { ...r, outcome: 'error', error: 'awaiting-new-host' });
			}
		} catch { /* unreadable: the probe reports "no result recorded" */ }
	}
}
// The REH fixture reaches surfaces the extension host cannot: chan:download,
// chan:mcpGatewayToolBroker, the raw-RPC identity spoof and the terminal
// pushes. Missing evidence is a failure unless the run says, in as many words,
// that it is not testing them.
//
// Waiving it used to print `PASS  rogue REH evidence present`, which is a
// false sentence: nothing was loaded and nothing was present. A green line
// asserting the opposite of what happened is worse than no line, because it is
// what gets quoted afterwards. The waiver is now reported as a waiver, names
// the probes it drops, and is counted so the run summary cannot be read as
// covering them.
if (noReh) {
	const dropped = Object.keys(expectations.rehProbes as Record<string, unknown>)
		.filter(k => k !== 'note');
	c('probes-waived', true, 'rogue REH evidence WAIVED by --no-reh',
		`not tested: ${dropped.length} probes (${dropped.join(', ')})`);
} else {
	load('reh-probes.json', 'rogue REH', true);
}

const specs: Record<string, Spec> = {
	...(expectations.probes as Record<string, Spec>),
	...(noReh ? {} : (expectations.rehProbes as Record<string, Spec>)),
};
delete (specs as Record<string, unknown>).note;
// A probe its payload arms only for one harness (`runner`) can't have run without that
// harness's selection, so a run that doesn't select it reports it as not judged, never as
// passed or failed (PR review, 2026-11-17).
const runnerOnly = Object.keys(specs).filter(id => typeof specs[id].runner === 'string' && !(only ?? []).includes(id));
if (runnerOnly.length) {
	c('probes-waived', true, `not judged here: ${runnerOnly.length} probe(s) run only by their own harness`, runnerOnly.map(id => `${id} (${specs[id].runner})`).join(', '));
	// The payload also records them on a full run (inconclusive there): out of the judged
	// results too, or the unreviewed-result check below fails them (PR review on #27).
	for (const id of runnerOnly) {
		delete specs[id];
		results.delete(id);
	}
}
if (only) {
	const unknown = only.filter(id => !(id in specs));
	c('probes-selected', unknown.length === 0, `judging only ${only.length} registered probe(s): ${only.join(', ')}`,
		unknown.length ? `not registered: ${unknown.join(', ')}` : `${Object.keys(specs).length - only.length} others not judged by this run`);
	for (const id of Object.keys(specs)) {
		if (!only.includes(id)) {
			delete specs[id];
		}
	}
}

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
	// Patch 0015: the tab window never dials the agent host the tab named, its gate logs the
	// refusal, and the same kind of entry in an empty window does dial (the positive control).
	'ai-remote-agent-host-dial': r =>
		fact(r, 'controlDialled') !== true ? 'the control window never dialled, so a quiet listener proves nothing'
			: fact(r, 'hostDialled') !== false ? 'the tab window dialled the agent host the tab named, from the host'
			: typeof fact(r, 'gateRefusals') !== 'number' || (fact(r, 'gateRefusals') as number) < 1 ? 'no refusal in the gate log' : null,
	'auth-get-session': r => {
		if (r.outcome !== 'succeeded' || fact(r, 'present') !== true) { return null; }
		const len = Number(fact(r, 'tokenLength') ?? 0);
		const sentinel = Number(process.env.SECLAB_SENTINEL_LEN ?? 64);
		return len > 0 && len !== sentinel ? `accessToken length ${len} is not a sentinel` : null;
	},
	'command-enumeration': r => {
		if (r.outcome !== 'succeeded') { return null; }
		const remoteCli = Number(fact(r, 'remoteCliVisible') ?? 0);
		return fact(r, 'newLocalVisible') === true || remoteCli > 0
			? `registry still exposes newLocal=${String(fact(r, 'newLocalVisible'))}, _remoteCLI.*=${remoteCli}` : null;
	},
	'secret-read-cross-tab': r => {
		if (r.outcome !== 'succeeded') { return null; }
		const other = String(process.env.SECLAB_OTHER_TAB_ID ?? '').replace(/[^A-Za-z0-9]/g, '').slice(0, 64);
		return other && tokens(r).includes(`seclabcanary_probe_secret_${other}`) ? `read the other tab's value (${other})` : null;
	},
	'webview-egress': () =>
		beaconPaths.has('/webview') ? 'webview still reached the host network' : null,
	'state-claim-tab-manager-read': r =>
		tokens(r).length > 0 ? 'the Tab Manager\'s seeded globalState canary reached the tab' : null,
	'state-claim-tab-manager-write': () => partitionReason(0, 1),
	// Patch 0034: the window still answers with the REH's profile path, but resolves no host
	// setting into it.
	'reh-profile-config-host-setting': r =>
		fact(r, 'sawProfilePath') !== true || fact(r, 'sawProfileEnv') !== true ? 'the window never sent the REH\'s profile path and env back'
			: tokens(r).length > 0 ? 'a host setting\'s canary came back in the profile launch'
				: fact(r, 'unresolved') !== true ? 'the profile path or env came back resolved to something else' : null,
	'secret-claim-tab-manager-write': () => partitionReason(2, 3),
	// Patch 0059: the server served its lie, and the window refused the environment (logged) rather
	// than reading the host file as the tab's settings.
	'reh-environment-host-settings': r =>
		served(r) < 1 ? 'the server never answered getEnvironmentData with the lie, so this proves nothing'
			: tokens(r).length > 0 ? 'the host file\'s canary reached the tab\'s REH'
				: !deniedRefs.has('data:server-locations') ? 'no refusal of the environment in the decision log' : null,
	// Patches 0053-0054 (DOCSYNC-R5): the window still asks the REH for profiles and starts its
	// terminal, but sends none of the host user's terminal settings.
	'reh-terminal-host-settings': r =>
		fact(r, 'sawGetProfiles') !== true || fact(r, 'sawCreateProcess') !== true ? 'the window never sent getProfiles and createProcess'
			: tokens(r).length > 0 ? 'a host terminal setting\'s canary reached the REH' : null,
	// The scan read every writable region, found the default profile's control canary, and nothing
	// the host user set (a skipped region could hold it: PR #70 review).
	'reh-exthost-terminal-profile': r =>
		fact(r, 'unreadRegions') !== 0 ? 'the scan could not read part of the extension host\'s memory, so it proves nothing'
			: fact(r, 'sawControl') !== true ? 'the scan did not find the default profile\'s control canary, so it proves nothing'
			: tokens(r).length > 0 ? 'a host terminal setting\'s canary is in the tab\'s extension host' : null,
};

/** How many times the rogue REH served its lie: a positive safe integer, else 0 (PR review on #66). */
function served(r: Result): number {
	const n = fact(r, 'served');
	return typeof n === 'number' && Number.isSafeInteger(n) && n > 0 ? n : 0;
}

/**
 * The partition checks read the profile's state database (test/containment/state-db.ts), so they
 * need the run's --user-data dir and --tab id. `escaped` is the finding that fails on an escape,
 * `ran` the one that shows the write landed in the partition.
 */
function partitionReason(escaped: number, ran: number): string | null {
	const userData = opt('--user-data');
	const tab = opt('--tab');
	if (!userData || !tab) {
		return 'needs --user-data and --tab to read where the write landed';
	}
	const f = partitionFindings(stateItems(path.resolve(userData)), tab);
	return !f[escaped].ok ? f[escaped].name.replace('did not', 'DID') : !f[ran].ok ? `${f[ran].name}: ${f[ran].detail}` : null;
}

// An unpatched run must show the escape itself, not just a return value: these probes
// "succeed" on both builds, so the outcome alone proves nothing.
const unpatchedPredicates: Record<string, (r: Result) => string | null> = {
	'state-claim-tab-manager-read': r =>
		tokens(r).length > 0 ? null : 'the read did not return the seeded canary, so the probe proves nothing',
	'provider-completion-host-file': r =>
		fact(r, 'sawHostContent') === true ? null : 'no host file content came back',
	'host-doc-open-userdata': r =>
		fact(r, 'sawHostContent') === true ? null : 'the host settings canary did not come back',
	'host-doc-show-userdata': r =>
		fact(r, 'sawHostContent') === true ? null : 'the host settings canary did not come back',
	'host-file-search-nested-uri': r =>
		fact(r, 'sawHostResult') === true ? null : 'no host resource in the search results',
	// The canary clipboard (a test build's in-memory store) must return this run's canary.
	'clipboard-read': r =>
		fact(r, 'sawCanary') === true ? null : 'the canary clipboard did not return the run\'s canary',
	// The REH push probes (patches 0030/0031) record facts the trusted side's reply carries,
	// since the REH can't write a host path: the command ran there, and the status it returned
	// describes the host rather than the Linux tab.
	'reh-onexecutecommand-windowopen': r => fact(r, 'ran') === true ? null : 'the trusted side did not run the command',
	'reh-onexecutecommand-manageextensions': r => fact(r, 'ran') === true ? null : 'the trusted side did not run the command',
	'reh-onexecutecommand-getsystemstatus': r =>
		fact(r, 'ran') !== true ? 'the trusted side did not run the command'
			: process.platform === 'darwin' && fact(r, 'hostIsMac') !== true ? 'the status returned does not describe the macOS host' : null,
	'reh-resolve-variables-host-env': r =>
		tokens(r).length > 0 ? null : 'the host environment canary did not come back',
	'reh-profile-config-host-setting': r =>
		fact(r, 'pathCanary') === true && fact(r, 'envCanary') === true ? null : 'the host setting canary did not come back in both the profile path and its env',
	'reh-environment-host-settings': r =>
		served(r) > 0 && tokens(r).some(t => t.startsWith('seclabcanary_HOSTREMOTE_')) ? null : 'the host file named as the tab\'s settings did not reach the REH',
	'reh-terminal-host-settings': r =>
		tokens(r).some(t => t.startsWith('seclabcanary_TERMINALENV_')) && tokens(r).some(t => t.startsWith('seclabcanary_TERMINALPROFILES_'))
			? null : 'the host terminal env and profiles canaries did not both reach the REH',
	'reh-exthost-terminal-profile': r =>
		fact(r, 'sawControl') !== true ? 'the scan did not find the default profile\'s control canary, so it proves nothing'
			: tokens(r).some(t => t.startsWith('seclabcanary_TERMINALAUTOMATI_')) ? null : 'the host automation profile canary is not in the tab\'s extension host',
	// A restart is proven only by a new extension host process settling the attempt, never by
	// an outcome that was simply not written (review rounds 14 and 15).
	'host-restart-extension-host': r => {
		const newPid = fact(r, 'newHostPid');
		const oldPid = fact(r, 'attemptPid');
		const settledMs = fact(r, 'settledMs');
		return Number.isSafeInteger(newPid) && Number.isSafeInteger(oldPid) && newPid !== oldPid
			&& fact(r, 'sameWindow') === true && typeof settledMs === 'number' && settledMs <= 60000
			? null : 'no new extension host in the same window, promptly after the attempt';
	},
	'state-claim-tab-manager-write': () => {
		const userData = opt('--user-data');
		if (!userData) { return 'needs --user-data'; }
		const f = partitionFindings(stateItems(path.resolve(userData)), opt('--tab') ?? '');
		return f[0].ok ? 'the write did not reach the Tab Manager\'s globalState' : null;
	},
	'secret-claim-tab-manager-write': () => {
		const userData = opt('--user-data');
		if (!userData) { return 'needs --user-data'; }
		const f = partitionFindings(stateItems(path.resolve(userData)), opt('--tab') ?? '');
		return f[2].ok ? 'the secret did not land under the Tab Manager\'s id' : null;
	},
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
	// `chan:server_initiated` and `push:` used to be exempt here, and skipped
	// by name in check_drift.py, so server-initiated surfaces were in neither
	// the digest nor this check. A probe could name one and link to nothing.
	// Both classes are now ordinary keys in coverage.json, so a probe that
	// references a push the policy does not know about fails like any other.
	const known = spec.policyRef in mapping
		|| composite(spec.policyRef)
		|| spec.policyRef.startsWith('data:')
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

	if (mode === 'unpatched' && typeof spec.noUnpatchedBaseline === 'string') {
		c('probes-waived', true, `${id} has no unpatched baseline`, spec.noUnpatchedBaseline);
		continue;
	}
	if (mode === 'unpatched') {
		// ERROR is not a pass: that is the whole reason this run exists.
		c('probes', r.outcome === 'succeeded' || !spec.required,
			`${id} succeeds on the unpatched build (${spec.why})`,
			`${r.outcome}: ${said(r)}`);
		const unpatchedPred = unpatchedPredicates[id];
		if (unpatchedPred && spec.required) {
			const reason = unpatchedPred(r);
			c('predicate', reason === null, `${id} shows the escape itself on the unpatched build`, reason ?? '');
		}
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
			`${r.outcome}: ${said(r)}`);
		// Corroborate with the host-side log rather than the tab-visible error,
		// which is deliberately indistinguishable from an unsupported operation.
		c('denial-log', deniedRefs.has(spec.policyRef) || !spec.required,
			`${id} denial recorded by the filter (${spec.policyRef})`,
			deniedRefs.has(spec.policyRef) ? ''
				: 'no host-side denial entry; the probe may have failed for another reason');
	} else {
		c('probes', r.outcome === want || !spec.required,
			`${id} is ${want} on the patched build`,
			`${r.outcome}: ${said(r)}`);
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
