/**
 * check-probes.ts against synthetic evidence: every way it must fail, failing.
 *
 * Run: node test/containment/check-probes.test.ts
 *
 * The checker is the oracle for every containment probe, and nothing ran it except a real
 * editor run. Each case here runs the real checker (a child process) over fixture evidence and
 * synthetic expectations (--expectations), and asserts the exact failing check, after a
 * control case shows the same fixture passes when nothing is wrong. Without the control, a
 * broken fixture would make every "must fail" case pass vacuously.
 */

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

const CHECKER_SOURCE = path.join(import.meta.dirname, 'check-probes.ts');
let CHECKER = CHECKER_SOURCE;
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'seclab-check-probes-'));

type Spec = { required: boolean; policyRef: string; why: string; patchedOutcome?: string; hostEffect?: string };
const EXPECTATIONS = (extra: Record<string, Spec> = {}) => ({
	schema: 1,
	probes: {
		'clipboard-read': { required: true, policyRef: 'rpc:MainThreadClipboard.$readText', why: 'synthetic' },
		'state-claim-tab-manager-read': { required: true, policyRef: 'rpc:MainThreadStorage.$initializeExtensionStorage', patchedOutcome: 'succeeded', why: 'synthetic' },
		...extra,
	},
	rehProbes: {
		'channel-download-host-write': { required: true, policyRef: 'chan:download', why: 'synthetic' },
	},
});
const GOOD_RPC = {
	inTab: true,
	results: [
		{ id: 'clipboard-read', policyRef: 'rpc:MainThreadClipboard.$readText', outcome: 'denied', error: 'unsupported-operation' },
		{ id: 'state-claim-tab-manager-read', policyRef: 'rpc:MainThreadStorage.$initializeExtensionStorage', outcome: 'succeeded', facts: { present: false, canaryTokens: [] } },
	],
};
/** The probes block of EXPECTATIONS(), for cases that bring their own rehProbes. */
const GOOD_EXPECT_PROBES = EXPECTATIONS().probes;
/** GOOD_RPC as an unpatched run records it: every probe succeeded and showed its escape. */
const UNPATCHED_RPC = {
	inTab: true,
	results: [
		{ id: 'clipboard-read', policyRef: 'rpc:MainThreadClipboard.$readText', outcome: 'succeeded', facts: { sawCanary: true, canaryTokens: [] } },
		{ id: 'state-claim-tab-manager-read', policyRef: 'rpc:MainThreadStorage.$initializeExtensionStorage', outcome: 'succeeded', facts: { present: true, canaryTokens: ['seclabcanary_tab_manager_state_1'] } },
	],
};
const GOOD_REH = { results: [{ id: 'channel-download-host-write', policyRef: 'chan:download', outcome: 'denied', error: 'unsupported-operation' }] };
const GOOD_DENIALS = ['rpc:MainThreadClipboard.$readText', 'chan:download'];

let n = 0;
/** One run of the real checker over a fresh fixture. */
function run(opts: {
	rpc?: unknown; reh?: unknown | null; denials?: string[] | null; beacon?: boolean;
	expectations?: unknown; args?: string[]; mode?: 'patched' | 'unpatched';
}): { status: number | null; out: string } {
	const dir = path.join(root, `case-${++n}`);
	const ev = path.join(dir, 'evidence');
	fs.mkdirSync(ev, { recursive: true });
	fs.writeFileSync(path.join(ev, 'rpc-probes.json'), JSON.stringify(opts.rpc ?? GOOD_RPC));
	if (opts.reh !== null) {
		fs.writeFileSync(path.join(ev, 'reh-probes.json'), JSON.stringify(opts.reh ?? GOOD_REH));
	}
	const exp = path.join(dir, 'expectations.json');
	fs.writeFileSync(exp, JSON.stringify(opts.expectations ?? EXPECTATIONS()));
	const args = [opts.mode ?? 'patched', ev, '--expectations', exp];
	if (opts.denials !== null) {
		const f = path.join(dir, 'denials.jsonl');
		fs.writeFileSync(f, (opts.denials ?? GOOD_DENIALS).map(policyRef => JSON.stringify({ policyRef })).join('\n') + '\n');
		args.push('--denials', f);
	}
	if (opts.beacon !== false && opts.mode !== 'unpatched') {
		const f = path.join(dir, 'beacon.log');
		fs.writeFileSync(f, '');
		args.push('--beacon', f);
	}
	args.push(...(opts.args ?? []));
	const r = spawnSync(process.execPath, [CHECKER, ...args], {
		encoding: 'utf8', env: { ...process.env, SECLAB_PROBE_RUNDIR: dir, SECLAB_PROBE_SELFTEST: '1' },
	});
	return { status: r.status, out: `${r.stdout}\n${r.stderr}` };
}
const failed = (out: string, name: RegExp): boolean => out.split('\n').some(l => /\bFAIL\b/.test(l) && name.test(l));

const tests: Array<[string, () => void]> = [
	['control: a clean patched fixture passes', () => {
		const r = run({});
		assert.equal(r.status, 0, r.out);
	}],
	['a missing REH evidence file fails unless --no-reh says so', () => {
		const r = run({ reh: null });
		assert.notEqual(r.status, 0);
		assert.ok(failed(r.out, /rogue REH evidence present/), r.out);
		const waived = run({ reh: null, args: ['--no-reh'] });
		assert.equal(waived.status, 0, waived.out);
		assert.match(waived.out, /WAIVED by --no-reh/);
	}],
	['a predicate miss fails (a canary in the claimed state is an escape)', () => {
		const rpc = structuredClone(GOOD_RPC);
		rpc.results[1].facts = { present: true, canaryTokens: ['seclabcanary_tab_manager_state_1'] };
		const r = run({ rpc });
		assert.notEqual(r.status, 0);
		assert.ok(failed(r.out, /state-claim-tab-manager-read patched predicate holds/), r.out);
	}],
	['patched mode without --beacon fails', () => {
		const r = run({ beacon: false });
		assert.notEqual(r.status, 0);
		assert.ok(failed(r.out, /beacon log supplied/), r.out);
	}],
	['patched mode without --denials fails, and then no denial is corroborated', () => {
		const r = run({ denials: null });
		assert.notEqual(r.status, 0);
		assert.ok(failed(r.out, /denial log supplied/), r.out);
		assert.ok(failed(r.out, /clipboard-read denial recorded by the filter/), r.out);
	}],
	['an uncorroborated denial fails: the tab saying "denied" is not evidence', () => {
		const r = run({ denials: ['chan:download'] });
		assert.notEqual(r.status, 0);
		assert.ok(failed(r.out, /clipboard-read denial recorded by the filter/), r.out);
	}],
	['a probe that succeeded where it must be denied fails', () => {
		const rpc = structuredClone(GOOD_RPC);
		rpc.results[0] = { id: 'clipboard-read', policyRef: 'rpc:MainThreadClipboard.$readText', outcome: 'succeeded', facts: { sawCanary: true, canaryTokens: [] } } as never;
		const r = run({ rpc });
		assert.notEqual(r.status, 0);
		assert.ok(failed(r.out, /clipboard-read did not succeed on the patched build/), r.out);
	}],
	['a required probe with no result fails', () => {
		const rpc = structuredClone(GOOD_RPC);
		rpc.results = [rpc.results[1]];
		const r = run({ rpc });
		assert.notEqual(r.status, 0);
		assert.ok(failed(r.out, /clipboard-read ran/), r.out);
	}],
	['a hostEffect that is not a filename throws rather than certifying "no host effect"', () => {
		const rpc = structuredClone(GOOD_RPC);
		rpc.results.push({ id: 'host-terminal-newlocal', policyRef: 'cmd:workbench.action.terminal.newLocal', outcome: 'denied', error: 'unsupported-operation' } as never);
		const r = run({
			rpc, denials: [...GOOD_DENIALS, 'cmd:workbench.action.terminal.newLocal'],
			expectations: EXPECTATIONS({ 'host-terminal-newlocal': { required: true, policyRef: 'cmd:workbench.action.terminal.newLocal', why: 'synthetic', hostEffect: 'a marker written outside the tab' } }),
		});
		assert.notEqual(r.status, 0);
		assert.match(r.out, /is not a filename/);
		// Control: the same probe with a filename effect resolves and passes (no file on disk).
		const ok = run({
			rpc, denials: [...GOOD_DENIALS, 'cmd:workbench.action.terminal.newLocal'],
			expectations: EXPECTATIONS({ 'host-terminal-newlocal': { required: true, policyRef: 'cmd:workbench.action.terminal.newLocal', why: 'synthetic', hostEffect: 'PWNED-newlocal' } }),
		});
		assert.equal(ok.status, 0, ok.out);
	}],
	['--only judges the selection, names it, and refuses an unregistered id', () => {
		const ok = run({ args: ['--only', 'channel-download-host-write'], rpc: { results: [] } });
		assert.equal(ok.status, 0, ok.out);
		assert.match(ok.out, /judging only 1 registered probe/);
		const bad = run({ args: ['--only', 'channel-download-host-write,no-such-probe'] });
		assert.ok(failed(bad.out, /judging only 2 registered probe/), bad.out);
	}],
	// The REH push probes (patches 0030/0031): a baseline must show the trusted side ran the
	// command or resolved the host canary, never just that something replied.
	['an unpatched push probe that did not run on the trusted side fails', () => {
		const exp = { schema: 1, probes: GOOD_EXPECT_PROBES, rehProbes: { 'reh-onexecutecommand-manageextensions': { required: true, policyRef: 'push:remoteterminal:$onExecuteCommand', why: 'synthetic' } } };
		const reh = (facts: unknown) => ({ results: [{ id: 'reh-onexecutecommand-manageextensions', policyRef: 'push:remoteterminal:$onExecuteCommand', outcome: 'succeeded', facts }] });
		const ok = run({ mode: 'unpatched', expectations: exp, rpc: UNPATCHED_RPC, reh: reh({ replied: true, ran: true, hostIsMac: false }) });
		assert.ok(!failed(ok.out, /reh-onexecutecommand-manageextensions/), ok.out);
		const r = run({ mode: 'unpatched', expectations: exp, rpc: UNPATCHED_RPC, reh: reh({ replied: true }) });
		assert.ok(failed(r.out, /reh-onexecutecommand-manageextensions shows the escape itself/), r.out);
	}],
	['an unpatched resolve-variables probe without the host canary fails', () => {
		const exp = { schema: 1, probes: GOOD_EXPECT_PROBES, rehProbes: { 'reh-resolve-variables-host-env': { required: true, policyRef: 'push:remoteterminal:$onPtyHostRequestResolveVariablesEvent', why: 'synthetic' } } };
		const reh = (tokens: string[]) => ({ results: [{ id: 'reh-resolve-variables-host-env', policyRef: 'push:remoteterminal:$onPtyHostRequestResolveVariablesEvent', outcome: 'succeeded', facts: { replied: true, canaryTokens: tokens } }] });
		const ok = run({ mode: 'unpatched', expectations: exp, rpc: UNPATCHED_RPC, reh: reh(['seclabcanary_editor_env_1']) });
		assert.ok(!failed(ok.out, /reh-resolve-variables-host-env/), ok.out);
		const r = run({ mode: 'unpatched', expectations: exp, rpc: UNPATCHED_RPC, reh: reh([]) });
		assert.ok(failed(r.out, /reh-resolve-variables-host-env shows the escape itself/), r.out);
	}],
	['the profile probe needs the canary in path and env on a baseline, and both unresolved after patch 0034', () => {
		const spec = { required: true, policyRef: 'data:remoteterminal-profile-path', patchedOutcome: 'succeeded', why: 'synthetic' };
		const exp = { schema: 1, probes: GOOD_EXPECT_PROBES, rehProbes: { 'reh-profile-config-host-setting': spec } };
		const base = { sawProfilePath: true, sawProfileEnv: true, pathCanary: false, envCanary: false, resolvedVariablesCanary: false, unresolved: true, canaryTokens: [] as string[] };
		const reh = (over: Record<string, unknown>) => ({ results: [{ id: 'reh-profile-config-host-setting', policyRef: 'data:remoteterminal-profile-path', outcome: 'succeeded', facts: { ...base, ...over } }] });
		const leaked = { pathCanary: true, envCanary: true, unresolved: false, canaryTokens: ['seclabcanary_user_settings_1'] };
		assert.ok(!failed(run({ mode: 'unpatched', expectations: exp, rpc: UNPATCHED_RPC, reh: reh(leaked) }).out, /reh-profile-config-host-setting/));
		assert.ok(failed(run({ mode: 'unpatched', expectations: exp, rpc: UNPATCHED_RPC, reh: reh({}) }).out, /reh-profile-config-host-setting shows the escape itself/));
		// The path leaking alone is not the env leak RFU1R-1 adds.
		assert.ok(failed(run({ mode: 'unpatched', expectations: exp, rpc: UNPATCHED_RPC, reh: reh({ ...leaked, envCanary: false }) }).out, /reh-profile-config-host-setting shows the escape itself/));
		assert.equal(run({ expectations: exp, reh: reh({}) }).status, 0);
		assert.ok(failed(run({ expectations: exp, reh: reh(leaked) }).out, /reh-profile-config-host-setting patched predicate holds/));
		// A patched run that never saw the env, or saw it resolved to some other value, proves nothing.
		assert.ok(failed(run({ expectations: exp, reh: reh({ sawProfileEnv: false }) }).out, /reh-profile-config-host-setting patched predicate holds/));
		assert.ok(failed(run({ expectations: exp, reh: reh({ unresolved: false }) }).out, /reh-profile-config-host-setting patched predicate holds/));
	}],
	['a probe run only by its own harness is not judged without that selection, and is required with it', () => {
		const spec = { required: true, runner: 'reh-push', policyRef: 'data:remoteterminal-profile-path', patchedOutcome: 'succeeded', why: 'synthetic' };
		const exp = { schema: 1, probes: GOOD_EXPECT_PROBES, rehProbes: { 'reh-profile-config-host-setting': spec } };
		// A full REH run whose payload never armed it: reported as not judged, not as a failure or a pass.
		const full = run({ expectations: exp, reh: { results: [] } });
		assert.equal(full.status, 0, full.out);
		assert.match(full.out, /not judged here: 1 probe\(s\) run only by their own harness/);
		assert.doesNotMatch(full.out, /PASS .*reh-profile-config-host-setting ran/);
		// Its own harness selects it, and then a missing result fails.
		const selected = run({ expectations: exp, reh: { results: [] }, args: ['--only', 'reh-profile-config-host-setting'] });
		assert.ok(failed(selected.out, /reh-profile-config-host-setting ran/), selected.out);
	}],
	['a patched push probe needs the refusal in the decision log', () => {
		const exp = { schema: 1, probes: GOOD_EXPECT_PROBES, rehProbes: { 'reh-onexecutecommand-windowopen': { required: true, policyRef: 'push:remoteterminal:$onExecuteCommand', why: 'synthetic' } } };
		const reh = { results: [{ id: 'reh-onexecutecommand-windowopen', policyRef: 'push:remoteterminal:$onExecuteCommand', outcome: 'denied', error: 'unsupported-operation' }] };
		const ok = run({ expectations: exp, reh, denials: [...GOOD_DENIALS, 'push:remoteterminal:$onExecuteCommand'] });
		assert.equal(ok.status, 0, ok.out);
		const r = run({ expectations: exp, reh });
		assert.ok(failed(r.out, /reh-onexecutecommand-windowopen denial recorded by the filter/), r.out);
	}],
];

let failures = 0;
for (const [name, fn] of tests) {
	try {
		fn();
		console.log(`ok   ${name}`);
	} catch (err) {
		failures++;
		console.error(`FAIL ${name}\n     ${(err as Error).message.split('\n').slice(0, 6).join('\n     ')}`);
	}
}

// Each fix reverted, one at a time, must be caught by at least one case above. A suite that
// stays green against a reverted fix pins nothing.
const MUTANTS: Array<[string, string, string]> = [
	['the REH evidence is not loaded', "load('reh-probes.json', 'rogue REH', true);", ''],
	['patched mode does not require --beacon', "c('oracles', !!beaconFile,", "c('oracles', true,"],
	['patched mode does not require --denials', "c('oracles', !!denialFile,", "c('oracles', true,"],
	['a denial need not be corroborated', 'c(\'denial-log\', deniedRefs.has(spec.policyRef) || !spec.required,', "c('denial-log', true,"],
	['the claimed-state predicate is gutted', "tokens(r).length > 0 ? 'the Tab Manager", "false ? 'the Tab Manager"],
	['a prose hostEffect is joined onto the run dir', 'if (!HOST_EFFECT_FILENAME.test(effect)) {', 'if (false) {'],
	['the push probes\' baseline predicate is gutted', "'reh-onexecutecommand-manageextensions': r => fact(r, 'ran') === true ? null", "'reh-onexecutecommand-manageextensions': r => true ? null"],
	['the resolve-variables baseline predicate is gutted', "tokens(r).length > 0 ? null : 'the host environment canary", "true ? null : 'the host environment canary"],
];
const source = fs.readFileSync(CHECKER_SOURCE, 'utf8');
// Mutants live in a scratch mirror of the checker's import closure (same relative layout), so
// the suite runs on a read-only checkout.
const repoRoot = path.resolve(import.meta.dirname, '../..');
const mirror = fs.mkdtempSync(path.join(process.env.SECLAB_SCRATCH ?? os.tmpdir(), 'seclab-check-probes-mutants-'));
for (const rel of ['test/containment/beacon.ts', 'test/containment/state-db.ts', 'test/containment/assert.ts', 'test/harness.ts', 'rpc-filter/policy/coverage.json']) {
	fs.mkdirSync(path.dirname(path.join(mirror, rel)), { recursive: true });
	fs.copyFileSync(path.join(repoRoot, rel), path.join(mirror, rel));
}
for (const [what, from, to] of MUTANTS) {
	if (!source.includes(from)) {
		failures++;
		console.error(`FAIL mutant "${what}": its target is gone from check-probes.ts; update the mutant`);
		continue;
	}
	const mutant = path.join(mirror, 'test', 'containment', 'check-probes.ts');
	fs.writeFileSync(mutant, source.replace(from, to));
	CHECKER = mutant;
	let caught = 0;
	try {
		for (const [, fn] of tests.slice(1)) {
			try { fn(); } catch { caught++; }
		}
	} finally {
		CHECKER = CHECKER_SOURCE;
	}
	if (caught === 0) {
		failures++;
		console.error(`FAIL mutant survived: ${what}`);
	} else {
		console.log(`ok   mutant caught: ${what} (${caught} case(s))`);
	}
}
fs.rmSync(mirror, { recursive: true, force: true });
fs.rmSync(root, { recursive: true, force: true });
console.log(`\n${failures ? `${failures} FAILED` : `${tests.length} cases and ${MUTANTS.length} mutants OK`}`);
process.exit(failures ? 1 : 0);
