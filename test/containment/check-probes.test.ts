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
import { createRequire } from 'node:module';
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
	rpc?: unknown; reh?: unknown | null; harness?: unknown; denials?: string[] | null; beacon?: boolean;
	expectations?: unknown; args?: string[]; mode?: 'patched' | 'unpatched';
}): { status: number | null; out: string } {
	const dir = path.join(root, `case-${++n}`);
	const ev = path.join(dir, 'evidence');
	fs.mkdirSync(ev, { recursive: true });
	fs.writeFileSync(path.join(ev, 'rpc-probes.json'), JSON.stringify(opts.rpc ?? GOOD_RPC));
	if (opts.reh !== null) {
		fs.writeFileSync(path.join(ev, 'reh-probes.json'), JSON.stringify(opts.reh ?? GOOD_REH));
	}
	if (opts.harness !== undefined) {
		fs.writeFileSync(path.join(ev, 'harness-probes.json'), JSON.stringify(opts.harness));
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
	['the environment probe needs the lie served and the canary on a baseline, and a logged refusal after patch 0059', () => {
		const exp = { schema: 1, probes: GOOD_EXPECT_PROBES, rehProbes: { 'reh-environment-host-settings': { required: true, policyRef: 'data:server-locations', patchedOutcome: 'succeeded', why: 'synthetic' } } };
		const reh = (facts: Record<string, unknown>) => ({ results: [{ id: 'reh-environment-host-settings', policyRef: 'data:server-locations', outcome: 'succeeded', facts: { served: 1, createProcess: 1, canaryTokens: [], ...facts } }] });
		const leaked = { canaryTokens: ['seclabcanary_HOSTREMOTE_1'] };
		assert.ok(!failed(run({ mode: 'unpatched', expectations: exp, rpc: UNPATCHED_RPC, reh: reh(leaked) }).out, /reh-environment-host-settings/));
		assert.ok(failed(run({ mode: 'unpatched', expectations: exp, rpc: UNPATCHED_RPC, reh: reh({}) }).out, /reh-environment-host-settings shows the escape itself/));
		assert.ok(failed(run({ mode: 'unpatched', expectations: exp, rpc: UNPATCHED_RPC, reh: reh({ ...leaked, served: 0 }) }).out, /reh-environment-host-settings shows the escape itself/));
		const denied = { denials: [...GOOD_DENIALS, 'data:server-locations'] };
		assert.equal(run({ expectations: exp, reh: reh({}), ...denied }).status, 0);
		assert.ok(failed(run({ expectations: exp, reh: reh(leaked), ...denied }).out, /reh-environment-host-settings patched predicate holds/));
		// A lie never served, or a refusal never logged, proves nothing.
		assert.ok(failed(run({ expectations: exp, reh: reh({ served: 0 }), ...denied }).out, /reh-environment-host-settings patched predicate holds/));
		// A malformed count isn't a count (PR review on #66).
		for (const bad of [{}, 'not-a-number', '1', 1.5, -1, Number.MAX_SAFE_INTEGER + 2]) {
			assert.ok(failed(run({ expectations: exp, reh: reh({ served: bad }), ...denied }).out, /reh-environment-host-settings patched predicate holds/), `served ${JSON.stringify(bad)}`);
			assert.ok(failed(run({ mode: 'unpatched', expectations: exp, rpc: UNPATCHED_RPC, reh: reh({ ...leaked, served: bad }) }).out, /reh-environment-host-settings shows the escape itself/), `baseline served ${JSON.stringify(bad)}`);
		}
		assert.ok(failed(run({ expectations: exp, reh: reh({}) }).out, /reh-environment-host-settings patched predicate holds/));
	}],
	['the terminal settings and extension-host scan probes need their canaries on a baseline and a control after the patches', () => {
		const exp = { schema: 1, probes: GOOD_EXPECT_PROBES, rehProbes: {
			'reh-terminal-host-settings': { required: true, policyRef: 'data:remoteterminal-host-settings', patchedOutcome: 'succeeded', why: 'synthetic' },
			'reh-exthost-terminal-profile': { required: true, policyRef: 'data:exthost-terminal-default-profile', patchedOutcome: 'succeeded', why: 'synthetic' },
		} };
		const reh = (settings: Record<string, unknown>, scan: Record<string, unknown>) => ({ results: [
			{ id: 'reh-terminal-host-settings', policyRef: 'data:remoteterminal-host-settings', outcome: 'succeeded', facts: { sawGetProfiles: true, sawCreateProcess: true, canaryTokens: [], ...settings } },
			{ id: 'reh-exthost-terminal-profile', policyRef: 'data:exthost-terminal-default-profile', outcome: 'succeeded', facts: { extensionHosts: 1, scannedMb: 300, unreadKb: 0, unreadRegions: 0, sawControl: true, canaryTokens: [], ...scan } },
		] });
		const hostSettings = { canaryTokens: ['seclabcanary_TERMINALENV_1', 'seclabcanary_TERMINALPROFILES_1'] };
		const hostAutomation = { canaryTokens: ['seclabcanary_TERMINALAUTOMATI_1'] };
		assert.ok(!failed(run({ mode: 'unpatched', expectations: exp, rpc: UNPATCHED_RPC, reh: reh(hostSettings, hostAutomation) }).out, /reh-(terminal-host-settings|exthost-terminal-profile)/));
		assert.ok(failed(run({ mode: 'unpatched', expectations: exp, rpc: UNPATCHED_RPC, reh: reh({}, hostAutomation) }).out, /reh-terminal-host-settings shows the escape itself/));
		assert.ok(failed(run({ mode: 'unpatched', expectations: exp, rpc: UNPATCHED_RPC, reh: reh(hostSettings, {}) }).out, /reh-exthost-terminal-profile shows the escape itself/));
		assert.equal(run({ expectations: exp, reh: reh({}, {}) }).status, 0);
		assert.ok(failed(run({ expectations: exp, reh: reh(hostSettings, {}) }).out, /reh-terminal-host-settings patched predicate holds/));
		assert.ok(failed(run({ expectations: exp, reh: reh({ sawGetProfiles: false }, {}) }).out, /reh-terminal-host-settings patched predicate holds/));
		assert.ok(failed(run({ expectations: exp, reh: reh({}, hostAutomation) }).out, /reh-exthost-terminal-profile patched predicate holds/));
		// A scan that never found the default profile's control canary proves nothing on either build (R5-4).
		assert.ok(failed(run({ expectations: exp, reh: reh({}, { sawControl: false }) }).out, /reh-exthost-terminal-profile patched predicate holds/));
		assert.ok(failed(run({ mode: 'unpatched', expectations: exp, rpc: UNPATCHED_RPC, reh: reh(hostSettings, { ...hostAutomation, sawControl: false }) }).out, /reh-exthost-terminal-profile shows the escape itself/));
		// A scan that couldn't read part of the extension host's memory proves no containment (PR #70 review).
		for (const unread of [1, undefined, '0', null]) {
			assert.ok(failed(run({ expectations: exp, reh: reh({}, { unreadRegions: unread }) }).out, /reh-exthost-terminal-profile patched predicate holds/), `unreadRegions ${JSON.stringify(unread)}`);
		}
	}],
	['the extension-host scan keeps a canary whatever byte follows it in memory', () => {
		// PR #70 review: the scan once took the greedy canary run and then dropped it for being too long.
		// As staged in the tab, probes.js finds probe-safety.js beside it.
		const req = createRequire(import.meta.url);
		const mod = { exports: {} as { exthostTokens: (t: string) => string[] } };
		new Function('require', 'module', 'exports', fs.readFileSync(path.join(import.meta.dirname, 'rogue-reh', 'probes.js'), 'utf8'))(
			(id: string) => req(id === './probe-safety.js' ? './probe-safety.js' : id), mod, mod.exports);
		const { exthostTokens } = mod.exports;
		const token = `seclabcanary_TERMINALAUTOMATI_${'0123456789abcdef'.repeat(2)}`;
		for (const after of ['', '"', 'X', '_', '7', 'a']) {
			for (const enc of ['latin1', 'utf16le'] as const) {
				const memory = Buffer.from(`\u0000junk${token}${after}more`, enc).toString(enc);
				assert.deepEqual(exthostTokens(memory), [token], `followed by ${JSON.stringify(after)} (${enc})`);
			}
		}
		// A fragment cut short is never a token.
		assert.deepEqual(exthostTokens(token.slice(0, -1)), []);
	}],
	['a probe run only by its own harness is not judged without that selection, and is required with it', () => {
		const spec = { required: true, runner: 'reh-push', policyRef: 'data:remoteterminal-profile-path', patchedOutcome: 'succeeded', why: 'synthetic' };
		const exp = { schema: 1, probes: GOOD_EXPECT_PROBES, rehProbes: { 'reh-profile-config-host-setting': spec } };
		// A full REH run whose payload never armed it: reported as not judged, not as a failure or a pass.
		const full = run({ expectations: exp, reh: { results: [] } });
		assert.equal(full.status, 0, full.out);
		assert.match(full.out, /not judged here: 1 probe\(s\) run only by their own harness/);
		assert.doesNotMatch(full.out, /PASS .*reh-profile-config-host-setting ran/);
		// The payload records it on a full run too (inconclusive there): still not judged, and not
		// "absent from expectations.json".
		const recorded = run({ expectations: exp, reh: { results: [{ id: 'reh-profile-config-host-setting', policyRef: 'data:remoteterminal-profile-path', outcome: 'error', error: 'not-armed' }] } });
		assert.equal(recorded.status, 0, recorded.out);
		assert.match(recorded.out, /not judged here: 1 probe\(s\)/);
		assert.doesNotMatch(recorded.out, /absent from expectations/);
		// Its own harness selects it, and then a missing result fails.
		const selected = run({ expectations: exp, reh: { results: [] }, args: ['--only', 'reh-profile-config-host-setting'] });
		assert.ok(failed(selected.out, /reh-profile-config-host-setting ran/), selected.out);
	}],
	['the agent-host dial is judged from its harness\'s record, with the empty-window control', () => {
		const id = 'ai-remote-agent-host-dial';
		const spec = { required: true, runner: 'reh-push', surface: 'client-push', policyRef: 'ai-setting:chat.workspaceRemoteAgentHosts', patchedOutcome: 'succeeded', why: 'synthetic', noUnpatchedBaseline: 'synthetic: the control stands in' };
		const exp = { schema: 1, probes: { ...GOOD_EXPECT_PROBES, [id]: spec }, rehProbes: { 'reh-onexecutecommand-windowopen': { required: false, policyRef: 'push:remoteterminal:$onExecuteCommand', why: 'synthetic' } } };
		const result = (facts: Record<string, unknown>) => ({ id, policyRef: spec.policyRef, outcome: 'succeeded', facts: { hostDialled: false, tabDialledClaimed: false, tabListenerLiveClaimed: true, controlDialled: true, gateRefusals: 2, ...facts } });
		const judge = (h: unknown, opts: { mode?: 'patched' | 'unpatched'; reh?: unknown } = {}) => run({ mode: opts.mode ?? 'patched', expectations: exp, rpc: { results: [] }, reh: opts.reh ?? { results: [] }, harness: h, args: ['--only', id] });
		const good = judge({ results: [result({})] });
		assert.equal(good.status, 0, good.out.split('\n').filter(l => /\bFAIL\b|exit|Error/.test(l)).join(' | ') || good.out.slice(-600));
		for (const bad of [{ controlDialled: false }, { hostDialled: true }, { gateRefusals: 0 }, { gateRefusals: '2' }, { hostDialled: undefined }]) {
			assert.ok(failed(judge({ results: [result(bad)] }).out, /ai-remote-agent-host-dial patched predicate holds/), JSON.stringify(bad));
		}
		// Claims from inside the tab are reported, never judged (AID-3, AID-5).
		assert.equal(judge({ results: [result({ tabDialledClaimed: true, tabListenerLiveClaimed: false })] }).status, 0);
		// Every payload's fault channel is kept wherever it is written (AID-6).
		const unarmed = { id: 'harness', policyRef: 'harness', outcome: 'error', error: 'not-armed' };
		const fault = run({ expectations: { ...exp, rehProbes: { ...exp.rehProbes, harness: { required: false, policyRef: 'harness', why: 'synthetic', status: 'not-implemented' } } }, rpc: { results: [unarmed] }, reh: { results: [unarmed] }, harness: { results: [result({})] }, args: ['--only', id] });
		assert.doesNotMatch(fault.out, /names harness|harness is recorded twice/, fault.out);
		// Its record is required when it is selected, and the rogue extension's is not.
		assert.ok(failed(judge(undefined).out, /harness-measured evidence present/));
		assert.ok(failed(judge({ results: [result({}), result({})] }).out, /ai-remote-agent-host-dial is recorded twice/));
		// The REH record keeps its own probes.
		assert.ok(failed(judge({ results: [result({}), { id: 'reh-onexecutecommand-windowopen', policyRef: 'push:remoteterminal:$onExecuteCommand', outcome: 'denied' }] }).out, /names reh-onexecutecommand-windowopen, which only reh-probes.json may record/));
		// No build here lacks patch 0015: an unpatched run names the waiver instead of a verdict (AID-2).
		const baseline = judge({ results: [result({})] }, { mode: 'unpatched' });
		assert.match(baseline.out, /ai-remote-agent-host-dial has no unpatched baseline/);
		assert.doesNotMatch(baseline.out, /ai-remote-agent-host-dial succeeds on the unpatched build/);
	}],
	['the AI chat probes are judged from the harness record, with the ordinary-window control', () => {
		const ids = ['ai-instructions-tool-call', 'ai-settings-reenable', 'ai-tab-invoke-tool'];
		const base = { required: true, runner: 'ai-probe', surface: 'trusted-ai', patchedOutcome: 'succeeded', why: 'synthetic' };
		const specs = {
			'ai-instructions-tool-call': { ...base, policyRef: 'ai-tool:vscode_fetchWebPage_internal' },
			'ai-settings-reenable': { ...base, policyRef: 'ai-setting:chat.agent.enabled' },
			'ai-tab-invoke-tool': { ...base, policyRef: 'ai-tool:vscode_fetchWebPage_internal', noUnpatchedBaseline: 'synthetic: the filter is in every build' },
		};
		const exp = { schema: 1, probes: { ...GOOD_EXPECT_PROBES, ...specs }, rehProbes: {} };
		const chat = { controlFetched: true, tabTriggered: 1, tabFetchedHost: false, tabFetchedTabClaimed: false, sendRequestRefusals: 1 };
		const goodFacts: Record<string, Record<string, unknown>> = {
			'ai-instructions-tool-call': chat,
			'ai-settings-reenable': { ...chat, reenableSettingsSeen: 3 },
			'ai-tab-invoke-tool': { controlFetched: true, toolFetchedHost: false, toolFetchedTabClaimed: false, invokeToolDenials: 1 },
		};
		const results = (over: Record<string, Record<string, unknown>> = {}) => ({ results: ids.map(id => ({ id, policyRef: specs[id as keyof typeof specs].policyRef, outcome: 'succeeded', facts: { ...goodFacts[id], ...(over[id] ?? {}) } })) });
		const judge = (h: unknown, mode: 'patched' | 'unpatched' = 'patched') => run({ mode, expectations: exp, rpc: { results: [] }, harness: h, args: ['--only', ids.join(','), '--no-reh'] });
		const good = judge(results());
		assert.equal(good.status, 0, good.out.split('\n').filter(l => /\bFAIL\b|exit|Error/.test(l)).join(' | ') || good.out.slice(-600));
		const bad: Array<[string, Record<string, unknown>]> = [
			['ai-instructions-tool-call', { controlFetched: false }], ['ai-instructions-tool-call', { tabFetchedHost: true }],
			['ai-instructions-tool-call', { sendRequestRefusals: 0 }], ['ai-instructions-tool-call', { tabTriggered: 0 }],
			['ai-instructions-tool-call', { tabFetchedHost: undefined }],
			['ai-settings-reenable', { reenableSettingsSeen: 0 }], ['ai-settings-reenable', { tabFetchedHost: true }], ['ai-settings-reenable', { controlFetched: false }],
			['ai-tab-invoke-tool', { controlFetched: false }], ['ai-tab-invoke-tool', { toolFetchedHost: true }], ['ai-tab-invoke-tool', { invokeToolDenials: 0 }],
		];
		for (const [id, over] of bad) {
			assert.ok(failed(judge(results({ [id]: over })).out, new RegExp(`${id} patched predicate holds`)), `${id} ${JSON.stringify(over)}`);
		}
		// A claim from inside the tab is reported, never judged.
		assert.equal(judge(results({ 'ai-instructions-tool-call': { tabFetchedTabClaimed: true } })).status, 0);
		// Baseline: the escape itself is required; the tab-side call has no baseline and names its waiver.
		const escaped = { tabFetchedHost: true, sendRequestRefusals: 0 };
		const baseline = judge(results({ 'ai-instructions-tool-call': escaped, 'ai-settings-reenable': escaped }), 'unpatched');
		assert.equal(baseline.status, 0, baseline.out.split('\n').filter(l => /\bFAIL\b/.test(l)).join(' | '));
		assert.match(baseline.out, /ai-tab-invoke-tool has no unpatched baseline/);
		const contained = judge(results(), 'unpatched');
		assert.ok(failed(contained.out, /ai-instructions-tool-call shows the escape itself on the unpatched build/), contained.out);
		assert.ok(failed(contained.out, /ai-settings-reenable shows the escape itself on the unpatched build/), contained.out);
	}],
	['the agent-host probes are judged host-side: the agents-on control, no transport opened and the gate refusal', () => {
		const ids = ['ai-agent-host-token-push', 'ai-agent-host-autoapprove-setting', 'ai-disable-ai-features-reenable'];
		const base = { required: true, runner: 'ai-agent-host-probe', surface: 'client-push', patchedOutcome: 'succeeded', why: 'synthetic' };
		const specs: Record<string, Record<string, unknown>> = {
			'ai-agent-host-token-push': { ...base, policyRef: 'push:agentHostProxy:frame' },
			'ai-agent-host-autoapprove-setting': { ...base, policyRef: 'push:agentHostProxy:frame' },
			'ai-disable-ai-features-reenable': { ...base, policyRef: 'ai-setting:chat.disableAIFeatures' },
		};
		const exp = { schema: 1, probes: { ...GOOD_EXPECT_PROBES, ...specs }, rehProbes: {} };
		const facts = { armConnectsClaimed: 0, armCallsClaimed: 0, armListensClaimed: 0, armGateOpened: 0, armGateDisabled: 2, controlConnectsClaimed: 1, controlGateOpened: 1, remoteAiFeaturesOn: true };
		const results = (over: Record<string, unknown> = {}) => ({ results: ids.map(id => ({ id, policyRef: specs[id].policyRef, outcome: 'succeeded', facts: { ...facts, ...over } })) });
		const judge = (h: unknown, mode: 'patched' | 'unpatched' = 'patched') => run({ mode, expectations: exp, rpc: { results: [] }, harness: h, args: ['--only', ids.join(','), '--no-reh'] });
		const good = judge(results());
		assert.equal(good.status, 0, good.out.split('\n').filter(l => /\bFAIL\b|exit|Error/.test(l)).join(' | ') || good.out.slice(-600));
		for (const over of [{ controlGateOpened: 0 }, { armGateOpened: 1 }, { armGateDisabled: 0 }, { armGateOpened: '0' }, { armGateOpened: undefined }, { controlGateOpened: -1 }]) {
			const out = judge(results(over)).out;
			for (const id of ids) {
				assert.ok(failed(out, new RegExp(`${id} patched predicate holds`)), `${id} ${JSON.stringify(over)}`);
			}
		}
		assert.ok(failed(judge(results({ remoteAiFeaturesOn: false })).out, /ai-disable-ai-features-reenable patched predicate holds/));
		// The hostile REH's counts are the tab's claim: never judged, either way (AIP-5).
		assert.equal(judge(results({ armConnectsClaimed: 3, controlConnectsClaimed: 0 })).status, 0);
		// Baseline: the window opens a transport, recorded host-side.
		const escaped = judge(results({ armGateOpened: 1 }), 'unpatched');
		assert.equal(escaped.status, 0, escaped.out.split('\n').filter(l => /\bFAIL\b/.test(l)).join(' | '));
		const forged = judge(results({ armConnectsClaimed: 5 }), 'unpatched');
		for (const id of ids) {
			assert.ok(failed(forged.out, new RegExp(`${id} shows the escape itself on the unpatched build`)), forged.out);
		}
	}],
	["the tab's REH record can't stand in for the host's dial measurement", () => {
		// AID-1: the host's record shows an escape; the tab's REH writes a clean one under the same id.
		const id = 'ai-remote-agent-host-dial';
		const spec = { required: true, runner: 'reh-push', surface: 'client-push', policyRef: 'ai-setting:chat.workspaceRemoteAgentHosts', patchedOutcome: 'succeeded', why: 'synthetic' };
		const exp = { schema: 1, probes: { ...GOOD_EXPECT_PROBES, [id]: spec }, rehProbes: {} };
		const clean = { tabDialled: false, tabDialledClaimed: false, tabListenerLive: true, tabListenerLiveClaimed: true, controlDialled: true };
		const result = (facts: Record<string, unknown>) => ({ id, policyRef: spec.policyRef, outcome: 'succeeded', facts: { ...clean, ...facts } });
		const forged = run({ expectations: exp, rpc: { results: [] }, harness: { results: [result({ hostDialled: true, gateRefusals: 0 })] }, reh: { results: [result({ hostDialled: false, gateRefusals: 7 })] }, args: ['--only', id] });
		assert.notEqual(forged.status, 0, 'a forged REH record passed the dial');
		assert.ok(failed(forged.out, /rogue REH evidence names ai-remote-agent-host-dial, which only harness-probes.json may record/), forged.out);
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
	['a waived probe\'s recorded result is still judged', '		results.delete(id);\n', ''],
	['the resolve-variables baseline predicate is gutted', "tokens(r).length > 0 ? null : 'the host environment canary", "true ? null : 'the host environment canary"],
	['a record may carry another record\'s probe', 'if (owner && owner !== file) {', 'if (false) {'],
	['an id may be recorded twice', '		if (results.has(r.id)) {', '		if (false) {'],
	['a waived probe needs no reason', "if (mode === 'unpatched' && typeof spec.noUnpatchedBaseline === 'string') {", "if (mode === 'unpatched') {"],
	['the dial control is not required', "fact(r, 'controlDialled') !== true ? 'the control window never dialled", "false ? 'the control window never dialled"],
	['the AI chat control is not required', "return fact(r, 'controlFetched') !== true ? 'the ordinary window", "return false ? 'the ordinary window"],
	['the AI chat refusal need not be logged', "n('sendRequestRefusals') < 1 ? 'no refusal", "false ? 'no refusal"],
	['the re-enable settings need not be in effect', "(fact(r, 'reenableSettingsSeen') as number) < 1\n\t\t\t? 'the tab window never read", "false\n\t\t\t? 'the tab window never read"],
	['the tab-side call needs no filter denial', "(fact(r, 'invokeToolDenials') as number) < 1 ? 'no denial", "false ? 'no denial"],
	['the AI chat baseline predicate is gutted', ": fact(r, 'tabFetchedHost') === true ? null : 'the tab window\\'s agent did not fetch from the host',\n\t'ai-settings-reenable'", ": true ? null : 'the tab window\\'s agent did not fetch from the host',\n\t'ai-settings-reenable'"],
	['the agent-host control is not required', "return safeCount(r, 'controlGateOpened') < 1 ? 'the control", "return false ? 'the control"],
	['an opened transport is not refused', ": safeCount(r, 'armGateOpened') !== 0 ? 'the tab window opened", ": false ? 'the tab window opened"],
	['the gate refusal is not required', ": safeCount(r, 'armGateDisabled') < 1 ? 'no refusal in the gate log'", ": false ? 'no refusal in the gate log'"],
	['a forged count reads as zero', '? v : -1;', '? v : 0;'],
	['the agent-host baseline predicate is gutted', "'ai-agent-host-token-push': r => safeCount(r, 'armGateOpened') > 0 ? null", "'ai-agent-host-token-push': r => true ? null"],
	['the agent-host baseline trusts the tab\'s count', "'ai-agent-host-token-push': r => safeCount(r, 'armGateOpened') > 0 ? null", "'ai-agent-host-token-push': r => safeCount(r, 'armConnectsClaimed') > 0 ? null"],
];
const source = fs.readFileSync(CHECKER_SOURCE, 'utf8');
// Mutants live in a scratch mirror of the checker's import closure (same relative layout), so
// the suite runs on a read-only checkout.
const repoRoot = path.resolve(import.meta.dirname, '../..');
const mirror = fs.mkdtempSync(path.join(process.env.SECLAB_SCRATCH ?? os.tmpdir(), 'seclab-check-probes-mutants-'));
// The closure is followed from the checker's own relative imports, so a new import can't leave
// every mutant crashing (and so "caught") before it reads any evidence (PR review, AID-4).
const closure = new Set<string>(['rpc-filter/policy/coverage.json']);
for (const queue = ['test/containment/check-probes.ts']; queue.length;) {
	const rel = queue.pop()!;
	for (const m of fs.readFileSync(path.join(repoRoot, rel), 'utf8').matchAll(/^import\b[^;]*?from\s+'(\.{1,2}\/[^']+)'/gm)) {
		const dep = path.relative(repoRoot, path.resolve(repoRoot, path.dirname(rel), m[1]));
		if (!closure.has(dep)) {
			closure.add(dep);
			queue.push(dep);
		}
	}
}
for (const rel of closure) {
	fs.mkdirSync(path.dirname(path.join(mirror, rel)), { recursive: true });
	fs.copyFileSync(path.join(repoRoot, rel), path.join(mirror, rel));
}
// Control: the unmutated checker in the mirror passes every case, or no mutant result means anything.
{
	const copy = path.join(mirror, 'test', 'containment', 'check-probes.ts');
	fs.writeFileSync(copy, source);
	CHECKER = copy;
	const broken: string[] = [];
	try {
		for (const [name, fn] of tests.slice(1)) {
			try { fn(); } catch { broken.push(name); }
		}
	} finally {
		CHECKER = CHECKER_SOURCE;
	}
	if (broken.length) {
		failures++;
		console.error(`FAIL control: the unmutated checker fails in the mirror, so no mutant result means anything: ${broken.join('; ')}`);
	} else {
		console.log('ok   control: the unmutated checker passes in the mirror');
	}
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
