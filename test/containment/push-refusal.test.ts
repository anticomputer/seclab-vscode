/**
 * Patches 0030 and 0031: in a tab window, upstream's handler for the two server-initiated
 * terminal pushes is never registered, and the refusal that replaces it reaches nothing.
 *
 * Run: node test/containment/push-refusal.test.ts
 *
 * Checked on the patch text, the artefact that ships. For each patch:
 *  - upstream's own registration is a context line, and the only added line before it is
 *    `if (!seclabTab) {`, closed by an added `}` after its handler;
 *  - `seclabTab` is `seclabIsTabAuthority(...)` of a host-side authority;
 *  - the refusing handler logs through `seclabRefusePush` with its policy key, answers at once,
 *    and names no command service, resolver, history, environment or tab-chosen field other
 *    than the request id, except that 0030's answer is upstream's own refusal of an unknown
 *    command, which echoes the command id back to the tab that sent it (review AIP-4).
 * Every rule is paired with a mutant of the real patch that it must reject, so the checker is
 * shown able to fail.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const read = (p: string) => readFileSync(join(REPO, p), 'utf8');

interface Spec {
	title: string;
	file: string;
	/** Upstream's registration line, as a context line of the patch. */
	upstream: string;
	authority: string;
	policyKey: string;
	/** The prompt answer the refusal must give. */
	reply: RegExp;
}

const SPECS: Spec[] = [
	{
		title: 'patch 0030: upstream onExecuteCommand handler is unreachable in a tab window, and the refusal reaches nothing',
		file: 'patches/0030-seclab-no-remote-cli-push-in-tabs.patch',
		upstream: 'this._register(this._remoteTerminalChannel.onExecuteCommand(async e => {',
		authority: 'remoteAuthority',
		policyKey: 'push:remoteterminal:$onExecuteCommand',
		reply: /^\s*this\._remoteTerminalChannel\.sendCommandResult\(e\.reqId, true, 'Invalid remote cli command: ' \+ e\.commandId\);\s*$/,
	},
	{
		title: 'patch 0031: upstream pty-host variable resolver is unreachable in a tab window, and the refusal reaches nothing',
		file: 'patches/0031-seclab-no-variable-resolution-for-tab-pty-hosts.patch',
		upstream: 'this._register(this._ptyHostController.onPtyHostRequestResolveVariables(async e => {',
		authority: 'seclabPtyHostAuthority',
		policyKey: 'push:remoteterminal:$onPtyHostRequestResolveVariablesEvent',
		reply: /^\s*this\._ptyHostController\.acceptPtyHostResolvedVariables\(e\.requestId, e\.originalText\.map\(t => String\(t\)\)\);\s*$/,
	},
];

/** What a refusal must never name: the services upstream's handler uses, or host state. */
const FORBIDDEN_IN_REFUSAL = /_commandService|executeCommand|revive\(|configurationResolverService|resolveAsync|historyService|shellEnv|getEnv|process\.env|e\.commandId|e\.commandArgs|e\.workspaceId|allowedCommands|_ptys/;

/** The added and context lines of one file's hunks, in order, with their kind. */
function linesOf(patch: string, fileSuffix: string): Array<{ kind: '+' | ' '; text: string }> {
	const out: Array<{ kind: '+' | ' '; text: string }> = [];
	let inFile = false;
	for (const raw of patch.split('\n')) {
		if (raw.startsWith('diff ')) {
			inFile = raw.endsWith(fileSuffix);
			continue;
		}
		if (!inFile || raw.startsWith('---') || raw.startsWith('+++') || raw.startsWith('@@')) {
			continue;
		}
		if (raw.startsWith('+')) {
			out.push({ kind: '+', text: raw.slice(1) });
		} else if (raw.startsWith(' ')) {
			out.push({ kind: ' ', text: raw.slice(1) });
		}
	}
	return out;
}

/** Problems with one patch, or an empty list. */
function check(patch: string, spec: Spec): string[] {
	const problems: string[] = [];
	const file = spec.file.includes('0030') ? 'remoteTerminalBackend.ts' : 'baseTerminalBackend.ts';
	const lines = linesOf(patch, file);
	const at = lines.findIndex(l => l.text.trim() === spec.upstream);
	if (at < 0) {
		return ['upstream registration not found'];
	}
	if (lines[at].kind !== ' ') {
		problems.push('upstream registration is added or altered, not context');
	}
	const prevAdded = lines.slice(0, at).filter(l => l.kind === '+').pop();
	if (!prevAdded || prevAdded.text.trim() !== 'if (!seclabTab) {' || lines[at - 1].kind !== '+') {
		problems.push('upstream registration is not directly guarded by if (!seclabTab) {');
	}
	if (lines.filter(l => l.text.trim() === spec.upstream).length !== 1) {
		problems.push('upstream registration appears more than once');
	}
	// Upstream's handler closes with the first context `}));` after it; the guard closes next.
	const close = lines.findIndex((l, i) => i > at && l.text.trim() === '}));');
	const after = close < 0 ? undefined : lines[close + 1];
	if (!after || after.kind !== '+' || after.text.trim() !== '}') {
		problems.push('the guard is not closed right after upstream\'s handler');
	}
	const decl = lines.find(l => l.kind === '+' && /const seclabTab = /.test(l.text));
	if (!decl || decl.text.trim() !== `const seclabTab = seclabIsTabAuthority(${spec.authority});`) {
		problems.push('seclabTab is not seclabIsTabAuthority of the host-side authority');
	}
	// The refusal: from `if (seclabTab) {` to the matching added `}` before upstream's guard.
	const start = lines.findIndex(l => l.kind === '+' && l.text.trim() === 'if (seclabTab) {');
	if (start < 0 || start > at) {
		problems.push('no refusing handler before upstream\'s registration');
		return problems;
	}
	const body = lines.slice(start + 1, at - 1);
	if (body.some(l => l.kind !== '+')) {
		problems.push('the refusing handler is not wholly ours');
	}
	const text = body.map(l => l.text).join('\n');
	// The answer is judged whole by `spec.reply`; everything else in the refusal names nothing.
	const rest = body.map(l => l.text).filter(t => !spec.reply.test(t)).join('\n');
	if (FORBIDDEN_IN_REFUSAL.test(rest)) {
		problems.push(`the refusal names ${rest.match(FORBIDDEN_IN_REFUSAL)![0]}`);
	}
	if (/seclab/i.test(body.filter(l => spec.reply.test(l.text) || /sendCommandResult|acceptPtyHostResolvedVariables/.test(l.text)).map(l => l.text).join('\n'))) {
		problems.push('the answer names seclab, so a tab can tell a policy refusal from upstream\'s');
	}
	if (!text.includes(`seclabRefusePush(${spec.authority}, '${spec.policyKey}');`)) {
		problems.push('the refusal does not log its policy key through seclabRefusePush');
	}
	if (!body.some(l => spec.reply.test(l.text))) {
		problems.push('the refusal does not answer at once');
	}
	if (/\basync\b|\bawait\b/.test(text)) {
		problems.push('the refusal is asynchronous');
	}
	return problems;
}

const tests: Array<[string, () => void]> = [];
const test = (name: string, fn: () => void) => tests.push([name, fn]);

for (const spec of SPECS) {
	const patch = read(spec.file);
	const tag = spec.file.slice('patches/'.length, 'patches/'.length + 4);
	test(spec.title, () => {
		assert.deepEqual(check(patch, spec), []);
	});
	const mutants: Array<[string, (p: string) => string]> = [
		['guard removed', p => p.replace('+\t\tif (!seclabTab) {\n', '')],
		['guard inverted', p => p.replace('+\t\tif (!seclabTab) {\n', '+\t\tif (seclabTab) {\n')],
		['refusal logs a tab-chosen field', p => p.replace(`seclabRefusePush(${spec.authority}, '${spec.policyKey}');`, `seclabRefusePush(${spec.authority}, '${spec.policyKey}'); void e.commandId;`)],
		['refusal reaches the command service', p => p.replace(`seclabRefusePush(${spec.authority}, '${spec.policyKey}');`, `seclabRefusePush(${spec.authority}, '${spec.policyKey}'); this._commandService;`)],
		['refusal does not log', p => p.replace(`seclabRefusePush(${spec.authority}, '${spec.policyKey}');`, '')],
		['refusal waits', p => p.replace(`seclabRefusePush(${spec.authority}, '${spec.policyKey}');`, `seclabRefusePush(${spec.authority}, '${spec.policyKey}'); await 0;`)],
		['authority from elsewhere', p => p.replace(`seclabIsTabAuthority(${spec.authority})`, 'seclabIsTabAuthority(undefined)')],
		...(tag === '0030' ? [
			['answer names the policy (AIP-4)', (p: string) => p.replace(`'Invalid remote cli command: ' + e.commandId`, `'seclab: denied'`)],
			['answer echoes the id beside another call', (p: string) => p.replace(`this._remoteTerminalChannel.sendCommandResult(e.reqId, true, 'Invalid remote cli command: ' + e.commandId);`, `void e.commandArgs; this._remoteTerminalChannel.sendCommandResult(e.reqId, true, 'Invalid remote cli command: ' + e.commandId);`)],
		] as Array<[string, (p: string) => string]> : []),
	];
	for (const [name, mutate] of mutants) {
		test(`${tag}: rejects the mutant "${name}"`, () => {
			const m = mutate(patch);
			assert.notEqual(m, patch, `mutant "${name}" changed nothing: the prover is broken, not the gate`);
			assert.notDeepEqual(check(m, spec), []);
		});
	}
}

test('seclabRefusePush logs only a closed set of policy keys and a fixed reason', () => {
	const src = read('rpc-filter/patch-src/seclabRpcFilter.ts');
	const type = src.match(/export type SeclabRefusedPush =([^;]+);/);
	assert.ok(type, 'SeclabRefusedPush is missing');
	const keys = [...type[1].matchAll(/'([^']+)'/g)].map(m => m[1]).sort();
	assert.deepEqual(keys, SPECS.map(s => s.policyKey).sort());
	const fn = src.match(/export function seclabRefusePush\(remoteAuthority: string \| null \| undefined, ref: SeclabRefusedPush\): void \{([\s\S]*?)\n\}/);
	assert.ok(fn, 'seclabRefusePush has changed its signature');
	assert.match(fn[1], /verdict: 'deny', reason: '[^']+', at: Date\.now\(\)/);
	assert.doesNotMatch(fn[1], /\$\{|\+ ref|\+ remoteAuthority/, 'the reason must be fixed text');
});

test('a decision made before the log installs is held for it, bounded', () => {
	const src = read('rpc-filter/patch-src/seclabRpcFilter.ts');
	assert.match(src, /const SECLAB_EARLY_MAX = \d+;/);
	assert.match(src, /if \(seclabListeners\.size === 0\) \{\n\t\tif \(seclabEarly\.length < SECLAB_EARLY_MAX\) \{\n\t\t\tseclabEarly\.push\(d\);/);
	assert.match(src, /const early = seclabEarly\.splice\(0\);/);
});

let failed = 0;
for (const [name, fn] of tests) {
	try {
		fn();
		console.log(`PASS  ${name}`);
	} catch (err) {
		failed++;
		console.log(`FAIL  ${name}\n      ${(err as Error).message.split('\n')[0]}`);
	}
}
console.log(`\n${tests.length - failed}/${tests.length} passed`);
process.exit(failed ? 1 : 0);
