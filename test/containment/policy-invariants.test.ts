/**
 * Policy invariants that hold over the generated table itself.
 *
 * Run: node test/containment/policy-invariants.test.ts
 *
 * These are assertions about `seclabPolicyData.ts` as shipped, so they catch a
 * regression introduced by the generator, by a policy edit, or by a hand edit
 * to the emitted module — angles that a check reading `policy.json` cannot see,
 * because it is reasoning about the input rather than the artefact.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const MODULE = readFileSync(
	join(REPO, 'rpc-filter', 'patch-src', 'seclabPolicyData.ts'), 'utf8');

const tests: Array<[string, () => void]> = [];
const test = (name: string, fn: () => void) => tests.push([name, fn]);

function denyPrefixes(): string[] {
	const m = MODULE.match(/SECLAB_COMMAND_DENY_PREFIXES[^=]*=\s*\[([\s\S]*?)\]/);
	assert.ok(m, 'SECLAB_COMMAND_DENY_PREFIXES is missing from the emitted module');
	return [...m[1].matchAll(/'([^']+)'/g)].map(x => x[1]);
}

function exactCommandIds(): string[] {
	const block = MODULE.split('SECLAB_COMMANDS')[1] ?? '';
	const end = block.indexOf(']);');
	return [...block.slice(0, end).matchAll(/\['([^']+)',/g)].map(x => x[1]);
}

test('the fork\'s own commands are denied by prefix', () => {
	assert.ok(denyPrefixes().includes('seclab.'),
		'seclab. must be denied before the table is consulted');
});

test('no seclab.* id reaches the exact table', () => {
	// `commands.exact` is resolved before rules, so an entry here would
	// override the prefix rule. The build check in check_drift.py enforces the
	// same thing against policy.json; this asserts it of the shipped artefact.
	assert.deepEqual(exactCommandIds().filter(id => id.startsWith('seclab.')), []);
});

test('the Tab Manager\'s approval dialogs are not reachable', () => {
	// A tab that can raise these supplies the prompt. The click is still the
	// user's, but an unlimited supply of genuine-looking approval dialogs is a
	// social-engineering surface, so the answer is that the tab cannot ask.
	const prefixes = denyPrefixes();
	for (const id of ['seclab.reviewChanges', 'seclab.confirmDeletes']) {
		assert.ok(prefixes.some(p => id.startsWith(p)), `${id} must be denied`);
	}
});

test('an unknown seclab command is denied too, not just the known two', () => {
	// The guarantee is on the namespace, so a command added later is covered
	// without anyone remembering to list it.
	assert.ok(denyPrefixes().some(p => 'seclab.somethingAddedLater'.startsWith(p)));
});

test('the default verdict is deny', () => {
	assert.match(MODULE, /SECLAB_DEFAULT_VERDICT: SeclabVerdict = 'deny'/);
});

test('only the recorded leaf exceptions are reachable, each validated and probed', () => {
	// While the deferred-laundering residual is open, a reachable command is allowed only as a
	// recorded leaf exception (check_drift.py::check_residuals): its handler never reaches
	// ICommandService, its arguments are validated, and a probe drives its dangerous shape.
	// An id appearing here that is not one of those is the thing to notice.
	const policy = JSON.parse(readFileSync(join(REPO, 'rpc-filter', 'policy', 'policy.json'), 'utf8'));
	const probes = JSON.parse(readFileSync(join(REPO, 'rpc-filter', 'probes', 'expectations.json'), 'utf8')).probes;
	const leaves: string[] = policy.residuals['deferred-laundering'].leaf_exceptions;
	const block = MODULE.split('SECLAB_COMMANDS')[1] ?? '';
	const end = block.indexOf(']);');
	const entries = [...block.slice(0, end).matchAll(/\['([^']+)', \{ verdict: '(\w+)'([^\n]*)\}\]/g)];
	const reachable = entries.filter(m => m[2] === 'allow' || m[2] === 'allow_with_constraint');
	assert.deepEqual(reachable.map(m => m[1]).sort(), [...leaves].sort(),
		'the reachable commands differ from residuals[deferred-laundering].leaf_exceptions');
	for (const m of reachable) {
		assert.equal(m[2], 'allow_with_constraint', `${m[1]} is reachable without a constraint`);
		assert.match(m[3], /validator: '\w+'/, `${m[1]} names no validator in the shipped table`);
		assert.ok(Object.values(probes).some((p: unknown) => (p as { policyRef?: string }).policyRef === `cmd:${m[1]}`),
			`${m[1]} has no probe in rpc-filter/probes/expectations.json`);
	}
});

let failed = 0;
for (const [name, fn] of tests) {
	try {
		fn();
		console.log(`ok   ${name}`);
	} catch (err) {
		failed++;
		console.error(`FAIL ${name}\n     ${(err as Error).message}`);
	}
}
console.log(`\n${tests.length - failed}/${tests.length} passed`);
process.exit(failed ? 1 : 0);
