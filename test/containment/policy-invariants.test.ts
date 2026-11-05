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

test('nothing in the exact table is reachable yet', () => {
	// The allow set is built from measured need in Phase 3. Until then every
	// exact entry should be deny or rewrite; an allow appearing here without a
	// probe run behind it is the thing to notice.
	const block = MODULE.split('SECLAB_COMMANDS')[1] ?? '';
	const end = block.indexOf(']);');
	const verdicts = [...block.slice(0, end).matchAll(/verdict: '(\w+)'/g)].map(x => x[1]);
	const reachable = verdicts.filter(v => v === 'allow' || v === 'allow_with_constraint');
	assert.deepEqual(reachable, [],
		'a command became reachable; that needs a reviewed entry and a probe, '
		+ 'see rpc-filter/policy/policy.json commands.reachable_allowlist_status');
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
