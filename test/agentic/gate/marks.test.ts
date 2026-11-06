// The probe runner's detached helpers must be reapable by the shared teardown gate. Twice now
// a mark passed review and failed only in a live run: round 2 (hand-written marks that could
// never match an absolute script path) and round 3 (a mark that broke teardown's run-directory
// rule, which makes the gate refuse to act at all and leaves the armed fixture running).
// These assert the marks against teardown's real rules, so the next drift fails `test unit`.

import assert from 'node:assert/strict';
import * as path from 'node:path';
import { test } from 'node:test';
import { manifestProblems } from '../../containment/teardown.ts';
import { repoRoot } from '../../harness.ts';
import { armSpawn, beaconSpawn } from '../runner/marks.ts';

const base = path.join(repoRoot, '.work', 'agentic-runner');
// `.work/`, not `~/.seclab-test/`: the isolated-profile check resolves the deepest existing
// ancestor, so a home root that does not exist (the unit tests run in a container, where it
// never does) made the deepest ancestor `$HOME` and failed the check. Both are accepted
// roots, and this one is always present.
const userData = path.join(repoRoot, '.work', 'agentic-runner-ud');
const beacon = beaconSpawn(repoRoot, path.join(base, 'beacon.log'), 18099);
const arm = armSpawn(path.join(repoRoot, 'test', 'agentic', 'runner', 'runner.ts'), userData, 'sbx', base);

test('teardown accepts the marks the runner actually writes', () => {
	assert.deepEqual(manifestProblems(base, {
		driver: 'sbx', userDataDir: userData, stateDirs: [path.join(userData, 'User')],
		commandMarks: [beacon.mark, arm.mark],
	}), []);
});

test('each mark is a run of whole argv tokens in the argv it was built from', () => {
	// teardown matches /(^|\s)<mark>(?=\s|$)/ against `<node> <argv…>`.
	for (const { argv, mark } of [beacon, arm]) {
		const commandLine = `${process.execPath} ${argv.join(' ')}`;
		const re = new RegExp(`(^|\\s)${mark.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?=\\s|$)`);
		assert.ok(re.test(commandLine), mark);
	}
});

test('a mark that does not end at the run directory is rejected, not silently accepted', () => {
	// The round 3 regression, in the shape it had: --run-dir before --user-data-dir.
	const bad = [path.join(repoRoot, 'test', 'agentic', 'runner', 'runner.ts'), 'arm', userData, '--run-dir', base, '--user-data-dir', userData].join(' ');
	assert.notDeepEqual(manifestProblems(base, { driver: 'sbx', userDataDir: userData, commandMarks: [bad] }), []);
});
