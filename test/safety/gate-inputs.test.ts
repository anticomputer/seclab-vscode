// Gates fail closed on empty or unreadable input (gate fail-open audit GATE-4 to GATE-7).
//   node --test test/safety/gate-inputs.test.ts

import * as assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { test } from 'node:test';

const repo = path.resolve(import.meta.dirname, '../..');
const scratch = fs.mkdtempSync(path.join(process.env.SECLAB_SCRATCH ?? path.join(repo, '.work', 'test-scratch'), 'gate-inputs-'));
const list = (name: string, entries: string[]) => {
	const f = path.join(scratch, name);
	fs.writeFileSync(f, entries.map(e => `${e}\0`).join(''));
	return f;
};
const run = (args: string[]) => spawnSync(process.execPath, args, { cwd: repo, encoding: 'utf8' });

test.after(() => fs.rmSync(scratch, { recursive: true, force: true }));

const PIN_ANCHORS = ['.github/workflows/ci-unit.yml', 'build/check-pins.ts', 'seclab', 'upstream.lock'];
const AV_ANCHORS = ['.github/workflows/ci-unit.yml', 'seclab', 'test/safety/fixture-lint.ts', 'upstream.lock'];

test('check-pins: an empty, foreign, truncated or canary-only list fails, a real one passes (GATE-4, SSS-1)', () => {
	const empty = run(['build/check-pins.ts', list('empty', [])]);
	assert.equal(empty.status, 1, empty.stdout);
	assert.match(empty.stdout, /file list \(0 entries\) is empty, truncated or isn't this repository's/);
	const foreign = run(['build/check-pins.ts', list('foreign', ['README.md'])]);
	assert.equal(foreign.status, 1, foreign.stdout);
	const truncated = run(['build/check-pins.ts', list('truncated', PIN_ANCHORS.slice(0, 3))]);
	assert.equal(truncated.status, 1, truncated.stdout);
	assert.match(truncated.stdout, /lacks upstream\.lock/);
	const real = run(['build/check-pins.ts', list('real', [...PIN_ANCHORS, 'README.md'])]);
	assert.equal(real.status, 0, real.stdout);
});

test('check-pins: a listed file that can\'t be read is a finding (GATE-7)', () => {
	const r = run(['build/check-pins.ts', list('missing', [...PIN_ANCHORS, 'no/such/tracked-file.yml'])]);
	assert.equal(r.status, 1, r.stdout);
	assert.match(r.stdout, /no\/such\/tracked-file\.yml: tracked but unreadable \(ENOENT\)/);
});

test('fixture-lint --av: an empty, truncated or canary-only list fails; an unreadable file is a finding (GATE-5, GATE-7, SSS-1)', () => {
	const empty = run(['test/safety/fixture-lint.ts', '--av', list('av-empty', [])]);
	assert.equal(empty.status, 1, empty.stdout);
	assert.match(empty.stdout, /is empty, truncated or isn't this repository's/);
	const canary = run(['test/safety/fixture-lint.ts', '--av', list('av-canary', ['test/safety/fixture-lint.ts'])]);
	assert.equal(canary.status, 1, canary.stdout);
	const missing = run(['test/safety/fixture-lint.ts', '--av', list('av-missing', [...AV_ANCHORS, 'no/such/file.ts'])]);
	assert.equal(missing.status, 1, missing.stdout);
	assert.match(missing.stdout, /no\/such\/file\.ts: tracked but unreadable \(ENOENT\)/);
	const real = run(['test/safety/fixture-lint.ts', '--av', list('av-real', [...AV_ANCHORS, 'README.md'])]);
	assert.equal(real.status, 0, real.stdout);
});

test('fixture-lint: a missing root fails, and a root with nothing to scan fails (GATE-6)', () => {
	const missing = run(['test/safety/fixture-lint.ts', path.relative(repo, path.join(scratch, 'absent'))]);
	assert.equal(missing.status, 2, missing.stderr);
	fs.mkdirSync(path.join(scratch, 'empty-root'));
	const empty = run(['test/safety/fixture-lint.ts', path.relative(repo, path.join(scratch, 'empty-root'))]);
	assert.equal(empty.status, 1, empty.stdout);
	assert.match(empty.stdout, /no file was scanned/);
});

test('teardown: no steal log means clean only if the watcher watched the editor to the end (GATE-10)', async () => {
	const { focusWatchProblem, focusWatchLog, editorLaunchRecord } = await import('../harness.ts');
	const ud = path.join(scratch, 'profile');
	fs.mkdirSync(ud);
	const line = (s: string) => fs.appendFileSync(focusWatchLog(ud), `2026-11-12T00:00:00.000Z ${s}\n`);
	assert.equal(focusWatchProblem(ud, 0, 'darwin'), undefined, 'no editor launched: nothing to watch');
	fs.writeFileSync(editorLaunchRecord(ud), '{}');
	assert.match(focusWatchProblem(ud, 0, 'darwin') ?? '', /never started/);
	line('started (watcher pid 1)');
	assert.match(focusWatchProblem(ud, 0, 'darwin') ?? '', /never saw the editor/);
	line('watching editor pid 2');
	assert.match(focusWatchProblem(ud, 0, 'darwin') ?? '', /did not run to the end/);
	line('stopped: no editor for 5 s, after 40 samples');
	assert.equal(focusWatchProblem(ud, 0, 'darwin'), undefined);
	assert.equal(focusWatchProblem(ud, 0, 'linux'), undefined, 'no watcher off macOS');
});
