// The required checks can't be skipped by the change they gate (EDR pr-landing, review PRL-5).
// GitHub counts a job skipped by a job-level `if:` as a passed required check, and a trigger
// filter (`paths:`, `branches:`, …) can keep the workflow from running at all. With pull-request
// landing and no required approvals, the workflow files are the change's own to edit, so this
// check, part of the required `lint` job, holds the property instead:
//   - each required check's job exists once, carries `name:` equal to the context, and has only
//     job-level keys that can't make it skip (no `if:`, `needs:`, `continue-on-error:`, ...);
//   - its workflow triggers on bare `push:` and `pull_request:`, with no filters under them.
//   node build/check-required-checks.ts [--self-test]

import * as fs from 'node:fs';
import * as path from 'node:path';
import { jobContexts, jobProblems } from './liveness/liveness.ts';

/** Required status check context -> the workflow and job that report it (ruleset 26572681). */
export const REQUIRED: ReadonlyArray<{ context: string; workflow: string; job: string }> = [
	{ context: 'unit', workflow: 'ci-unit.yml', job: 'unit' },
	{ context: 'lint', workflow: 'workflow-lint.yml', job: 'lint' },
	{ context: 'docs', workflow: 'docs-check.yml', job: 'docs' },
	{ context: 'patch-build', workflow: 'patch-build.yml', job: 'patch-build' },
];

/** The problems with one required check's workflow text. */
export function problems(yml: string, context: string, job: string): string[] {
	const out: string[] = [];
	const lines = yml.split('\n');
	// Triggers: the `on:` block must hold bare `push:` and `pull_request:` and nothing under them.
	const on = lines.findIndex(l => /^(?:on|"on"|'on')\s*:/.test(l));
	if (on < 0 || lines[on].replace(/^[^:]+:/, '').replace(/#.*/, '').trim()) {
		out.push(`${context}: \`on:\` must be a block with bare push: and pull_request:`);
	} else {
		const block: string[] = [];
		for (const l of lines.slice(on + 1)) {
			if (/^\S/.test(l)) {
				break;
			}
			if (!/^\s*(#.*)?$/.test(l)) {
				block.push(l.replace(/\s+#.*$/, ''));
			}
		}
		for (const t of ['push', 'pull_request']) {
			const i = block.findIndex(l => l === `  ${t}:`);
			if (i < 0) {
				out.push(`${context}: must trigger on a bare \`${t}:\` (no inline value)`);
			} else if (i + 1 < block.length && /^ {3,}\S/.test(block[i + 1])) {
				out.push(`${context}: \`${t}:\` has a filter; a required check must run on every ${t}`);
			}
		}
		if (block.some(l => !/^ {2}\S/.test(l) && !/^ {3,}\S/.test(l))) {
			out.push(`${context}: \`on:\` is not indented as expected`);
		}
	}
	const jp = jobProblems(yml, job, context);
	out.push(...jp.problems);
	if (!jp.found) {
		return out;
	}
	const body = jp.body;
	const name = body.find(l => /^ {4}name\s*:/.test(l))?.replace(/^ {4}name\s*:\s*/, '').replace(/\s+#.*$/, '').replace(/^['"]|['"]$/g, '');
	if (name !== context) {
		out.push(`${context}: job \`${job}\` must be named \`${context}\` (the required context), not ${JSON.stringify(name)}`);
	}
	return out;
}

/** Only the registered job may report a required context: GitHub matches a required check by its
 *  name, so a job of that name in any other workflow could satisfy it while the real one is
 *  gutted or gone (review CR-4). A workflow whose jobs can't be read in full fails too. */
export function reporters(files: Record<string, string>): string[] {
	const out: string[] = [];
	for (const [f, yml] of Object.entries(files)) {
		const jobs = jobContexts(yml);
		if (!jobs) {
			out.push(`${f}: its jobs can't be read in full, so it might report a required context`);
			continue;
		}
		for (const j of jobs) {
			const r = REQUIRED.find(x => x.context === j.context);
			if (r && !(r.workflow === f && r.job === j.id)) {
				out.push(`${f}: job \`${j.id}\` reports the required context \`${j.context}\`, which only ${r.workflow}#${r.job} may`);
			}
		}
	}
	return out;
}

function selfTest(): void {
	const good = 'on:\n  push:\n  pull_request:\n\njobs:\n  unit:\n    name: unit\n    runs-on: x\n    steps:\n      - run: x\n';
	const cases: Array<[string, string, RegExp | null]> = [
		['control', good, null],
		['a required job with a job-level if', good.replace('    name: unit\n', '    name: unit\n    if: false\n'), /job-level if/],
		['paths filter on push', good.replace('  push:\n', '  push:\n    paths: [docs/**]\n'), /push:` has a filter/],
		['branches filter on pull_request', good.replace('  pull_request:\n', '  pull_request:\n    branches: [nope]\n'), /pull_request:` has a filter/],
		['pull_request dropped', good.replace('  pull_request:\n', ''), /bare `pull_request:`/],
		['inline on:', good.replace('on:\n  push:\n  pull_request:\n', 'on: [push]\n'), /must be a block/],
		['job renamed', good.replace('    name: unit\n', '    name: unit-x\n'), /must be named/],
		['job removed', 'on:\n  push:\n  pull_request:\njobs:\n  other:\n    name: unit\n', /not found/],
		['a step-level if is fine', good.replace('      - run: x\n', '      - run: x\n        if: always()\n'), null],
		['a double-quoted if key', good.replace('    name: unit\n', '    name: unit\n    "if": false\n'), /job-level if/],
		['a single-quoted if key', good.replace('    name: unit\n', "    name: unit\n    'if': false\n"), /job-level if/],
		['an escaped quoted key', good.replace('    name: unit\n', '    name: unit\n    "i\\x66": false\n'), /isn't a plain key/],
		['a merge key', good.replace('    name: unit\n', '    name: unit\n    <<: *skip\n'), /isn't a plain key/],
		['an alias as a property value', good.replace('    runs-on: x\n', '    runs-on: x\n    strategy: *s\n'), /anchor or alias/],
		['the job declared twice', good + '  "unit":\n    name: unit\n    if: false\n', /declared 2 times/],
		['needs on a skipped gate job', good.replace('    name: unit\n', '    name: unit\n    needs: gate\n'), /has `needs:`/],
		['needs as a list', good.replace('    name: unit\n', '    name: unit\n    needs: [gate]\n'), /has `needs:`/],
		['continue-on-error', good.replace('    name: unit\n', '    name: unit\n    continue-on-error: true\n'), /has `continue-on-error:`/],
		['an empty matrix', good.replace('    name: unit\n', '    name: unit\n    strategy:\n      matrix:\n        v: []\n'), /has `strategy:`/],
		['a reusable workflow', good.replace('    runs-on: x\n', '    uses: ./.github/workflows/x.yml\n'), /has `uses:`/],
		['a quoted needs', good.replace('    name: unit\n', '    name: unit\n    "needs": gate\n'), /has `needs:`/],
		['permissions and timeout are fine', good.replace('    runs-on: x\n', '    runs-on: x\n    timeout-minutes: 5\n    permissions:\n      contents: read\n'), null],
		['defaults (could no-op every step)', good.replace('    runs-on: x\n', '    runs-on: x\n    defaults:\n      run:\n        shell: /usr/bin/true {0}\n'), /has `defaults:`/],
		['a job with an empty body', good.replace('  unit:\n    name: unit\n    runs-on: x\n    steps:\n      - run: x\n', '  unit:\n'), /must be named/],
		['a flow-style job', good.replace('  unit:\n    name: unit\n    runs-on: x\n    steps:\n      - run: x\n', '  unit: {name: unit, if: false}\n'), /not found|declared/],
	];
	const wf = (job: string) => `on:\n  push:\n  pull_request:\njobs:\n${job}`;
	const real = { 'ci-unit.yml': good, 'workflow-lint.yml': good.replace(/unit/g, 'lint'), 'docs-check.yml': good.replace(/unit/g, 'docs'), 'patch-build.yml': good.replace(/unit/g, 'patch-build') };
	for (const [name, extra, want] of [
		['control: the real four and an unrelated job', { 'x.yml': wf('  other:\n    name: other\n    steps:\n      - run: x\n') }, null],
		['a decoy job named lint', { 'shadow.yml': wf('  a:\n    name: lint\n    steps:\n      - run: x\n') }, /reports the required context `lint`/],
		['a decoy job id unit with no name', { 'shadow.yml': wf('  unit:\n    steps:\n      - run: x\n') }, /reports the required context `unit`/],
		['a quoted decoy name', { 'shadow.yaml': wf('  a:\n    "name": "docs"\n    steps:\n      - run: x\n') }, /reports the required context `docs`/],
		['an expression name', { 'shadow.yml': wf("  a:\n    name: ${{ 'lint' }}\n    steps:\n      - run: x\n") }, /can't be read in full/],
		['an escaped name', { 'shadow.yml': wf('  a:\n    name: "li\\x6et"\n    steps:\n      - run: x\n') }, /can't be read in full/],
		['flow-style jobs', { 'shadow.yml': 'on: push\njobs: {a: {name: lint}}\n' }, /can't be read in full/],
		['a flow-style job', { 'shadow.yml': wf('  a: {name: lint}\n') }, /can't be read in full/],
	] as Array<[string, Record<string, string>, RegExp | null]>) {
		const got = reporters({ ...real, ...extra });
		if (want ? !got.some(p => want.test(p)) : got.length) {
			throw new Error(`required-checks self-test "${name}": got ${JSON.stringify(got)}`);
		}
	}
	for (const [name, yml, want] of cases) {
		const got = problems(yml, 'unit', 'unit');
		if (want ? !got.some(p => want.test(p)) : got.length) {
			throw new Error(`required-checks self-test "${name}": got ${JSON.stringify(got)}`);
		}
	}
	console.log(`required-checks self-test: ${cases.length + 8} cases OK`);
}

if (import.meta.main) {
	if (process.argv[2] === '--self-test') {
		selfTest();
	} else {
		const root = path.resolve(import.meta.dirname, '..');
		const dir = path.join(root, '.github/workflows');
		const files = Object.fromEntries(fs.readdirSync(dir).filter(f => /\.ya?ml$/.test(f)).map(f => [f, fs.readFileSync(path.join(dir, f), 'utf8')]));
		const all = [...REQUIRED.flatMap(r => files[r.workflow] === undefined ? [`${r.context}: workflow ${r.workflow} is missing`] : problems(files[r.workflow], r.context, r.job)),
			...reporters(files)];
		for (const p of all) {
			console.error(`required-checks: ${p}`);
		}
		if (all.length) {
			process.exit(1);
		}
		console.log(`required-checks: ok (${REQUIRED.map(r => r.context).join(', ')})`);
	}
}
