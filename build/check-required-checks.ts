// The required checks can't be skipped by the change they gate (EDR pr-landing, review PRL-5).
// GitHub counts a job skipped by a job-level `if:` as a passed required check, and a trigger
// filter (`paths:`, `branches:`, …) can keep the workflow from running at all. With pull-request
// landing and no required approvals, the workflow files are the change's own to edit, so this
// check, part of the required `lint` job, holds the property instead:
//   - each required check's job exists, carries `name:` equal to the context, and has no
//     job-level `if:`;
//   - its workflow triggers on bare `push:` and `pull_request:`, with no filters under them.
//   node build/check-required-checks.ts [--self-test]

import * as fs from 'node:fs';
import * as path from 'node:path';

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
	// The job: present, named as the context, no job-level `if:`.
	const start = lines.findIndex(l => l === `  ${job}:`);
	if (start < 0 || !lines.slice(0, start).some(l => l === 'jobs:')) {
		out.push(`${context}: job \`${job}\` not found under jobs:`);
		return out;
	}
	const body: string[] = [];
	for (const l of lines.slice(start + 1)) {
		if (/^ {0,2}\S/.test(l)) {
			break;
		}
		body.push(l);
	}
	const keys = body.filter(l => /^ {4}[A-Za-z_-]+\s*:/.test(l)).map(l => /^ {4}([A-Za-z_-]+)/.exec(l)![1]);
	if (keys.includes('if')) {
		out.push(`${context}: job \`${job}\` has a job-level if:, and a skipped job passes a required check`);
	}
	const name = body.find(l => /^ {4}name\s*:/.test(l))?.replace(/^ {4}name\s*:\s*/, '').replace(/\s+#.*$/, '').replace(/^['"]|['"]$/g, '');
	if (name !== context) {
		out.push(`${context}: job \`${job}\` must be named \`${context}\` (the required context), not ${JSON.stringify(name)}`);
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
	];
	for (const [name, yml, want] of cases) {
		const got = problems(yml, 'unit', 'unit');
		if (want ? !got.some(p => want.test(p)) : got.length) {
			throw new Error(`required-checks self-test "${name}": got ${JSON.stringify(got)}`);
		}
	}
	console.log(`required-checks self-test: ${cases.length} cases OK`);
}

if (import.meta.main) {
	if (process.argv[2] === '--self-test') {
		selfTest();
	} else {
		const root = path.resolve(import.meta.dirname, '..');
		const all = REQUIRED.flatMap(r => problems(fs.readFileSync(path.join(root, '.github/workflows', r.workflow), 'utf8'), r.context, r.job));
		for (const p of all) {
			console.error(`required-checks: ${p}`);
		}
		if (all.length) {
			process.exit(1);
		}
		console.log(`required-checks: ok (${REQUIRED.map(r => r.context).join(', ')})`);
	}
}
