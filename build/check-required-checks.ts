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

/** Write scopes a workflow may grant; any scope may be read or none. Not checks or statuses: a step
 *  holding either could post a passing required context as GitHub Actions itself (review CR-8). */
const WRITE_OK = new Set(['id-token', 'attestations', 'issues']);

/** A workflow's lines with block-scalar content (a `run: |` script) blanked: escapes and quotes
 *  there are shell text, not YAML. */
function yamlLines(yml: string): string[] {
	const out: string[] = [];
	let blockIndent = -1;
	for (const l of yml.split('\n')) {
		const ind = /^ */.exec(l)![0].length;
		if (blockIndent >= 0 && (/^\s*$/.test(l) || ind > blockIndent)) {
			out.push('');
			continue;
		}
		blockIndent = /^\s*(?:-\s+)?[^\s#][^#]*?:\s*[|>][-+0-9]*\s*(?:#.*)?$/.test(l) ? ind : -1;
		// A full-line comment, and a plain scalar after a plain key, are text YAML never decodes:
		// `run: printf "%s\n" ok` holds no escape (Copilot review on PR 32). A `permissions:`
		// value stays, since that's what is read below.
		// Only a value the scans below would trip on is blanked; a blanked scope line inside a
		// `permissions:` block still reads as unreadable.
		const plain = /^(\s*(?:-\s+)?)([A-Za-z0-9_][A-Za-z0-9_.-]*)(\s*:\s+)([^\s"'{[\]}&*!|>%@`?#,].*)$/.exec(l);
		out.push(/^\s*#/.test(l) ? '' : plain && plain[2] !== 'permissions' && /\\|<</.test(plain[4]) ? plain[1] + plain[2] + plain[3].trimEnd() : l);
	}
	return out;
}

/** Every `permissions:` grant, read fail-closed (reviews CR-8, CR-9). Actions decodes YAML the way
 *  a text match doesn't, so a double-quoted escape, a complex key or a merge key anywhere outside a
 *  script fails the workflow, and a `permissions:` value must read as `read-all`, `{}`, a flow
 *  map of plain pairs, or plain `scope: read|write|none` lines. Write only where WRITE_OK says. */
export function permissionsProblems(files: Record<string, string>, writeOk: (f: string, scope: string) => boolean = (_, s) => WRITE_OK.has(s)): string[] {
	const out: string[] = [];
	for (const [f, yml] of Object.entries(files)) {
		const lines = yamlLines(yml);
		const bad = (why: string) => out.push(`${f}: ${why}; it might grant a token scope unseen`);
		if (lines.some(l => /(^|[\s:[{,-])"[^"]*\\/.test(l))) {
			bad('a double-quoted YAML escape');
			continue;
		}
		if (lines.some(l => /^\s*(?:-\s+)?\?(\s|$)/.test(l) || /(^|[\s{,])<<\s*:/.test(l))) {
			bad('a complex or merge key');
			continue;
		}
		// An alias as a mapping key (`*p :` with `&p permissions` elsewhere) names the key the
		// anchor holds, which a text scan can't see (Copilot review on PR 32).
		if (lines.some(l => /^\s*(?:-\s+)?\*[^\s:]*\s*:/.test(l) || /[{,]\s*\*[^\s:,}]*\s*:/.test(l))) {
			bad('an alias as a mapping key');
			continue;
		}
		const pair = (scope: string, value: string, where: number) => {
			if (!/^[a-z][a-z-]*$/.test(scope) || !/^(read|write|none)$/.test(value)) {
				bad(`line ${where + 1}: unreadable permission ${JSON.stringify(`${scope}: ${value}`)}`);
			} else if (value === 'write' && !writeOk(f, scope)) {
				out.push(`${f}: line ${where + 1} grants ${scope}: write, which isn't allowed`);
			}
		};
		const unq = (s: string) => s.replace(/^'([^']*)'$/, '$1').replace(/^"([^"]*)"$/, '$1');
		for (let i = 0; i < lines.length; i++) {
			const m = /^(\s*)(?:-\s+)?(["']?)permissions\2\s*:\s*(.*?)\s*(?:#.*)?$/.exec(lines[i]);
			if (!m) {
				// Only where `permissions` could be a key: right before a colon, comments aside. A step
				// named "Verify permissions" isn't one (Copilot review on PR 32).
				// A quoted `permissions` key anywhere is one; otherwise quoted values are text, so a
				// label like 'Verify permissions: read-only' isn't (Copilot review on PR 32).
				const code = lines[i].replace(/(^|\s)#.*$/, '');
				if (/(["'])permissions\1\s*:/.test(code) || /(^|[^\w-])permissions\s*:/.test(code.replace(/'(?:[^']|'')*'|"[^"\\]*"/g, '""'))) {
					bad(`line ${i + 1}: a permissions key it can't read`);
				}
				continue;
			}
			const v = m[3];
			if (v === 'read-all' || v === '{}') {
				continue;
			}
			if (v === 'write-all') {
				out.push(`${f}: line ${i + 1} grants write-all`);
				continue;
			}
			const flow = /^\{(.*)\}$/.exec(v);
			if (flow) {
				for (const kv of flow[1].split(',').map(x => x.trim()).filter(Boolean)) {
					const p = /^(["']?)([^"':\s]+)\1\s*:\s*(.+)$/.exec(kv);
					if (!p) {
						bad(`line ${i + 1}: unreadable permission ${JSON.stringify(kv)}`);
					} else {
						pair(p[2], unq(p[3].trim()), i);
					}
				}
				continue;
			}
			if (v !== '') {
				bad(`line ${i + 1}: unreadable permissions value ${JSON.stringify(v)}`);
				continue;
			}
			const ind = m[1].length;
			let any = false;
			for (let j = i + 1; j < lines.length; j++) {
				const l = lines[j];
				if (/^\s*(#.*)?$/.test(l)) {
					continue;
				}
				if (/^ */.exec(l)![0].length <= ind) {
					break;
				}
				const p = /^\s+(["']?)([^"':\s]+)\1\s*:\s*(.*?)\s*(?:#.*)?$/.exec(l);
				if (!p) {
					bad(`line ${j + 1}: unreadable permission ${JSON.stringify(l.trim())}`);
				} else {
					pair(p[2], unq(p[3]), j);
				}
				any = true;
			}
			if (!any) {
				bad(`line ${i + 1}: an empty permissions block`);
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
		['CR-7 a required job indented 6 hiding if', good.replace('    name: unit\n    runs-on: x\n    steps:\n      - run: x\n', '      name: unit\n      if: false\n      runs-on: x\n      steps:\n        - run: x\n'), /not indented 4/],
		['CR-7 if after a column-0 comment', good.replace('    steps:\n', '# note\n    if: false\n    steps:\n'), /job-level if/],
		['a job-level if after a multiline quoted step value', good.replace('      - run: x\n', '      - run: "true\nignored"\n    if: false\n'), /unfinished quoted or flow value/],
		['a job after an open quoted scalar', 'name: "x\n' + good.replace('on:\n', '"\non:\n'), /open flow collection or quoted scalar/],
		['a flow-style job', good.replace('  unit:\n    name: unit\n    runs-on: x\n    steps:\n      - run: x\n', '  unit: {name: unit, if: false}\n'), /not found|declared/],
	];
	const wf = (job: string) => `on:\n  push:\n  pull_request:\njobs:\n${job}`;
	const real = { 'ci-unit.yml': good, 'workflow-lint.yml': good.replace(/unit/g, 'lint'), 'docs-check.yml': good.replace(/unit/g, 'docs'), 'patch-build.yml': good.replace(/unit/g, 'patch-build') };
	for (const [name, extra, want] of [
		['CR-8 checks: write', { 'x.yml': wf('  a:\n    permissions:\n      checks: write\n    steps:\n      - run: x\n') }, /grants checks: write/],
		['CR-8 statuses: write in flow style', { 'x.yml': 'permissions: {statuses: write}\n' + wf('  a:\n    steps:\n      - run: x\n') }, /grants statuses: write/],
		['CR-8 write-all', { 'x.yml': 'permissions: write-all\n' + wf('  a:\n    steps:\n      - run: x\n') }, /grants write-all/],
		['CR-9 an escaped scope key', { 'x.yml': 'permissions:\n  "check\\x73": write\n' + wf('  a:\n    steps:\n      - run: x\n') }, /double-quoted YAML escape/],
		['CR-9 an escaped value', { 'x.yml': 'permissions:\n  checks: "writ\\x65"\n' + wf('  a:\n    steps:\n      - run: x\n') }, /double-quoted YAML escape/],
		['CR-9 a folded value', { 'x.yml': 'permissions:\n  checks: >-\n    write\n' + wf('  a:\n    steps:\n      - run: x\n') }, /permission|empty/],
		['CR-9 a literal value', { 'x.yml': 'permissions:\n  statuses: |-\n    write\n' + wf('  a:\n    steps:\n      - run: x\n') }, /permission|empty/],
		['CR-9 a complex permissions key', { 'x.yml': '? permissions\n: {checks: write}\n' + wf('  a:\n    steps:\n      - run: x\n') }, /complex or merge key/],
		['CR-9 a merge key', { 'x.yml': wf('  a:\n    <<: *p\n    steps:\n      - run: x\n') }, /complex or merge key/],
		['CR-9 a quoted write in a flow map', { 'x.yml': "permissions: {'statuses': 'write'}\n" + wf('  a:\n    steps:\n      - run: x\n') }, /statuses: write/],
		['CR-9 an unknown write scope', { 'x.yml': wf('  a:\n    permissions:\n      pull-requests: write\n    steps:\n      - run: x\n') }, /pull-requests: write/],
		['an allowed write and a script escape', { 'x.yml': wf('  a:\n    permissions:\n      id-token: write\n      contents: read\n    steps:\n      - run: |\n          echo "a\\b"\n') }, null],
		['a step named after permissions, and a comment', { 'x.yml': wf('  a:\n    steps:\n      - name: Verify permissions\n        run: x # permissions: are fine\n# permissions: here too\n') }, null],
		['a permissions key inside a flow step', { 'x.yml': wf('  a:\n    steps:\n      - { name: x, permissions: {checks: write} }\n') }, /can't read/],
		['a plain-scalar run with an escape, and comments', { 'x.yml': wf('  a:\n    steps:\n      - run: printf "%s\\n" ok > result.txt\n        # "a\\b" and <<: here\n') }, null],
		['a plain scalar does not hide a later escaped key', { 'x.yml': wf('  a:\n    permissions:\n      "check\\x73": write\n    steps:\n      - run: printf "%s\\n" ok\n') }, /double-quoted YAML escape/],
		['an escaped key after a plain-scalar value on a flow line', { 'x.yml': wf('  a:\n    steps:\n      - { run: x, "per\\x6dissions": {checks: write} }\n') }, /double-quoted YAML escape/],
		['a plain scope value with a backslash', { 'x.yml': wf('  a:\n    permissions:\n      checks: wr\\ite\n    steps:\n      - run: x\n') }, /unreadable permission/],
		['an alias as a block permissions key', { 'x.yml': wf('  a:\n    name: &p permissions\n    steps:\n      - run: x\n') + '*p :\n  checks: write\n' }, /an alias as a mapping key/],
		['an alias as a flow permissions key', { 'x.yml': wf('  a:\n    name: &p permissions\n    steps:\n      - { run: x, *p : {checks: write} }\n') }, /an alias as a mapping key/],
		['a quoted label holding permissions:', { 'x.yml': wf("  a:\n    steps:\n      - name: 'Verify permissions: read-only'\n        run: x\n      - name: \"Check permissions: none\"\n        run: y\n") }, null],
		['a quoted permissions key in a flow step', { 'x.yml': wf("  a:\n    steps:\n      - { name: x, 'permissions': {checks: write} }\n") }, /can't read|permissions/],
		['checks: read is fine', { 'x.yml': wf('  a:\n    permissions:\n      checks: read\n    steps:\n      - run: x\n') }, null],
		['control: the real four and an unrelated job', { 'x.yml': wf('  other:\n    name: other\n    steps:\n      - run: x\n') }, null],
		['a decoy job named lint', { 'shadow.yml': wf('  a:\n    name: lint\n    steps:\n      - run: x\n') }, /reports the required context `lint`/],
		['a decoy job id unit with no name', { 'shadow.yml': wf('  unit:\n    steps:\n      - run: x\n') }, /reports the required context `unit`/],
		['a quoted decoy name', { 'shadow.yaml': wf('  a:\n    "name": "docs"\n    steps:\n      - run: x\n') }, /reports the required context `docs`/],
		['an expression name', { 'shadow.yml': wf("  a:\n    name: ${{ 'lint' }}\n    steps:\n      - run: x\n") }, /can't be read in full/],
		['an escaped name', { 'shadow.yml': wf('  a:\n    name: "li\\x6et"\n    steps:\n      - run: x\n') }, /can't be read in full/],
		['a decoy id lint with a null name', { 'shadow.yml': wf('  lint:\n    name: null\n    steps:\n      - run: x\n') }, /can't be read in full/],
		['a decoy id lint with a ~ name', { 'shadow.yml': wf('  lint:\n    name: ~\n    steps:\n      - run: x\n') }, /can't be read in full/],
		['a decoy id lint with an empty quoted name', { 'shadow.yml': wf("  lint:\n    name: ''\n    steps:\n      - run: x\n") }, /can't be read in full/],
		['a decoy jobs block inside a quoted name', { 'shadow.yml': '{name: "x\njobs:\n  a:\n    name: ok\n", jobs: {lint: {steps: [{run: x}]}}, on: push}\n' }, /can't be read in full/],
		['flow-style jobs', { 'shadow.yml': 'on: push\njobs: {a: {name: lint}}\n' }, /can't be read in full/],
		['a flow-style job', { 'shadow.yml': wf('  a: {name: lint}\n') }, /can't be read in full/],
		['CR-7 a name indented 6', { 'shadow.yml': wf('  a:\n      name: lint\n      steps:\n        - run: x\n') }, /can't be read in full/],
		['CR-7 a name indented 3', { 'shadow.yml': wf('  a:\n   name: lint\n   steps:\n     - run: x\n') }, /can't be read in full/],
		['CR-7 an escaped name key', { 'shadow.yml': wf('  a:\n    "na\\x6de": lint\n    steps:\n      - run: x\n') }, /can't be read in full/],
		['CR-7 a decoy after a column-0 comment', { 'shadow.yml': wf('  a:\n    name: ok\n    steps:\n      - run: x\n# a note\n  b:\n    name: lint\n    steps:\n      - run: x\n') }, /reports the required context `lint`/],
		['an uppercase extension', { 'shadow.YML': wf('  a:\n    name: unit\n    steps:\n      - run: x\n') }, /reports the required context `unit`/],
	] as Array<[string, Record<string, string>, RegExp | null]>) {
		const got = [...reporters({ ...real, ...extra }), ...permissionsProblems({ ...real, ...extra })];
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
	console.log(`required-checks self-test: ${cases.length + 40} cases OK`);
}

if (import.meta.main) {
	if (process.argv[2] === '--self-test') {
		selfTest();
	} else {
		const root = path.resolve(import.meta.dirname, '..');
		const dir = path.join(root, '.github/workflows');
		const files = Object.fromEntries(fs.readdirSync(dir).filter(f => /\.ya?ml$/i.test(f)).map(f => [f, fs.readFileSync(path.join(dir, f), 'utf8')]));
		const all = [...REQUIRED.flatMap(r => files[r.workflow] === undefined ? [`${r.context}: workflow ${r.workflow} is missing`] : problems(files[r.workflow], r.context, r.job)),
			...reporters(files), ...permissionsProblems(files)];
		for (const p of all) {
			console.error(`required-checks: ${p}`);
		}
		if (all.length) {
			process.exit(1);
		}
		console.log(`required-checks: ok (${REQUIRED.map(r => r.context).join(', ')})`);
	}
}
