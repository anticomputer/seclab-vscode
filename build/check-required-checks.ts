// The required checks can't be skipped by the change they gate (EDR pr-landing, review PRL-5).
// GitHub counts a job skipped by a job-level `if:` as a passed required check, and a trigger
// filter (`paths:`, `branches:`, …) can keep the workflow from running at all. With pull-request
// landing and no required approvals, the workflow files are the change's own to edit, so this
// check, part of the required `lint` job, holds the property instead:
//   - each required check's job exists once, carries `name:` equal to the context, and has only
//     job-level keys that can't make it skip (no `if:`, `needs:`, `continue-on-error:`, ...);
//   - its workflow triggers on bare `push:` and `pull_request:`, with no filters under them.
//   node build/check-required-checks.ts [--self-test]

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import * as os from 'node:os';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { jobContexts, jobProblems, triggers } from './liveness/liveness.ts';

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

interface Tok { kind: 'plain' | 'sq' | 'dq' | 'alias'; text: string; open: boolean; key: boolean }

/** One YAML line split into scalars and aliases, each marked a key when a `:` follows it. A quote
 *  opens a scalar only where a node starts, a plain scalar runs to `: ` or a comment (and to `,`,
 *  `]` or `}` inside a flow collection), so quotes inside it are text; a single-quoted scalar's
 *  backslashes are literal and its quote is doubled (Copilot review on PR 32). */
function scanLine(l: string): Tok[] {
	const out: Tok[] = [];
	let depth = 0;
	let prev = '';
	const starter = () => prev === '' || /[:\-[{,?]/.test(prev);
	const keyAfter = (rest: string) => /^\s*:(\s|$|[,\]}])/.test(rest);
	for (let k = 0; k < l.length; k++) {
		const c = l[k];
		if (/\s/.test(c)) {
			continue;
		}
		if (c === '#' && (k === 0 || /\s/.test(l[k - 1]))) {
			break;
		}
		if (!starter() || c === ':' || c === ',') {
			if ((c === ']' || c === '}') && depth > 0) {
				depth--;
			}
			prev = c;
			continue;
		}
		if (c === '"' || c === "'") {
			let j = k + 1, text = '', open = true;
			while (j < l.length) {
				if (c === '"' && l[j] === '\\') {
					text += l[j] + (l[j + 1] ?? '');
					j += 2;
					continue;
				}
				if (c === "'" && l[j] === "'" && l[j + 1] === "'") {
					text += "'";
					j += 2;
					continue;
				}
				if (l[j] === c) {
					open = false;
					break;
				}
				text += l[j++];
			}
			out.push({ kind: c === '"' ? 'dq' : 'sq', text, open, key: !open && keyAfter(l.slice(j + 1)) });
			k = j;
			prev = c;
		} else if (c === '[' || c === '{') {
			depth++;
			prev = c;
		} else if ((c === ']' || c === '}') && depth > 0) {
			depth--;
			prev = c;
		} else if (c === '-' && (k + 1 >= l.length || /\s/.test(l[k + 1]))) {
			prev = '-';
		} else if (c === '&' || c === '!' || c === '*') {
			let j = k;
			while (j + 1 < l.length && !/[\s,\]}]/.test(l[j + 1])) {
				j++;
			}
			if (c === '*') {
				out.push({ kind: 'alias', text: l.slice(k + 1, j + 1), open: false, key: keyAfter(l.slice(j + 1)) });
				prev = '*';
			}
			k = j;
		} else {
			let j = k;
			while (j < l.length && !(l[j] === ':' && (j + 1 >= l.length || /\s/.test(l[j + 1]) || (depth > 0 && /[,\]}]/.test(l[j + 1]))))
				&& !(depth > 0 && /[,\]}]/.test(l[j])) && !(l[j] === '#' && /\s/.test(l[j - 1] ?? ''))) {
				j++;
			}
			out.push({ kind: 'plain', text: l.slice(k, j).trimEnd(), open: false, key: l[j] === ':' });
			k = j - 1;
			prev = 'x';
		}
	}
	return out;
}

/** Whether a double-quoted scalar on the line holds a backslash (an escape YAML decodes), or is
 *  left open (unreadable, so fail closed). */
function dqEscape(l: string): boolean {
	return scanLine(l).some(t => t.kind === 'dq' && (t.open || t.text.includes('\\')));
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
		if (lines.some(dqEscape)) {
			bad('a double-quoted YAML escape');
			continue;
		}
		if (lines.some(l => /^\s*(?:-\s+)?\?(\s|$)/.test(l) || /(^|[\s{,])<<\s*:/.test(l))) {
			bad('a complex or merge key');
			continue;
		}
		// An alias as a mapping key (`*p :` with `&p permissions` elsewhere) names the key the
		// anchor holds, which a text scan can't see (Copilot review on PR 32).
		if (lines.some(l => scanLine(l).some(t => t.kind === 'alias' && t.key))) {
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
				if (scanLine(lines[i]).some(t => t.key && t.kind !== 'alias' && t.text === 'permissions')) {
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


/** The pre-merge gate (EDR 20261117-required-jobs-gate): the one workflow that may hold
 *  `statuses: write`, and only while it keeps every invariant here, since a file that could also
 *  run on a push or pull request would hand that scope to branch code (CR-8 again). */
export const GATE = 'required-jobs-ran.yml';
/** The reviewed gate, byte for byte. Its shape rules don't constrain what the script does, and a
 *  doctored copy on main would pass every future PR, so a change to it changes this constant in
 *  the same reviewed change (review RJG-8). */
export const GATE_SHA256 = '176930babd84a6612cd547c0117fc3cde76d384810002cced63aa6cfac68b27c';
const GATE_EXPRESSIONS = new Set(['github.token', 'github.repository', 'github.event.workflow_run.head_sha']);
export function gateProblems(files: Record<string, string>): string[] {
	const yml = files[GATE];
	if (yml === undefined) {
		return [`${GATE}: the required-jobs gate is missing`];
	}
	const out: string[] = [];
	const bad = (why: string) => out.push(`${GATE}: ${why}`);
	if (createHash('sha256').update(yml).digest('hex') !== GATE_SHA256) {
		bad('differs from the reviewed gate (GATE_SHA256 in build/check-required-checks.ts)');
	}
	const t = triggers(yml);
	if (t.length !== 1 || t[0] !== 'workflow_run') {
		bad(`must trigger on workflow_run alone, not ${JSON.stringify(t)}`);
	}
	const lines = yamlLines(yml);
	// Outside its script, in any spelling: block or flow (review RJG-4).
	if (lines.some(l => /\buses["']?\s*:/.test(l.replace(/(^|\s)#.*$/, '')))) {
		bad('has a uses: step (no checkout, no artifact download, no action at all)');
	}
	const FLOW_OK = new Set(['permissions: {}', '    workflows: [ci-unit, workflow-lint, docs-check, patch-build]', '    types: [completed]']);
	lines.forEach((l, i) => {
		if (/[{}[\]]/.test(l.replace(/\$\{\{[^}]*\}\}/g, '').replace(/\s+#.*$/, '')) && !FLOW_OK.has(l.replace(/\s+#.*$/, ''))) {
			bad(`line ${i + 1}: a flow collection outside the fixed trigger and permissions lines`);
		}
	});
	if (/\bsecrets\s*[.[]/.test(yml)) {
		bad('reads a secret');
	}
	yml.split('\n').forEach((l, i) => {
		for (const m of l.matchAll(/\$\{\{([^}]*)\}\}/g)) {
			if (!GATE_EXPRESSIONS.has(m[1].trim())) {
				bad(`line ${i + 1}: the expression \${{${m[1]}}} isn't one of ${[...GATE_EXPRESSIONS].join(', ')}`);
			}
		}
		if (l.includes('${{') && !/^ {10}(GH_TOKEN|REPO|SHA): \$\{\{ [a-z_.]+ \}\}$/.test(l) && !/^ {2}group: required-jobs-ran-\$\{\{ github\.event\.workflow_run\.head_sha \}\}$/.test(l)) {
			bad(`line ${i + 1}: an expression outside the step's env and the concurrency group`);
		}
	});
	if (!lines.some(l => /^permissions\s*:\s*\{\}\s*$/.test(l))) {
		bad('top-level permissions must be {}');
	}
	const grants = lines.filter(l => /^\s+["']?[a-z-]+["']?\s*:\s*["']?(read|write|none)["']?\s*(#.*)?$/.test(l))
		.map(l => l.trim().replace(/\s*#.*$/, '').replace(/["']/g, '').replace(/\s*:\s*/, ': ')).sort();
	if (grants.join(', ') !== 'actions: read, statuses: write') {
		bad(`its token must hold exactly actions: read and statuses: write, not ${JSON.stringify(grants)}`);
	}
	// The one loop, inside the script: a comment can't stand in for it (review RJG-4).
	const loops = yml.split('\n').map((l, i) => ({ l, i })).filter(x => x.l.includes('for pair in'));
	if (loops.length !== 1 || lines[loops[0].i] !== '' || !/^ {10}for pair in [^;]+; do$/.test(loops[0].l)) {
		bad('must hold exactly one `for pair in ...; do` loop, inside its script');
	}
	const pairs = loops.length === 1 ? /for pair in ([^;\n]+);/.exec(loops[0].l)?.[1].trim().split(/\s+/) ?? [] : [];
	const wantPairs = REQUIRED.map(r => `${r.workflow}:${r.context}`);
	if (pairs.join(' ') !== wantPairs.join(' ')) {
		bad(`checks ${JSON.stringify(pairs)}, not the required ${JSON.stringify(wantPairs)}`);
	}
	const names = /^ {4}workflows:\s*\[([^\]]*)\]\s*$/m.exec(yml)?.[1].split(',').map(s => s.trim()) ?? [];
	const wantNames = REQUIRED.map(r => /^name:\s*(\S+)\s*$/m.exec(files[r.workflow] ?? '')?.[1] ?? `?${r.workflow}`);
	if (names.join(' ') !== wantNames.join(' ')) {
		bad(`runs after ${JSON.stringify(names)}, not the required workflows ${JSON.stringify(wantNames)}`);
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
		['a plain-scalar command holding a quoted bracket', good.replace('      - run: x\n', '      - run: echo "["\n      - run: echo \'{\' x\n'), null],
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
		['a single-quoted run holding an escape-like backslash', { 'x.yml': wf("  a:\n    steps:\n      - run: 'printf \"%s\\n\" ok'\n      - run: 'it''s \\x'\n") }, null],
		['a double-quoted escape after a single-quoted value', { 'x.yml': wf("  a:\n    permissions: {'x': 'y', \"check\\x73\": write}\n    steps:\n      - run: x\n") }, /double-quoted YAML escape/],
		['a plain label holding a lone double quote', { 'x.yml': wf('  a:\n    steps:\n      - name: Check "literal\n        run: x\n') }, null],
		['JSON with a permissions key inside a single-quoted value', { 'x.yml': wf("  a:\n    env:\n      CONFIG: '{\"permissions\":\"read-all\"}'\n    steps:\n      - run: x\n") }, null],
		['an escape inside a flow mapping', { 'x.yml': wf('  a:\n    steps:\n      - { run: x, name: "a\\x41" }\n') }, /double-quoted YAML escape/],
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
		['a decoy name inside a quoted step at the end of the file', { 'shadow.yml': wf('  lint:\n    steps:\n      - run: "true\n    name: harmless\n        "\n') }, /can't be read in full|reports the required context `lint`/],
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
	// The gate: the real file and the real required workflows, each invariant broken in turn.
	const wfDir = path.join(import.meta.dirname, '..', '.github', 'workflows');
	const realFiles = Object.fromEntries([GATE, ...REQUIRED.map(r => r.workflow)].map(f => [f, fs.readFileSync(path.join(wfDir, f), 'utf8')]));
	const g = realFiles[GATE];
	const allowStatuses = (files: Record<string, string>) => permissionsProblems(files, (f, scope) => WRITE_OK.has(scope) || (f === GATE && scope === 'statuses' && gateProblems(files).length === 0));
	for (const [name, edit, want] of [
		['gate control', (s: string) => s, null],
		['gate on pull_request too', (s: string) => s.replace('\non:\n', '\non:\n  pull_request:\n'), /workflow_run alone/],
		['gate checks out code', (s: string) => s.replace('    steps:\n', '    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n'), /uses: step/],
		['gate downloads an artifact', (s: string) => s.replace('    steps:\n', '    steps:\n      - name: get\n        uses: actions/download-artifact@0000000000000000000000000000000000000000\n'), /uses: step/],
		['gate reads a secret', (s: string) => s.replace('GH_TOKEN: ${{ github.token }}', 'GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}'), /reads a secret/],
		['gate uses a PR-controlled expression', (s: string) => s.replace('SHA: ${{ github.event.workflow_run.head_sha }}', 'SHA: ${{ github.event.workflow_run.head_branch }}'), /isn't one of/],
		['gate expression in run', (s: string) => s.replace('set -euo pipefail', 'set -euo pipefail; echo ${{ github.repository }}'), /outside the step's env/],
		['gate gains contents: write', (s: string) => s.replace('      statuses: write\n', '      statuses: write\n      contents: write\n'), /exactly actions: read and statuses: write/],
		['gate top-level permissions not empty', (s: string) => s.replace('permissions: {}\n', 'permissions:\n  contents: read\n'), /top-level permissions/],
		['gate drops a required job', (s: string) => s.replace(' docs-check.yml:docs', ''), /not the required/],
		['RJG-4 a flow-style uses step', (s: string) => s.replace('    steps:\n', '    steps:\n      - { uses: ./.github/actions/x, with: { x: y } }\n'), /uses: step|flow collection/],
		['RJG-4 the pair list only in a comment', (s: string) => s.replace(/for pair in [^;]+;/, 'for pair in ci-unit.yml:unit;').replace('on:\n', '# for pair in ci-unit.yml:unit workflow-lint.yml:lint docs-check.yml:docs patch-build.yml:patch-build;\non:\n'), /exactly one `for pair in/],
		['RJG-8 an extra step', (s: string) => s + '      - name: x\n        run: echo x\n', /differs from the reviewed gate/],
		['RJG-8 an unconditional success', (s: string) => s.replace('          state=success\n', '          state=success\n          gh api -X POST "repos/$REPO/statuses/$SHA" -f state=success -f context=required-jobs-ran\n'), /differs from the reviewed gate/],
		['gate waits on another workflow list', (s: string) => s.replace('workflows: [ci-unit, workflow-lint, docs-check, patch-build]', 'workflows: [ci-unit]'), /not the required workflows/],
	] as Array<[string, (s: string) => string, RegExp | null]>) {
		const files = { ...realFiles, [GATE]: edit(g) };
		const got = [...gateProblems(files), ...allowStatuses(files)];
		if (want ? !got.some(p => want.test(p)) || (name !== 'gate control' && !got.some(p => /statuses: write/.test(p))) : got.length) {
			throw new Error(`required-checks self-test "${name}": got ${JSON.stringify(got)}`);
		}
	}
	if (!gateProblems({}).some(p => /missing/.test(p))) {
		throw new Error('required-checks self-test "gate missing": not reported');
	}
	for (const [name, yml, want] of cases) {
		const got = problems(yml, 'unit', 'unit');
		if (want ? !got.some(p => want.test(p)) : got.length) {
			throw new Error(`required-checks self-test "${name}": got ${JSON.stringify(got)}`);
		}
	}
	// The gate's own script, run with bash against a stub gh serving fixture runs (RJG-2, RJG-6): it
	// judges every run of each file and reads every page. The stub ignores --jq and serves what the
	// filter would yield: "<id> <status>" lines per file, a conclusion per run.
	const lines = g.split('\n');
	const at = lines.findIndex(l => /^ {8}run: \|$/.test(l));
	const script = lines.slice(at + 1).filter(l => l === '' || l.startsWith('          ')).map(l => l.slice(10)).join('\n');
	const stub = `#!/bin/bash
all="$*"
echo "$all" >> "$FIX/log"
case "$all" in
  *"-X POST"*) for a; do case "$a" in state=*) echo "\${a#state=}" > "$FIX/state";; esac; done ;;
  *"/workflows/"*"/runs?"*) [[ "$1 $2" == "api --paginate" ]] || exit 9; w="\${all#*/workflows/}"; w="\${w%%/*}"; [[ -f "$FIX/runs-$w" ]] && cat "$FIX/runs-$w"; true ;;
  *"/runs/"*"/jobs?"*) i="\${all#*/runs/}"; i="\${i%%/*}"; cat "$FIX/job-$i" ;;
  *) exit 8 ;;
esac
`;
	const runGate = (fixture: Record<string, string>): string => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rjg-'));
		try {
			fs.mkdirSync(path.join(dir, 'bin'));
			fs.writeFileSync(path.join(dir, 'bin', 'gh'), stub, { mode: 0o755 });
			for (const [k, v] of Object.entries(fixture)) {
				fs.writeFileSync(path.join(dir, k), v);
			}
			const r = spawnSync('bash', ['-c', script], { env: { PATH: `${dir}/bin:${process.env.PATH}`, FIX: dir, SHA: 'a'.repeat(40), REPO: 'o/r' }, encoding: 'utf8' });
			const state = fs.existsSync(path.join(dir, 'state')) ? fs.readFileSync(path.join(dir, 'state'), 'utf8').trim() : `none (exit ${r.status})`;
			return state;
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	};
	const allGreen: Record<string, string> = {
		'runs-ci-unit.yml': '1 completed\n', 'runs-workflow-lint.yml': '2 completed\n', 'runs-docs-check.yml': '3 completed\n', 'runs-patch-build.yml': '4 completed\n',
		'job-1': 'success\n', 'job-2': 'success\n', 'job-3': 'success\n', 'job-4': 'success\n',
	};
	const gateRuns: Array<[string, Record<string, string>, string]> = [
		['gate script: every required job ran to success', allGreen, 'success'],
		['gate script RJG-2: lint ran on push but was skipped on the PR run', { ...allGreen, 'runs-workflow-lint.yml': '2 completed\n5 completed\n', 'job-5': 'skipped\n' }, 'failure'],
		['gate script RJG-2: the skipped run listed first', { ...allGreen, 'runs-workflow-lint.yml': '5 completed\n2 completed\n', 'job-5': 'skipped\n' }, 'failure'],
		['gate script: a cancelled required job', { ...allGreen, 'job-3': 'cancelled\n' }, 'failure'],
		['gate script: a required job missing from its run', { ...allGreen, 'job-4': 'missing\n' }, 'failure'],
		['gate script: no run of a required workflow', Object.fromEntries(Object.entries(allGreen).filter(([k]) => k !== 'runs-docs-check.yml')), 'failure'],
		['gate script: a required run still in progress', { ...allGreen, 'runs-ci-unit.yml': '1 in_progress\n' }, 'pending'],
		['gate script: a failure beats a pending run', { ...allGreen, 'runs-ci-unit.yml': '1 in_progress\n', 'job-3': 'failure\n' }, 'failure'],
	];
	for (const [name, fixture, want] of gateRuns) {
		const got = runGate(fixture);
		if (got !== want) {
			throw new Error(`required-checks self-test "${name}": posted ${got}, want ${want}`);
		}
	}
	// RJG-6: without --paginate the stub refuses, so the gate posts nothing (fail closed) and this fails.
	if (!script.includes('gh api --paginate "repos/$REPO/actions/workflows/$wf/runs?')) {
		throw new Error('required-checks self-test "gate script RJG-6": the runs list is not read with --paginate');
	}
	console.log(`required-checks self-test: ${cases.length + 40 + gateRuns.length} cases OK`);
}

if (import.meta.main) {
	if (process.argv[2] === '--self-test') {
		selfTest();
	} else if (process.argv[2] === '--list') {
		// workflow:context pairs, for ./seclab landing verify
		console.log(REQUIRED.map(r => `${r.workflow}:${r.context}`).join(' '));
	} else {
		const root = path.resolve(import.meta.dirname, '..');
		const dir = path.join(root, '.github/workflows');
		const files = Object.fromEntries(fs.readdirSync(dir).filter(f => /\.ya?ml$/i.test(f)).map(f => [f, fs.readFileSync(path.join(dir, f), 'utf8')]));
		const all = [...REQUIRED.flatMap(r => files[r.workflow] === undefined ? [`${r.context}: workflow ${r.workflow} is missing`] : problems(files[r.workflow], r.context, r.job)),
			...reporters(files), ...gateProblems(files),
			...permissionsProblems(files, (f, scope) => WRITE_OK.has(scope) || (f === GATE && scope === 'statuses' && gateProblems(files).length === 0))];
		for (const p of all) {
			console.error(`required-checks: ${p}`);
		}
		if (all.length) {
			process.exit(1);
		}
		console.log(`required-checks: ok (${REQUIRED.map(r => r.context).join(', ')})`);
	}
}
