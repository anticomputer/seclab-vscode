// Workflow log lint: an Actions log on a public repository is public, so no workflow or CI
// script echoes the environment, a secret-derived value or host data (EDR 20261112-publish-gate).
//   E1  no `${{ secrets.* }}` inside a run: block (bind it in env: and pass it as a file or stdin)
//   E2  no environment dump or shell trace: env, printenv, set, export -p, declare -p, compgen -v,
//       set -x / -o xtrace, bash -x
//   E3  no echo/printf/cat/tee of a variable bound to a secret in the same workflow (or, in a CI
//       script, to a secret anywhere in .github/workflows), except `::add-mask::`
//   E4  no host-data commands: whoami, hostname, uname -a, ifconfig, ip a/addr, docker info,
//       cat /etc/{hosts,resolv.conf,passwd}
//   S1  no branch-controlled code runs with a repository secret (review round 17, finding 1): a
//       job that reads `secrets.*` must run only on a push to main (`if:` naming both), in the
//       `denylist` environment, with no `ref:` override on its checkout; no workflow has a
//       `pull_request_target` or `workflow_run` trigger; `secrets: inherit` is refused.
// A line may carry `# lint-allow: echo <reason>`; the reason is required (E rules only).
//   node build/check-workflow-echo.ts [--self-test]

import * as fs from 'node:fs';
import * as path from 'node:path';

const repo = path.resolve(import.meta.dirname, '..');

interface Finding { file: string; line: number; rule: string }

const DUMP = /(?:^\s*|[;&|(]\s*|\bthen\s+|\bdo\s+)(?:env|printenv(?:\s+\S+)?|set|export\s+-p|declare\s+-p|compgen\s+-v)\s*(?:$|[;&|>)])|\b(?:set|bash|sh)\s+-[a-z]*x[a-z]*\b|\bset\s+-o\s+xtrace\b/;
const HOST = /\b(?:whoami|hostname|uname\s+-a|ifconfig|ip\s+a(?:ddr)?\b|docker\s+info)\b|\bcat\s+\/etc\/(?:hosts|resolv\.conf|passwd)\b/;
const PRINTS = /\b(?:echo|printf|cat|tee|head|tail|less|more|xxd|od|strings)\b/;
// Output that reaches the log: no redirect, a redirect to stdout/stderr, or the step summary.
const TO_FILE = /(?:^|[^<>&0-9])>>?\s*(?!&|\/dev\/std|"?\$\{?GITHUB_STEP_SUMMARY)[^\s>]/;
const ALLOW = /#\s*lint-allow:\s*echo\s+\S/;

/** Env names bound to a secret in a workflow's text. */
export function secretVars(yaml: string): Set<string> {
	const out = new Set<string>();
	for (const m of yaml.matchAll(/^\s+([A-Za-z_][A-Za-z0-9_]*):\s*\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}\s*$/gm)) {
		out.add(m[1]);
	}
	return out;
}

/** The (1-based) line numbers inside `run:` blocks. */
function runLines(lines: string[]): Set<number> {
	const out = new Set<number>();
	for (let i = 0; i < lines.length; i++) {
		const m = /^(\s*)(?:-\s+)?run:\s*(.*)$/.exec(lines[i]);
		if (!m) {
			continue;
		}
		const indent = m[1].length + (/^\s*-\s+/.test(lines[i]) ? 2 : 0);
		if (m[2] && !/^[|>][-+]?\s*$/.test(m[2])) {
			out.add(i + 1);
			continue;
		}
		for (let j = i + 1; j < lines.length; j++) {
			if (lines[j].trim() !== '' && lines[j].search(/\S/) <= indent) {
				break;
			}
			out.add(j + 1);
		}
	}
	return out;
}

/**
 * The secret-derived names in scope (R19-7): variables bound to a secret, variables assigned from
 * one (`X="$S"`, `local X=${S}`, `X=$(cat FILE)`), variables `read` from a here-string of one, and
 * files a tainted value is written to (`… "$S" > "$dir/list"`). Iterated to a fixpoint.
 */
export function taint(lines: string[], secrets: Set<string>): { vars: Set<string>; files: Set<string> } {
	const vars = new Set(secrets);
	const files = new Set<string>();
	const mentions = (l: string) => [...vars].some(v => new RegExp(`\\$\\{?${v}\\b`).test(l)) || [...files].some(f => l.includes(f));
	for (let changed = true; changed;) {
		changed = false;
		const add = (set: Set<string>, v: string) => { if (!set.has(v)) { set.add(v); changed = true; } };
		const text = lines.join('\n');
		for (const l of lines) {
			const a = /^\s*(?:(?:local|export|readonly|declare(?:\s+-\w+)*)\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(l);
			if (a && mentions(a[2])) {
				add(vars, a[1]);
			}
			const w = /(?:^|[^<>&0-9])>>?\s*("[^"]+"|'[^']+'|[^\s;|&]+)/.exec(l);
			if (w && mentions(l.slice(0, w.index + 1))) {
				// Path-like targets only: a one-letter name would taint every line containing it.
				const target = w[1].replace(/^["']|["']$/g, '');
				if (/[/.]/.test(target) || target.length >= 3) {
					add(files, target);
				}
			}
		}
		for (const v of [...vars]) {
			if (new RegExp(`<<<\\s*"?\\$\\{?${v}\\b`).test(text)) {
				for (const m of text.matchAll(/\bread\s+(?:-[a-z]+\s+)*([A-Za-z_][A-Za-z0-9_ ]*)/g)) {
					for (const n of m[1].trim().split(/\s+/)) {
						add(vars, n);
					}
				}
			}
		}
	}
	return { vars, files };
}

function checkLines(file: string, lines: string[], inRun: (n: number) => boolean, secrets: Set<string>): Finding[] {
	const out: Finding[] = [];
	const t = taint(lines.map((l, i) => inRun(i + 1) ? l.replace(/^\s*(?:-\s+)?run:\s*/, '') : ''), secrets);
	const printsTainted = (l: string) => [...t.vars].some(v => new RegExp(`\\$\\{?${v}\\b`).test(l)) || [...t.files].some(f => /\b(?:cat|tee|head|tail|less|more)\b/.test(l) && l.includes(f));
	lines.forEach((raw, i) => {
		const n = i + 1;
		if (!inRun(n) || ALLOW.test(raw)) {
			return;
		}
		const l = raw.replace(/^\s*(?:-\s+)?run:\s*/, '').replace(/(^|\s)#.*$/, '$1');
		if (/\$\{\{\s*secrets\./.test(l)) {
			out.push({ file, line: n, rule: 'E1' });
		}
		if (DUMP.test(l)) {
			out.push({ file, line: n, rule: 'E2' });
		}
		// An assignment (`Y=$(cat f)`) captures output; it does not print it.
		// Only a line that is solely a capture (`Y=$(cat f)`) prints nothing (R20-2); `X=1; echo …`
		// and `FOO=bar echo …` still do.
		const assignment = /^\s*(?:(?:local|export|readonly|declare(?:\s+-\w+)*)\s+)?[A-Za-z_][A-Za-z0-9_]*=\$\([^;&|]*\)\s*$/.test(l);
		if (!assignment && PRINTS.test(l) && !l.includes('::add-mask::') && (/\btee\b/.test(l) || !TO_FILE.test(l)) && printsTainted(l)) {
			out.push({ file, line: n, rule: 'E3' });
		}
		if (HOST.test(l)) {
			out.push({ file, line: n, rule: 'E4' });
		}
	});
	return out;
}

export function checkWorkflow(file: string, text: string): Finding[] {
	const lines = text.split('\n');
	const run = runLines(lines);
	return checkLines(file, lines, n => run.has(n), secretVars(text));
}

export function checkScript(file: string, text: string, secrets: Set<string>): Finding[] {
	return checkLines(file, text.split('\n'), () => true, secrets);
}

/**
 * S1: no branch-controlled code runs with a repository secret. Jobs are the two-space keys under
 * `jobs:`; a job that reads `secrets.*` must be gated to a push to main by its own `if:` (both
 * conditions, no `||`), run in the `denylist` environment (whose deployment-branch rule admits
 * main only), and check out the pushed ref (no `ref:` override). Triggers that run branch input
 * with secrets, and `secrets: inherit`, are refused anywhere.
 */
export function checkSecretScope(file: string, text: string): Finding[] {
	const out: Finding[] = [];
	const lines = text.split('\n');
	// Any way a context expression can name secrets: case-insensitive, dot, index or toJSON (R22-3).
	const SECRET = /\$\{\{[^}]*\bsecrets\b/i;
	const comment = (l: string) => /^\s*(?:#.*)?$/.test(l);
	lines.forEach((l, i) => {
		if (/^\s*(?:-\s*)?["']?(?:pull_request_target|workflow_run)["']?\s*:?\s*(?:#.*)?$/.test(l) || /\b(?:pull_request_target|workflow_run)\b\s*[:,\]}]/.test(l)) {
			out.push({ file, line: i + 1, rule: 'S1' });
		}
		if (/\bsecrets:\s*inherit\b/.test(l)) {
			out.push({ file, line: i + 1, rule: 'S1' });
		}
	});
	const start = lines.findIndex(l => /^jobs:\s*(?:#.*)?$/.test(l));
	// A secret named outside a recognised job (workflow-level env, a file with no readable jobs
	// section) reaches every job: refused (R22-4).
	const inJob = new Set<number>();
	if (start >= 0) {
		const heads: number[] = [];
		let i = start + 1;
		for (; i < lines.length; i++) {
			const l = lines[i];
			if (comment(l) || /^ {4,}\S/.test(l)) {
				continue;
			}
			if (/^ {2}(?:[A-Za-z0-9_-]+|"[A-Za-z0-9_-]+"|'[A-Za-z0-9_-]+'):\s*(?:#.*)?$/.test(l)) {
				heads.push(i);
				continue;
			}
			if (/^\S/.test(l)) {
				break; // the next top-level key
			}
			// Anything else in the jobs section (a flow mapping, an odd indent) is a job this lint
			// can't read: fail closed (R22-1, R22-2).
			out.push({ file, line: i + 1, rule: 'S1' });
		}
		const end = i;
		heads.forEach((h, k) => {
			const stop = k + 1 < heads.length ? heads[k + 1] : end;
			for (let j = h; j < stop; j++) {
				inJob.add(j);
			}
			const body = lines.slice(h + 1, stop);
			const uses = body.findIndex(l => !comment(l) && SECRET.test(l));
			if (uses < 0) {
				return;
			}
			const cond = body.find(l => /^ {4}if:/.test(l)) ?? '';
			const pushMain = /github\.event_name\s*==\s*'push'/.test(cond) && /github\.ref\s*==\s*'refs\/heads\/main'/.test(cond) && !/\|\||!\s*\(/.test(cond);
			const env = body.some((l, j) => /^ {4}environment:\s*denylist\s*(?:#.*)?$/.test(l)
				|| (/^ {4}environment:\s*$/.test(l) && /^ {6}name:\s*denylist\s*(?:#.*)?$/.test(body[j + 1] ?? '')));
			const ref = body.some(l => /\bref:/.test(l));
			if (!pushMain || !env || ref) {
				out.push({ file, line: h + 2 + uses, rule: 'S1' });
			}
		});
	}
	lines.forEach((l, i) => {
		if (!comment(l) && SECRET.test(l) && !inJob.has(i)) {
			out.push({ file, line: i + 1, rule: 'S1' });
		}
	});
	return out;
}

function selfTest(): number {
	const bad: string[] = [];
	let cases = 0;
	const expect = (name: string, ok: boolean) => { cases++; if (!ok) { bad.push(name); } };
	const wf = (body: string) => `jobs:\n  j:\n    steps:\n      - name: x\n        env:\n          TOKEN: \${{ secrets.T }}\n        run: |\n${body.split('\n').map(l => `          ${l}`).join('\n')}\n      - run: echo done\n`;
	const rules = (t: string) => checkWorkflow('w.yml', t).map(f => f.rule).sort().join();
	expect('clean', rules(wf('build/ci.sh')) === '');
	expect('E1: a secret expression in run', rules(wf('tool --header "x: ${{ secrets.T }}"')) === 'E1');
	expect('E1: a secret bound in env is fine', rules(wf('tool --token-file f')) === '');
	expect('E2: env dump', rules(wf('env')) === 'E2' && rules(wf('env | sort')) === 'E2' && rules(wf('printenv')) === 'E2');
	expect('E2: set and trace', rules(wf('set')) === 'E2' && rules(wf('set -euxo pipefail')) === 'E2' && rules(wf('bash -x x.sh')) === 'E2');
	expect('E2: set -euo pipefail and env VAR=x cmd are fine', rules(wf('set -euo pipefail\nenv FOO=1 tool')) === '');
	expect('E3: echoing a secret-bound variable', rules(wf('echo "$TOKEN"')) === 'E3' && rules(wf('printf %s ${TOKEN} | tee f')) === 'E3');
	expect('E3: masking is fine', rules(wf('echo "::add-mask::$TOKEN"')) === '');
	expect('E3: into a private file is fine, into the step summary is not', rules(wf('printf %s "$TOKEN" >"$dir/list"')) === '' && rules(wf('echo "$TOKEN" >> "$GITHUB_STEP_SUMMARY"')) === 'E3' && rules(wf('echo "$TOKEN" >&2')) === 'E3');
	expect('E4: host data', rules(wf('whoami')) === 'E4' && rules(wf('uname -a')) === 'E4' && rules(wf('cat /etc/resolv.conf')) === 'E4');
	expect('a reasoned lint-allow suppresses', rules(wf('hostname # lint-allow: echo needed for x')) === '');
	expect('a bare lint-allow does not', rules(wf('hostname # lint-allow: echo')) === 'E4');
	expect('outside run: blocks nothing is checked', checkWorkflow('w.yml', 'name: env\non:\n  push:\n').length === 0);
	expect('a one-line run: is checked', rules('jobs:\n  j:\n    steps:\n      - run: printenv\n') === 'E2');
	expect('scripts: a secret var echoed', checkScript('s.sh', 'echo "$DENYLIST"\n', new Set(['DENYLIST'])).length === 1);
	// S1 (round 17, finding 1): the shape that holds, then each way branch code could reach a secret.
	const job = (cond: string, env: string, extra = '') => `on:\n  push:\n  pull_request:\njobs:\n  lint:\n    runs-on: x\n    steps:\n      - run: ./seclab lint\n  denylist:\n${cond}${env}    runs-on: x\n    steps:\n      - uses: actions/checkout@abc\n        with:\n          persist-credentials: false\n${extra}      - env:\n          DENYLIST: \${{ secrets.SECLAB_DENYLIST }}\n        run: build/ci-denylist.sh\n`;
	const okCond = "    if: github.event_name == 'push' && github.ref == 'refs/heads/main'\n";
	const okEnv = '    environment: denylist\n';
	const s1 = (t: string) => checkSecretScope('w.yml', t).length;
	expect('S1: a main-only push job in the denylist environment passes', s1(job(okCond, okEnv)) === 0);
	expect('S1: the environment as a name block passes', s1(job(okCond, '    environment:\n      name: denylist\n')) === 0);
	expect('S1: a secret job with no if blocks', s1(job('', okEnv)) === 1);
	expect('S1: a secret job gated to push only (any branch) blocks', s1(job("    if: github.event_name == 'push'\n", okEnv)) === 1);
	expect('S1: an or-widened condition blocks', s1(job("    if: github.event_name == 'push' && github.ref == 'refs/heads/main' || github.event_name == 'pull_request'\n", okEnv)) === 1);
	expect('S1: a secret job outside the denylist environment blocks', s1(job(okCond, '')) === 1);
	expect('S1: a checkout of another ref blocks', s1(job(okCond, okEnv, '          ref: ${{ github.head_ref }}\n')) === 1);
	expect('S1: a workflow_run trigger blocks', s1(job(okCond, okEnv).replace('  pull_request:\n', '  workflow_run:\n')) === 1);
	expect('S1: a pull_request_target trigger blocks', s1(job(okCond, okEnv).replace('  pull_request:\n', '  pull_request_target:\n')) === 1);
	expect('S1: secrets: inherit blocks', s1(job(okCond, okEnv) + '  call:\n    uses: ./.github/workflows/x.yml\n    secrets: inherit\n') === 1);
	// Round 22: shapes the line reader can't follow fail closed; other spellings are secrets too.
	const evil = '  "evil":\n    runs-on: x\n    steps:\n      - env:\n          X: ${{ secrets.SECLAB_DENYLIST }}\n        run: tool\n';
	expect('R22-2: a quoted job after a compliant one is its own job', s1(job(okCond, okEnv) + evil) === 1);
	expect('R22-1: a column-0 comment does not end the jobs section', s1(job(okCond, okEnv) + '# ---- more jobs ----\n' + evil) === 1);
	expect('R22-1: a flow-mapping job fails closed', s1(job(okCond, okEnv) + '  evil: { runs-on: x, steps: [] }\n') >= 1);
	expect('R22-1: an odd job indent fails closed', s1(job(okCond, okEnv) + '   evil:\n     runs-on: x\n') >= 1);
	expect('R22-1: jobs: with a trailing comment is read', s1(job('', okEnv).replace('jobs:\n', 'jobs: # all\n')) === 1);
	for (const spelling of ['${{ SECRETS.SECLAB_DENYLIST }}', "${{ secrets['SECLAB_DENYLIST'] }}", '${{ toJSON(secrets) }}']) {
		expect(`R22-3: ${spelling} is a secret use`, s1(job('', okEnv).replace('${{ secrets.SECLAB_DENYLIST }}', spelling)) === 1);
	}
	expect('R22-4: a workflow-level secret binding blocks', s1('on:\n  push:\nenv:\n  X: ${{ secrets.T }}\njobs:\n  a:\n    runs-on: x\n') === 1);
	expect('R22-1: with: {ref: …} blocks', s1(job(okCond, okEnv).replace('        with:\n          persist-credentials: false\n', '        with: { ref: x }\n')) === 1);
	// R19-7: taint follows assignments, here-string reads and the temp file the secret is written to.
	const s = new Set(['DENYLIST']);
	expect('taint: through an assignment', checkScript('s.sh', 'X="$DENYLIST"\necho "$X"\n', s).length === 1);
	expect('taint: through a temp file', checkScript('s.sh', 'printf "%s" "$DENYLIST" >"$dir/list"\ncat "$dir/list"\n', s).length === 1);
	expect('taint: a temp file read back into a variable', checkScript('s.sh', 'printf "%s" "$DENYLIST" >"$dir/list"\nY=$(cat "$dir/list")\necho "$Y" >/dev/stderr\n', s).length === 1);
	expect('taint: a here-string read loop', checkScript('s.sh', 'while read -r line; do\n  echo "$line"\ndone <<<"$DENYLIST"\n', s).length === 1);
	expect('taint: masking a derived value is fine', checkScript('s.sh', 'while read -r line; do\n  e="${line%%#*}"\n  echo "::add-mask::$e"\ndone <<<"$DENYLIST"\n', s).length === 0);
	expect('taint: passing the temp file to a tool is fine', checkScript('s.sh', 'printf "%s" "$DENYLIST" >"$dir/list"\ntool --list "$dir/list"\n', s).length === 0);
	// R20-2: an env prefix or a leading assignment does not exempt a print.
	for (const l of ['X=1; echo "$DENYLIST"', 'FOO=bar echo "$DENYLIST"', '  Q=2 && echo "$DENYLIST"', 'X=1 printf "%s" "$DENYLIST"']) {
		expect(`E3: ${l.trim()}`, checkScript('s.sh', l + '\n', s).length === 1);
	}
	// R20-6: head/tail of the temp file print it.
	expect('taint: head of the temp file', checkScript('s.sh', 'printf "%s" "$DENYLIST" >"$dir/list"\nhead -1 "$dir/list"\n', s).length === 1);
	console.log(bad.length ? `workflow-echo self-test FAILED: ${bad.join('; ')}` : `workflow-echo self-test: ${cases} cases OK`);
	return bad.length ? 1 : 0;
}

function main(): number {
	const wfDir = path.join(repo, '.github', 'workflows');
	const findings: Finding[] = [];
	const secrets = new Set<string>();
	for (const f of fs.readdirSync(wfDir).filter(f => /\.ya?ml$/.test(f)).sort()) {
		const text = fs.readFileSync(path.join(wfDir, f), 'utf8');
		secretVars(text).forEach(v => secrets.add(v));
		findings.push(...checkWorkflow(`.github/workflows/${f}`, text), ...checkSecretScope(`.github/workflows/${f}`, text));
	}
	// CI scripts and the shell they source in a secret-bearing job (R19-7).
	const scripts = [
		...fs.readdirSync(path.join(repo, 'build')).filter(f => /^ci-.*\.sh$/.test(f)).map(f => `build/${f}`),
		...fs.readdirSync(path.join(repo, 'build', 'hooks')).filter(f => /\.sh$/.test(f)).map(f => `build/hooks/${f}`),
	].sort();
	for (const f of scripts) {
		findings.push(...checkScript(f, fs.readFileSync(path.join(repo, f), 'utf8'), secrets));
	}
	for (const f of findings) {
		console.error(`workflow-echo: ${f.file}:${f.line}: ${f.rule}`);
	}
	console.log(findings.length ? `workflow-echo: ${findings.length} finding(s)` : 'workflow-echo: clean');
	return findings.length ? 1 : 0;
}

if (import.meta.main) {
	process.exit(process.argv[2] === '--self-test' ? selfTest() : main());
}
