// Source check for what ships (EDR patch-series, review PG-1): first-party code in the
// release must not contain test hooks. Scans the shipped sources (extensions listed in
// extensions/series, and tabd/src which ships inside the Tab Manager) for:
//   - process.env access: only at reviewed sites (build/source-allowlist.txt)
//   - child_process / spawn / exec / fork: only at reviewed sites
//   - dynamic module loading: require()/import() with a non-literal argument, createRequire,
//     module.require, new Function, node:vm -> never allowed
//   - SECLAB_TEST_ONLY markers -> never allowed in shipped sources
// Usage: node build/check-source.ts      exit 0 clean, 1 findings ("file:line: rule: text")
// Allowlist lines: "<file>:<rule>:<exact trimmed source line>" (reviewed; churn is intended).

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

const repo = path.resolve(import.meta.dirname, '..');

/** Problems with what will be scanned: an empty extensions/series scans only tabd/src
 *  (GATE-16), and an empty patches/series scans no patch line (review FBA-4). */
export function rootProblems(series: string[], patches: string[], exists: (rel: string) => boolean): string[] {
	const p: string[] = [];
	if (series.length === 0) {
		p.push('extensions/series lists no extension, so no shipped extension would be scanned');
	}
	for (const n of series) {
		if (!exists(path.join('extensions', n, 'src'))) {
			p.push(`extensions/series names ${n}, but extensions/${n}/src doesn't exist`);
		}
	}
	if (patches.length === 0) {
		p.push('patches/series lists no patch, so no core patch line would be scanned');
	}
	for (const n of patches) {
		if (!exists(path.join('patches', n))) {
			p.push(`patches/series names ${n}, but patches/${n} doesn't exist`);
		}
	}
	return p;
}
const listOf = (root: string, rel: string) => fs.readFileSync(path.join(root, rel), 'utf8').split('\n').map(l => l.replace(/#.*/, '').trim()).filter(Boolean);
/** The run's starting findings for a checkout: what the scan below begins with. */
export function initialFindings(root: string): string[] {
	return rootProblems(listOf(root, 'extensions/series'), listOf(root, 'patches/series'), rel => fs.existsSync(path.join(root, rel)));
}
if (process.argv[2] === '--self-test') {
	// The wiring too: a checkout whose series are empty starts with findings (FBA-4).
	const fake = fs.mkdtempSync(path.join(os.tmpdir(), 'check-source-self-test-'));
	fs.mkdirSync(path.join(fake, 'extensions'));
	fs.mkdirSync(path.join(fake, 'patches'));
	fs.writeFileSync(path.join(fake, 'extensions', 'series'), '# none\n');
	fs.writeFileSync(path.join(fake, 'patches', 'series'), '# none\n');
	const wired = initialFindings(fake);
	fs.rmSync(fake, { recursive: true, force: true });
	const cases: Array<[string, boolean]> = [
		['an empty extensions/series fails (GATE-16)', rootProblems([], ['0001-x.patch'], () => true).length === 1],
		['a series entry with no src dir fails', rootProblems(['seclab-x'], ['0001-x.patch'], rel => !rel.startsWith('extensions')).length === 1],
		['an empty patches/series fails (FBA-4)', rootProblems(['seclab-tab-manager'], [], () => true).length === 1],
		['a patches/series entry with no file fails', rootProblems(['seclab-tab-manager'], ['0001-x.patch'], rel => !rel.startsWith('patches')).length === 1],
		['a checkout with empty series starts with both findings (the wiring the run uses)', wired.length === 2],
		['a real series passes', rootProblems(['seclab-tab-manager'], ['0001-x.patch'], () => true).length === 0],
		['this checkout passes', initialFindings(repo).length === 0],
	];
	const failed = cases.filter(([, ok]) => !ok).map(([n]) => n);
	console.log(failed.length ? `check-source self-test FAILED: ${failed.join(', ')}` : `check-source self-test: ${cases.length} cases OK`);
	process.exit(failed.length ? 1 : 0);
}

const series = listOf(repo, 'extensions/series');
const roots = [...series.map(n => path.join('extensions', n, 'src')), 'tabd/src'];
const allow = new Set(fs.readFileSync(path.join(repo, 'build', 'source-allowlist.txt'), 'utf8').split('\n').map(l => l.replace(/^#.*/, '').trim()).filter(Boolean));

const RULES: Array<{ id: string; re: RegExp; reviewable: boolean }> = [
	{ id: 'env', re: /\bprocess\.env\b|\bprocess\[['"`]env['"`]\]|\{\s*env\s*\}\s*=\s*process\b/, reviewable: true },
	{ id: 'process-spawn', re: /^import\s+(?!type\b)[^;]*['"](node:)?child_process['"]|\brequire\(\s*['"](node:)?child_process['"]\)|(?<![.\w])(spawn|spawnSync|execFile|execFileSync|execSync|exec|fork)\s*\(/, reviewable: true },
	{ id: 'dynamic-load', re: /\b(require|import)\(\s*(?!(['"`])[^'"`$]*\2\s*\))|\bcreateRequire\b|\bmodule\.require\b|\bnew\s+Function\b|\bnode:vm\b|\brequire\(\s*['"`]vm['"`]\)/, reviewable: false },
	{ id: 'test-marker', re: /SECLAB_TEST_ONLY|seclab-test-hook/, reviewable: false },
];

const findings: string[] = initialFindings(repo);
const used = new Set<string>();
function scanLines(rel: string, lines: Array<[number, string]>): void {
	for (const [n, raw] of lines) {
		const line = raw.trim();
		if (line.startsWith('//') || line.startsWith('*') || line.startsWith('/*')) {
			continue; // comments
		}
		for (const r of RULES) {
			if (!r.re.test(line)) {
				continue;
			}
			const key = `${rel}:${r.id}:${line}`;
			if (r.reviewable && allow.has(key)) {
				used.add(key);
				continue;
			}
			findings.push(`${rel}:${n}: ${r.id}${r.reviewable ? ' (not in build/source-allowlist.txt)' : ''}: ${line.slice(0, 140)}`);
		}
	}
}
function scan(file: string): void {
	scanLines(path.relative(repo, file), fs.readFileSync(file, 'utf8').split('\n').map((l, i) => [i + 1, l]));
}
function walk(p: string): void {
	const st = fs.statSync(p); // follows the tabd-src symlink on purpose: it ships
	if (st.isDirectory()) {
		for (const e of fs.readdirSync(p)) {
			walk(path.join(p, e));
		}
	} else if (/\.(ts|js|mjs|cjs)$/.test(p)) {
		scan(p);
	}
}
for (const r of roots) {
	walk(path.join(repo, r));
}
// Core patches ship too (review UU-3): the lines each patch in patches/series adds.
const patches = listOf(repo, 'patches/series');
for (const p of patches) {
	const rel = path.join('patches', p);
	scanLines(rel, fs.readFileSync(path.join(repo, rel), 'utf8').split('\n')
		.map((l, i): [number, string] => [i + 1, l]).filter(([, l]) => l.startsWith('+') && !l.startsWith('+++')).map(([n, l]) => [n, l.slice(1)]));
}
for (const k of allow) {
	if (!used.has(k)) {
		findings.push(`build/source-allowlist.txt: stale entry (no longer matches): ${k.slice(0, 160)}`);
	}
}
for (const f of findings) {
	console.log(f);
}
console.log(findings.length ? `check-source: ${findings.length} finding(s)` : `check-source: clean (${roots.join(', ')}, ${patches.length} patches)`);
process.exit(findings.length ? 1 : 0);
