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
import * as path from 'node:path';

const repo = path.resolve(import.meta.dirname, '..');
const series = fs.readFileSync(path.join(repo, 'extensions', 'series'), 'utf8').split('\n').map(l => l.replace(/#.*/, '').trim()).filter(Boolean);
const roots = [...series.map(n => path.join('extensions', n, 'src')), 'tabd/src'];
const allow = new Set(fs.readFileSync(path.join(repo, 'build', 'source-allowlist.txt'), 'utf8').split('\n').map(l => l.replace(/^#.*/, '').trim()).filter(Boolean));

const RULES: Array<{ id: string; re: RegExp; reviewable: boolean }> = [
	{ id: 'env', re: /\bprocess\.env\b|\bprocess\[['"`]env['"`]\]|\{\s*env\s*\}\s*=\s*process\b/, reviewable: true },
	{ id: 'process-spawn', re: /^import\s+(?!type\b)[^;]*['"](node:)?child_process['"]|\brequire\(\s*['"](node:)?child_process['"]\)|(?<![.\w])(spawn|spawnSync|execFile|execFileSync|execSync|exec|fork)\s*\(/, reviewable: true },
	{ id: 'dynamic-load', re: /\b(require|import)\(\s*(?!(['"`])[^'"`$]*\2\s*\))|\bcreateRequire\b|\bmodule\.require\b|\bnew\s+Function\b|\bnode:vm\b|\brequire\(\s*['"`]vm['"`]\)/, reviewable: false },
	{ id: 'test-marker', re: /SECLAB_TEST_ONLY|seclab-test-hook/, reviewable: false },
];

const findings: string[] = [];
const used = new Set<string>();
function scan(file: string): void {
	const rel = path.relative(repo, file);
	fs.readFileSync(file, 'utf8').split('\n').forEach((raw, i) => {
		const line = raw.trim();
		if (line.startsWith('//') || line.startsWith('*') || line.startsWith('/*')) {
			return; // comments
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
			findings.push(`${rel}:${i + 1}: ${r.id}${r.reviewable ? ' (not in build/source-allowlist.txt)' : ''}: ${line.slice(0, 140)}`);
		}
	});
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
for (const k of allow) {
	if (!used.has(k)) {
		findings.push(`build/source-allowlist.txt: stale entry (no longer matches): ${k.slice(0, 160)}`);
	}
}
for (const f of findings) {
	console.log(f);
}
console.log(findings.length ? `check-source: ${findings.length} finding(s)` : `check-source: clean (${roots.join(', ')})`);
process.exit(findings.length ? 1 : 0);
