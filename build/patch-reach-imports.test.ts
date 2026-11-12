// Regressions for review VV-6 and VV-7 (import edges) and for the patch-header report from the
// RPC session (`diff -ruN` headers skipped): the real script runs on a synthetic upstream tree.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { test } from 'node:test';
import { patchedFiles, runtimeSpecs } from './patch-reach-imports.ts';

test('runtime imports are edges', () => {
	assert.deepEqual(runtimeSpecs([
		`import { A } from './a.js';`,
		`import * as B from './b.js';`,
		`import './c.js';`,
		`export { D } from './d.js';`,
		`export * from './e.js';`,
		`const f = await import('./f.js');`,
		`import { type G, H } from './gh.js';`,
	].join('\n')), ['./a.js', './b.js', './c.js', './d.js', './e.js', './f.js', './gh.js']);
});

test('commented-out imports are not edges', () => {
	assert.deepEqual(runtimeSpecs([
		`// import { A } from './a.js';`,
		`/* import './b.js';`,
		`   export * from './c.js'; */`,
		`const s = '// not a comment'; import { D } from './d.js';`,
	].join('\n')), ['./d.js']);
});

test('type-only imports and exports are not edges', () => {
	assert.deepEqual(runtimeSpecs([
		`import type { A } from './a.js';`,
		`export type { B } from './b.js';`,
		`import { type C, type D as E } from './cd.js';`,
		`import type * as F from './f.js';`,
	].join('\n')), []);
});

test('import-like text inside string and template literals is not an edge (VV-7)', () => {
	assert.deepEqual(runtimeSpecs([
		`const a = "import './a.js'";`,
		`const b = ' import("./b.js") ';`,
		'const c = `',
		`import { C } from './c.js';`,
		'${x}`;',
		`import { D } from './d.js';`,
	].join('\n')), ['./d.js']);
});

const header = (style: 'git' | 'diff', file: string) => style === 'git'
	? `diff --git a/${file} b/${file}\nindex 1111111..2222222 100644\n--- a/${file}\n+++ b/${file}\n`
	: `diff -ruN a/${file} b/${file}\n--- a/${file}\t2026-11-05 13:58:33.000000000 +0000\n+++ b/${file}\t2026-11-05 13:58:33.000000000 +0000\n`;
const hunk = '@@ -1 +1,2 @@\n export const x = 1;\n+export const y = 2;\n';

test('patch headers: git and diff -ruN styles, deletions, unreadable headers fail', () => {
	for (const style of ['git', 'diff'] as const) {
		assert.deepEqual(patchedFiles(header(style, 'src/vs/a.ts') + hunk + header(style, 'build/b.ts') + hunk), ['src/vs/a.ts', 'build/b.ts']);
	}
	assert.deepEqual(patchedFiles('--- a/src/vs/gone.ts\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n'), []);
	assert.deepEqual(patchedFiles(header('git', 'src/vs/a.ts') + '@@ -1 +1,2 @@\n x\n+++ added line that looks like a header\n'), ['src/vs/a.ts']);
	assert.throws(() => patchedFiles('--- vscode.orig/src/vs/a.ts\n+++ vscode/src/vs/a.ts\n'), /unreadable patch header/);
	assert.throws(() => patchedFiles('--- a/x\n+++ b/src/../../etc/x.ts\n'), /unreadable patch header/);
	// WW-5: renames and copies without ---/+++ headers, deletions, binary and unpaired headers.
	assert.deepEqual(patchedFiles('diff --git a/src/vs/agent.ts b/src/vs/moved.ts\nsimilarity index 100%\nrename from src/vs/agent.ts\nrename to src/vs/moved.ts\n'), ['src/vs/moved.ts']);
	assert.deepEqual(patchedFiles('diff --git a/src/vs/agent.ts b/src/vs/copy.ts\nsimilarity index 100%\ncopy from src/vs/agent.ts\ncopy to src/vs/copy.ts\n'), ['src/vs/copy.ts']);
	assert.deepEqual(patchedFiles('diff --git a/src/vs/x.ts b/src/vs/x.ts\nold mode 100644\nnew mode 100755\n'), ['src/vs/x.ts']);
	assert.deepEqual(patchedFiles('diff --git a/src/vs/x.ts b/src/vs/x.ts\ndeleted file mode 100644\nindex 1..0\n--- a/src/vs/x.ts\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n'), []);
	assert.throws(() => patchedFiles('diff --git a/src/vs/x.ts b/src/vs/x.ts\nGIT binary patch\nliteral 1\n'), /unreadable patch header/);
	assert.throws(() => patchedFiles('+++ b/src/vs/x.ts\n'), /unreadable patch header/);
	assert.throws(() => patchedFiles('diff --git "a/src/vs/x y.ts" "b/src/vs/x y.ts"\n'), /unreadable patch header/);
	// Hunk content that looks like headers is consumed by the hunk's line counts.
	assert.deepEqual(patchedFiles(header('git', 'src/vs/a.ts') + '@@ -1,2 +1,2 @@\n--- a/src/vs/evil.ts\n+++ b/src/vs/evil.ts\n x\n'), ['src/vs/a.ts']);
});

// A minimal upstream tree: desktop, server and web entry points read from the same places the
// real script reads them, a module only web reaches, and one desktop reaches.
const scratch = path.join(import.meta.dirname, '..', '.work', 'test-scratch', `reach-${process.pid}`);
const write = (rel: string, text: string) => {
	fs.mkdirSync(path.dirname(path.join(scratch, rel)), { recursive: true });
	fs.writeFileSync(path.join(scratch, rel), text);
};
// Both policy files are required (GATE-2/3); by default the helper writes minimal valid ones.
const DEFAULT_REACH = { '0001-x.patch': ['desktop'] };
const DEFAULT_UNREACHABLE = { desktop: { deny: ['src/vs/webonly.ts'] } };
const runReach = (patch: string, reach: object | null = DEFAULT_REACH, unreachable: object | string | null = DEFAULT_UNREACHABLE) => {
	const pdir = path.join(scratch, 'patches');
	fs.rmSync(pdir, { recursive: true, force: true });
	fs.mkdirSync(pdir, { recursive: true });
	fs.writeFileSync(path.join(pdir, 'series'), '0001-x.patch\n');
	fs.writeFileSync(path.join(pdir, '0001-x.patch'), patch);
	if (reach) {
		fs.writeFileSync(path.join(pdir, 'reach.json'), JSON.stringify(reach));
	}
	if (unreachable !== null) {
		fs.writeFileSync(path.join(pdir, 'unreachable.json'), typeof unreachable === 'string' ? unreachable : JSON.stringify(unreachable));
	}
	return spawnSync(process.execPath, [path.join(import.meta.dirname, 'check-patch-reach.ts'), path.join(scratch, 'tree'), '--patches', pdir], { encoding: 'utf8' });
};

test('check-patch-reach: a web-only file fails and a desktop file passes, in both header styles', () => {
	fs.rmSync(scratch, { recursive: true, force: true });
	try {
		write('tree/build/next/index.ts', [
			`const workerEntryPoints = ['vs/w1', 'vs/w2', 'vs/w3'];`,
			`const desktopWorkerEntryPoints = [];`,
			`const desktopEntryPoints = ['vs/desk'];`,
			`const codeEntryPoints = [];`,
			`const serverEntryPoints = ['vs/srv'];`,
			`const webOnlyEntryPoints = ['vs/webmain'];`,
		].join('\n'));
		write('tree/build/lib/esbuild.ts', `switch (t) {\n\tcase 'desktop': return ['vs/boot1', 'vs/boot2'];\n\tcase 'server': return ['vs/sboot1', 'vs/sboot2'];\n}\n`);
		for (const ep of ['w1', 'w2', 'w3', 'boot1', 'boot2', 'sboot1', 'sboot2', 'srv']) {
			write(`tree/src/vs/${ep}.ts`, 'export {};\n');
		}
		write('tree/src/vs/desk.ts', `import './shared.js';\n`);
		write('tree/src/vs/webmain.ts', `import './webonly.js';\n`);
		write('tree/src/vs/workbench/workbench.web.main.internal.ts', `import '../webonly.js';\n`);
		write('tree/src/vs/shared.ts', 'export const s = 1;\n');
		write('tree/src/vs/webonly.ts', 'export const w = 1;\n');
		for (const style of ['git', 'diff'] as const) {
			const web = runReach(header(style, 'src/vs/webonly.ts') + hunk);
			assert.equal(web.status, 1, `${style}: web-only file must fail\n${web.stdout}${web.stderr}`);
			assert.match(web.stderr, /webonly\.ts is not reachable from the desktop build or the REH/);
			const desk = runReach(header(style, 'src/vs/shared.ts') + hunk, { '0001-x.patch': ['desktop'] });
			assert.equal(desk.status, 0, `${style}: desktop file must pass\n${desk.stdout}${desk.stderr}`);
			assert.match(desk.stdout, /ok \(1 patched files/);
			const srv = runReach(header(style, 'src/vs/shared.ts') + hunk, { '0001-x.patch': ['server'] });
			assert.equal(srv.status, 1, `${style}: reach.json server requirement must fail\n${srv.stdout}${srv.stderr}`);
		}
		const bad = runReach('--- vscode.orig/src/vs/shared.ts\n+++ vscode/src/vs/shared.ts\n' + hunk);
		assert.equal(bad.status, 1);
		assert.match(bad.stderr, /unreadable patch header/);
		// unreachable.json: desktop reaching a forbidden module fails (file or `dir/` prefix, WW-6);
		// `except` exempts one module; a missing listed path fails.
		write('tree/src/vs/agent/a.ts', 'export {};\n');
		write('tree/src/vs/agent/worker.ts', 'export {};\n');
		const ok = header('git', 'src/vs/shared.ts') + hunk;
		const pdir = path.join(scratch, 'patches');
		const runWith = (forbid: object) => {
			runReach(ok);
			fs.writeFileSync(path.join(pdir, 'unreachable.json'), JSON.stringify(forbid));
			return spawnSync(process.execPath, [path.join(import.meta.dirname, 'check-patch-reach.ts'), path.join(scratch, 'tree'), '--patches', pdir], { encoding: 'utf8' });
		};
		assert.equal(runWith({ desktop: { deny: ['src/vs/agent/a.ts', 'src/vs/agent/'] } }).status, 0, 'unreached forbidden modules pass');
		write('tree/src/vs/desk.ts', `import './shared.js';\nimport './agent/worker.js';\n`);
		const byPrefix = runWith({ desktop: { deny: ['src/vs/agent/'] } });
		assert.equal(byPrefix.status, 1);
		assert.match(byPrefix.stderr, /agent\/worker\.ts must not be reachable from desktop/);
		assert.equal(runWith({ desktop: { deny: ['src/vs/agent/'], except: ['src/vs/agent/worker.ts'] } }).status, 0, 'except exempts one module');
		write('tree/src/vs/desk.ts', `import './shared.js';\nimport './agent/worker.js';\nimport './agent/a.js';\n`);
		const byFile = runWith({ desktop: { deny: ['src/vs/agent/a.ts'] } });
		assert.equal(byFile.status, 1);
		assert.match(byFile.stderr, /agent\/a\.ts must not be reachable from desktop/);
		const missing = runWith({ desktop: { deny: ['src/vs/renamed/'] } });
		assert.equal(missing.status, 1);
		assert.match(missing.stderr, /renamed\/ does not exist/);
		assert.equal(runWith({ desktop: ['src/vs/agent/a.ts'] }).status, 1, 'the old array format is refused');
		// GATE-2/3: each policy file missing, unparseable or empty fails, never reads as "nothing
		// to check"; unreachable.json must deny something for desktop (I8).
		write('tree/src/vs/desk.ts', `import './shared.js';\n`);
		assert.equal(runReach(ok).status, 0, 'baseline: both files valid');
		const cases: Array<[string, object | null, object | string | null, RegExp]> = [
			['reach.json missing', null, DEFAULT_UNREACHABLE, /reach\.json is required/],
			['reach.json unparseable', null, DEFAULT_UNREACHABLE, /reach\.json is required/],
			['reach.json empty', {}, DEFAULT_UNREACHABLE, /reach\.json must be a non-empty JSON object/],
			['unreachable.json missing', DEFAULT_REACH, null, /unreachable\.json is required/],
			['unreachable.json unparseable', DEFAULT_REACH, '{"desktop":', /unreachable\.json is required/],
			['unreachable.json empty', DEFAULT_REACH, {}, /unreachable\.json must be a non-empty JSON object/],
			['unreachable.json without desktop', DEFAULT_REACH, { server: { deny: ['src/vs/webonly.ts'] } }, /must deny at least one module for desktop/],
			['unreachable.json with an empty desktop deny', DEFAULT_REACH, { desktop: { deny: [] } }, /must deny at least one module for desktop/],
		];
		for (const [what, reach, unreachable, want] of cases) {
			const r = what === 'reach.json unparseable'
				? (() => { runReach(ok, null, unreachable); fs.writeFileSync(path.join(pdir, 'reach.json'), '{"0001-x.patch": ['); return spawnSync(process.execPath, [path.join(import.meta.dirname, 'check-patch-reach.ts'), path.join(scratch, 'tree'), '--patches', pdir], { encoding: 'utf8' }); })()
				: runReach(ok, reach, unreachable);
			assert.equal(r.status, 1, `${what} must fail\n${r.stdout}${r.stderr}`);
			assert.match(r.stderr, want, what);
		}
	} finally {
		fs.rmSync(scratch, { recursive: true, force: true });
	}
});
