// Regressions for review VV-6: comments and type-only imports don't create reach edges.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { runtimeSpecs } from './patch-reach-imports.ts';

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
