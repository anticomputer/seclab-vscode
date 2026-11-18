/**
 * Patch 0052: a tab's extension host sends one file's text matches in pieces small enough for
 * the RPC filter (PR review on #52). Upstream batches whole files, so a file with more matching
 * lines than tabTextMatches accepts had its whole batch refused, and the results went missing.
 *
 * This runs upstream's own collector (`TextSearchResultsCollector` and `BatchedCollector`, from
 * the pinned checkout's textSearchManager.ts), unpatched as the control and with 0052's hunks
 * applied, on one file with more matches than the bound. That part of the file needs only
 * `resources.isEqual` and `TextSearchMatch2`, which are supplied here.
 *
 * Run: ./seclab test search-split   (mounts the pinned file; SECLAB_TEXT_SEARCH_MANAGER points at it)
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const UPSTREAM = process.env.SECLAB_TEXT_SEARCH_MANAGER;
if (!UPSTREAM) {
	console.error('search-split: set SECLAB_TEXT_SEARCH_MANAGER to the pinned textSearchManager.ts (./seclab test search-split does)');
	process.exit(1);
}
const PATCH = readFileSync(join(REPO, 'patches', '0052-seclab-split-large-text-matches.patch'), 'utf8');
const VALIDATORS = readFileSync(join(REPO, 'rpc-filter', 'patch-src', 'seclabArgValidators.ts'), 'utf8');

/** Apply a one-file unified diff by replacing each hunk's old lines with its new lines, exactly once. */
function applyPatch(source: string, patch: string): string {
	let out = source;
	for (const hunk of patch.split(/\n(?=@@ )/).slice(1)) {
		const lines = hunk.split('\n').slice(1).filter(l => l.length > 0);
		const old = lines.filter(l => l[0] === ' ' || l[0] === '-').map(l => l.slice(1)).join('\n');
		const neu = lines.filter(l => l[0] === ' ' || l[0] === '+').map(l => l.slice(1)).join('\n');
		assert.equal(out.split(old).length - 1, 1, 'a 0052 hunk no longer applies to the pinned file');
		out = out.replace(old, neu);
	}
	return out;
}

class TextSearchMatch2 {
	readonly uri: unknown;
	readonly ranges: unknown[];
	readonly previewText: string;
	constructor(uri: unknown, ranges: unknown[], previewText: string) {
		this.uri = uri;
		this.ranges = ranges;
		this.previewText = previewText;
	}
}

/** The collector section of textSearchManager.ts, run with what it needs. */
function collectorFrom(source: string): { TextSearchResultsCollector: new (cb: (items: Array<{ resource: unknown; results: unknown[] }>) => void) => { add(data: unknown, folderIdx: number): void; flush(): void } } {
	const start = source.search(/\n(\/\*\*\n \* seclab: the most results|export class TextSearchResultsCollector)/);
	assert.ok(start > 0, 'the collector is no longer where this test looks for it');
	const js = stripTypeScriptTypes(source.slice(start), { mode: 'transform' }).replace(/^export /gm, '');
	const resources = { isEqual: (a: unknown, b: unknown) => a === b };
	return new Function('resources', 'TextSearchMatch2', `${js}\nreturn { TextSearchResultsCollector };`)(resources, TextSearchMatch2);
}

function run(source: string, count: number): Array<{ resource: unknown; results: unknown[] }> {
	const items: Array<{ resource: unknown; results: unknown[] }> = [];
	const { TextSearchResultsCollector } = collectorFrom(source);
	const c = new TextSearchResultsCollector(batch => items.push(...batch));
	const uri = { path: '/w/big.txt' };
	for (let i = 0; i < count; i++) {
		c.add(new TextSearchMatch2(uri, [], `line ${i}`), 0);
	}
	c.flush();
	return items;
}

const bound = Number(/const MAX_TEXT_MATCHES = (\d+);/.exec(VALIDATORS)?.[1]);
const upstream = readFileSync(UPSTREAM, 'utf8');
const tests: Array<[string, () => void]> = [
	['0052 splits at exactly the bound the filter accepts', () => {
		assert.ok(bound > 0, 'MAX_TEXT_MATCHES not found in seclabArgValidators.ts');
		assert.equal(Number(/const SECLAB_MAX_RESULTS_PER_MATCH = (\d+);/.exec(PATCH)?.[1]), bound);
	}],
	['control: upstream sends a large file as one match, over the bound', () => {
		const items = run(upstream, bound * 2 + 1);
		assert.equal(items.length, 1);
		assert.equal(items[0].results.length, bound * 2 + 1);
	}],
	['a large single file arrives in matches within the bound, every result kept in order (review on #52)', () => {
		const items = run(applyPatch(upstream, PATCH), bound * 2 + 1);
		assert.ok(items.length >= 3, `${items.length} matches`);
		assert.ok(items.every(m => m.results.length > 0 && m.results.length <= bound), items.map(m => m.results.length).join(','));
		assert.ok(items.every(m => m.resource === items[0].resource));
		const all = items.flatMap(m => m.results as Array<{ previewText: string }>);
		assert.equal(all.length, bound * 2 + 1);
		assert.ok(all.every((r, i) => r.previewText === `line ${i}`), 'results out of order or changed');
	}],
	['mutant: without the bound in the condition, the large file is one match again', () => {
		const patched = applyPatch(upstream, PATCH);
		const cond = ' || this._currentFileMatch.results!.length >= SECLAB_MAX_RESULTS_PER_MATCH';
		assert.equal(patched.split(cond).length - 1, 1, 'mutant no longer applies; update it');
		assert.equal(run(patched.replace(cond, ''), bound * 2 + 1).length, 1);
	}],
];

let failed = 0;
for (const [name, fn] of tests) {
	try {
		fn();
		console.log(`ok   ${name}`);
	} catch (err) {
		failed++;
		console.log(`FAIL ${name}\n     ${(err as Error).message.split('\n')[0]}`);
	}
}
console.log(`\n${tests.length - failed}/${tests.length} passed`);
process.exit(failed ? 1 : 0);
