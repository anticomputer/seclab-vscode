/**
 * The decision log's line formatter, as shipped: every line it writes must parse.
 *
 * Run: node test/containment/decision-line.test.ts   (or ./seclab test decision-line)
 *
 * Review round 10 finding 2: the formatter sliced the SERIALIZED line at its byte cap, and
 * `reason` was unbounded tab-chosen text, so a tab could make its own denial records invalid
 * JSON, which every consumer drops. log-throttle.test.ts re-implements the formatter as a
 * model, so it reproduced the slice instead of catching it. This test does not model: it cuts
 * the shipped `line` function and the constants it uses out of seclabRpcFilter.ts and runs
 * them. SECLAB_FILTER_SRC points it at another copy of the source (how the unfixed version was
 * shown to fail).
 */

import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SRC = readFileSync(process.env.SECLAB_FILTER_SRC ?? join(REPO, 'rpc-filter', 'patch-src', 'seclabRpcFilter.ts'), 'utf8');

/** One top-level declaration, cut from the source by its first line and its closing line. */
function cut(start: RegExp, end: string): string {
	const m = start.exec(SRC);
	assert.ok(m, `${start} is missing from seclabRpcFilter.ts`);
	const close = SRC.indexOf(end, m.index);
	assert.ok(close > m.index, `no end for ${start}`);
	return SRC.slice(m.index, close + end.length);
}

const consts = ['SECLAB_LOG_LINE_MAX', 'SECLAB_LOG_REF_MAX', 'SECLAB_LOG_REASON_MAX']
	.map(n => (new RegExp(`const ${n} = [^;]+;`).exec(SRC) ?? [`const ${n} = 0;`])[0]);
const bound = /function seclabBound\(/.test(SRC) ? cut(/function seclabBound\(/, '\n}\n') : '';
const lineFn = cut(/\tconst line = \(d: SeclabDecision\): string => \{/, '\n\t};');
const dir = mkdtempSync(join(tmpdir(), 'seclab-line-'));
const file = join(dir, 'line.ts');
writeFileSync(file, `type SeclabDecision = { surface: string; ref: string; verdict: string; reason?: string; constraint?: string; claimedExtensionId?: string; count?: number };\n${consts.join('\n')}\n${bound}\nexport ${lineFn.trim()}\n`);
const { line } = await import(file) as { line: (d: Record<string, unknown>) => string };
const LINE_MAX = Number(/const SECLAB_LOG_LINE_MAX = (\d+);/.exec(SRC)?.[1]);

const deny = (over: Record<string, unknown> = {}) => ({ surface: 'rpc', ref: 'rpc:MainThreadX.$y', verdict: 'deny', reason: 'policy', ...over });
const parsed = (d: Record<string, unknown>) => {
	const l = line(d);
	assert.ok(l.length <= LINE_MAX, `line is ${l.length} bytes, over ${LINE_MAX}`);
	return JSON.parse(l) as { detail: Record<string, unknown> };
};

const tests: Array<[string, () => void]> = [];
const test = (name: string, fn: () => void) => tests.push([name, fn]);

test('an ordinary denial is written whole', () => {
	const p = parsed(deny());
	assert.equal(p.detail.ref, 'rpc:MainThreadX.$y');
	assert.equal(p.detail.reason, 'policy');
});
test('a 64 KB tab-chosen reason still produces a line that parses, with the decision intact', () => {
	const p = parsed(deny({ reason: 'x'.repeat(64 * 1024) }));
	assert.equal(p.detail.verdict, 'deny');
	assert.equal(p.detail.ref, 'rpc:MainThreadX.$y');
});
test('escaping cannot push a bounded field over the cap: control characters and quotes', () => {
	for (const ch of ['\u0001', '"', '\\', '\n']) {
		const p = parsed(deny({ ref: `rpc:${ch.repeat(300)}`, reason: ch.repeat(64 * 1024), claimedExtensionId: ch.repeat(4096) }));
		assert.equal(p.detail.verdict, 'deny');
	}
});
test('a long claimed extension id and constraint are bounded too', () => {
	const p = parsed(deny({ claimedExtensionId: 'e'.repeat(10_000), constraint: 'c'.repeat(10_000) }));
	assert.ok(String(p.detail.claimedExtensionId).length <= 256);
});

let failed = 0;
for (const [name, fn] of tests) {
	try {
		fn();
		console.log(`ok   ${name}`);
	} catch (err) {
		failed++;
		console.error(`FAIL ${name}\n     ${(err as Error).message}`);
	}
}
console.log(`\n${tests.length - failed}/${tests.length} passed`);
process.exit(failed ? 1 : 0);
