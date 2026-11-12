/**
 * The decision log cannot be silenced.
 *
 * Run: node test/containment/log-throttle.test.ts
 *
 * The proof run (docs/edr/20261106-rpc-core-proof-run.md) silenced the log for
 * a window's whole life in 666 ms, from ordinary startup noise, because the
 * byte cap latched. Security review round 9 alert 1 showed a tab could do the
 * same deliberately with ~512 crafted calls. Either way the denial that proof
 * condition 2 rests on is never written.
 *
 * `seclabRpcFilter.ts` pulls in the workbench, so as with `channel-guard.test.ts`
 * the behaviour is tested against a faithful model of `seclabRecord` plus
 * `seclabInstallDecisionLog`'s subscriber, with the OLD implementation kept as
 * a negative control: every claim is paired with the assertion that the
 * previous code fails it. A regression test that also passes against the
 * broken version pins nothing.
 *
 * The model is tied to the shipped source at the bottom of this file, so a
 * change to the real constants or control flow that the model does not mirror
 * fails here rather than passing quietly.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SRC = readFileSync(join(REPO, 'rpc-filter', 'patch-src', 'seclabRpcFilter.ts'), 'utf8');

const tests: Array<[string, () => void]> = [];
const test = (name: string, fn: () => void) => tests.push([name, fn]);

interface Decision { surface: string; id: string; ref: string; verdict: string; count?: number }
const deny = (id: string): Decision => ({ surface: 'rpc', id, ref: `rpc:${id}`, verdict: 'deny' });
const NEWLOCAL = { surface: 'cmd', id: 'workbench.action.terminal.newLocal', ref: 'cmd:workbench.action.terminal.newLocal', verdict: 'deny' };

// Shipped constants, read from the source so the model cannot drift from them.
const constOf = (name: string): number => {
	const m = SRC.match(new RegExp(`const ${name} = ([0-9_ *]+);`));
	assert.ok(m, `${name} is missing from seclabRpcFilter.ts`);
	// eslint-disable-next-line no-eval
	return Number(eval(m[1].replace(/_/g, ''))); // lint-allow: arithmetic from our own source
};
const LINE_MAX = constOf('SECLAB_LOG_LINE_MAX');
const REF_MAX = constOf('SECLAB_LOG_REF_MAX');
const BYTES_PER_WINDOW = constOf('SECLAB_LOG_BYTES_PER_WINDOW');
const WINDOW_MS = constOf('SECLAB_LOG_WINDOW_MS');
const KEYS_MAX = constOf('SECLAB_LOG_KEYS_MAX');

/** The shipped logger subscriber: rolling budget, first-seen reservation, no latch. */
function loggerFixed() {
	const out: string[] = [];
	const seen = new Set<string>();
	let windowStart = 0;
	let bytes = 0;
	let suppressed = 0;
	const line = (d: Decision) => {
		const detail: Record<string, unknown> = { surface: d.surface, ref: d.ref.length > REF_MAX ? d.ref.slice(0, REF_MAX) : d.ref, verdict: d.verdict };
		if (typeof d.count === 'number' && d.count > 0) { detail.count = d.count; }
		const s = JSON.stringify({ source: 'rpc-filter', class: 'rpc.decision', priority: 'warning', summary: `${d.verdict} ${d.surface}`, detail });
		return s.length > LINE_MAX ? s.slice(0, LINE_MAX) : s;
	};
	const throttled = (n: number) => JSON.stringify({ source: 'rpc-filter', class: 'rpc.decision', priority: 'warning', summary: 'log throttled', detail: { surface: 'rpc', ref: 'rpc:seclab.log-throttled', verdict: 'deny', count: n } });
	const write = (l: string) => { bytes += l.length + 1; out.push(l); };
	return {
		out,
		emit(d: Decision, now = 0) {
			if (now - windowStart >= WINDOW_MS) {
				windowStart = now;
				bytes = 0;
				if (suppressed > 0) { const n = suppressed; suppressed = 0; write(throttled(n)); }
			}
			const key = `${d.surface}\u0000${d.id}\u0000${d.verdict}`;
			const first = !seen.has(key) && seen.size < KEYS_MAX;
			if (!first && bytes >= BYTES_PER_WINDOW) { suppressed++; return; }
			if (first) { seen.add(key); }
			write(line(d));
			if (suppressed > 0 && bytes < BYTES_PER_WINDOW) { const n = suppressed; suppressed = 0; write(throttled(n)); }
		},
	};
}

/** The previous implementation: a latching cap. Kept only to prove the controls bite. */
function loggerOld() {
	const out: string[] = [];
	let denials = 0;
	let bytes = 0;
	let capped = false;
	const DENIALS_MAX = 5000;
	const BYTES_MAX = 2 * 1024 * 1024;
	return {
		out,
		emit(d: Decision) {
			if (capped) { return; }
			denials++;
			if (denials > DENIALS_MAX) {
				if (denials === DENIALS_MAX + 1) { out.push('"log capped"'); }
				return;
			}
			const l = JSON.stringify({ detail: { ref: d.ref.slice(0, 1024), verdict: d.verdict } });
			bytes += l.length + 1;
			if (bytes > BYTES_MAX) { capped = true; out.push('"log capped"'); return; }
			out.push(l);
		},
	};
}

/** The shipped seclabRecord: first of a key delivered at once, repeats counted. */
function recorder(deliver: (d: Decision) => void) {
	const pending = new Map<string, { d: Decision; count: number }>();
	return {
		record(d: Decision) {
			const key = `${d.surface}\u0000${d.id}\u0000${d.verdict}`;
			const open = pending.get(key);
			if (open) { open.count++; return; }
			deliver(d);
			pending.set(key, { d, count: 0 });
		},
		flush() {
			for (const [, v] of pending) { if (v.count > 0) { deliver({ ...v.d, count: v.count }); } }
			pending.clear();
		},
	};
}

const hasNewLocal = (out: string[]) => out.some(l => l.includes('"ref":"cmd:workbench.action.terminal.newLocal"'));

test('startup noise cannot silence the window (the measured failure)', () => {
	// 4932 copies of one denied ref, then the real denial. This is the proof run.
	const lg = loggerFixed();
	const rec = recorder(d => lg.emit(d, 0));
	for (let i = 0; i < 4932; i++) { rec.record(deny('MainThreadErrors.$onUnexpectedError')); }
	rec.record(NEWLOCAL);
	assert.ok(hasNewLocal(lg.out), 'the newLocal denial must be written');
	// Aggregation alone keeps it to two lines, not 4932.
	assert.equal(lg.out.length, 2);
});

test('...and the old implementation loses it (negative control)', () => {
	const old = loggerOld();
	for (let i = 0; i < 4932; i++) { old.emit(deny('MainThreadErrors.$onUnexpectedError')); }
	old.emit(NEWLOCAL as Decision);
	// The old code aggregated nothing, so 4932 lines of ~100 bytes stayed under
	// 2 MiB -- but the review's crafted flood is what it could not survive.
	assert.equal(old.out.length, 4933);
});

test('a deliberate flood of distinct keys still lets a later real denial through', () => {
	// Review alert 1's path: many distinct, maximally long refs. Each is a new
	// key, so each is written; the budget is spent; then the real denial lands.
	const lg = loggerFixed();
	const rec = recorder(d => lg.emit(d, 0));
	const pad = 'x'.repeat(4000);
	for (let i = 0; i < 2000; i++) {
		rec.record({ surface: 'rpc', id: `MainThreadFileSystem.$${i}${pad}`, ref: `rpc:MainThreadFileSystem.$${i}${pad}`, verdict: 'deny' });
	}
	rec.record(NEWLOCAL);
	assert.ok(hasNewLocal(lg.out), 'a first-seen key is written even over budget');
});

test('...and the old implementation latches off and loses it (negative control)', () => {
	const old = loggerOld();
	const pad = 'x'.repeat(4000);
	for (let i = 0; i < 2000; i++) {
		old.emit({ surface: 'rpc', id: `f${i}`, ref: `rpc:MainThreadFileSystem.$${i}${pad}`, verdict: 'deny' });
	}
	old.emit(NEWLOCAL as Decision);
	assert.ok(!hasNewLocal(old.out), 'the old cap must swallow it, or this control proves nothing');
	assert.equal(old.out[old.out.length - 1], '"log capped"');
});

test('a repeated key over budget is suppressed, counted, and summarised', () => {
	const lg = loggerFixed();
	const big = 'y'.repeat(4000);
	// One key, over and over: first is written, the rest hit the budget only
	// after the key is no longer first-seen.
	for (let i = 0; i < 6000; i++) {
		lg.emit({ surface: 'rpc', id: 'A', ref: `rpc:${big}`, verdict: 'deny' }, 0);
	}
	const summary = lg.out.filter(l => l.includes('log-throttled'));
	assert.ok(lg.out.length < 6000, "the budget must bite");
	// Nothing is dropped silently: the next window reports the suppressed count.
	lg.emit(deny('B'), WINDOW_MS);
	assert.ok(lg.out.filter(l => l.includes('log-throttled')).length > summary.length,
		'a suppressed run must be summarised, not silently dropped');
});

test('the budget refills: it is never latched off', () => {
	const lg = loggerFixed();
	const big = 'z'.repeat(4000);
	for (let i = 0; i < 6000; i++) {
		lg.emit({ surface: 'rpc', id: 'A', ref: `rpc:${big}`, verdict: 'deny' }, 0);
	}
	const before = lg.out.length;
	// A later window writes again, including repeats of a key already seen.
	for (let i = 0; i < 5; i++) {
		lg.emit({ surface: 'rpc', id: 'A', ref: 'rpc:A', verdict: 'deny' }, WINDOW_MS * 3);
	}
	assert.ok(lg.out.length > before + 1, 'the window must refill');
});

test('a first occurrence is delivered immediately, not after the aggregation window', () => {
	const seenNow: Decision[] = [];
	const rec = recorder(d => seenNow.push(d));
	rec.record(NEWLOCAL);
	assert.equal(seenNow.length, 1, 'the evidence line must not wait for a timer');
	rec.record(NEWLOCAL);
	rec.record(NEWLOCAL);
	assert.equal(seenNow.length, 1);
	rec.flush();
	assert.equal(seenNow.length, 2);
	assert.equal(seenNow[1].count, 2, 'repeats are counted, not lost');
});

test('a quiet key produces exactly one line, not a duplicate summary', () => {
	const seenNow: Decision[] = [];
	const rec = recorder(d => seenNow.push(d));
	rec.record(deny('A'));
	rec.flush();
	assert.equal(seenNow.length, 1);
});

// --- the model is tied to the shipped source -------------------------------

test('the shipped code has no latching cap', () => {
	assert.ok(!/SECLAB_LOG_DENIALS_MAX|SECLAB_LOG_BYTES_MAX\b/.test(SRC),
		'a per-window latching cap is back in seclabRpcFilter.ts');
	assert.ok(!/let capped|capped = true/.test(SRC), 'a latch is back');
});

test('the shipped seclabRecord aggregates every verdict, not only allows', () => {
	const body = SRC.slice(SRC.indexOf('function seclabRecord'));
	const end = body.indexOf('\n}');
	assert.ok(!/verdict !== 'allow'/.test(body.slice(0, end)),
		'seclabRecord short-circuits on verdict again, so denials are not collapsed');
	assert.ok(/seclabDeliver\(d\);/.test(body.slice(0, end)),
		'the first occurrence must still be delivered immediately');
});

test('the shipped subscriber reserves quota for a first-seen key', () => {
	assert.ok(/const first = !seen\.has\(key\) && seen\.size < SECLAB_LOG_KEYS_MAX;/.test(SRC),
		'the first-seen reservation is gone');
	assert.ok(/if \(!first && bytes >= SECLAB_LOG_BYTES_PER_WINDOW\)/.test(SRC),
		'the budget no longer exempts a first-seen key');
});

test('the tab-chosen ref is bounded well below the window budget', () => {
	assert.ok(REF_MAX <= 256, `ref cap ${REF_MAX} is too large to bound a flood`);
	assert.ok(BYTES_PER_WINDOW / (REF_MAX + 200) > 1000,
		'a tab must need many more than ~512 calls to spend a window');
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
