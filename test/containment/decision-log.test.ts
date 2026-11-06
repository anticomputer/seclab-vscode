/**
 * The trusted-side decision log has a reader, and that reader is strict.
 *
 * Run: node test/containment/decision-log.test.ts
 *
 * Proof condition 2 of the newLocal containment claim is "the denial is
 * observed on the trusted side". That rests entirely on `rpcDecisions` finding
 * the right line in `<userData>/logs/<session>/window<N>/seclabRpcFilter.log`.
 * A reader that silently returns nothing would turn a missing denial into a
 * passing run, which is the same "cannot fail" shape as a probe with no
 * assertion. So the cases that must NOT match are asserted here too: the fields
 * a tab can influence (`ref`, `claimedExtensionId`) are matched exactly and
 * never as free text.
 */

import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { rpcDecisions } from './assert.ts';

const tests: Array<[string, () => void]> = [];
const test = (name: string, fn: () => void) => tests.push([name, fn]);

const DENY = {
	source: 'rpc-filter', class: 'rpc.decision', priority: 'warning',
	summary: 'deny MainThreadCommands.$executeCommand',
	detail: { surface: 'MainThreadCommands.$executeCommand', ref: 'cmd:workbench.action.terminal.newLocal', verdict: 'deny', reason: 'command verdict deny' },
};

/** A profile whose window logs hold `lines`, laid out the way the editor lays them out. */
function profile(lines: string[], opts: { window?: string } = {}): string {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), 'seclab-declog-'));
	const dir = path.join(root, 'logs', '20261106T120000', opts.window ?? 'window1');
	fs.mkdirSync(dir, { recursive: true });
	// ILoggerService prefixes every entry with a timestamp and a level.
	fs.writeFileSync(path.join(dir, 'seclabRpcFilter.log'),
		lines.map(l => `2026-11-06 12:00:00.000 [info] ${l}`).join('\n') + '\n');
	return root;
}

const newLocalDenials = (root: string) => rpcDecisions(root)
	.filter(d => d.detail?.ref === 'cmd:workbench.action.terminal.newLocal' && d.detail?.verdict === 'deny');

test('the newLocal denial is found in a window log', () => {
	assert.equal(newLocalDenials(profile([JSON.stringify(DENY)])).length, 1);
});

test('it is found under window2, not only window1', () => {
	assert.equal(newLocalDenials(profile([JSON.stringify(DENY)], { window: 'window2' })).length, 1);
});

test('an empty profile yields no denial (the gate can fail)', () => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), 'seclab-declog-'));
	assert.deepEqual(rpcDecisions(root), []);
	assert.equal(newLocalDenials(root).length, 0);
});

test('an allow for the same command is not a denial', () => {
	const allow = { ...DENY, summary: 'allow MainThreadCommands.$executeCommand', detail: { ...DENY.detail, verdict: 'allow', reason: undefined } };
	assert.equal(newLocalDenials(profile([JSON.stringify(allow)])).length, 0);
});

test('a denial of some other command is not a newLocal denial', () => {
	const other = { ...DENY, detail: { ...DENY.detail, ref: 'cmd:workbench.action.terminal.sendSequence' } };
	assert.equal(newLocalDenials(profile([JSON.stringify(other)])).length, 0);
});

test('a tab-chosen string that merely CONTAINS the ref does not match', () => {
	// `claimedExtensionId` and `ref` carry strings the tab chose. Matching on
	// substrings anywhere in the line would let a tab forge its own acquittal.
	const forged = {
		...DENY, summary: 'deny MainThreadCommands.$executeCommand',
		detail: { ...DENY.detail, ref: 'cmd:evil', claimedExtensionId: 'cmd:workbench.action.terminal.newLocal' },
	};
	assert.equal(newLocalDenials(profile([JSON.stringify(forged)])).length, 0);
});

test('non-JSON and truncated lines are skipped, not guessed at', () => {
	const root = profile(['not json at all', '{"class":"rpc.decision","detail":{"ref":"cmd:x","ver', JSON.stringify(DENY)]);
	assert.equal(rpcDecisions(root).length, 1);
	assert.equal(newLocalDenials(root).length, 1);
});

test('a line of another class in the same file is not a decision', () => {
	const root = profile([JSON.stringify({ ...DENY, class: 'obs.other' }), JSON.stringify(DENY)]);
	assert.equal(rpcDecisions(root).length, 1);
});

test('the throttle marker is a decision, and is not a newLocal denial', () => {
	const throttled = {
		source: 'rpc-filter', class: 'rpc.decision', priority: 'warning', summary: 'log throttled',
		detail: { surface: 'rpc', ref: 'rpc:seclab.log-throttled', verdict: 'deny', reason: 'over the window byte budget; repeats were counted, not dropped silently', count: 17 },
	};
	const root = profile([JSON.stringify(throttled)]);
	assert.equal(rpcDecisions(root).length, 1);
	assert.equal(newLocalDenials(root).length, 0);
});

test('a log file by any other name is not read', () => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), 'seclab-declog-'));
	const dir = path.join(root, 'logs', '20261106T120000', 'window1');
	fs.mkdirSync(dir, { recursive: true });
	fs.writeFileSync(path.join(dir, 'renderer.log'), JSON.stringify(DENY) + '\n');
	assert.deepEqual(rpcDecisions(root), []);
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
