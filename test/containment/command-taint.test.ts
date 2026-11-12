/**
 * The laundering backstop's depth-1 hole, pinned.
 *
 * Run: node test/containment/command-taint.test.ts
 *
 * The taint threads a tab's origin through `ICommandService` by rebinding it
 * for the handler. A handler that ignores its accessor and uses a *global*
 * `ICommandService` escapes that, which is why `seclabTaintInFlight` has a
 * backstop: while a tab command is running, a global execution of anything not
 * explicitly `allow` is refused.
 *
 * That backstop only works while the counter says a tab command is running,
 * and the counter was incremented solely inside the tainted service. The
 * outermost call -- the one `seclabExecuteFromTab` starts -- did not count, so
 * a handler one level down escaped both the taint and the backstop written to
 * catch exactly that shape.
 *
 * Latent, because every command verdict is currently `deny` and the global
 * path is refused for that reason instead. The first `allow` would have made
 * it reachable, and it would have looked like the backstop working.
 *
 * The model below is a transliteration of the shipped control flow, not an
 * import: `seclabRpcFilter.ts` pulls in the workbench. Each assertion is
 * therefore paired with the *old* arrangement, which must exhibit the bug --
 * a regression test that also passes against the broken version pins nothing.
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

type Verdict = 'allow' | 'allow_with_constraint' | 'prompt' | 'rewrite' | 'deny';

/** One run of the shipped shape, parameterised by where the counter moves. */
function makeService(verdicts: Map<string, Verdict>, countAtEntryPoint: boolean) {
	let inFlight = 0;
	const escapes: string[] = [];

	const taintInFlight = (id: string, origin: unknown): Error | undefined => {
		if (origin) {
			const v = verdicts.get(id) ?? 'deny';
			return v === 'allow' || v === 'allow_with_constraint'
				? undefined
				: new Error('Unsupported operation');
		}
		if (inFlight > 0 && verdicts.get(id) !== 'allow') {
			escapes.push(id);
			return new Error('Unsupported operation');
		}
		return undefined;
	};

	const handlers = new Map<string, (svc: Svc) => unknown>();
	interface Svc { executeCommand(id: string, ...args: unknown[]): Promise<unknown> }

	const tryExecute = async (id: string, args: unknown[], origin?: unknown): Promise<unknown> => {
		const refused = taintInFlight(id, origin);
		if (refused) { throw refused; }
		const handler = handlers.get(id);
		if (!handler) { return undefined; }
		// The accessor the handler *should* use carries the origin onward.
		const tainted: Svc = {
			executeCommand: (nid, ...nargs) => executeFromTab(nid, nargs, origin),
		};
		return handler(origin ? tainted : globalService);
	};

	const executeFromTab = async (id: string, args: unknown[], origin: unknown): Promise<unknown> => {
		if (countAtEntryPoint) { inFlight++; }
		try {
			return await tryExecute(id, args, origin);
		} finally {
			if (countAtEntryPoint) { inFlight--; }
		}
	};

	// The global service: no origin. This is what an injected ICommandService is.
	const globalService: Svc = { executeCommand: (id, ...args) => tryExecute(id, args) };

	return { handlers, executeFromTab, globalService, escapes: () => escapes };
}

const tests: Array<[string, () => Promise<void> | void]> = [];
const test = (n: string, f: () => Promise<void> | void) => tests.push([n, f]);

/** An allowed outer command whose handler launders through the global service. */
function scenario(countAtEntryPoint: boolean) {
	const verdicts = new Map<string, Verdict>([['outer.allowed', 'allow']]);
	const svc = makeService(verdicts, countAtEntryPoint);
	let ran = false;
	svc.handlers.set('outer.allowed', (injected) => injected.executeCommand('inner.denied'));
	svc.handlers.set('inner.denied', () => { ran = true; return 'host effect'; });
	return { svc, didInnerRun: () => ran };
}

test('a laundered depth-1 command is refused', async () => {
	const { svc, didInnerRun } = scenario(true);
	// The handler deliberately uses the global service, not its accessor.
	svc.handlers.set('outer.allowed', () => svc.globalService.executeCommand('inner.denied'));
	await assert.rejects(() => svc.executeFromTab('outer.allowed', [], { tab: 't-abc' }));
	assert.equal(didInnerRun(), false, 'the denied inner command must not run');
});

test('control: the old counting let it through', async () => {
	// Same scenario, counter incremented only inside the tainted wrapper, so
	// the outermost call does not register as in-flight.
	const { svc, didInnerRun } = scenario(false);
	svc.handlers.set('outer.allowed', () => svc.globalService.executeCommand('inner.denied'));
	await svc.executeFromTab('outer.allowed', [], { tab: 't-abc' });
	assert.equal(didInnerRun(), true,
		'the old arrangement is expected to run the denied command; if it does '
		+ 'not, the test above is not pinning the bug it claims to');
});

test('the backstop records the escape rather than swallowing it', async () => {
	const { svc } = scenario(true);
	svc.handlers.set('outer.allowed', () => svc.globalService.executeCommand('inner.denied'));
	await assert.rejects(() => svc.executeFromTab('outer.allowed', [], { tab: 't-abc' }));
	assert.deepEqual(svc.escapes(), ['inner.denied'],
		'a denied laundering attempt must be visible to the probes');
});

test('the counter unwinds, so a later trusted call is not refused', async () => {
	const { svc } = scenario(true);
	svc.handlers.set('outer.allowed', () => 'fine');
	await svc.executeFromTab('outer.allowed', [], { tab: 't-abc' });
	// With the tab command finished, a trusted global call must work again.
	svc.handlers.set('later.trusted', () => 'ok');
	assert.equal(await svc.globalService.executeCommand('later.trusted'), 'ok');
});

test('an allowed inner command still runs through the accessor', async () => {
	const verdicts = new Map<string, Verdict>([
		['outer.allowed', 'allow'], ['inner.allowed', 'allow'],
	]);
	const svc = makeService(verdicts, true);
	let ran = false;
	svc.handlers.set('outer.allowed', (injected) => injected.executeCommand('inner.allowed'));
	svc.handlers.set('inner.allowed', () => { ran = true; return 'ok'; });
	await svc.executeFromTab('outer.allowed', [], { tab: 't-abc' });
	assert.equal(ran, true, 'the taint must not break legitimate nesting');
});

// The model above documents the semantics; on its own it would stay green if
// the shipped counting were deleted, because it is a transliteration rather
// than an import. These assertions tie it to the patch that actually ships, so
// removing the fix fails here even though the model cannot notice.
const repoRoot = path.resolve(import.meta.dirname, '..', '..');
const patch = (name: string) =>
	fs.readFileSync(path.join(repoRoot, 'patches', name), 'utf8');

test('the shipped entry point counts the command as in flight', () => {
	const p = patch('0007-seclab-command-taint.patch');
	const body = p.split('\n').filter(l => l.startsWith('+')).join('\n');
	assert.match(body, /seclabExecuteFromTab/,
		'0007 must still define the tab entry point');
	assert.match(body, /seclabEnterTabCommand\(\)/,
		'seclabExecuteFromTab must increment the in-flight counter: without it a '
		+ 'handler one level down escapes both the taint and the backstop');
	assert.match(body, /seclabExitTabCommand\(\)/,
		'the counter must unwind, or every later trusted command is refused');
});

test('the tainted service does not double-count the nested call', () => {
	const filter = fs.readFileSync(path.join(
		repoRoot, 'rpc-filter', 'patch-src', 'seclabRpcFilter.ts'), 'utf8');
	// Exactly one increment and one decrement, both in the exported helpers.
	assert.equal((filter.match(/seclabInFlight\+\+/g) ?? []).length, 1);
	assert.equal((filter.match(/seclabInFlight--/g) ?? []).length, 1);
});

test('the backstop and the tainted path read one verdict, not two', () => {
	const filter = fs.readFileSync(path.join(
		repoRoot, 'rpc-filter', 'patch-src', 'seclabRpcFilter.ts'), 'utf8');
	// The backstop must not read the raw table: that skips the deny prefixes
	// and rejects allow_with_constraint, so the two paths could disagree in the
	// open direction the moment any command stops being denied.
	const backstop = filter.slice(filter.indexOf('seclabInFlight > 0'));
	const window = backstop.slice(0, 200);
	assert.doesNotMatch(window, /SECLAB_COMMANDS\.get/,
		'the backstop must call seclabCommandVerdict, not read the table');
	// Module-internal on purpose: both callers live in this file, and the
	// patch queue's dead-entry-point check treats an export with no external
	// caller as the shape that type-checks, reviews well and never runs.
	assert.match(filter, /\nfunction seclabCommandVerdict/,
		'one shared verdict function must exist');
	assert.match(filter, /backstopVerdict !== 'allow_with_constraint'/,
		'the backstop must accept allow_with_constraint like the tainted path');
});

let failed = 0;
for (const [name, fn] of tests) {
	try {
		await fn();
		console.log(`ok   ${name}`);
	} catch (err) {
		failed++;
		console.error(`FAIL ${name}\n     ${(err as Error).message}`);
	}
}
console.log(`\n${tests.length - failed}/${tests.length} passed`);
process.exit(failed ? 1 : 0);
