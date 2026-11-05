/**
 * The channel guard's two failure modes, pinned.
 *
 * Run: node test/containment/channel-guard.test.ts
 *
 * Review round 5, finding 6. Both defects were about *when* and *how* the
 * guard runs, not about the policy it enforces, so they are tested against a
 * faithful model of `ChannelServer.registerChannel` rather than against the
 * real class, which would drag in the whole IPC stack.
 *
 * The model is kept honest by its negative controls: each test is paired with
 * one running the *old* implementation, asserting it exhibits the bug. A
 * regression test that also passes against the broken version pins nothing.
 */

import assert from 'node:assert/strict';

type Guard = (ctx: unknown, channel: string, method: string) => Error | undefined;

const EventNone = (_listener: unknown) => ({ dispose() { } });

/** The shipped behaviour: wrap always, read the guard at call time. */
function registerFixed(channels: Map<string, any>, name: string, channel: any, getGuard: () => Guard | undefined) {
	const ctx = 'ctx';
	channels.set(name, {
		call(c: unknown, command: string) {
			const refused = getGuard()?.(ctx, name, command);
			return refused ? Promise.reject(refused) : channel.call(c, command);
		},
		listen(c: unknown, event: string) {
			const refused = getGuard()?.(ctx, name, event);
			if (refused) { return EventNone; }
			return channel.listen(c, event);
		},
	});
}

/** The previous behaviour, kept only to prove the controls bite. */
function registerOld(channels: Map<string, any>, name: string, channel: any, guardNow: Guard | undefined) {
	const ctx = 'ctx';
	const guard = guardNow;
	channels.set(name, guard ? {
		call(c: unknown, command: string) {
			const refused = guard(ctx, name, command);
			return refused ? Promise.reject(refused) : channel.call(c, command);
		},
		listen(c: unknown, event: string) {
			const refused = guard(ctx, name, event);
			if (refused) { throw refused; }
			return channel.listen(c, event);
		},
	} : channel);
}

const realChannel = {
	called: 0, listened: 0,
	call(_c: unknown, _m: string) { realChannel.called++; return Promise.resolve('served'); },
	listen(_c: unknown, _e: string) { realChannel.listened++; return (_l: unknown) => ({ dispose() { } }); },
};
const denyAll: Guard = () => new Error('Unsupported operation');

const tests: Array<[string, () => void | Promise<void>]> = [];
const test = (n: string, f: () => void | Promise<void>) => tests.push([n, f]);

// -- the ordering bug --------------------------------------------------------

test('a channel registered before the guard is installed is still guarded', async () => {
	const channels = new Map();
	let guard: Guard | undefined;                 // not installed yet
	registerFixed(channels, 'download', realChannel, () => guard);
	guard = denyAll;                              // workbench installs it later
	await assert.rejects(() => channels.get('download').call('c', 'anything'));
});

test('control: the old version left that channel unguarded forever', () => {
	const channels = new Map();
	registerOld(channels, 'download', realChannel, undefined);  // none installed yet
	// Even with a guard installed afterwards, the stored channel is the raw one.
	const stored = channels.get('download');
	assert.equal(stored, realChannel,
		'the old version is expected to store the channel unwrapped; if it does '
		+ 'not, the test above is not pinning the bug it claims to');
});

test('a channel registered after the guard is installed is guarded too', async () => {
	const channels = new Map();
	const guard: Guard | undefined = denyAll;
	registerFixed(channels, 'download', realChannel, () => guard);
	await assert.rejects(() => channels.get('download').call('c', 'anything'));
});

test('removing the guard restores service, so the lookup really is per call', async () => {
	const channels = new Map();
	let guard: Guard | undefined = denyAll;
	registerFixed(channels, 'download', realChannel, () => guard);
	await assert.rejects(() => channels.get('download').call('c', 'x'));
	guard = undefined;
	assert.equal(await channels.get('download').call('c', 'x'), 'served');
});

// -- the listen refusal ------------------------------------------------------

test('a refused listen returns an event, and does not throw', () => {
	const channels = new Map();
	registerFixed(channels, 'download', realChannel, () => denyAll);
	let event: any;
	assert.doesNotThrow(() => { event = channels.get('download').listen('c', 'onFoo'); },
		'onEventListen has no try/catch, so a throw here escapes into the '
		+ 'message handler and breaks the connection instead of refusing one '
		+ 'capability');
	const sub = event(() => assert.fail('a refused listen must never fire'));
	assert.equal(typeof sub.dispose, 'function', 'caller needs a real disposable');
	sub.dispose();
});

test('control: the old version threw out of listen', () => {
	const channels = new Map();
	registerOld(channels, 'download', realChannel, denyAll);
	assert.throws(() => channels.get('download').listen('c', 'onFoo'),
		'the old version is expected to throw; if it does not, the test above '
		+ 'is not pinning the bug it claims to');
});

test('an allowed listen still reaches the real channel', () => {
	const channels = new Map();
	const before = realChannel.listened;
	registerFixed(channels, 'download', realChannel, () => undefined);
	channels.get('download').listen('c', 'onFoo');
	assert.equal(realChannel.listened, before + 1);
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
