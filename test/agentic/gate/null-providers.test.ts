// Patch 0019's inert stand-ins. The point of every test here is the same: a nulled provider
// must never look MORE capable than the real one. Review rounds on this branch have repeatedly
// found checks that could not fail, so each test below is written so that the obvious wrong
// implementation (a proxy returning no-op functions, or `undefined` everywhere) fails it.

import { strict as assert } from 'node:assert';
import { test } from 'node:test';

import {
	SECLAB_NO_SHAPE_NEEDED,
	SECLAB_NULL_PROVIDERS,
	assertShapesMatchRealServices,
	seclabNullProvider,
	seclabNullProviderEvent,
	unshapedProblems,
	type SeclabNullDeps,
} from '../../../agentic/patch-src/src/vs/platform/agentHost/common/seclabNullProviders.ts';

/** Stands in for upstream's `constObservable` and `Event.None`. */
const deps: SeclabNullDeps = {
	constObservable: (value: unknown) => ({ get: () => value, read: (_reader: unknown) => value }),
	noEvent: Object.assign(() => ({ dispose() { } }), { __none: true }),
	noDisposable: { dispose() { } },
};

const shapeNamed = (name: string) => {
	const s = SECLAB_NULL_PROVIDERS.find(p => p.name === name);
	assert.ok(s, `no shape named ${name}`);
	return s;
};

test('THE POINT: a capability flag reads false, not as a truthy function', () => {
	// This is the fail-open the design exists to avoid, and it is declared in the tree:
	// `enabled: boolean` on the Mission Control service. Under a proxy that returns a no-op
	// function for every property read, `enabled` is a function and so truthy, and the window
	// would render the provider as enabled precisely because it had been nulled.
	const inert = seclabNullProvider(shapeNamed('missionControlEnvironmentService'), deps);
	assert.equal(inert['enabled'], false);
	assert.equal(typeof inert['enabled'], 'boolean');
	assert.ok(!inert['enabled']);
});

test('a tri-state observable reports the named contained value, never undefined', () => {
	// `state: IObservable<'disabled' | 'connecting' | 'enabled'>`. `undefined` is not safe:
	// a `=== 'disabled'` guard would fail while a `!== 'enabled'` guard would pass, so the
	// call site, not the stand-in, would decide whether the result was contained.
	const inert = seclabNullProvider(shapeNamed('missionControlSharingService'), deps);
	const state = inert['state'] as { get(): unknown; read(r: unknown): unknown };
	assert.equal(state.get(), 'disabled');
	assert.equal(state.read(undefined), 'disabled');
	assert.notEqual(state.get(), undefined);
});

test('a member the shape does not name is absent, and is never callable', () => {
	// The rule that keeps the next interface change from failing open: an unnamed member is
	// `undefined`, which is falsy, and calling it throws rather than quietly succeeding.
	const inert = seclabNullProvider(shapeNamed('missionControlSharingService'), deps);
	for (const unknownMember of ['enabled', 'connect', 'token', 'isAvailable', 'hosts']) {
		assert.equal(inert[unknownMember], undefined, unknownMember);
		assert.notEqual(typeof inert[unknownMember], 'function', unknownMember);
		assert.ok(!inert[unknownMember], `${unknownMember} must be falsy`);
	}
	assert.throws(() => (inert as unknown as { connect(): void }).connect(), TypeError);
});

test('the stand-in has no prototype, so nothing is inherited into it', () => {
	// A plain object literal would inherit `toString`, `valueOf` and friends, and
	// `'constructor' in inert` would be true. A consumer probing for a member it expects
	// could then get Object.prototype's, which is exactly the capable-direction guess the
	// rule forbids.
	const inert = seclabNullProvider(shapeNamed('missionControlSharingService'), deps);
	assert.equal(Object.getPrototypeOf(inert), null);
	assert.equal((inert as Record<string, unknown>)['constructor'], undefined);
	assert.equal((inert as Record<string, unknown>)['toString'], undefined);
});

test('every declared method is an awaitable no-op that resolves to undefined', async () => {
	const inert = seclabNullProvider(shapeNamed('missionControlEnvironmentService'), deps);
	for (const m of ['initialize', 'refresh', 'connect', 'disconnect', 'delete', 'setDisplayName']) {
		assert.equal(typeof inert[m], 'function', m);
		assert.equal(await (inert[m] as () => Promise<unknown>)(), undefined, m);
	}
});

test('an event member is the no-op event, not a fresh function', () => {
	const inert = seclabNullProvider({ name: 'x', members: { onDidChange: { kind: 'event' } } }, deps);
	assert.equal(inert['onDidChange'], deps.noEvent);
});

test('every stand-in is disposable, whether or not its shape says so', () => {
	// The instantiation service disposes services it created. A stand-in without `dispose`
	// would throw on window teardown.
	for (const shape of SECLAB_NULL_PROVIDERS) {
		const inert = seclabNullProvider(shape, deps);
		assert.equal(typeof inert['dispose'], 'function', shape.name);
		assert.doesNotThrow(() => (inert['dispose'] as () => void)());
	}
	// ...and a shape that declares its own dispose keeps it rather than being overwritten.
	let called = false;
	const own = seclabNullProvider({ name: 'y', members: { dispose: { kind: 'method' } } }, deps);
	assert.doesNotThrow(() => { (own['dispose'] as () => void)(); called = true; });
	assert.ok(called);
});

test('no shape gives a truthy value to a plain property', () => {
	// A blanket guard over the table rather than over one member, so a future shape cannot
	// reintroduce the fail-open by adding a capability flag with a convenient default.
	for (const shape of SECLAB_NULL_PROVIDERS) {
		for (const [name, member] of Object.entries(shape.members)) {
			if (member.kind === 'property') {
				assert.ok(!member.value, `${shape.name}.${name} must be falsy, got ${String(member.value)}`);
			}
		}
	}
});

test('the null-provider event names the provider, so a run asserts rather than infers', () => {
	// The plan requires every run to assert that each service resolved to the null provider.
	// An event that did not name which provider could not tell two of them apart.
	const e = seclabNullProviderEvent('missionControlSharingService') as { summary: string; detail: Record<string, unknown> };
	assert.match(e.summary, /seclab\.null-provider\.registered missionControlSharingService/);
	assert.equal(e.detail['gateRule'], 'seclab.null-provider.registered');
	assert.equal(e.detail['provider'], 'missionControlSharingService');
	assert.equal(e.detail['verdict'], 'deny');
	assert.notEqual(seclabNullProviderEvent('a').summary, seclabNullProviderEvent('b').summary);
});

test('THE REAL POINT: a shape is checked against the service it claims to stand in for', () => {
	// Review round 13, alert 1. The shapes were named correctly and filed with the WRONG
	// interface's members: `missionControlAvailabilityService` carried the environment
	// service's nine members, while the real interface declares exactly one, `available`.
	// Its live consumer reads `available.get()`, so the stand-in threw in the trusted
	// renderer. The unit test and the probe both asserted against the wrong interface, so
	// neither could fail, and the containment claim was circular.
	//
	// The only part of an interface that survives to runtime is the implementation class's
	// prototype, so that is what a shape's methods are compared against.
	class RealEnvironment { initialize() { } refresh() { } connect() { } disconnect() { } delete() { } setDisplayName() { } }
	class RealAvailability { }
	class RealSharing { setEnvironmentName() { } setEnabled() { } setProjectFolders() { } }
	class RealResolver { createResolver() { } takePendingSessionRemovals() { } }
	const real = new Map<string, unknown>([
		['missionControlEnvironmentService', RealEnvironment],
		['missionControlAvailabilityService', RealAvailability],
		['missionControlSharingService', RealSharing],
		['agentHostAdvertisedAuthenticationResolver', RealResolver],
	]);
	assert.deepEqual(assertShapesMatchRealServices(real), []);

	// ...and the check fails on exactly the defect that shipped: the environment service's
	// members filed under the availability service's name.
	const swapped = new Map<string, unknown>([
		['missionControlEnvironmentService', RealAvailability],
		['missionControlAvailabilityService', RealEnvironment],
		['missionControlSharingService', RealSharing],
		['agentHostAdvertisedAuthenticationResolver', RealResolver],
	]);
	const problems = assertShapesMatchRealServices(swapped);
	assert.ok(problems.length >= 6, `the swap must be caught, got ${problems.length}`);
	assert.match(problems.join('\n'), /missionControlEnvironmentService\.initialize is not a method/);

	// A shape naming a service nothing registers is also a problem, not a pass.
	assert.match(assertShapesMatchRealServices(new Map()).join('\n'), /no service is registered under that id/);
});

test('the availability service stands in with its own single declared member', () => {
	// `available: IObservable<boolean | undefined>`, and `false` is the contained value,
	// because upstream treats `available.get() === true` as available.
	const inert = seclabNullProvider(shapeNamed('missionControlAvailabilityService'), deps);
	const available = inert['available'] as { get(): unknown };
	assert.equal(typeof available, 'object');
	assert.equal(available.get(), false);
	// It does NOT carry the neighbouring service's members, which is what went wrong.
	for (const notMine of ['hosts', 'accountKey', 'enabled', 'initialize', 'connect']) {
		assert.equal(inert[notMine], undefined, notMine);
	}
});

test('a guarded name is shaped or recorded, never silently empty', () => {
	// Review round 13, alert 2. Eleven of thirteen guarded names had no shape and collapsed
	// to `{ dispose }` with nothing reporting it.
	const shaped = SECLAB_NULL_PROVIDERS.map(p => p.name);
	const recorded = Object.keys(SECLAB_NO_SHAPE_NEEDED);
	assert.deepEqual(unshapedProblems([...shaped, ...recorded]), []);
	assert.match(unshapedProblems(['somethingNewUpstreamAdded']).join('\n'), /neither a shape nor a recorded reason/);
	// Every recorded exemption carries a reason; an empty one would be a silent default
	// wearing a label.
	for (const [name, why] of Object.entries(SECLAB_NO_SHAPE_NEEDED)) {
		assert.ok(why.trim().length > 20, `${name} needs a real reason, got "${why}"`);
	}
});

test('a disposable-returning member yields a disposable, not a promise', () => {
	// Review round 13, alert 2. `store.add(service.register(...))` rejects a promise, so an
	// async no-op would break the window rather than contain it. Fail-closed has to mean the
	// right shape of nothing.
	const inert = seclabNullProvider({ name: 'x', members: { register: { kind: 'disposable-method' } } }, deps);
	const result = (inert['register'] as () => { dispose?: unknown })();
	assert.equal(typeof (result as { dispose?: unknown }).dispose, 'function');
	assert.notEqual(typeof (result as { then?: unknown }).then, 'function');
});

test('the authentication resolver stand-in supplies createResolver, which the remote agent-host factory calls first', async () => {
	// PR #43 review. The remote agent-host service stays unwrapped in a tab window, and its
	// connection factory calls `createResolver(address)` before building the protocol client.
	// With no shape the call threw a TypeError, so a tab-written remote-host entry failed before
	// patch 0015's gate could refuse it and log the refusal.
	const inert = seclabNullProvider(shapeNamed('agentHostAdvertisedAuthenticationResolver'), deps);
	assert.equal(typeof inert['createResolver'], 'function');
	const auth = (inert['createResolver'] as (address: string) => { resolve(a: readonly unknown[]): Promise<readonly unknown[]>; dispose(): void })('127.0.0.1:1');
	// Synchronous: the factory uses the result at once, not a promise of it.
	assert.notEqual(typeof (auth as { then?: unknown }).then, 'function');
	assert.deepEqual(await auth.resolve([{ provider: 'p' }]), []);
	auth.dispose();
	assert.deepEqual((inert['takePendingSessionRemovals'] as (address: string) => readonly unknown[])('127.0.0.1:1'), []);
	assert.ok(!('agentHostAdvertisedAuthenticationResolver' in SECLAB_NO_SHAPE_NEEDED), 'it has a consumer outside the withheld contributions, so it cannot be exempt');
});
