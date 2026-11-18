/*---------------------------------------------------------------------------------------------
 *  seclab patch 0019: no other agent-host providers in a tab window.
 *
 *  A `seclab+` window must not reach any agent host but its own, gated one. Upstream registers
 *  ten services and three workbench contributions for remote and cloud-sandbox agent hosts, and
 *  one of those contributions registers chat agents for a *remote* connection. That is the only
 *  way an agent belonging to another connection enters the window, so it is what patch 0018's
 *  security property depends on not existing (finding R12-2).
 *
 *  This module is the testable half: given a declared shape, it builds the inert stand-in that
 *  takes each service's place. It deliberately imports nothing, so that the unit tests can run
 *  it directly under Node's type stripping, and so that the rule it enforces can be read in one
 *  place.
 *
 *  THE RULE, and the reason this is not a Proxy: a stand-in must never be MORE capable-looking
 *  than the real service. The compact way to satisfy ten interfaces is a proxy whose every
 *  property read returns a no-op function, and that is a fail-open, in this tree, today: the
 *  Mission Control service declares `enabled: boolean`, and a function is truthy, so a nulled
 *  provider would report itself as enabled. The sharing service declares
 *  `state: IObservable<'disabled' | 'connecting' | 'enabled'>`, where `undefined` is no safer,
 *  because `=== 'disabled'` then fails while `!== 'enabled'` passes and the call site decides
 *  whether the result is contained.
 *
 *  So each member carries an explicit SAFE VALUE, not merely a safe kind, and a member the
 *  shape does not name is absent rather than defaulted. An absent member reads as `undefined`,
 *  which is falsy; calling it throws, which is loud and contained. Guessing in the capable
 *  direction is how a null provider becomes a provider that lies.
 *--------------------------------------------------------------------------------------------*/

/** What a member is, which decides how its safe value is wrapped. */
export type SeclabMemberKind = 'observable' | 'event' | 'property' | 'method' | 'disposable-method' | 'value-method';

export interface SeclabMember {
	readonly kind: SeclabMemberKind;
	/** The contained value. For an observable, the value it always reports. Methods ignore it. */
	readonly value?: unknown;
}

export interface SeclabProviderShape {
	/** Reported in the gate log, so a run can assert which provider was nulled. */
	readonly name: string;
	readonly members: Readonly<Record<string, SeclabMember>>;
}

/**
 * The host pieces this builder needs, passed in rather than imported: this module must stay
 * free of value imports so the unit tests can run it under type stripping, which rejects
 * value imports carrying `.js` specifiers across patch modules.
 */
export interface SeclabNullDeps {
	/** Upstream's `constObservable`. */
	readonly constObservable: (value: unknown) => unknown;
	/** Upstream's `Event.None`. */
	readonly noEvent: unknown;
	/** Upstream's `Disposable.None`, for a member whose caller adds the result to a store. */
	readonly noDisposable: unknown;
}

/** Builds the inert stand-in for one service. */
export function seclabNullProvider(shape: SeclabProviderShape, deps: SeclabNullDeps): Record<string, unknown> {
	const inert: Record<string, unknown> = Object.create(null);
	for (const [name, member] of Object.entries(shape.members)) {
		switch (member.kind) {
			case 'observable':
				inert[name] = deps.constObservable(member.value);
				break;
			case 'event':
				inert[name] = deps.noEvent;
				break;
			case 'property':
				inert[name] = member.value;
				break;
			case 'disposable-method':
				// A member whose caller does `store.add(service.register(...))`. An async no-op
				// would return a promise, which a DisposableStore rejects: fail-closed has to
				// mean the right SHAPE of nothing, not merely nothing (review round 13).
				inert[name] = () => deps.noDisposable;
				break;
			case 'value-method':
				// A synchronous method whose caller uses the result at once, so it returns the
				// contained value itself rather than a promise of it.
				inert[name] = () => member.value;
				break;
			case 'method':
				// Async, because every method these interfaces declare either returns void or a
				// promise, and a caller that awaits a plain `undefined` is fine either way.
				inert[name] = async () => undefined;
				break;
		}
	}
	// Services are disposed by the instantiation service whether or not they declare it.
	if (!('dispose' in inert)) {
		inert['dispose'] = () => undefined;
	}
	return inert;
}

/** The event a nulled provider emits, so a run can assert the null provider rather than infer it. */
export function seclabNullProviderEvent(name: string): object {
	return {
		source: 'ahp-gate',
		class: 'ahp.decision',
		priority: 'notice',
		summary: `seclab.null-provider.registered ${name}`,
		detail: { gateRule: 'seclab.null-provider.registered', provider: name, connection: 0, verdict: 'deny' },
	};
}

/**
 * The shapes, one per service nulled in a tab window. Each member is here because the declared
 * interface has it; the value is the contained one.
 *
 * `state` is `'disabled'` rather than `undefined` for the reason given at the top: consumers
 * compare it against the three named values. `enabled` is explicitly `false` for the same
 * reason in the other direction.
 */
/**
 * The name is the SERVICE ID upstream registers the provider under, because that is what the
 * registration wrapper has to hand. A shape whose name did not match would be looked up, missed,
 * and silently replaced by an empty stand-in: no `enabled: false`, no contained `state`, nothing.
 * The probe caught exactly that mismatch before this shipped, which is why the names are not
 * prettier.
 */
/**
 * An `IAgentHostAdvertisedAuthentication` that authenticates nothing. Frozen, and shared by
 * every caller: it holds no state, so there is nothing for one connection to leak to another.
 */
export const SECLAB_NO_AUTHENTICATION: Readonly<{ resolve(agents: readonly unknown[]): Promise<readonly unknown[]>; dispose(): void }> = Object.freeze({
	resolve: async () => [],
	dispose: () => undefined,
});

export const SECLAB_NULL_PROVIDERS: readonly SeclabProviderShape[] = [
	{
		// `IMissionControlSharingService`.
		name: 'missionControlSharingService',
		members: {
			state: { kind: 'observable', value: 'disabled' },
			environmentName: { kind: 'observable', value: undefined },
			setEnvironmentName: { kind: 'method' },
			setEnabled: { kind: 'method' },
			setProjectFolders: { kind: 'method' },
		},
	},
	{
		// `IMissionControlEnvironmentService`. These members were filed under the availability
		// service's name until review round 13: the names were right and the MEMBERS were not,
		// and both the unit test and the probe asserted against the wrong interface, so neither
		// could fail. That is why `assertShapesMatchRealServices` below exists.
		name: 'missionControlEnvironmentService',
		members: {
			hosts: { kind: 'observable', value: [] },
			accountKey: { kind: 'property', value: undefined },
			enabled: { kind: 'property', value: false },
			initialize: { kind: 'method' },
			refresh: { kind: 'method' },
			connect: { kind: 'method' },
			disconnect: { kind: 'method' },
			delete: { kind: 'method' },
			setDisplayName: { kind: 'method' },
		},
	},
	{
		// `IMissionControlAvailabilityService` declares exactly one member. Its live consumer is
		// the remote-connections action item, which reads `available.get()`, so an absent member
		// here is not fail-closed, it is a throw in the trusted renderer.
		// `false` is the contained value: upstream treats `available.get() === true` as available.
		name: 'missionControlAvailabilityService',
		members: {
			available: { kind: 'observable', value: false },
		},
	},
	{
		// `IAgentHostAdvertisedAuthenticationResolver`. Not reached only from the withheld
		// contribution, as first recorded: the remote agent-host service, which stays unwrapped,
		// calls `createResolver(address)` in its connection factory BEFORE it builds the protocol
		// client. Absent, that call threw a TypeError, so a tab-written remote-host entry failed
		// before patch 0015's gate could refuse and log it (PR #43 review). The contained value is
		// an authentication that resolves nothing, so the client is built and the gate refuses its
		// transport, as 0015 intends.
		name: 'agentHostAdvertisedAuthenticationResolver',
		members: {
			createResolver: { kind: 'value-method', value: SECLAB_NO_AUTHENTICATION },
			takePendingSessionRemovals: { kind: 'value-method', value: Object.freeze([]) },
		},
	},
];

/**
 * The guarded services that deliberately have no shape, with the reason. A guarded name that is
 * on neither list is a mistake, not a default: see `unshapedProblems`.
 *
 * These are inert-by-absence rather than inert-by-shape because every consumer of them in a tab
 * window is itself one of the withheld contributions. That is a fact about the tree, so it is
 * written down and checked, not assumed.
 */
export const SECLAB_NO_SHAPE_NEEDED: Readonly<Record<string, string>> = {
	cloudSandboxTelemetryService: 'only the withheld cloud-sandbox contributions report through it',
	cloudSandboxApiService: 'reached only from the withheld cloud-sandbox contributions',
	cloudSandboxDraftPreparationService: 'reached only from the withheld cloud-sandbox contributions',
	cloudSandboxModelCatalogService: 'reached only from the withheld cloud-sandbox contributions',
	cloudSandboxAgentHostService: 'the provider this patch exists to remove; nothing else may reach it',
	remoteAgentHostConnectionCustomizationService: 'its only tab-window caller is reached through the withheld editor cloud-sandbox contribution',
	remoteAgentHostContribution: 'a withheld workbench contribution, not a service anything resolves',
	editorCloudSandboxContribution: 'a withheld workbench contribution, not a service anything resolves',
	missionControlContribution: 'a withheld workbench contribution, not a service anything resolves',
};

/**
 * Every guarded name must be either shaped or explicitly listed as needing no shape. Without
 * this, a name with no shape silently became an empty stand-in, which is the quiet default the
 * whole design forbids (review round 13, alert 2).
 */
export function unshapedProblems(guarded: readonly string[]): string[] {
	const shaped = new Set(SECLAB_NULL_PROVIDERS.map(p => p.name));
	return guarded
		.filter(n => !shaped.has(n) && !(n in SECLAB_NO_SHAPE_NEEDED))
		.map(n => `${n} is guarded but has neither a shape nor a recorded reason to need none`);
}

/**
 * Checks each shape against the REAL service it stands in for, by the only part of it that
 * survives to runtime: the implementation class's prototype methods.
 *
 * This is the check that was missing. A shape filed under the wrong service name still looked
 * right to a test that named the shape itself; it does not survive being compared with the
 * class upstream actually registers under that id.
 */
export function assertShapesMatchRealServices(realCtors: ReadonlyMap<string, unknown>): string[] {
	const problems: string[] = [];
	for (const shape of SECLAB_NULL_PROVIDERS) {
		const ctor = realCtors.get(shape.name);
		if (!ctor) {
			problems.push(`${shape.name}: no service is registered under that id`);
			continue;
		}
		const proto = (ctor as { prototype?: object }).prototype;
		const real = new Set(proto ? Object.getOwnPropertyNames(proto) : []);
		for (const [member, { kind }] of Object.entries(shape.members)) {
			// Only methods live on the prototype; observables and plain properties are instance
			// fields and cannot be checked this way, so they are not claimed to be.
			if ((kind === 'method' || kind === 'disposable-method' || kind === 'value-method') && !real.has(member)) {
				problems.push(`${shape.name}.${member} is not a method of the real ${(ctor as { name?: string }).name}`);
			}
		}
	}
	return problems;
}
