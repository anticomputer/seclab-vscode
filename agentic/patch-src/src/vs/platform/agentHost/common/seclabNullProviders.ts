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
export type SeclabMemberKind = 'observable' | 'event' | 'property' | 'method';

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
export const SECLAB_NULL_PROVIDERS: readonly SeclabProviderShape[] = [
	{
		name: 'missionControlSharing',
		members: {
			state: { kind: 'observable', value: 'disabled' },
			environmentName: { kind: 'observable', value: undefined },
			setEnvironmentName: { kind: 'method' },
			setEnabled: { kind: 'method' },
			setProjectFolders: { kind: 'method' },
		},
	},
	{
		name: 'missionControlAvailability',
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
];
