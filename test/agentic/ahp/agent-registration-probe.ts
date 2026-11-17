// Patch 0019's probe: in a tab window, no agent-host provider but this window's own may be
// registered, so an agent id forged by a tab cannot select an agent belonging to any other
// connection.
//
// Why this exists, and why it is not a unit test. Patch 0018 refuses a chat request unless its
// session resolves to this window's own gated agent-host connection. Its round 2 security
// review found that this authorises the SESSION while the AGENT ID that decides where the
// request actually executes is chosen separately: from the caller, from a participant mention
// parsed out of the request text, or from participant detection. `IChatAgentData` carries an
// extension id and no connection, so there is no comparison 0018 could make. The property it
// needs is not about one request; it is about which agents can be registered at all. That is
// finding R12-2, and this probe is what closes it with evidence rather than with an argument.
//
// The observation is made against the REAL upstream registries, after really importing the
// real registration module, in a container with no network and no window. Nothing here is a
// copy of the registration code: a probe with its own copy of what it checks proves nothing
// about what ships.
//
// THE BASELINE MUST FAIL. Run against pristine upstream, the remote agent-host providers are
// registered and the contribution that registers another connection's agents is the real one.
// That is the vulnerability, and this probe reports it as `vulnerable`. Run against the tree
// the real patch series produces, every one of them is the guarded registration instead, and
// constructing it in a tab window yields the inert stand-in without ever building the real
// service. A probe that could not report `vulnerable` would not be evidence of anything.

import { getSingletonServiceDescriptors } from 'vs/platform/instantiation/common/extensions.js';
import { IInstantiationService } from 'vs/platform/instantiation/common/instantiation.js';
import { IWorkbenchEnvironmentService } from 'vs/workbench/services/environment/common/environmentService.js';

// Importing the module for its side effects is the point: `registerSingleton` and
// `registerWorkbenchContribution2` run at module load, which is exactly why the patch cannot
// branch on the window's authority at registration time and must decide at construction.
import 'vs/workbench/contrib/chat/browser/remoteAgentHost/remoteAgentHost.contribution.js';

const MODE = process.env.PROBE_MODE === 'gated' ? 'gated' : 'baseline';

/** The providers patch 0019 covers. Named by their service id, as upstream registers them. */
const COVERED = [
	'cloudSandboxTelemetryService', 'cloudSandboxApiService', 'cloudSandboxDraftPreparationService',
	'cloudSandboxModelCatalogService', 'cloudSandboxAgentHostService', 'missionControlEnvironmentService',
	'missionControlSharingService', 'missionControlAvailabilityService',
	'remoteAgentHostConnectionCustomizationService', 'agentHostAdvertisedAuthenticationResolver',
];

const GUARD = 'SeclabGuardedProvider';

interface Finding { readonly check: string; readonly verdict: 'vulnerable' | 'contained'; readonly detail: unknown }
const findings: Finding[] = [];
const add = (check: string, verdict: Finding['verdict'], detail: unknown) => findings.push({ check, verdict, detail });

// ---------------------------------------------------------------------------------------
// 1. What the real registry actually holds, read back rather than assumed.
// ---------------------------------------------------------------------------------------
const registered = new Map<string, string>();
for (const [id, descriptor] of getSingletonServiceDescriptors()) {
	const name = (id as { toString(): string }).toString();
	const ctor = (descriptor as { ctor?: { name?: string } }).ctor;
	registered.set(name, ctor?.name ?? '<none>');
}

const covered = COVERED.filter(n => registered.has(n));
const unguarded = covered.filter(n => registered.get(n) !== GUARD);
if (covered.length !== COVERED.length) {
	// Upstream renamed or moved a provider. Fail rather than quietly checking fewer things:
	// a probe that silently narrows its own scope is the failure mode this project keeps
	// finding, so this is an error in both modes.
	add('providers-present', 'vulnerable', { expected: COVERED.length, found: covered.length, missing: COVERED.filter(n => !registered.has(n)) });
} else if (unguarded.length) {
	add('providers-guarded', 'vulnerable', { unguarded, ctors: unguarded.map(n => registered.get(n)) });
} else {
	add('providers-guarded', 'contained', { guarded: covered.length });
}

// ---------------------------------------------------------------------------------------
// 2. The guarded registration's construction behaviour, driven for real.
//    This is where the forged agent id is actually stopped: the contribution that registers
//    another connection's agents is never constructed in a tab window, so there is no such
//    agent for a forged id to name.
// ---------------------------------------------------------------------------------------
function constructAs(authority: string | undefined, ctor: unknown): { built: boolean; value: unknown } {
	let built = false;
	const services = new Map<unknown, unknown>([
		[IWorkbenchEnvironmentService, { remoteAuthority: authority, configuration: {} }],
		[IInstantiationService, { createInstance: (real: unknown) => { built = true; return { real }; } }],
	]);
	// The decorated constructor takes its services positionally, in declaration order.
	const value = new (ctor as new (...a: unknown[]) => unknown)(
		services.get(IWorkbenchEnvironmentService), services.get(IInstantiationService));
	return { built, value };
}

const sample = (() => {
	for (const [id, descriptor] of getSingletonServiceDescriptors()) {
		if ((id as { toString(): string }).toString() === 'missionControlAvailabilityService') {
			return (descriptor as { ctor?: unknown }).ctor;
		}
	}
	return undefined;
})();

if (!sample) {
	add('provider-construction', 'vulnerable', { reason: 'the sampled provider is not registered at all' });
} else if (registered.get('missionControlAvailabilityService') !== GUARD) {
	// Baseline: there is no guard, so a tab window gets the real provider. Constructing the
	// real one here would reach its own dependency graph, which is not what is under test;
	// that it is registered unguarded is already the finding.
	add('provider-construction', 'vulnerable', { ctor: registered.get('missionControlAvailabilityService') });
} else {
	const tab = constructAs('seclab+t-probe', sample);
	const ordinary = constructAs(undefined, sample);
	const inert = tab.value as Record<string, unknown>;
	// Contained means all of: the real service was never built, the stand-in reports itself
	// as not enabled, and it does not lie in the capable direction about anything it carries.
	const enabledIsFalse = inert['enabled'] === false;
	const noTruthyProperty = ['enabled', 'accountKey'].every(k => !inert[k]);
	const ordinaryUnaffected = ordinary.built === true;
	const ok = !tab.built && enabledIsFalse && noTruthyProperty && ordinaryUnaffected;
	add('provider-construction', ok ? 'contained' : 'vulnerable',
		{ builtRealInTab: tab.built, enabledIsFalse, noTruthyProperty, ordinaryUnaffected });
}

// ---------------------------------------------------------------------------------------
// 3. The claim this probe is really about, stated as its own check so a run cannot read
//    containment into the other two passing for unrelated reasons.
// ---------------------------------------------------------------------------------------
const remoteAgentsReachable = registered.get('cloudSandboxAgentHostService') !== GUARD;
add('forged-agent-id', remoteAgentsReachable ? 'vulnerable' : 'contained', {
	note: remoteAgentsReachable
		? 'a provider for an agent host that is not this window own is live, so an agent id forged by a tab can select an agent belonging to another connection'
		: 'no provider for any other agent host is constructible in a tab window, so there is no other connection agent for a forged id to name',
});

const vulnerable = findings.filter(f => f.verdict === 'vulnerable');
const expected = MODE === 'baseline' ? 'vulnerable' : 'contained';
const actual = vulnerable.length ? 'vulnerable' : 'contained';
console.log(JSON.stringify({ mode: MODE, actual, expected, findings }, undefined, '\t'));

if (actual !== expected) {
	console.error(`agent-registration probe: ${MODE} should be ${expected}, got ${actual}`);
	process.exit(1);
}
