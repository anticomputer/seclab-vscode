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
// From patch-src, not from the upstream tree: in the BASELINE arm that module does not exist,
// because the patch has not been applied. `sync-patch --check` (run by the unit suite) keeps
// patch-src and the shipped patch byte-identical, so this is the same code that ships.
import { assertShapesMatchRealServices, unshapedProblems } from '/patchsrc/seclabNullProviders.ts';
import { Registry } from 'vs/platform/registry/common/platform.js';
import { Extensions as WorkbenchExtensions } from 'vs/workbench/common/contributions.js';
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

/**
 * The three workbench contributions patch 0019 withholds. These are the actual mechanism that
 * closes R12-2: `RemoteAgentHostContribution._registerAgent` is the only site in the tree that
 * registers a chat agent for a connection other than this window's own. Until review round 13
 * this probe never looked at them at all, and inferred containment from a sibling service's
 * registration instead.
 */
const CONTRIBUTIONS = [
	'workbench.contrib.remoteAgentHostContribution',
	'workbench.contrib.editorCloudSandbox',
	'workbench.contrib.missionControl',
];
/**
 * The names the registration wrapper looks shapes up by, which are NOT the registry ids above:
 * a contribution is registered under its own `ID` constant. Both are needed, and conflating
 * them is what made the first version of this check report "<not registered>" for all three.
 */
const CONTRIBUTION_SHAPE_NAMES = ['remoteAgentHostContribution', 'editorCloudSandboxContribution', 'missionControlContribution'];

/** The one that registers another connection's agents. */
const AGENT_REGISTERING = 'workbench.contrib.remoteAgentHostContribution';

interface Finding { readonly check: string; readonly verdict: 'vulnerable' | 'contained'; readonly detail: unknown }
const findings: Finding[] = [];
const shapeProblems: string[] = [];
/**
 * The probe could not look at something it is meant to look at: a name it lists twice, a
 * provider or contribution not registered under the id it expects, a registry it cannot read.
 * These fail BOTH arms. Recording them as `vulnerable` would let the baseline control pass on a
 * lookup failure, so the control would stop controlling (PR #43 review).
 */
const measurementProblems: string[] = [];
const add = (check: string, verdict: Finding['verdict'], detail: unknown) => findings.push({ check, verdict, detail });

for (const [what, names] of [['COVERED', COVERED], ['CONTRIBUTIONS', CONTRIBUTIONS], ['CONTRIBUTION_SHAPE_NAMES', CONTRIBUTION_SHAPE_NAMES]] as const) {
	const dupes = names.filter((n, i) => names.indexOf(n) !== i);
	if (dupes.length) {
		measurementProblems.push(`${what} lists ${dupes.join(', ')} more than once, so it checks fewer things than it counts`);
	}
}

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
	measurementProblems.push(`providers not registered under the expected id: ${COVERED.filter(n => !registered.has(n)).join(', ')}`);
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
		if ((id as { toString(): string }).toString() === 'missionControlEnvironmentService') {
			return (descriptor as { ctor?: unknown }).ctor;
		}
	}
	return undefined;
})();

if (!sample) {
	measurementProblems.push('the sampled provider, missionControlEnvironmentService, is not registered at all');
} else if (registered.get('missionControlEnvironmentService') !== GUARD) {
	// Baseline: there is no guard, so a tab window gets the real provider. Constructing the
	// real one here would reach its own dependency graph, which is not what is under test;
	// that it is registered unguarded is already the finding.
	add('provider-construction', 'vulnerable', { ctor: registered.get('missionControlEnvironmentService') });
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
// 3. The three workbench contributions, read from the real contributions registry. This is
//    the mechanism that actually closes R12-2, and until review round 13 the probe did not
//    look at it: it inferred containment from a sibling service's registration instead.
// ---------------------------------------------------------------------------------------
const contributionCtors = new Map<string, string>();
{
	const reg = Registry.as(WorkbenchExtensions.Workbench) as unknown as { contributionsById?: Map<string, { ctor?: { name?: string } }> };
	const byId = reg.contributionsById;
	if (!(byId instanceof Map)) {
		// Upstream changed how contributions are stored. Fail in both modes rather than check
		// nothing and report containment.
		measurementProblems.push('the workbench contributions registry could not be read');
	} else {
		for (const id of CONTRIBUTIONS) {
			const ctor = byId.get(id)?.ctor;
			if (!ctor) {
				// A wrong id or a moved registration is a lookup failure, not a live contribution.
				measurementProblems.push(`no contribution is registered under ${id}`);
				continue;
			}
			contributionCtors.set(id, ctor.name ?? '<anonymous>');
		}
		const unguarded = CONTRIBUTIONS.filter(id => contributionCtors.has(id) && contributionCtors.get(id) !== GUARD);
		if (contributionCtors.size === CONTRIBUTIONS.length) {
			add('contributions-guarded', unguarded.length ? 'vulnerable' : 'contained',
				{ ctors: Object.fromEntries(contributionCtors), unguarded });
		}
	}
}

// The agent-registering contribution, constructed for real in a tab window. If the real class
// is never built, `_registerAgent` never runs, and there is no other connection's agent for a
// forged id to name. This is an observation, not a restatement of check 1.
const remoteCtor = (() => {
	const reg = Registry.as(WorkbenchExtensions.Workbench) as unknown as { contributionsById?: Map<string, { ctor?: unknown }> };
	return reg.contributionsById instanceof Map ? reg.contributionsById.get(AGENT_REGISTERING)?.ctor : undefined;
})();

if (!remoteCtor) {
	measurementProblems.push(`the agent-registering contribution is not registered under ${AGENT_REGISTERING}`);
} else if (contributionCtors.get(AGENT_REGISTERING) !== GUARD) {
	add('forged-agent-id', 'vulnerable', {
		ctor: contributionCtors.get(AGENT_REGISTERING),
		note: 'the contribution that registers another connection agents is live in a tab window, so an agent id forged by a tab can select one of them',
	});
} else {
	const tab = constructAs('seclab+t-probe', remoteCtor);
	const ordinary = constructAs(undefined, remoteCtor);
	add('forged-agent-id', !tab.built && ordinary.built ? 'contained' : 'vulnerable', {
		builtRealInTab: tab.built,
		ordinaryUnaffected: ordinary.built,
		note: 'CONTAINED: the agent-registering contribution is never constructed in a tab window, so a forged agent id has no other connection agent to name',
	});
}

// ---------------------------------------------------------------------------------------
// 4. Baseline only: every shape is checked against the REAL class upstream registers under
//    that id. Review round 13 found shapes filed under the wrong service name, which no test
//    that named the shapes itself could catch.
// ---------------------------------------------------------------------------------------
if (MODE === 'baseline') {
	const realCtors = new Map<string, unknown>();
	for (const [id, descriptor] of getSingletonServiceDescriptors()) {
		realCtors.set(String(id), (descriptor as { ctor?: unknown }).ctor);
	}
	const problems = assertShapesMatchRealServices(realCtors);
	const unshaped = unshapedProblems([...COVERED, ...CONTRIBUTION_SHAPE_NAMES]);
	if (problems.length || unshaped.length) {
		shapeProblems.push(...problems, ...unshaped);
	}
}

const vulnerable = findings.filter(f => f.verdict === 'vulnerable');
// The baseline is the control, and it must be vulnerable for the RIGHT reasons: the providers
// and the contributions are live. Accepting any failure would let a probe whose own scope had
// narrowed (an upstream rename, an unreadable registry) still report a passing control.
const BASELINE_MUST_SHOW = ['providers-guarded', 'contributions-guarded', 'forged-agent-id'];
const baselineOk = BASELINE_MUST_SHOW.every(c => findings.some(f => f.check === c && f.verdict === 'vulnerable'));
const actual = vulnerable.length ? 'vulnerable' : 'contained';
const expected = MODE === 'baseline' ? 'vulnerable' : 'contained';
const ok = MODE === 'baseline' ? baselineOk : actual === 'contained';

console.log(JSON.stringify({ mode: MODE, actual, expected, measurementProblems, shapeProblems, findings }, undefined, '\t'));

if (measurementProblems.length) {
	console.error(`agent-registration probe: ${measurementProblems.length} measurement problem(s), so nothing this arm reports is evidence:\n  ${measurementProblems.join('\n  ')}`);
	process.exit(1);
}
if (shapeProblems.length) {
	console.error(`agent-registration probe: ${shapeProblems.length} shape problem(s):\n  ${shapeProblems.join('\n  ')}`);
	process.exit(1);
}
if (!ok) {
	console.error(MODE === 'baseline'
		? `agent-registration probe: the baseline control must show ${BASELINE_MUST_SHOW.join(', ')} vulnerable; it showed ${vulnerable.map(f => f.check).join(', ') || 'nothing'}`
		: `agent-registration probe: gated should be contained, got ${actual}`);
	process.exit(1);
}
