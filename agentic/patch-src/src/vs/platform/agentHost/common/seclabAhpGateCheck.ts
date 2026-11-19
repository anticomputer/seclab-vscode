/*---------------------------------------------------------------------------------------------
 *  seclab-vscode: the AHP gate's construction invariant (patch 0015).
 *  `AgentHostProtocolClient` calls `seclabAhpCheckTransport` for every transport it installs.
 *  In a seclab tab window every transport reports `ahp-gate.opened`; one built over the gate
 *  then reports `ahp-gate.verified`, and any other is refused. The brand lives in this module's
 *  private WeakMap, which nothing outside the renderer can reach.
 *--------------------------------------------------------------------------------------------*/

import type { SeclabAhpEvent } from './seclabAhpPolicy.js';

export const SECLAB_AUTHORITY_PREFIX = 'seclab+';

const gated = new WeakMap<object, number>();
let sink: ((e: SeclabAhpEvent) => void) | undefined;
let nextConnection = 1;

/** True for a `seclab+<tab>` remote authority. */
export function isSeclabAuthority(authority: string | undefined): boolean {
	// In any case, as the RPC filter's tab test (review SRCH3-14).
	return typeof authority === 'string' && authority.toLowerCase().startsWith(SECLAB_AUTHORITY_PREFIX);
}

/** Marks this window as a seclab tab window: from now on every agent-host transport in it
 *  must be gated. Called once, at startup, by the workbench; it can't be undone. */
export function seclabAhpInstallWindow(eventSink: (e: SeclabAhpEvent) => void): void {
	sink ??= eventSink;
}

/** The setting both gates read. Defined here, in the common layer, so that patch 0018's
 *  chat gate (whose caller is in `chat/common/`) and 0015's browser gate name one constant. */
export const SECLAB_AGENTS_ENABLED_SETTING = 'seclab.agents.enabled';

/** The shape of a configuration `inspect()` result this rule reads. */
export interface SeclabInspectedSetting { readonly policyValue?: boolean; readonly defaultValue?: boolean }

/**
 * Whether an agent host is enabled for this window, from sources a TAB CANNOT WRITE:
 * enterprise policy, the registered default, or `SECLAB_AGENTS_ENABLED=1` in the host main
 * process environment, stamped onto the window configuration at load.
 *
 * `getValue` is deliberately not used: it merges the user, remote and workspace layers, and a
 * tab extension can write the user layer through `$updateConfigurationOption`.
 *
 * This lives here, in the common layer, so that BOTH callers share one implementation: 0015's
 * `seclabAgentHostAllowed` (browser) and 0018's chat gate, whose caller is in `chat/common/`
 * and may not import from `browser/`. Two copies of an enablement rule would be a drift
 * hazard in the one place drift is least acceptable.
 */
export function seclabAgentsEnabled(inspected: SeclabInspectedSetting, windowSeclabAgentsEnabled: boolean | undefined): boolean {
	return inspected.policyValue === true
		|| windowSeclabAgentsEnabled === true
		|| (inspected.policyValue === undefined && inspected.defaultValue === true);
}

/**
 * Writes an event to this window's gate log, for callers in the common layer that have no
 * `ServicesAccessor` to hand (patch 0018's chat gate). Silent before the sink is installed,
 * which is startup only: the gate log exists before any chat request can be dispatched.
 */
export function seclabAhpEmit(event: SeclabAhpEvent): void {
	sink?.(event);
}

/** A fresh connection number, shared by gated and ungated transports. */
export function seclabAhpNextConnection(): number {
	return nextConnection++;
}

/** Called by the gate for a transport it built over its filtered channel. */
export function seclabAhpBrandTransport(transport: object, connection: number): void {
	gated.set(transport, connection);
}

function connectionEvent(rule: string, connection: number, priority: SeclabAhpEvent['priority'], verdict: string): SeclabAhpEvent {
	return { source: 'ahp-gate', class: 'ahp.decision', priority, summary: `${rule} connection ${connection}`, detail: { gateRule: rule, connection, verdict } };
}

/** The invariant. Throws for an ungated transport in a seclab tab window. */
export function seclabAhpCheckTransport(identity: unknown, transport: object): void {
	const tabIdentity = typeof identity === 'string' && identity.toLowerCase().startsWith(`vscode-remote://${SECLAB_AUTHORITY_PREFIX}`);
	if (!sink && !tabIdentity) {
		return;
	}
	const branded = gated.get(transport);
	const connection = branded ?? seclabAhpNextConnection();
	sink?.(connectionEvent('ahp-gate.opened', connection, 'informational', 'allow'));
	if (branded !== undefined) {
		sink?.(connectionEvent('ahp-gate.verified', connection, 'informational', 'allow'));
		return;
	}
	sink?.(connectionEvent('ahp-gate.refused', connection, 'critical', 'deny'));
	throw new Error('seclab: refusing an agent-host transport that does not pass through the gate');
}
