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
	return typeof authority === 'string' && authority.startsWith(SECLAB_AUTHORITY_PREFIX);
}

/** Marks this window as a seclab tab window: from now on every agent-host transport in it
 *  must be gated. Called once, at startup, by the workbench; it can't be undone. */
export function seclabAhpInstallWindow(eventSink: (e: SeclabAhpEvent) => void): void {
	sink ??= eventSink;
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
	const tabIdentity = typeof identity === 'string' && identity.startsWith(`vscode-remote://${SECLAB_AUTHORITY_PREFIX}`);
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
