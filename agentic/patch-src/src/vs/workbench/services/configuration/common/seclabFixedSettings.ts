/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * seclab patch 0017: settings that are fixed in a tab window.
 *
 * These keys are policy-bearing for agent hosts and **tab-writable** in a `seclab+` window:
 * each is registered at `WINDOW` scope or not registered at all where an editor window reads
 * it, and `REMOTE_MACHINE_SCOPES` lets the REH's remote user settings supply anything that is
 * not `APPLICATION`. So a tab can turn them on for the trusted window that is reading them.
 *
 * Upstream declares no policy on these registrations, so they cannot be pinned the way a
 * policy-bearing setting is (design §3.5, review round 2 finding 4). The user's decision on
 * 0011 rules out re-registering them globally: lock tab windows, leave ordinary windows alone.
 * This patch therefore fixes the **read** in a tab window and changes no registration.
 *
 * It is one override point, not one per reader, deliberately. The readers are spread across
 * the browser view service, the chat contribution and the sessions providers, and a list of
 * call sites would silently miss a reader added by an upstream bump; the configuration
 * service is the single place every one of them goes through.
 *
 * `workbench.browser.enableRemoteProxy` is deliberately NOT here yet. Security review round 6
 * found a third open path the measurement had missed: the browser tools resolve the network
 * with the PUBLIC `resolveNetwork`, which yields `undefined` when the proxy is off, so the
 * page loads on the HOST network for a model-chosen URL. Our own authority always reports
 * `proxySupported: true`, so that is a real change, not a no-op. Forcing `false` would
 * therefore open a host-network egress path that leaving the setting alone does not. The
 * value is settled in its own increment; see the EDR.
 */

/** The fixed values, by setting id. Tab windows only. */
export const SECLAB_FIXED_TAB_SETTINGS: ReadonlyMap<string, unknown> = new Map<string, unknown>([
	['chat.automations.enabled', false],
	['chat.automations.cloud.enabled', false],
]);

/**
 * The authority prefix of a seclab tab window. Declared here rather than imported from
 * 0015's `seclabAhpGateCheck`, because a value import across patch modules does not resolve
 * under `node --test`'s type stripping and would make this module untestable. Drift is held
 * by a unit test that imports both and asserts they are equal, which is a stronger guarantee
 * than the import it replaces (security review round 6).
 */
export const SECLAB_TAB_AUTHORITY_PREFIX = 'seclab+';

/** Whether this window is a seclab tab window, from its remote authority. */
export function isSeclabTabAuthority(authority: string | undefined): boolean {
	return typeof authority === 'string' && authority.startsWith(SECLAB_TAB_AUTHORITY_PREFIX);
}

/** The fixed value for an exact setting id in a tab window, or `undefined` when none is. */
export function seclabFixedSetting(authority: string | undefined, section: string | undefined): { value: unknown } | undefined {
	if (!isSeclabTabAuthority(authority) || typeof section !== 'string') {
		return undefined;
	}
	const value = SECLAB_FIXED_TAB_SETTINGS.get(section);
	return value === undefined ? undefined : { value };
}

/**
 * Replace every fixed key inside a value read for `section`, so that a caller asking for a
 * prefix (`workbench.browser`) or for the whole configuration cannot read the tab's value
 * around the exact-key override. Returns the input unchanged outside a tab window, and when
 * nothing below `section` is fixed. Never mutates the input.
 */
export function seclabScrubFixedSettings(authority: string | undefined, section: string | undefined, value: unknown): unknown {
	if (!isSeclabTabAuthority(authority) || value === null || typeof value !== 'object' || Array.isArray(value)) {
		return value;
	}
	let out = value as Record<string, unknown>;
	let copied = false;
	for (const [key, fixedValue] of SECLAB_FIXED_TAB_SETTINGS) {
		if (section !== undefined && !key.startsWith(`${section}.`)) {
			continue;
		}
		const path = (section === undefined ? key : key.slice(section.length + 1)).split('.');
		if (readPath(out, path) === undefined) {
			continue;
		}
		if (!copied) {
			out = { ...out };
			copied = true;
		}
		writePath(out, path, fixedValue);
	}
	return out;
}

function readPath(root: Record<string, unknown>, path: string[]): unknown {
	let current: unknown = root;
	for (const part of path) {
		if (current === null || typeof current !== 'object') {
			return undefined;
		}
		current = (current as Record<string, unknown>)[part];
	}
	return current;
}

/** Writes `value` at `path`, copying every object it descends through so the input is not mutated. */
function writePath(root: Record<string, unknown>, path: string[], value: unknown): void {
	let current = root;
	for (let i = 0; i < path.length - 1; i++) {
		const next = current[path[i]];
		if (next === null || typeof next !== 'object' || Array.isArray(next)) {
			return;
		}
		current[path[i]] = { ...next as Record<string, unknown> };
		current = current[path[i]] as Record<string, unknown>;
	}
	current[path[path.length - 1]] = value;
}
