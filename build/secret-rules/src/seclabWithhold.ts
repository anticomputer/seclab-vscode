/*---------------------------------------------------------------------------------------------
 *  seclab: would a setting be withheld from a tab as a credential? (patch 0036, EDR
 *  configuration-snapshot). Shared, dependency-free code: the workbench's tab configuration filter
 *  and the Tab Manager (which checks a "setting withheld" notice before raising it) run this same
 *  file. Source of truth: build/secret-rules/src/, synced into the patch by
 *  build/secret-rules/sync-patch.ts.
 *--------------------------------------------------------------------------------------------*/

import { seclabSecretRuleHit } from './seclabSecretScan.js';

/** In the workbench bundle wherever the filter installs; the Tab Manager requires it (obs v1). */
export const SECLAB_SETTINGS_WITHHELD_MARKER = 'seclabSettingsWithheld:v1';

/**
 * Names that mean "credential" whatever the value looks like (scanners miss weak passwords), plus
 * environment maps such as `terminal.integrated.env.*`.
 */
const CREDENTIAL_NAME = /token|passw|pwd|secret|auth|api[_-]?key|credential|private[_-]?key|(?:^|\.)env(?:\.|$)/i;

export type SeclabWithholdReason = 'credential-name' | 'secret-value';

function names(value: unknown, out: string[]): void {
	if (value && typeof value === 'object') {
		for (const [k, v] of Object.entries(value)) {
			out.push(k);
			names(v, out);
		}
	}
}

function leaves(value: unknown, path: string, out: Array<[string, string]>): void {
	if (typeof value === 'string') {
		out.push([path, value]);
	} else if (value && typeof value === 'object') {
		for (const [k, v] of Object.entries(value)) {
			leaves(v, `${path}.${k}`, out);
		}
	}
}

/**
 * Why `key` with `value` must not reach a tab, or undefined if nothing about it looks like a
 * credential:
 * - `credential-name`: the key, or any key name inside the value, names a credential;
 * - `secret-value`: a string in the value is a secret by gitleaks' default rules, checked as the
 *   line `"<key path>": "<string>"`.
 */
export function withholdReason(key: string, value: unknown): SeclabWithholdReason | undefined {
	const all = [key];
	names(value, all);
	if (all.some(n => CREDENTIAL_NAME.test(n))) {
		return 'credential-name';
	}
	const strings: Array<[string, string]> = [];
	leaves(value, key, strings);
	if (strings.some(([p, v]) => seclabSecretRuleHit(`${JSON.stringify(p)}: ${JSON.stringify(v)}`) !== undefined)) {
		return 'secret-value';
	}
	return undefined;
}
