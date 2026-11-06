// The policy a tab's broker loads (plan tabd-broker-wiring, decision 1): a built-in deny-all
// default, or the user's policy from the host state directory. Never from the workspace or any
// file a tab can write: the state directory is tabd's own (0700, outside every mount). The
// broker validates the policy against its schema on `policy.load` and rejects it with -32602;
// tabd treats that as a failed start (fail closed).

import * as fs from 'node:fs';
import * as path from 'node:path';

export const USER_POLICY_FILE = 'broker-policy.json';
const MAX_POLICY_BYTES = 256 * 1024;

/**
 * Deny-all. `baseline` keeps the broker's built-in allow rules (the extension gallery).
 * Unmatched requests are held for a prompt only when the connected client shows prompts (the
 * Tab Manager, B3); otherwise they are denied at once rather than held for a prompt nobody sees.
 */
export function defaultPolicy(tabId: string, prompts = false): Record<string, unknown> {
	return { version: 1, tabId, baseline: true, prompt: { enabled: prompts }, allow: [] };
}

export class PolicyError extends Error { }

/** The user's policy if present (tabId forced to this tab), else the default. */
export function tabPolicy(stateDir: string, tabId: string, prompts = false): Record<string, unknown> {
	const f = path.join(stateDir, USER_POLICY_FILE);
	let st: fs.Stats;
	try {
		st = fs.lstatSync(f);
	} catch {
		return defaultPolicy(tabId, prompts);
	}
	if (!st.isFile() || st.size > MAX_POLICY_BYTES) {
		throw new PolicyError(`${USER_POLICY_FILE}: not a regular file under ${MAX_POLICY_BYTES} bytes`);
	}
	if (process.platform !== 'win32' && (st.mode & 0o022) !== 0) {
		throw new PolicyError(`${USER_POLICY_FILE}: writable by group or others`);
	}
	let p: unknown;
	try {
		p = JSON.parse(fs.readFileSync(f, 'utf8'));
	} catch (e) {
		throw new PolicyError(`${USER_POLICY_FILE}: not JSON (${(e as Error).message.slice(0, 120)})`);
	}
	if (!p || typeof p !== 'object' || Array.isArray(p) || (p as { version?: unknown }).version !== 1) {
		throw new PolicyError(`${USER_POLICY_FILE}: not a version 1 policy object`);
	}
	const tid = (p as { tabId?: unknown }).tabId;
	if (tid !== undefined && tid !== tabId) {
		throw new PolicyError(`${USER_POLICY_FILE}: names tab ${JSON.stringify(tid)}; omit tabId for a policy that applies to every tab`);
	}
	return { ...(p as Record<string, unknown>), tabId, prompt: userPrompt((p as { prompt?: unknown }).prompt, prompts) };
}

/** The user's prompt settings, but prompts only where a client can answer them, and only if the user didn't turn them off. */
function userPrompt(v: unknown, prompts: boolean): Record<string, unknown> {
	const o = v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : {};
	return { ...o, enabled: prompts && o.enabled !== false };
}
