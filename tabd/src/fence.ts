// sbx fence logic (pure): parse `sbx policy ls --wide --json` and decide whether a
// sandbox can reach anything other than its own broker. See
// docs/edr/20261104-sbx-fence-spike.md. Fails closed on anything unexpected.

import { assertPolicyResource } from './validate.ts';

export interface PolicyRule {
	readonly id: string;
	readonly applies_to: string;
	readonly scope: string;
	readonly decision: string;
	readonly resource_type: string;
	readonly resources: readonly string[];
	readonly actions: readonly string[];
	readonly status: string;
}

// The global fallback deny ("deny when no rule decides") never overrides an allow,
// so it must not count as coverage.
const FALLBACK_DENY_IDS = new Set(['default-deny-all']);
const KNOWN_ACTIONS = new Set(['net:connect:tcp', 'net:connect:udp']);
// Filesystem rules govern which host paths sbx may mount; the supervisor alone chooses
// mounts (validate.ts), so they are known-but-irrelevant. Anything else fails closed.
const KNOWN_RESOURCE_TYPES = new Set(['network', 'filesystem:read', 'filesystem:write']);

export function parsePolicyJson(raw: string): PolicyRule[] {
	let doc: unknown;
	try {
		doc = JSON.parse(raw);
	} catch {
		throw new Error('sbx policy output is not JSON');
	}
	const rules = (doc as { rules?: unknown })?.rules;
	if (!Array.isArray(rules)) {
		throw new Error('sbx policy output has no rules array');
	}
	return rules.map((r, i) => {
		const o = r as Record<string, unknown>;
		const str = (k: string) => {
			if (typeof o[k] !== 'string') {
				throw new Error(`rule ${i}: field ${k} missing or not a string`);
			}
			return o[k] as string;
		};
		const arr = (k: string) => {
			const v = o[k];
			if (!Array.isArray(v) || !v.every(x => typeof x === 'string')) {
				throw new Error(`rule ${i}: field ${k} missing or not a string array`);
			}
			return v as string[];
		};
		return {
			id: str('id'), applies_to: str('applies_to'), scope: str('scope'), decision: str('decision'),
			resource_type: str('resource_type'), resources: arr('resources'), actions: arr('actions'), status: str('status'),
		};
	});
}

/** Network allow resources that apply to this sandbox (global + scoped), excluding the broker. */
export function effectiveAllows(rules: readonly PolicyRule[], sandboxName: string): Array<{ resource: string; action: string; ruleId: string }> {
	const out: Array<{ resource: string; action: string; ruleId: string }> = [];
	for (const r of applicable(rules, sandboxName)) {
		if (r.decision !== 'allow') {
			continue;
		}
		for (const res of r.resources) {
			for (const a of r.actions) {
				out.push({ resource: res, action: a, ruleId: r.id });
			}
		}
	}
	return out;
}

function applicable(rules: readonly PolicyRule[], sandboxName: string): PolicyRule[] {
	return rules.filter(r =>
		r.resource_type === 'network' && r.status === 'active' &&
		(r.applies_to === 'all' || r.applies_to === `sandbox:${sandboxName}`));
}

/** Resources to deny per-sandbox at create time: every allow that applies globally. */
export function resourcesToMirror(rules: readonly PolicyRule[]): string[] {
	const set = new Set<string>();
	for (const r of rules) {
		if (r.resource_type === 'network' && r.status === 'active' && r.decision === 'allow' && r.applies_to === 'all') {
			for (const res of r.resources) {
				set.add(assertPolicyResource(res));
			}
		}
	}
	return [...set].sort();
}

/**
 * The fence invariant: every network allow applying to the sandbox, except
 * `localhost:<brokerPort>`/tcp, is covered by a sandbox-scoped deny with the same
 * resource and action. Unknown decisions/actions/statuses on applicable rules fail.
 */
export function checkFence(rules: readonly PolicyRule[], sandboxName: string, brokerPort?: number): string[] {
	const problems: string[] = [];
	const scoped = `sandbox:${sandboxName}`;
	const covered = new Set<string>();
	for (const r of rules) {
		if (!KNOWN_RESOURCE_TYPES.has(r.resource_type)) {
			problems.push(`rule ${r.id}: unknown resource type ${JSON.stringify(r.resource_type)}`);
			continue;
		}
		if (r.resource_type !== 'network') {
			continue;
		}
		if (r.applies_to !== 'all' && r.applies_to !== scoped) {
			continue;
		}
		if (r.status !== 'active') {
			// Inactive rules don't apply; but an unknown status is suspicious.
			if (r.status !== 'inactive' && r.status !== 'disabled') {
				problems.push(`rule ${r.id}: unknown status ${JSON.stringify(r.status)}`);
			}
			continue;
		}
		if (r.decision !== 'allow' && r.decision !== 'deny') {
			problems.push(`rule ${r.id}: unknown decision ${JSON.stringify(r.decision)}`);
			continue;
		}
		for (const a of r.actions) {
			if (!KNOWN_ACTIONS.has(a)) {
				problems.push(`rule ${r.id}: unknown action ${JSON.stringify(a)}`);
			}
		}
		if (r.decision === 'deny' && r.applies_to === scoped && !FALLBACK_DENY_IDS.has(r.id)) {
			for (const res of r.resources) {
				for (const a of r.actions) {
					covered.add(`${res}\u0000${a}`);
				}
			}
		}
	}
	const broker = brokerPort !== undefined ? `localhost:${brokerPort}` : undefined;
	for (const { resource, action, ruleId } of effectiveAllows(rules, sandboxName)) {
		if (broker && resource === broker && action === 'net:connect:tcp' && ruleId !== undefined) {
			const rule = rules.find(r => r.id === ruleId);
			if (rule?.applies_to === scoped) {
				continue; // our own broker allow
			}
		}
		if (!covered.has(`${resource}\u0000${action}`)) {
			problems.push(`allow ${resource} (${action}) from rule ${ruleId} is not denied for ${sandboxName}`);
		}
	}
	return problems;
}
