/*---------------------------------------------------------------------------------------------
 *  seclab: does a string hold a secret by gitleaks' default rules? (patch 0036, EDR
 *  configuration-snapshot). A port of gitleaks' per-rule decision (detect/detect.go detectRule,
 *  checkFindingAllowed; utils.go shannonEntropy) over the rule table generated from its pinned
 *  config. Paths and commits don't exist here, so path allowlists never allow anything.
 *  Shared, dependency-free code (source of truth build/secret-rules/src/, synced into the patch).
 *--------------------------------------------------------------------------------------------*/

import { SECLAB_SECRET_GLOBAL_ALLOW, SECLAB_SECRET_RULES } from './seclabSecretRules.js';
import type { SeclabSecretRule } from './seclabSecretRules.js';

interface Allow { readonly target: string; readonly and: boolean; readonly regexes: RegExp[]; readonly stopwords: readonly string[] }
interface Compiled { readonly rule: SeclabSecretRule; readonly re: RegExp; readonly once: RegExp; readonly allow: Allow[] }

let compiled: { rules: Compiled[]; global: Allow } | undefined;
function compile(): { rules: Compiled[]; global: Allow } {
	compiled ??= {
		rules: SECLAB_SECRET_RULES.map(rule => ({
			rule,
			re: new RegExp(rule.source, rule.flags + 'g'),
			once: new RegExp(rule.source, rule.flags),
			allow: rule.allow.map(a => ({ target: a.target, and: a.and, stopwords: a.stopwords, regexes: a.regexes.map(r => new RegExp(r.source, r.flags)) })),
		})),
		global: { target: 'secret', and: false, stopwords: SECLAB_SECRET_GLOBAL_ALLOW.stopwords, regexes: SECLAB_SECRET_GLOBAL_ALLOW.regexes.map(r => new RegExp(r.source, r.flags)) },
	};
	return compiled;
}

const encoder = new TextEncoder();
function entropy(s: string): number {
	const bytes = encoder.encode(s).length;
	if (!bytes) {
		return 0;
	}
	const counts = new Map<string, number>();
	for (const ch of s) {
		counts.set(ch, (counts.get(ch) ?? 0) + 1);
	}
	let e = 0;
	for (const n of counts.values()) {
		const f = n / bytes;
		e -= f * Math.log2(f);
	}
	return e;
}

function allowed(a: Allow, secret: string, match: string, line: string): boolean {
	const target = a.target === 'match' ? match : a.target === 'line' ? line : secret;
	const regex = a.regexes.some(r => r.test(target));
	const lower = secret.toLowerCase();
	const stop = a.stopwords.some(w => lower.includes(w));
	if (a.and) {
		const checks = [...(a.regexes.length ? [regex] : []), ...(a.stopwords.length ? [stop] : [])];
		return checks.length > 0 && checks.every(Boolean);
	}
	return regex || stop;
}

/** The id of the first gitleaks default rule that finds a secret in `line`, or undefined. */
export function seclabSecretRuleHit(line: string): string | undefined {
	const { rules, global } = compile();
	const lower = line.toLowerCase();
	for (const c of rules) {
		if (c.rule.keywords.length && !c.rule.keywords.some(k => lower.includes(k))) {
			continue;
		}
		c.re.lastIndex = 0;
		for (const m of line.matchAll(c.re)) {
			const match = m[0].replace(/^\n+|\n+$/g, '');
			let secret = match;
			// gitleaks takes the groups from the pattern applied again to the trimmed match.
			const groups = c.once.exec(match);
			if (groups && groups.length >= 2) {
				if (c.rule.group > 0) {
					if (groups.length <= c.rule.group) {
						continue;
					}
					secret = groups[c.rule.group] ?? '';
				} else {
					secret = groups.slice(1).find(g => !!g) ?? secret;
				}
			}
			if (c.rule.entropy !== 0 && entropy(secret) <= c.rule.entropy) {
				continue;
			}
			if (allowed(global, secret, match, line) || c.allow.some(a => allowed(a, secret, match, line))) {
				continue;
			}
			return c.rule.id;
		}
	}
	return undefined;
}
