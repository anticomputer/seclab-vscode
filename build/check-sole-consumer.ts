// Sole-consumer invariants (EDR patch-build gate, 0010/0015 seam).
//
// Some patches are safe only because exactly one call site reaches a capability. Patch 0015
// gates the agent-host transport by wrapping the `agentHostProxy` channel INSIDE
// `EditorRemoteAgentHostServiceClient`, rather than at whichever site selects that client.
// That is what makes the gate hold for any caller, including patch 0010's selection in
// `agentHostService.ts`: there is no ungated client to hand out. It also means a second
// consumer of that channel, added by a later patch or by an upstream bump, would silently
// reopen the hole while every other gate check still passed, because the gate would simply
// never see those frames.
//
// A runtime probe cannot establish this: it can show that the connections it observed were
// gated, never that no other consumer exists. So it is asserted statically, over the patched
// tree, by `patches/sole-consumer.json`:
//
//   { "<symbol>": { "why": "...", "files": { "<path>": "<substring every match line must contain>" } } }
//
// Every file that mentions the symbol must be listed, and every line that mentions it must
// contain that file's required substring (use "" to allow any line, e.g. for server-side
// registration). An unlisted file, or a listed file that no longer mentions the symbol, fails.

import * as fs from 'node:fs';
import * as path from 'node:path';

interface Rule { why: string; files: Record<string, string> }
interface UpstreamInvariants { why: string; rules: { file: string; mustContain: string[]; why: string }[] }

/** Returns the problems found; empty means the invariants hold. */
export function soleConsumerProblems(src: string, configFile: string): string[] {
	if (!fs.existsSync(configFile)) {
		return [];
	}
	const parsed = JSON.parse(fs.readFileSync(configFile, 'utf8')) as Record<string, Rule | UpstreamInvariants>;
	const problems: string[] = [];
	// Facts about upstream that a patch's security argument rests on. They live here, not in
	// a unit test, because the unit container has no upstream checkout, and this check already
	// runs over the patched tree.
	const invariants = parsed.__upstreamInvariants as UpstreamInvariants | undefined;
	for (const rule of invariants?.rules ?? []) {
		const file = path.join(src, rule.file);
		if (!fs.existsSync(file)) {
			problems.push(`upstream invariant: ${rule.file} does not exist (${rule.why})`);
			continue;
		}
		const text = fs.readFileSync(file, 'utf8');
		for (const needle of rule.mustContain) {
			if (!text.includes(needle)) {
				problems.push(`upstream invariant: ${rule.file} no longer contains ${JSON.stringify(needle)}\n      ${rule.why}`);
			}
		}
	}
	const rules = Object.fromEntries(Object.entries(parsed).filter(([k]) => !k.startsWith('__'))) as Record<string, Rule>;
	for (const [symbol, rule] of Object.entries(rules)) {
		const found = new Map<string, string[]>();
		for (const file of sourceFiles(path.join(src, 'src', 'vs'))) {
			const rel = path.relative(src, file);
			// Upstream's own tests are not shipped and are rewritten freely upstream.
			if (/(^|\/)test(s)?\//.test(rel)) {
				continue;
			}
			const hits = fs.readFileSync(file, 'utf8').split('\n')
				.map((line, i) => ({ line, n: i + 1 }))
				.filter(({ line }) => line.includes(symbol));
			if (hits.length) {
				found.set(rel, hits.map(({ line, n }) => `${n}: ${line.trim()}`));
			}
		}
		for (const [rel, lines] of found) {
			const required = rule.files[rel];
			if (required === undefined) {
				problems.push(`${symbol}: unexpected consumer ${rel} (${rule.why})\n      ${lines.join('\n      ')}`);
				continue;
			}
			for (const line of lines) {
				if (required && !line.includes(required)) {
					problems.push(`${symbol}: ${rel} mentions it outside \`${required}\`\n      ${line}`);
				}
			}
		}
		for (const rel of Object.keys(rule.files)) {
			if (!found.has(rel)) {
				problems.push(`${symbol}: ${rel} no longer mentions it; the invariant is stale and must be re-derived`);
			}
		}
	}
	return problems;
}

function sourceFiles(root: string): string[] {
	const out: string[] = [];
	const stack = [root];
	while (stack.length) {
		for (const e of fs.readdirSync(stack.pop()!, { withFileTypes: true })) {
			const p = path.join(e.parentPath, e.name);
			if (e.isDirectory()) {
				stack.push(p);
			} else if (e.name.endsWith('.ts')) {
				out.push(p);
			}
		}
	}
	return out;
}
