// Runtime import specifiers of a TypeScript source, for build/check-patch-reach.ts (review VV-6,
// VV-7). One left-to-right token pass: comments and string/template literals are consumed whole,
// so import-like text inside them is never an edge; type-only imports/exports (`import type`,
// `export type`, `import { type A, type B }`) are skipped, since they are erased at compile time.
// Known overstatement (accepted, EDR patch-build gate): a value import whose names are used only
// as types is elided by the compiler but counted here. Reach is a proxy; the runtime-probe rule
// in AGENTS.md is the backstop.
const TOKEN = new RegExp([
	/\/\*[\s\S]*?\*\/|\/\/[^\n]*/.source,
	/(?:^|[\s;])(import|export)\s+(type\s+)?([^'"`;]*?)from\s*['"]([^'"\n]+)['"]/.source,
	/(?:^|[\s;])import\s*['"]([^'"\n]+)['"]/.source,
	/\bimport\(\s*['"]([^'"\n]+)['"]\s*\)/.source,
	/"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`/.source,
].join('|'), 'g');
const TYPE_ONLY_CLAUSE = /^\{\s*type\s+[\w$]+(?:\s+as\s+[\w$]+)?(?:\s*,\s*type\s+[\w$]+(?:\s+as\s+[\w$]+)?)*\s*,?\s*\}$/;

export const runtimeSpecs = (text: string): string[] => {
	const out: string[] = [];
	for (const m of text.matchAll(TOKEN)) {
		if (m[4] !== undefined) {
			if (!m[2] && !TYPE_ONLY_CLAUSE.test(m[3].trim())) {
				out.push(m[4]);
			}
		} else if (m[5] !== undefined || m[6] !== undefined) {
			out.push(m[5] ?? m[6]);
		}
	}
	return out;
};
