// Runtime import specifiers of a TypeScript source, for build/check-patch-reach.ts (review VV-6).
// Comments are stripped first, and type-only imports/exports (`import type`, `export type`,
// `import { type A, type B }`) are skipped: they are erased at compile time and don't make a
// module reachable. A misparse can only drop edges, which makes the reach check stricter.
const IMPORT = /(?:^|[\s;])(import|export)\s+(type\s+)?([^'"`;]*?)from\s*['"]([^'"]+)['"]|(?:^|[\s;])import\s*['"]([^'"]+)['"]|\bimport\(\s*['"]([^'"]+)['"]\s*\)/g;
const TYPE_ONLY_CLAUSE = /^\{\s*type\s+[\w$]+(?:\s+as\s+[\w$]+)?(?:\s*,\s*type\s+[\w$]+(?:\s+as\s+[\w$]+)?)*\s*,?\s*\}$/;

export const stripComments = (text: string): string =>
	text.replace(/("(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`)|\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, (_, str) => str ?? ' ');

export const runtimeSpecs = (text: string): string[] => {
	const out: string[] = [];
	for (const m of stripComments(text).matchAll(IMPORT)) {
		if (m[4] !== undefined) {
			if (!m[2] && !TYPE_ONLY_CLAUSE.test(m[3].trim())) {
				out.push(m[4]);
			}
		} else {
			out.push(m[5] ?? m[6]);
		}
	}
	return out;
};
