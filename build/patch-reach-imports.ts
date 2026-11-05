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

/**
 * Every file a unified diff creates or modifies, in any header style: `git diff` (`diff --git`,
 * `+++ b/PATH`, `rename to`/`copy to` for header-less renames and copies) and `diff -ruN`
 * (`+++ b/PATH<TAB>timestamp`). Hunks are consumed by their line counts, so content lines that
 * look like headers are never read as headers. Deleted files are left out. Anything this can't
 * read throws, so the gate fails rather than shrinking what it checks: an unreadable or unpaired
 * header, a binary patch, a quoted or relative path (RPC session report: an end-anchored regex
 * skipped every `diff -ruN` header and passed with nothing checked; review WW-5).
 */
export const patchedFiles = (patch: string): string[] => {
	const out = new Set<string>();
	const bad = (line: string): never => {
		throw new Error(`unreadable patch header: ${JSON.stringify(line.slice(0, 200))}`);
	};
	const clean = (p: string, line: string): string =>
		/^[^\s"]+$/.test(p) && !p.split('/').some(s => s === '..' || s === '.' || s === '') ? p : bad(line);
	const lines = patch.split('\n').map(l => l.replace(/\r$/, ''));
	let oldLeft = 0;
	let newLeft = 0;
	let current: string | undefined;
	for (let i = 0; i < lines.length; i++) {
		const line = lines[i];
		if (oldLeft > 0 || newLeft > 0) {
			const c = line[0];
			if (c === ' ' || line === '') {
				oldLeft--;
				newLeft--;
			} else if (c === '-') {
				oldLeft--;
			} else if (c === '+') {
				newLeft--;
			} else if (c !== '\\') {
				bad(line);
			}
			continue;
		}
		if (line.startsWith('@@ ')) {
			const m = /^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@/.exec(line) ?? bad(line);
			oldLeft = m[1] === undefined ? 1 : Number(m[1]);
			newLeft = m[2] === undefined ? 1 : Number(m[2]);
		} else if (line.startsWith('diff ')) {
			const m = /^diff (?:--git|-\S+) a\/(\S+) b\/(\S+)$/.exec(line) ?? bad(line);
			current = clean(m[2], line);
			out.add(current);
		} else if (/^(rename|copy) to /.test(line)) {
			out.add(clean(line.replace(/^(rename|copy) to /, ''), line));
		} else if (line.startsWith('deleted file mode') && current) {
			out.delete(current);
		} else if (line.startsWith('GIT binary patch') || line.startsWith('Binary files ')) {
			bad(line);
		} else if (line.startsWith('--- ')) {
			const next = lines[i + 1] ?? '';
			if (!next.startsWith('+++ ')) {
				bad(line);
			}
			i++;
			const p = next.slice(4).split('\t')[0].trimEnd();
			if (p === '/dev/null') {
				if (current) {
					out.delete(current);
				}
				continue;
			}
			out.add(p.startsWith('b/') ? clean(p.slice(2), next) : bad(next));
		} else if (line.startsWith('+++ ')) {
			bad(line);
		}
	}
	return [...out];
};
