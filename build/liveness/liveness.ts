// Liveness gate (EDR 20261109-liveness-gate): everything that only matters if something runs it
// must name what runs it, with evidence that it ran at least once. Five artefacts were complete
// except for the part that runs them: a test hook "applied by the harness" that no harness
// applied, eight probes that never ran, a decision-listener API with no listener behind a false
// exemption, a taint-escape array nobody read, and a scheduled workflow nobody had ever run.
//
// Static half (offline, every push):
//   exports  every exported value in tabd (with observability), the Tab Manager and the broker
//            is reached from code that runs: a file's top-level statements, or a live use in a
//            file that imports it. Liveness propagates only from live declarations, so a
//            cluster that only references itself never vouches for itself. Comments, imports
//            and tests don't count.
//   scripts  every in-tab program in sandbox/rootfs/opt/seclab/bin is named by product code.
//   exempt   an exemption names its consumer, which must exist and use the symbol, or says
//            `consumer: null` and why (printed on every run, so the claim stays visible). An
//            exemption for something live is stale and fails, and so does a subject exempted
//            twice (a union merge keeps both an old and a superseding entry).
//   removed  a tombstone for an exemption removed on purpose: re-adding that subject to
//            `exempt` fails, even when a merge also brings back the code that made it dead.
//            Append-only against the base register (--base); `restored` says why one came back.
// Runtime half (register.json `subjects`, matched exactly against what the tree contains):
//   workflow every workflow with a schedule, or that never runs on push or pull_request. Its
//            evidence is runs of that workflow only (a push run shows the code, not the schedule);
//   hook     every test-only hook in test/builds/variants.json;
//   fixture  every child of a test `fixtures` dir, and every test extension (a dir with a
//            package.json under test/);
//   each with what runs it and at least one piece of evidence:
//     run    a GitHub Actions run of `workflow`; with --verify-runs (CI) it must exist, be a
//            successful dispatch or scheduled run of that workflow, with a successful `job` if named.
//     ci     a CI job (`file.yml#job`) whose last step is `./seclab liveness marks` for that job,
//            and a `mark` the runner records with liveMark (test/liveness.ts) when it saw the
//            subject run. That step fails the job when a mark is missing.
//     record a doc naming the subject id: only for runs CI can't do (macOS, sbx). Listed on
//            every run.
//
// Usage (through ./seclab liveness, which feeds `git ls-files -z` on stdin):
//        node build/liveness/liveness.ts check - --base BASE_REGISTER_FILE
//        node build/liveness/liveness.ts marks FILE.yml#JOB LOGFILE
//        node build/liveness/liveness.ts --self-test

import * as fs from 'node:fs';
import * as path from 'node:path';
import { jobProblems } from '../check-required-checks.ts';

export interface Exempt { subject: string; consumer: string | null; reason: string }
/** A declaration a host calls (VS Code calls `activate`): live, and so is what it reaches. */
export interface Entry { subject: string; calledBy: string; declaredIn: string }
export interface Evidence { run?: number; workflow?: string; job?: string; sha?: string; date?: string; ci?: string; mark?: string; runner?: string; record?: string }
export interface Subject { id: string; runBy: string; evidence: Evidence[] }
/**
 * An exemption removed on purpose, kept so that a merge cannot quietly bring it back. Append-only
 * against the base register; `restored` says why bringing it back is deliberate.
 */
export interface Removed { subject: string; reason: string; restored?: string }
export interface Register { entry?: Entry[]; exempt: Exempt[]; removed?: Removed[]; subjects: Subject[] }

const REGISTER = 'build/liveness/register.json';
// Code that runs: product sources (every built-in extension's src), and the tools CI or an
// operator runs (doc generators, log CLI).
const IN_SCOPE = /^(?:tabd\/src\/|tabd\/tools\/|extensions\/[^/]+\/src\/|broker\/seclab_broker\/|broker\/tools\/)/;
const BIN = 'sandbox/rootfs/opt/seclab/bin/';
// Who may invoke an in-tab program: product code and the image build, not tests.
const BIN_USERS = ['tabd/src/', 'sandbox/', 'build/', 'extensions/seclab-tab-manager/src/'];

// ---- source scanning ----------------------------------------------------------------------

type Lang = 'ts' | 'py' | 'sh';
export const langOf = (f: string): Lang | undefined =>
	/\.(m?ts)$/.test(f) && !f.endsWith('.d.ts') ? 'ts' : f.endsWith('.py') ? 'py' : undefined;

/**
 * Executable text: comments and imports removed; with `blankStrings`, string contents too (a
 * name inside a message is not a use; template `${}` code is kept). A small lexer, because
 * regexes can't tell `'/**'` from a comment: one string in supervisor.ts once made a regex
 * stripper eat 560 lines. Where the lexer guesses (regex vs division), it can hide a use, which
 * fails the gate; it never invents one.
 */
export function codeOnly(text: string, lang: Lang, blankStrings = false): string {
	if (lang === 'ts') {
		return lexTs(text, blankStrings)
			.replace(/^\s*import\s[\s\S]*?\bfrom\s*['"][^'"]*['"]\s*;?[ \t]*$/gm, '')
			.replace(/^\s*import\s+['"][^'"]*['"]\s*;?[ \t]*$/gm, '')
			.replace(/^\s*export\s*(?:type\s*)?\{[^}]*\}\s*from\s*['"][^'"]*['"]\s*;?[ \t]*$/gm, '')
			.replace(/^\s*export\s*\*\s*(?:as\s+\w+\s*)?from\s*['"][^'"]*['"]\s*;?[ \t]*$/gm, '');
	}
	if (lang === 'py') {
		return lexPy(text, blankStrings)
			.replace(/^\s*from\s+\S+\s+import\s*\([\s\S]*?\)[ \t]*$/gm, '')
			.replace(/^\s*(?:from\s+\S+\s+)?import\s[^\n]*$/gm, '');
	}
	return text.replace(/(^|\s)#[^\n]*/g, '$1');
}

/**
 * Marks a TS file passes to liveMark('…') in code. The call is found in the string-blanked
 * lexer output (so a mention inside a string or comment doesn't count) and its argument is read
 * at the same offset from the unblanked output: both have the same length.
 */
export function markCalls(text: string): string[] {
	const code = lexTs(text, false);
	const blank = lexTs(text, true);
	const out: string[] = [];
	for (const m of blank.matchAll(/(?<![\w$.])liveMark\(\s*'/g)) {
		const at = m.index! + m[0].length;
		const end = code.indexOf('\'', at);
		if (end > at) {
			out.push(code.slice(at, end));
		}
	}
	return out;
}

/** TS/JS: drop comments; keep string delimiters (and contents unless blanked); keep newlines. */
function lexTs(src: string, blank: boolean): string {
	let out = '';
	let i = 0;
	const braces: number[] = []; // per open template: brace depth inside its current `${`
	let lastSig = '';
	const regexAllowed = () => lastSig === '' || /[(,=:[!&|?{};+\-*%<>~^]$/.test(lastSig) || /\b(?:return|typeof|instanceof|in|of|new|delete|void|throw|case|do|else|yield|await)$/.test(lastSig);
	const keep = (s: string) => {
		out += s;
		if (/\S/.test(s)) {
			lastSig = (lastSig + s).replace(/\s+/g, '').slice(-12);
		}
	};
	const body = (s: string) => blank ? s.replace(/[^\n]/g, ' ') : s;
	const template = () => { // at a backtick or a `}` closing `${`: scan to the next `${` or closing backtick
		let s = '';
		while (i < src.length) {
			const c = src[i];
			if (c === '\\') {
				s += src.slice(i, i + 2);
				i += 2;
			} else if (c === '`') {
				keep(body(s) + '`');
				i++;
				return;
			} else if (c === '$' && src[i + 1] === '{') {
				keep(body(s) + '${');
				i += 2;
				braces.push(0);
				return;
			} else {
				s += c;
				i++;
			}
		}
		keep(body(s));
	};
	while (i < src.length) {
		const c = src[i];
		const n = src[i + 1];
		if (c === '/' && n === '/') {
			while (i < src.length && src[i] !== '\n') {
				i++;
			}
		} else if (c === '/' && n === '*') {
			const end = src.indexOf('*/', i + 2);
			const chunk = src.slice(i, end < 0 ? src.length : end + 2);
			out += chunk.replace(/[^\n]/g, '');
			i += chunk.length;
		} else if (c === '\'' || c === '"') {
			let j = i + 1;
			while (j < src.length && src[j] !== c && src[j] !== '\n') {
				j += src[j] === '\\' ? 2 : 1;
			}
			keep(c + body(src.slice(i + 1, j)) + c);
			i = j + 1;
		} else if (c === '`') {
			keep('`');
			i++;
			template();
		} else if (c === '{' && braces.length) {
			braces[braces.length - 1]++;
			keep(c);
			i++;
		} else if (c === '}' && braces.length && braces[braces.length - 1] === 0) {
			braces.pop();
			keep('}');
			i++;
			template();
		} else if (c === '}' && braces.length) {
			braces[braces.length - 1]--;
			keep(c);
			i++;
		} else if (c === '/' && regexAllowed()) {
			let j = i + 1;
			let cls = false;
			while (j < src.length && src[j] !== '\n' && (cls || src[j] !== '/')) {
				if (src[j] === '\\') {
					j++;
				} else if (src[j] === '[') {
					cls = true;
				} else if (src[j] === ']') {
					cls = false;
				}
				j++;
			}
			while (/[a-z]/.test(src[j + 1] ?? '')) {
				j++;
			}
			keep('/' + body(src.slice(i + 1, j)) + '/');
			i = j + 1;
		} else {
			keep(c);
			i++;
		}
	}
	return out;
}

/** Python: drop comments; keep string delimiters (contents unless blanked; f-string `{}` kept). */
function lexPy(src: string, blank: boolean): string {
	let out = '';
	let i = 0;
	while (i < src.length) {
		const c = src[i];
		if (c === '#') {
			while (i < src.length && src[i] !== '\n') {
				i++;
			}
			continue;
		}
		const m = /^([rRbBuUfF]{0,2})('''|"""|'|")/.exec(src.slice(i, i + 5));
		if (m && (i === 0 || !/[\w]/.test(src[i - 1]) || m[1] === '')) {
			const q = m[2];
			const fstr = /f/i.test(m[1]);
			let j = i + m[0].length;
			while (j < src.length && !src.startsWith(q, j) && (q.length === 3 || src[j] !== '\n')) {
				j += src[j] === '\\' && !/r/i.test(m[1]) ? 2 : 1;
			}
			const inner = src.slice(i + m[0].length, j);
			const shown = !blank ? inner : fstr ? inner.replace(/\{([^{}]*)\}|[^\n]/g, (all, expr) => expr !== undefined ? `{${expr}}` : ' ') : inner.replace(/[^\n]/g, ' ');
			out += m[0] + shown + q;
			i = j + q.length;
			continue;
		}
		out += c;
		i++;
	}
	return out;
}

/** Repo files this file imports (relative TS specifiers; relative or seclab_broker Python imports). */
export function importsOf(file: string, text: string, have: Set<string>, links: Map<string, string> = new Map()): Set<string> {
	const out = new Set<string>();
	const dir = path.posix.dirname(file);
	// A tracked symlink (extensions/seclab-tab-manager/tabd-src -> tabd/src) is its target.
	const unlink = (p: string) => {
		for (const [from, to] of links) {
			if (p === from || p.startsWith(`${from}/`)) {
				return to + p.slice(from.length);
			}
		}
		return p;
	};
	const add = (cands: string[]) => {
		const hit = cands.map(c => unlink(path.posix.normalize(c))).find(c => have.has(c));
		if (hit) {
			out.add(hit);
		}
	};
	if (langOf(file) === 'ts') {
		const src = lexTs(text, false);
		for (const m of src.matchAll(/(?:\bfrom\s*|\bimport\s*\(\s*|^\s*import\s+)['"](\.{1,2}\/[^'"]+)['"]/gm)) {
			const p = path.posix.join(dir, m[1]);
			add([p, p.replace(/\.js$/, '.ts'), `${p}.ts`, `${p}/index.ts`]);
		}
	} else {
		const src = lexPy(text, false);
		const pkgRoot = 'broker/seclab_broker';
		const modPath = (base: string, dotted: string) => path.posix.join(base, ...dotted.split('.').filter(Boolean));
		for (const m of src.matchAll(/^\s*from\s+(\.+|seclab_broker\.?)([\w.]*)\s+import\s+\(?([^)\n]*(?:\n[^)\n]*)*?)\)?[ \t]*$/gm)) {
			let base: string;
			if (m[1].startsWith('seclab_broker')) {
				base = pkgRoot;
			} else {
				base = dir;
				for (let i = 1; i < m[1].length; i++) {
					base = path.posix.dirname(base);
				}
			}
			const mod = modPath(base, m[2]);
			add([`${mod}.py`, `${mod}/__init__.py`]);
			for (const name of m[3].split(',').map(s => s.trim().split(/\s+as\s+/)[0]).filter(Boolean)) {
				add([`${path.posix.join(mod, name)}.py`, `${path.posix.join(mod, name)}/__init__.py`]);
			}
		}
		for (const m of src.matchAll(/^\s*import\s+seclab_broker\.([\w.]+)/gm)) {
			const mod = modPath(pkgRoot, m[1]);
			add([`${mod}.py`, `${mod}/__init__.py`]);
		}
		// A script's own directory is on sys.path: `import sibling`, `from sibling import x`.
		for (const m of src.matchAll(/^\s*(?:import\s+([\w, ]+)|from\s+(\w+)\s+import\b)/gm)) {
			for (const name of (m[1] ?? m[2]).split(',').map(s => s.trim().split(/\s+as\s+/)[0]).filter(Boolean)) {
				add([`${dir}/${name}.py`]);
			}
		}
	}
	return out;
}

/**
 * Module aliases a file binds to repo modules: `import * as ns from './x.ts'` (TS);
 * `from . import mod`, `from seclab_broker import mod`, `import seclab_broker.mod as m` (Python).
 * `alias.name` is a use of that module's `name` (any other `.name` is not: KKK-6).
 */
export function aliasesOf(file: string, text: string, have: Set<string>, links: Map<string, string> = new Map()): Array<[string, string]> {
	const out: Array<[string, string]> = [];
	const dir = path.posix.dirname(file);
	const pick = (cands: string[]) => cands.map(c => path.posix.normalize(c)).map(c => {
		for (const [from, to] of links) {
			if (c === from || c.startsWith(`${from}/`)) {
				return to + c.slice(from.length);
			}
		}
		return c;
	}).find(c => have.has(c));
	if (langOf(file) === 'ts') {
		for (const m of lexTs(text, false).matchAll(/\bimport\s*\*\s*as\s+([A-Za-z_$][\w$]*)\s+from\s*['"](\.{1,2}\/[^'"]+)['"]/g)) {
			const p = path.posix.join(dir, m[2]);
			const hit = pick([p, p.replace(/\.js$/, '.ts'), `${p}.ts`, `${p}/index.ts`]);
			if (hit) {
				out.push([hit, m[1]]);
			}
		}
		return out;
	}
	const src = lexPy(text, false);
	for (const m of src.matchAll(/^\s*from\s+(\.+|seclab_broker)\s+import\s+([^\n(]+)$/gm)) {
		let base = 'broker/seclab_broker';
		if (m[1].startsWith('.')) {
			base = dir;
			for (let i = 1; i < m[1].length; i++) {
				base = path.posix.dirname(base);
			}
		}
		for (const part of m[2].split(',')) {
			const [name, alias] = part.trim().split(/\s+as\s+/);
			const hit = name ? pick([`${base}/${name}.py`]) : undefined;
			if (hit) {
				out.push([hit, alias ?? name]);
			}
		}
	}
	for (const m of src.matchAll(/^\s*import\s+seclab_broker\.([\w.]+)\s+as\s+(\w+)/gm)) {
		const hit = pick([`broker/seclab_broker/${m[1].split('.').join('/')}.py`]);
		if (hit) {
			out.push([hit, m[2]]);
		}
	}
	for (const m of src.matchAll(/^\s*import\s+(\w+)\s*$/gm)) {
		const hit = pick([`${dir}/${m[1]}.py`]);
		if (hit) {
			out.push([hit, m[1]]);
		}
	}
	return out;
}

interface Decl { name: string; exported: boolean; body: string; file: string }
interface Parsed { decls: Decl[]; roots: string; imports: Set<string>; aliases: Array<[string, string]> }

const TS_DECL = /^(export\s+)?(?:default\s+)?(?:declare\s+)?(?:abstract\s+)?(?:async\s+)?(function\*?|const|let|var|class|enum|interface|type)\s+([A-Za-z_$][\w$]*)/;
const PY_DECL = /^(?:async\s+)?(def|class)\s+([A-Za-z_]\w*)/;
const PY_ASSIGN = /^([A-Za-z_]\w*)\s*(?::[^=\n]*)?=(?!=)/;

/** Top-level statements of a file: named declarations, and the anonymous code that runs at load. */
export function parse(file: string, text: string, have: Set<string>, links?: Map<string, string>): Parsed {
	const lang = langOf(file)!;
	const code = codeOnly(text, lang, true);
	const decls: Decl[] = [];
	let roots = '';
	let cur: { name?: string; exported: boolean; kind?: string; buf: string[] } = { exported: false, buf: [] };
	const flush = () => {
		const body = cur.buf.join('\n');
		if (cur.name && cur.kind !== 'interface' && cur.kind !== 'type') {
			decls.push({ name: cur.name, exported: cur.exported, body, file });
		} else if (!cur.name) {
			roots += body + '\n';
		}
	};
	for (const line of code.split('\n')) {
		// A top-level statement starts at column 0 with something other than a closer or a
		// continuation (a decorator belongs to the next declaration: it stays in roots, harmless).
		const starts = /^[^\s})\]]/.test(line)
			&& !(lang === 'py' && /^(?:else|elif|except|finally)\b/.test(line))
			&& !/^(?:\.|\?|:|&&|\|\||\+|-|\*|=>)/.test(line);
		if (!starts) {
			cur.buf.push(line);
			continue;
		}
		flush();
		if (lang === 'ts') {
			const m = TS_DECL.exec(line);
			cur = m ? { name: m[3], exported: !!m[1], kind: m[2], buf: [line] } : { exported: false, buf: [line] };
		} else {
			const m = PY_DECL.exec(line);
			const a = m ? null : PY_ASSIGN.exec(line);
			const name = m ? m[2] : a ? a[1] : undefined;
			// Python has no export keyword: a public module-level name is the module's API.
			cur = name ? { name, exported: !name.startsWith('_') && name !== '__all__', kind: m ? m[1] : 'assign', buf: [line] } : { exported: false, buf: [line] };
		}
	}
	flush();
	if (lang === 'ts') {
		for (const m of code.matchAll(/^export\s*\{([^}]*)\}\s*;?[ \t]*$/gm)) {
			for (const part of m[1].split(',')) {
				const d = decls.find(x => x.name === part.trim().split(/\s+as\s+/)[0]);
				if (d) {
					d.exported = true;
				}
			}
		}
		roots = roots.replace(/^export\s*\{[^}]*\}\s*;?[ \t]*$/gm, ''); // an export list is not a use
	}
	return { decls, roots, imports: importsOf(file, text, have, links), aliases: aliasesOf(file, text, have, links) };
}

const word = (name: string) => new RegExp(`(?<![\\w$])${name.replace(/\$/g, '\\$')}(?![\\w$])`);
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');

/**
 * Whether `text` uses `name` as a binding (KKK-6): a bare word, but not a member access
 * (`x.name`, though `...name` is a use), an object or destructuring key (`{ name: …`,
 * `, name: …`), or a keyword argument (`(name=`, `, name=`).
 */
export function uses(text: string, name: string): boolean {
	for (const m of text.matchAll(new RegExp(word(name).source, 'g'))) {
		const i = m.index!;
		if (text[i - 1] === '.' && text[i - 2] !== '.') {
			continue;
		}
		const prev = /(\S)\s*$/.exec(text.slice(Math.max(0, i - 200), i))?.[1];
		const after = text.slice(i + name.length, i + name.length + 3).replace(/^\s+/, '');
		if ((prev === '{' || prev === ',') && /^:(?!:)/.test(after)) {
			continue;
		}
		if ((prev === '(' || prev === ',') && /^=(?!=)/.test(after)) {
			continue;
		}
		return true;
	}
	return false;
}

/**
 * Exported declarations that nothing which runs reaches. Seeds: each non-test file's anonymous
 * top-level code. From a live declaration (or a seed), references to declarations in the same
 * file, or to exported ones in files it imports, become live.
 */
export function deadExports(texts: Map<string, string>, entries: string[] = [], links?: Map<string, string>): Array<{ file: string; name: string }> {
	const have = new Set(texts.keys());
	const parsed = new Map<string, Parsed>();
	for (const [f, t] of texts) {
		parsed.set(f, parse(f, t, have, links));
	}
	const key = (d: Decl) => `${d.file}#${d.name}`;
	const live = new Set<string>();
	const queue: Array<{ file: string; body: string }> = [];
	const reach = (from: { file: string; body: string }) => {
		const p = parsed.get(from.file)!;
		const targets = [...p.decls, ...[...p.imports].flatMap(i => parsed.get(i)?.decls.filter(d => d.exported) ?? [])];
		for (const t of targets) {
			if (live.has(key(t)) || t.body === from.body) {
				continue;
			}
			const viaAlias = t.file !== from.file && p.aliases.some(([f, a]) => f === t.file
				&& new RegExp(`(?<![\\w$.])${escapeRe(a)}\\s*\\.\\s*${escapeRe(t.name)}(?![\\w$])`).test(from.body));
			if (viaAlias || uses(from.body, t.name)) {
				live.add(key(t));
				queue.push(t);
			}
		}
	};
	for (const [f, p] of parsed) {
		reach({ file: f, body: p.roots });
	}
	for (const e of entries) {
		const [f, name] = e.split('#');
		const d = parsed.get(f)?.decls.find(x => x.name === name);
		if (d && !live.has(key(d))) {
			live.add(key(d));
			queue.push(d);
		}
	}
	while (queue.length) {
		reach(queue.pop()!);
	}
	const out: Array<{ file: string; name: string }> = [];
	for (const p of parsed.values()) {
		for (const d of p.decls) {
			if (d.exported && !live.has(key(d))) {
				out.push({ file: d.file, name: d.name });
			}
		}
	}
	return out;
}

// ---- workflows ----------------------------------------------------------------------------

/**
 * Whether a line leaves a flow collection (`[`, `{`) or a quoted scalar open at its end. A quote
 * opens a scalar only where one can start (after indentation, `:`, `-`, `[`, `{` or `,`), so an
 * apostrophe inside a plain scalar doesn't count; `#` after a space, outside quotes, is a comment.
 */
export function lineOpen(line: string): boolean {
	let depth = 0;
	let q: '"' | "'" | undefined;
	let prev = '';
	for (let k = 0; k < line.length; k++) {
		const c = line[k];
		if (q === '"') {
			if (c === '\\') {
				k++;
			} else if (c === '"') {
				q = undefined;
			}
		} else if (q === "'") {
			if (c === "'" && line[k + 1] === "'") {
				k++;
			} else if (c === "'") {
				q = undefined;
			}
		} else if (c === '#' && (k === 0 || /\s/.test(line[k - 1]))) {
			break;
		} else if ((c === '"' || c === "'") && (prev === '' || /[:\-[{,]/.test(prev))) {
			q = c;
		} else if ((c === '&' || c === '!') && (prev === '' || /[:\-[{,]/.test(prev))) {
			// An anchor or tag sits before the node it names (`&b [foo,`): skip it, so the
			// collection after it still counts as starting where a node can start (LSR-12).
			while (k + 1 < line.length && !/\s/.test(line[k + 1])) {
				k++;
			}
			continue;
		} else if ((c === '[' || c === '{') && (depth > 0 || prev === '' || /[:\-[{,]/.test(prev))) {
			depth++;
		} else if ((c === ']' || c === '}') && depth > 0) {
			depth--;
		}
		if (!/\s/.test(c)) {
			prev = c;
		}
	}
	return depth !== 0 || q !== undefined;
}

/**
 * A filter item's value if it is a scalar the scanner reads in full: a quoted scalar, or a plain
 * one that can't start anything else (block scalar, alias, anchor, tag, flow collection).
 * Undefined otherwise, which the caller treats as unreadable.
 */
export function scalarItem(raw: string): string | undefined {
	const s = raw.replace(/\s+#.*$/, '').trim();
	// A double-quoted scalar is read only without escapes: Actions decodes `"ma\u0069n"` to `main`,
	// and an undecoded escape compared literally would miss it (review on PR 13). An escape makes
	// the item unreadable, which counts against the workflow.
	if (/^"[^"\\]*"$/.test(s)) {
		return s.slice(1, -1);
	}
	if (/^'(?:[^']|'')*'$/.test(s)) {
		return s.slice(1, -1).replace(/''/g, "'");
	}
	if (/^[^\s>|&*!?{}[\]"',#%@`-][^#]*$/.test(s) || /^-[^\s#][^#]*$/.test(s)) {
		return s;
	}
	return undefined;
}

/** Whether any line of the `on:` block starting at line `i` is left open (block scalars skipped). */
function openFlow(lines: string[], i: number): boolean {
	if (lineOpen(lines[i].replace(/^[^:]+:/, ''))) {
		return true;
	}
	return anyOpen(lines.slice(i + 1), true);
}

/** Whether any of these lines is left open; `block` stops at the first top-level line. */
function anyOpen(lines: string[], block: boolean): boolean {
	let scalar: number | undefined;
	for (const l of lines) {
		if (/^\s*$/.test(l)) {
			continue;
		}
		const n = /^ */.exec(l)![0].length;
		if (scalar !== undefined && n > scalar) {
			continue;
		}
		scalar = undefined;
		if (/^\s*#/.test(l)) {
			continue;
		}
		if (block && /^\S/.test(l)) {
			break;
		}
		if (lineOpen(l)) {
			return true;
		}
		if (/:\s*[|>][-+0-9]*\s*(?:#.*)?$/.test(l)) {
			scalar = n;
		}
	}
	return false;
}

/**
 * Trigger names of a workflow (`on:` as a map, a list or a scalar). A push or pull_request
 * trigger that can't run on main is left out: a `branches` filter that excludes main (KKK-7),
 * a `paths-ignore` of everything, or `paths` matching no tracked file (MMM-1, given `files`).
 */
export function triggers(yml: string, files?: string[]): string[] {
	const lines = yml.split('\n');
	const onKey = /^(?:on|"on"|'on')\s*:/;
	const i = lines.findIndex(l => onKey.test(l));
	if (i < 0) {
		return [];
	}
	// The `on:` line must be the real top-level key: a value left open on an earlier line can
	// continue at column 0 with a decoy `on: push` that would be read instead (LSR-15). So the
	// lines before it must all be closed, and only one line may look like `on:`.
	if (lines.filter(l => onKey.test(l)).length > 1 || anyOpen(lines.slice(0, i), false)) {
		return ['unparsed'];
	}
	// YAML lets any key be quoted ("schedule":), so every trigger name is unquoted before use:
	// a positive match on `schedule` must not miss a spelling GitHub accepts (review LSR-1).
	const unq = (s: string) => s.trim().replace(/^['"]|['"]$/g, '');
	// The scanner reads a line at a time, so a flow collection or quoted scalar that runs onto
	// the next line would be read short: a filter list truncated before `main`, or a quoted
	// continuation at column 0 ending the block before `schedule` (LSR-9). Any line of the block
	// left open makes the whole block unreadable, and so the workflow a subject.
	if (openFlow(lines, i)) {
		return ['unparsed'];
	}
	const inline = lines[i].replace(/^[^:]+:\s*/, '').replace(/#.*/, '').trim();
	if (inline) {
		return inline.replace(/^\[|\]$/g, '').split(',').map(unq).filter(Boolean);
	}
	// Indent-aware, not column-anchored (LSR-7): YAML only needs a child deeper than its parent,
	// so the trigger level is the first child's indent and each trigger's filter level is its own
	// first child's. Anything the scanner can't read fails closed: a trigger line it can't parse
	// is `unparsed` (the workflow becomes a subject), and a trigger with an inline value or an
	// unreadable filter is treated as filtered off main.
	const out: string[] = [];
	let cur: string | undefined;
	let key: string | undefined;
	let level: number | undefined;
	let fLevel: number | undefined;
	const filters = new Map<string, Map<string, string[]>>();
	const opaque = new Set<string>();
	const emptyKeys: Array<[string, string]> = [];
	const indent = (l: string) => /^ */.exec(l)![0].length;
	for (const l of lines.slice(i + 1)) {
		if (/^\s*(#.*)?$/.test(l)) {
			continue;
		}
		if (/^\S/.test(l)) {
			break;
		}
		const n = indent(l);
		level ??= n;
		if (n < level) {
			out.push('unparsed');
			continue;
		}
		if (n === level) {
			const m = /^ *(["']?)([A-Za-z_]+)\1\s*:\s*(.*)$/.exec(l) ?? /^ *- (["']?)([A-Za-z_]+)\1\s*(?:#.*)?$/.exec(l);
			if (!m) {
				out.push('unparsed');
				cur = undefined;
				continue;
			}
			out.push(m[2]);
			cur = m[2];
			key = undefined;
			fLevel = undefined;
			const v = (m[3] ?? '').replace(/#.*/, '').trim();
			if (v && !/^(?:null|~|\{\})$/.test(v)) {
				opaque.add(cur);
			}
			continue;
		}
		if (!cur) {
			continue;
		}
		fLevel ??= n;
		// A filter is read only from items it positively recognises: a plain or quoted scalar.
		// Anything else under a filter key (a block-scalar item, a bare `-`, a continuation, an
		// anchor or tag) makes the trigger opaque. Dropping an unread item from an *-ignore list
		// would otherwise read as "main not ignored", which is live (LSR-11).
		const item = /^ *-(?:\s+(.*))?$/.exec(l);
		if (key && n >= fLevel && (item || n > fLevel)) {
			const s = item?.[1] !== undefined ? scalarItem(item[1]) : undefined;
			if (s === undefined) {
				opaque.add(cur);
			} else {
				filters.get(cur)!.get(key)!.push(s);
			}
			continue;
		}
		if (n === fLevel) {
			const k = /^ *(["']?)([A-Za-z_-]+)\1\s*:\s*(.*)$/.exec(l);
			key = undefined;
			if (!k) {
				opaque.add(cur);
			} else if (['branches', 'branches-ignore', 'tags', 'tags-ignore', 'paths', 'paths-ignore', 'types'].includes(k[2])) {
				key = k[2];
				const v = k[3].replace(/(?:^|\s)#.*/, '').trim();
				const f = filters.get(cur) ?? new Map<string, string[]>();
				let list: Array<string | undefined> = [];
				if (/^\[.*\]$/.test(v)) {
					list = v.slice(1, -1).split(',').map(x => x.trim()).filter(Boolean).map(scalarItem);
				} else if (v) {
					list = [scalarItem(v)];
				} else {
					emptyKeys.push([cur, key]);
				}
				if (list.some(x => x === undefined)) {
					opaque.add(cur);
				}
				f.set(key, list.filter((x): x is string => x !== undefined));
				filters.set(cur, f);
			} else {
				// A key the gate doesn't model under a trigger: only push and pull_request are ever
				// judged, and for them an unknown key can only make the trigger fire less (LSR-14).
				opaque.add(cur);
			}
		} else if (n < fLevel) {
			opaque.add(cur);
		}
	}
	// `branches-ignore:` with no items at all is not "ignore nothing": it was not read (LSR-11).
	for (const [t, k] of emptyKeys) {
		if (!filters.get(t)?.get(k)?.length) {
			opaque.add(t);
		}
	}
	const glob = (g: string) => new RegExp(`^${g.split(/(\*\*\/?|\*)/).map(p => p === '**' || p === '**/' ? '.*' : p === '*' ? '[^/]*' : p.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('')}$`);
	// GitHub filters are globs with `?`, `+`, `[]` and `!` negation besides `*` and `**`. The gate
	// models only `*` and `**`: an entry using anything else counts against the trigger, never
	// for it, on either side (an include that might miss main, an ignore that might cover it).
	const unmodelled = (p: string) => /[?+[\]!]/.test(p);
	const covers = (p: string, s: string) => !unmodelled(p) && glob(p).test(s);
	const runs = (t: string) => {
		if (opaque.has(t)) {
			return false;
		}
		const f = filters.get(t);
		if (!f) {
			return true;
		}
		const br = f.get('branches');
		if (br && (br.some(unmodelled) || !br.some(p => covers(p, 'main')))) {
			return false;
		}
		// An ignore list is read as globs: `m*`, `main*` and `ma?n` all cover main (LSR-13).
		const bri = f.get('branches-ignore');
		if (bri && bri.some(p => unmodelled(p) || covers(p, 'main'))) {
			return false;
		}
		// A push filtered only by tags never fires on a branch (LSR-14).
		if ((f.has('tags') || f.has('tags-ignore')) && !br && !bri) {
			return false;
		}
		// pull_request fires on main's PRs only for its default activity types.
		const ty = f.get('types');
		if (ty && (t !== 'pull_request' || !ty.some(x => ['opened', 'synchronize', 'reopened'].includes(x)))) {
			return false;
		}
		const pi = f.get('paths-ignore');
		if (pi && (pi.some(unmodelled) || !files || files.every(file => pi.some(p => covers(p, file))))) {
			return false;
		}
		const ps = f.get('paths')?.filter(p => !p.startsWith('!'));
		if (ps && files && !files.some(file => ps.some(p => glob(p).test(file)))) {
			return false;
		}
		return true;
	};
	return out.filter(t => (t !== 'push' && t !== 'pull_request') || runs(t));
}

export interface Step { run: string; if?: string; continueOnError?: string }
export interface Job { if?: string; continueOnError?: string; steps: Step[] }

/** One job: its own `if:`/`continue-on-error:`, and each step's `run:` text and the same keys. */
export function jobOf(yml: string, job: string): Job | undefined {
	const lines = yml.split('\n');
	const start = lines.findIndex(l => l === `  ${job}:`);
	if (start < 0 || !lines.slice(0, start).some(l => l === 'jobs:')) {
		return undefined;
	}
	const out: Job = { steps: [] };
	let cur: Step | undefined;
	let inRun = false;
	for (const l of lines.slice(start + 1)) {
		if (/^ {2}\S/.test(l) || /^\S/.test(l)) {
			break;
		}
		const jobKey = /^ {4}(if|continue-on-error):\s*(.*)$/.exec(l);
		if (jobKey) {
			out[jobKey[1] === 'if' ? 'if' : 'continueOnError'] = jobKey[2].trim();
			continue;
		}
		if (/^ {6}- /.test(l)) {
			if (cur) {
				out.steps.push(cur);
			}
			cur = { run: '' };
			inRun = false;
		}
		const key = /^ {6}(?:- )? {0,2}(run|if|continue-on-error):\s*(.*)$/.exec(l);
		if (key && cur) {
			if (key[1] === 'run') {
				inRun = true;
				if (!/^[|>][-+]?$/.test(key[2].trim())) {
					cur.run = key[2].trim();
				}
			} else {
				inRun = false;
				cur[key[1] === 'if' ? 'if' : 'continueOnError'] = key[2].trim();
			}
		} else if (inRun && cur && /^ {10}\S/.test(l)) {
			cur.run += (cur.run ? '\n' : '') + l.trim();
		} else if (/^ {8}\S/.test(l)) {
			inRun = false;
		}
	}
	if (cur) {
		out.steps.push(cur);
	}
	return out;
}

// ---- discovery ----------------------------------------------------------------------------

/** Every subject the tree contains that only matters if something runs it. */
export function discover(files: string[], read: (f: string) => string): Map<string, string> {
	const out = new Map<string, string>();
	for (const f of files.filter(f => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(f))) {
		const t = triggers(read(f), files);
		// Push runs show the pushed code works, not the scheduled class: a scheduled workflow needs
		// run evidence of its own even when it also runs on push (liveness-refresh, review MMM).
		if ((!t.includes('push') && !t.includes('pull_request')) || t.includes('schedule') || t.includes('unparsed')) {
			out.set(`workflow:${path.posix.basename(f).replace(/\.ya?ml$/, '')}`, f);
		}
	}
	if (files.includes('test/builds/variants.json')) {
		const v = JSON.parse(read('test/builds/variants.json')) as Record<string, { hooks?: Array<{ id: string; patch: string }> }>;
		for (const [name, variant] of Object.entries(v)) {
			for (const h of variant.hooks ?? []) {
				out.set(`hook:${name}/${h.id}`, h.patch);
			}
		}
	}
	const fixtureRoots = new Set<string>();
	for (const f of files) {
		const m = /^((?:test|tabd\/test|broker\/tests)\/(?:[^/]+\/)*?fixtures)\/([^/]+)/.exec(f);
		if (m) {
			fixtureRoots.add(`${m[1]}/${m[2]}`);
		}
	}
	for (const f of files) {
		const m = /^(test\/(?:[^/]+\/)*[^/]+)\/package\.json$/.exec(f);
		if (m && ![...fixtureRoots].some(r => m[1] === r || m[1].startsWith(`${r}/`))) {
			fixtureRoots.add(m[1]);
		}
	}
	for (const r of fixtureRoots) {
		out.set(`fixture:${r}`, r);
	}
	return out;
}

// ---- the check ----------------------------------------------------------------------------

export interface Report { errors: string[]; notes: string[] }

export async function check(files: string[], read: (f: string) => string, opts: { links?: Map<string, string>; base?: Register | null } = {}): Promise<Report> {
	const errors: string[] = [];
	const notes: string[] = [];
	const has = new Set(files);
	let reg: Register;
	try {
		reg = JSON.parse(read(REGISTER)) as Register;
	} catch (e) {
		return { errors: [`${REGISTER}: ${(e as Error).message}`], notes };
	}

	// Static: exports.
	const sources = new Map<string, string>();
	for (const f of files) {
		if (IN_SCOPE.test(f) && langOf(f)) {
			sources.set(f, read(f));
		}
	}
	const entries: string[] = [];
	for (const x of reg.entry ?? []) {
		if (!x || typeof x.subject !== 'string' || typeof x.calledBy !== 'string' || !x.calledBy.trim() || typeof x.declaredIn !== 'string') {
			errors.push(`entry ${JSON.stringify(x)}: needs subject, calledBy and declaredIn`);
			continue;
		}
		const [file, name] = x.subject.split('#');
		if (!sources.has(file) || !name || !new RegExp(`^export\\s+(?:async\\s+)?function\\s+${escapeRe(name)}\\b`, 'm').test(codeOnly(sources.get(file)!, langOf(file)!))) {
			errors.push(`entry ${x.subject}: no exported function ${name} in ${file}`);
			continue;
		}
		// The only host-called entries: a VS Code extension's activate/deactivate, declared by the
		// `main` of that extension's own package.json (KKK-3).
		const extRoot = /^(extensions\/[^/]+)\/src\//.exec(file)?.[1];
		let main: unknown;
		try {
			main = extRoot && x.declaredIn === `${extRoot}/package.json` && has.has(x.declaredIn) ? (JSON.parse(read(x.declaredIn)) as { main?: unknown }).main : undefined;
		} catch {
			main = undefined;
		}
		const stem = path.posix.basename(file).replace(/\.\w+$/, '');
		if (!['activate', 'deactivate'].includes(name) || typeof main !== 'string' || path.posix.basename(main).replace(/\.js$/, '') !== stem) {
			errors.push(`entry ${x.subject}: only an extension's activate/deactivate, in the module its own package.json \`main\` names`);
			continue;
		}
		notes.push(`entry: ${x.subject} (${x.calledBy})`);
		entries.push(x.subject);
	}
	const dead = new Map(deadExports(sources, entries, opts.links).map(d => [`${d.file}#${d.name}`, d]));
	// Static: in-tab programs.
	const bins = files.filter(f => f.startsWith(BIN) && !f.slice(BIN.length).includes('/'));
	const users = files.filter(f => BIN_USERS.some(u => f.startsWith(u)) && !f.startsWith(BIN) && !/\/test\//.test(f));
	const binDead = new Set<string>();
	for (const b of bins) {
		const name = path.posix.basename(b);
		const others = [...users, ...bins.filter(x => x !== b)];
		const used = others.some(u => {
			let t: string;
			try {
				t = read(u);
			} catch {
				return false;
			}
			return word(name).test(codeOnly(t, langOf(u) ?? 'sh'));
		});
		if (!used) {
			binDead.add(b);
		}
	}

	const exempted = new Set<string>();
	const tombs = new Map<string, Removed>();
	for (const t of reg.removed ?? []) {
		if (!t || typeof t.subject !== 'string' || !/^[^#\s]+#?[^#\s]*$/.test(t.subject) || typeof t.reason !== 'string' || !t.reason.trim()
			|| (t.restored !== undefined && (typeof t.restored !== 'string' || !t.restored.trim()))) {
			errors.push(`removed ${JSON.stringify(t)}: needs subject and reason (and, if present, a non-empty restored)`);
			continue;
		}
		if (tombs.has(t.subject)) {
			errors.push(`removed ${t.subject}: listed twice`);
		}
		tombs.set(t.subject, t);
	}
	// Tombstones are append-only against the base register (main, or the push's previous head):
	// a resolution that takes a branch's whole register, or an edit, can't drop one (LSR-6).
	if (opts.base !== undefined) {
		for (const t of opts.base?.removed ?? []) {
			if (t && typeof t.subject === 'string' && !tombs.has(t.subject)) {
				errors.push(`removed ${t.subject}: dropped, but tombstones are append-only (the base register has it); to bring the exemption back on purpose, give the tombstone \`restored\` with why`);
			}
		}
	}
	for (const x of reg.exempt ?? []) {
		if (!x || typeof x.subject !== 'string' || typeof x.reason !== 'string' || !x.reason.trim() || !('consumer' in x)) {
			errors.push(`exempt ${JSON.stringify(x)}: needs subject, consumer (a path or null) and reason`);
			continue;
		}
		// A union merge keeps both the old and the superseding entry for a still-dead subject,
		// and a tombstoned subject comes back with its code; neither trips the stale rule (LSR-3).
		if (exempted.has(x.subject)) {
			errors.push(`exempt ${x.subject}: listed twice (a merge kept an old entry and the one that replaced it?)`);
		}
		const tomb = tombs.get(x.subject);
		if (tomb && tomb.restored === undefined) {
			errors.push(`exempt ${x.subject}: its exemption was removed on purpose (${tomb.reason}); drop it, or give the tombstone \`restored\` with why if bringing it back is deliberate`);
		}
		exempted.add(x.subject);
		const [file, name] = x.subject.split('#');
		if (!dead.has(x.subject) && !binDead.has(x.subject)) {
			errors.push(`exempt ${x.subject}: ${has.has(file) ? 'it is live (or not an export): remove the stale exemption' : 'no such file'}`);
			continue;
		}
		if (x.consumer === null) {
			notes.push(`no consumer: ${x.subject} (${x.reason})`);
			continue;
		}
		if (!has.has(x.consumer)) {
			errors.push(`exempt ${x.subject}: consumer ${x.consumer} does not exist`);
			continue;
		}
		const sym = name ?? path.posix.basename(file);
		if (!uses(codeOnly(read(x.consumer), langOf(x.consumer) ?? 'sh', true), sym)) {
			errors.push(`exempt ${x.subject}: consumer ${x.consumer} never uses ${sym} (comments don't count). The exemption claims something untrue.`);
		}
	}
	// `restored` is one-shot: it stands only while the exemption it let back exists, so an armed
	// tombstone can't sit inert for a later merge to bring the exemption back silently (LSR-8).
	for (const t of tombs.values()) {
		if (t.restored !== undefined && !exempted.has(t.subject)) {
			errors.push(`removed ${t.subject}: says restored, but nothing exempts it; drop \`restored\` to re-arm the tombstone`);
		}
	}
	for (const [k, d] of dead) {
		if (!exempted.has(k)) {
			errors.push(`${d.file} exports ${d.name}, but nothing that runs reaches it. Wire it, delete it, or exempt it in ${REGISTER} naming its consumer.`);
		}
	}
	for (const b of binDead) {
		if (!exempted.has(b)) {
			errors.push(`${b}: no product code or image build invokes it`);
		}
	}

	// Runtime subjects.
	const found = discover(files, read);
	// GitHub runs x.yml and x.yaml as two workflows, but both are subject `workflow:x`: the twin
	// would need no evidence of its own (LSR-5).
	const stems = new Map<string, string>();
	for (const f of files.filter(f => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(f))) {
		const stem = path.posix.basename(f).replace(/\.ya?ml$/, '');
		if (stems.has(stem)) {
			errors.push(`${stems.get(stem)} and ${f} are both subject workflow:${stem}; rename one`);
		}
		stems.set(stem, f);
	}
	const ids = new Set<string>();
	for (const s of reg.subjects ?? []) {
		if (!s || typeof s.id !== 'string' || typeof s.runBy !== 'string' || !s.runBy.trim() || !Array.isArray(s.evidence) || !s.evidence.length) {
			errors.push(`subject ${JSON.stringify(s?.id)}: needs id, runBy and at least one evidence`);
			continue;
		}
		if (ids.has(s.id)) {
			errors.push(`subject ${s.id}: listed twice`);
		}
		ids.add(s.id);
		if (!found.has(s.id)) {
			errors.push(`subject ${s.id}: not in the tree (stale entry)`);
		}
		// A workflow subject is proven only by runs of that workflow: a ci mark or a record
		// comes from push-class or local runs, which say nothing about its schedule (LSR-2).
		const wfFile = s.id.startsWith('workflow:') ? found.get(s.id) : undefined;
		if (wfFile && s.evidence.some(e => !e || e.run === undefined || e.workflow !== path.posix.basename(wfFile))) {
			errors.push(`subject ${s.id}: every evidence must be a run of ${path.posix.basename(wfFile)}`);
		}
		for (const e of s.evidence) {
			const kinds = ['run', 'ci', 'record'].filter(k => k in e);
			if (kinds.length !== 1) {
				errors.push(`subject ${s.id}: each evidence is exactly one of run, ci, record`);
				continue;
			}
			if (e.run !== undefined) {
				if (!Number.isSafeInteger(e.run) || e.run <= 0 || typeof e.workflow !== 'string' || !has.has(`.github/workflows/${e.workflow}`)
					|| typeof e.sha !== 'string' || !/^[0-9a-f]{40}$/.test(e.sha) || typeof e.date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(e.date)) {
					errors.push(`subject ${s.id}: run evidence needs a run id, an existing workflow file, the run's head sha (40 hex) and date (YYYY-MM-DD)`);
				}
			} else if (e.ci !== undefined) {
				const [wf, job] = e.ci.split('#');
				const yml = has.has(`.github/workflows/${wf}`) ? read(`.github/workflows/${wf}`) : undefined;
				const j = yml && job ? jobOf(yml, job) : undefined;
				const last = j?.steps.at(-1);
				// Exactly the marks step, unconditional, failing the job (KKK-1).
				const want = `./seclab liveness marks ${e.ci} "$SECLAB_LIVENESS_LOG"`;
				if (!j || !yml) {
					errors.push(`subject ${s.id}: ci evidence ${e.ci}: no such workflow job`);
				} else {
					const t = triggers(yml, files);
					if (!t.includes('push') && !t.includes('pull_request')) {
						errors.push(`subject ${s.id}: ci job ${e.ci} must run on push or pull_request`);
					}
					if (j.if !== undefined || j.continueOnError !== undefined) {
						errors.push(`subject ${s.id}: ci job ${e.ci} must have no if: or continue-on-error:`);
					}
					// Any other way to skip it (quoted keys, needs:, a matrix, a reusable workflow): the
					// required-checks rule for jobs that must run (review CR-1).
					for (const p of jobProblems(yml, job, `subject ${s.id}: ci job ${e.ci}`).problems) {
						errors.push(p);
					}
					if (!last || last.run !== want || last.if !== undefined || last.continueOnError !== undefined) {
						errors.push(`subject ${s.id}: ci job ${e.ci} must end with exactly \`${want}\` (no if:, no continue-on-error:), or nothing checks its marks`);
					}
				}
				// The registered runner itself calls liveMark with this mark, in code (KKK-2): not in a
				// comment, not inside a string, not in some other file.
				if (typeof e.mark !== 'string' || !/^[a-z0-9][a-z0-9:/._-]{2,120}$/.test(e.mark)) {
					errors.push(`subject ${s.id}: ci evidence needs a mark ([a-z0-9:/._-])`);
				} else if (typeof e.runner !== 'string' || !/^(?:test|tabd\/test)\/.+\.ts$/.test(e.runner) || !has.has(e.runner)) {
					errors.push(`subject ${s.id}: ci evidence needs runner, the test file that calls liveMark`);
				} else if (!markCalls(read(e.runner)).includes(e.mark)) {
					errors.push(`subject ${s.id}: runner ${e.runner} never calls liveMark('${e.mark}') in code`);
				}
			} else if (e.record !== undefined) {
				// A structured line, as in the liveness EDR's "Evidence on record": a passing mention
				// (even "never ran") doesn't count (KKK-5). Dated, so the weekly refresh job can ask
				// for a re-run of what CI can't run (Level B rotted unnoticed, 2026-11-09).
				const line = new RegExp(`^- \\*\\*\`${escapeRe(s.id)}\`:\\*\\* \\S`, 'm');
				if (!/^docs\/.+\.md$/.test(e.record) || !has.has(e.record)) {
					errors.push(`subject ${s.id}: record ${e.record} is not a doc in docs/`);
				} else if (!line.test(read(e.record))) {
					errors.push(`subject ${s.id}: record ${e.record} has no "- **\`${s.id}\`:** …" evidence line`);
				} else if (typeof e.date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(e.date) || !Number.isFinite(Date.parse(e.date))
					|| new Date(Date.parse(e.date)).toISOString().slice(0, 10) !== e.date || Date.parse(e.date) > Date.now()) {
					// A date that doesn't parse, or one in the future, would switch off the 30-day rule (NNN-6).
					errors.push(`subject ${s.id}: record evidence needs the run's date (a real, past YYYY-MM-DD)`);
				} else if (!s.evidence.some(x => x.run !== undefined || x.ci !== undefined)) {
					notes.push(`record only: ${s.id} (${e.record}, ${e.date})`);
				}
			}
		}
	}
	for (const [id, where] of found) {
		if (!ids.has(id)) {
			errors.push(`${id} (${where}) only matters if something runs it: add it to ${REGISTER} with runBy and evidence it ran`);
		}
	}
	return { errors, notes };
}

/** CI: every mark expected from this job is in its log. */
export function checkMarks(reg: Register, job: string, log: string | undefined): string[] {
	const expected = (reg.subjects ?? []).flatMap(s => s.evidence.filter(e => e.ci === job && e.mark).map(e => ({ id: s.id, mark: e.mark! })));
	if (!expected.length) {
		return [`no subject names ${job}: this step checks nothing`];
	}
	if (log === undefined) {
		return [`no liveness log: nothing recorded a mark in ${job}`];
	}
	const got = new Set(log.split('\n').map(l => l.trim()).filter(Boolean));
	return expected.filter(x => !got.has(x.mark)).map(x => `${x.id}: never ran in ${job} (no mark ${x.mark})`);
}

type Api = (p: string) => Promise<{ status: number; body?: Record<string, unknown> }>;

/**
 * The register's Actions runs (KKK-4: this needs only the register, so its networked, token-
 * holding container mounts nothing else). Each must be a successful dispatch or scheduled run
 * of the named workflow, at the recorded head sha and date, with a successful `job` if named. A run
 * deleted at the retention horizon degrades to a note, so expiry can't block every PR (KKK-5).
 */
export async function verifyRuns(reg: Register, api: Api, now = Date.now()): Promise<Report> {
	const errors: string[] = [];
	const notes: string[] = [];
	for (const s of reg.subjects ?? []) {
		// A record is a run CI can't do: older than 30 days, it is due again (a note here, a
		// failure in the weekly refresh job).
		for (const e of (s.evidence ?? []).filter(x => x.record !== undefined && typeof x.date === 'string')) {
			if ((now - Date.parse(e.date!)) / 86_400_000 > 30) {
				notes.push(`subject ${s.id}: record from ${e.date} (${e.record}); re-run: ${s.runBy}`);
			}
		}
		for (const e of (s.evidence ?? []).filter(x => x.run !== undefined)) {
			const at = `subject ${s.id}: run ${e.run}`;
			if (!Number.isSafeInteger(e.run) || typeof e.sha !== 'string' || typeof e.date !== 'string' || typeof e.workflow !== 'string') {
				errors.push(`${at}: malformed evidence (run the offline check)`);
				continue;
			}
			const r = await api(String(e.run));
			if (r.status === 404 && (now - Date.parse(e.date)) / 86_400_000 > 85) {
				notes.push(`${at}: expired (recorded ${e.date}); re-run and update the register`);
				continue;
			}
			const run = r.body;
			if (r.status !== 200 || !run) {
				errors.push(`${at}: lookup failed (HTTP ${r.status})`);
				continue;
			}
			const bad = run.path !== `.github/workflows/${e.workflow}` ? `is a run of ${String(run.path)}, not ${e.workflow}`
				: run.event !== 'workflow_dispatch' && run.event !== 'schedule' ? `was triggered by ${String(run.event)}, not dispatch or schedule`
				: run.conclusion !== 'success' ? `concluded ${String(run.conclusion)}`
				: run.head_sha !== e.sha ? `ran at ${String(run.head_sha)}, not the recorded ${e.sha}`
				: !String(run.created_at ?? '').startsWith(e.date) ? `ran on ${String(run.created_at)}, not the recorded ${e.date}`
				: undefined;
			if (bad) {
				errors.push(`${at}: ${bad}`);
				continue;
			}
			if (e.job) {
				// A job, not an artifact: artifacts expire within days, jobs live as long as the run.
				const j = await api(`${e.run}/jobs?per_page=100`);
				const jobs = (j.body as { jobs?: Array<{ name?: string; conclusion?: string }> } | undefined)?.jobs ?? [];
				if (!jobs.some(x => x.name === e.job && x.conclusion === 'success')) {
					errors.push(`${at}: has no successful job "${e.job}"`);
					continue;
				}
			}
			// Warn ahead of the retention horizon (90 days by default), never fail on age.
			if ((now - Date.parse(e.date)) / 86_400_000 > 75) {
				notes.push(`${at}: recorded ${e.date}, near the retention horizon; re-run and update the register`);
			}
		}
	}
	return { errors, notes };
}

/** --refresh: every note (due near or past the retention horizon) is an error. */
export function refreshReport(r: Report): Report {
	return { errors: [...r.errors, ...r.notes.map(n => `refresh due: ${n}`)], notes: [] };
}

function githubApi(): Api {
	const repo = process.env.GITHUB_REPOSITORY;
	const token = process.env.GITHUB_TOKEN;
	if (!repo || !/^[\w.-]+\/[\w.-]+$/.test(repo) || !token) {
		throw new Error('verify-runs needs GITHUB_REPOSITORY and GITHUB_TOKEN');
	}
	return async p => {
		const r = await fetch(`https://api.github.com/repos/${repo}/actions/runs/${p}`, { headers: { accept: 'application/vnd.github+json', authorization: `Bearer ${token}` } });
		return { status: r.status, body: r.ok ? await r.json() as Record<string, unknown> : undefined };
	};
}

// ---- self-test ----------------------------------------------------------------------------

/**
 * A clean synthetic tree passes, and each of the five recorded failures, injected alone into a
 * fresh copy, fails with its own message. The control runs first and must pass: a prover that
 * fails everything is as broken as one that passes everything.
 */
async function selfTest(): Promise<void> {
	const base: Record<string, string> = {
		'.github/workflows/ci.yml': 'on:\n  push:\njobs:\n  oci:\n    steps:\n      - run: ./seclab test containment\n      - name: marks\n        run: ./seclab liveness marks ci.yml#oci "$SECLAB_LIVENESS_LOG"\n',
		'.github/workflows/weekly.yml': "on:\n  schedule:\n    - cron: '1 1 * * 1'\n  workflow_dispatch:\njobs:\n  r:\n    steps:\n      - run: echo\n",
		'test/builds/variants.json': '{"v":{"hooks":[{"id":"h","patch":"test/h.patch"}]}}',
		'test/h.patch': '',
		'test/x/fixtures/evil/a.txt': '',
		'test/run.ts': "import { liveMark } from './liveness.ts';\nliveMark('evil-ran');\n",
		'docs/proof.md': '- **`hook:v/h`:** ran in run 7\n',
		'extensions/e/package.json': '{"main": "./out/extension"}',
		'extensions/e/src/extension.ts': "import { boot } from './boot.ts';\nexport function activate() { boot(); }\n",
		'extensions/e/src/boot.ts': 'export function boot() {}\nexport function keyOnly() {}\nconst o = { keyOnly: 1 }; o.keyOnly;\n',
		// Module-alias uses are uses (KKK-6 must not drop them): Python `mod.fn`, TS `ns.fn`.
		'broker/seclab_broker/protocol.py': 'def check(x):\n    return x\n',
		'broker/seclab_broker/core.py': 'from . import protocol\n\nprotocol.check(1)\n',
		'tabd/src/ns.ts': 'export function viaNs() {}\n',
		'tabd/src/usens.ts': "import * as ns from './ns.ts';\nns.viaNs();\n",
		'tabd/src/main.ts': "import { start } from './sup.ts';\nimport { onDecision } from './rpc.ts';\nstart();\nonDecision(() => {});\n",
		'tabd/src/sup.ts': "import { mint } from './scan.ts';\nexport function start() { helper(); }\nfunction helper() { const glob = '/**'; mint(); /* a comment */ }\n",
		'tabd/src/scan.ts': "export function mint() {}\nexport function msgOnly() {}\nexport const note = `uses ${mint.name} but msgOnly only in text`;\n",
		'tabd/src/rpc.ts': 'const listeners = [];\nexport function onDecision(f) { listeners.push(f); }\nexport const escapes = [];\nexport function record(x) { escapes.push(x); }\n',
		'tabd/test/rpc.test.ts': "import { record } from '../src/rpc.ts';\nrecord(1);\n",
		'sandbox/rootfs/opt/seclab/bin/seclab-x': '#!/bin/sh\n',
		'tabd/src/drivers.ts': "export const X = '/opt/seclab/bin/seclab-x';\n",
		'build/liveness/register.json': JSON.stringify({
			entry: [{ subject: 'extensions/e/src/extension.ts#activate', calledBy: 'VS Code', declaredIn: 'extensions/e/package.json' }],
			exempt: [
				{ subject: 'tabd/src/rpc.ts#escapes', consumer: null, reason: 'nothing reads it yet' },
				{ subject: 'tabd/src/rpc.ts#record', consumer: 'tabd/test/rpc.test.ts', reason: 'test only' },
				{ subject: 'tabd/src/drivers.ts#X', consumer: null, reason: 'synthetic' },
				{ subject: 'tabd/src/scan.ts#msgOnly', consumer: null, reason: 'synthetic: named only inside a string' },
				{ subject: 'tabd/src/scan.ts#note', consumer: null, reason: 'synthetic' },
				{ subject: 'extensions/e/src/boot.ts#keyOnly', consumer: null, reason: 'synthetic: only an object key and a member' },
			],
			removed: [{ subject: 'tabd/src/zombie.ts#resurrected', reason: 'synthetic: the file was deleted with its exemption' }],
			subjects: [
				{ id: 'workflow:weekly', runBy: 'schedule', evidence: [{ run: 1, workflow: 'weekly.yml', sha: 'a'.repeat(40), date: '2026-11-01' }] },
				{ id: 'hook:v/h', runBy: 'harness', evidence: [{ record: 'docs/proof.md', date: '2026-11-01' }] },
				{ id: 'fixture:test/x/fixtures/evil', runBy: 'test/run.ts', evidence: [{ ci: 'ci.yml#oci', mark: 'evil-ran', runner: 'test/run.ts' }] },
			],
		}),
	};
	const run = (tree: Record<string, string>, base?: Register | null) => check(Object.keys(tree).sort(), f => {
		if (!(f in tree)) {
			throw new Error(`ENOENT ${f}`);
		}
		return tree[f];
	}, { base });
	const control = await run(base, JSON.parse(base['build/liveness/register.json']) as Register);
	if (control.errors.length) {
		throw new Error(`self-test control failed. Either the gate or this self-test is wrong: establish which before believing either (re-run the control alone):\n${control.errors.join('\n')}`);
	}
	const reg = () => JSON.parse(base['build/liveness/register.json']) as Register;
	const withReg = (r: Register, extra: Record<string, string> = {}) => ({ ...base, ...extra, 'build/liveness/register.json': JSON.stringify(r) });
	const injections: Array<[string, Record<string, string>, RegExp]> = [];
	{ // 1. a hook nothing records running (the rogue-REH hook)
		const r = reg();
		r.subjects = r.subjects.filter(s => s.id !== 'hook:v/h');
		injections.push(['unrun hook', withReg(r), /hook:v\/h .* add it to/]);
	}
	{ // 2. a fixture/probe whose runner never records it (the eight rogue-REH probes)
		injections.push(['probe never run', { ...base, 'test/run.ts': "import { liveMark } from './liveness.ts';\n// liveMark('evil-ran');\n" }, /never calls liveMark\('evil-ran'\) in code/]);
	}
	{ // 3. a listener API with no listener, behind an exemption claiming one (seclabOnDecision)
		const r = reg();
		r.exempt.push({ subject: 'tabd/src/rpc.ts#onDecision', consumer: 'tabd/src/main.ts', reason: 'the Tab Manager subscribes' });
		injections.push(['false exemption', withReg(r, { 'tabd/src/main.ts': "import { start } from './sup.ts';\n// onDecision is subscribed elsewhere\nstart();\n" }), /consumer tabd\/src\/main\.ts never uses onDecision/]);
	}
	{ // a merge that unions the register re-adds an exemption main removed when the export went live
		const r = reg();
		r.exempt.push({ subject: 'tabd/src/sup.ts#start', consumer: 'tabd/src/main.ts', reason: 'removed on main, re-added by a union merge' });
		injections.push(['union merge re-adds a removed exemption', withReg(r), /exempt tabd\/src\/sup\.ts#start: it is live/]);
	}
	// Review LSR: what the stale rule alone lets a union merge, or a quoted key, through.
	{
		const r = reg();
		r.exempt.push({ subject: 'tabd/src/rpc.ts#escapes', consumer: null, reason: 'the entry main replaced' });
		injections.push(['LSR-3 union merge keeps a superseded exemption', withReg(r), /exempt tabd\/src\/rpc\.ts#escapes: listed twice/]);
	}
	{
		const r = reg();
		r.exempt.push({ subject: 'tabd/src/zombie.ts#resurrected', consumer: null, reason: 'came back with its file' });
		injections.push(['LSR-3 union merge resurrects a tombstoned exemption with its code', withReg(r, { 'tabd/src/zombie.ts': 'export function resurrected() {}\n' }), /exempt tabd\/src\/zombie\.ts#resurrected: its exemption was removed on purpose/]);
	}
	{
		const r = reg();
		r.removed!.push({ subject: 'tabd/src/zombie.ts#resurrected', reason: 'again' });
		injections.push(['LSR-3 a tombstone listed twice', withReg(r), /removed tabd\/src\/zombie\.ts#resurrected: listed twice/]);
	}
	{
		const r = reg();
		r.subjects = r.subjects.map(s => s.id === 'workflow:weekly' ? { ...s, evidence: [{ ci: 'ci.yml#oci', mark: 'evil-ran', runner: 'test/run.ts' }] } : s);
		injections.push(['LSR-2 a scheduled workflow proven by a ci mark', withReg(r), /workflow:weekly: every evidence must be a run of weekly\.yml/]);
		const r2 = reg();
		r2.subjects = r2.subjects.map(s => s.id === 'workflow:weekly' ? { ...s, evidence: [{ run: 1, workflow: 'ci.yml', sha: 'a'.repeat(40), date: '2026-11-01' }] } : s);
		injections.push(['LSR-2 a scheduled workflow proven by another workflow\'s run', withReg(r2), /workflow:weekly: every evidence must be a run of weekly\.yml/]);
	}
	for (const [spelling, on] of [['"schedule":', 'on:\n  "schedule":\n    - cron: \'1 1 * * 1\'\n  push:\n'], ["'schedule' :", "on:\n  'schedule' :\n    - cron: '1 1 * * 1'\n  push:\n"], ['an inline quoted list', 'on: ["schedule", push]\n']]) {
		injections.push([`LSR-1 schedule spelled ${spelling}`, { ...base, '.github/workflows/alarm.yml': `${on}jobs:\n  a:\n    steps:\n      - run: x\n` }, /workflow:alarm .* add it to/]);
	}
	for (const [spelling, filter] of [['"branches": [nope]', '    "branches": [nope]\n'], ['branches : [nope]', '    branches : [nope]\n'], ["'paths-ignore': ['**']", "    'paths-ignore': ['**']\n"]]) {
		injections.push([`LSR-4 push filter spelled ${spelling}`, { ...base, '.github/workflows/nightly.yml': `on:\n  workflow_dispatch:\n  push:\n${filter}jobs:\n  a:\n    steps:\n      - run: x\n` }, /workflow:nightly .* add it to/]);
	}
	// LSR-7: indentation is YAML's, not a fixed column; what the scanner can't read fails closed.
	for (const [shape, on] of [
		['a 6-space filter', 'on:\n  workflow_dispatch:\n  push:\n      branches: [nope]\n'],
		['a 3-space filter', 'on:\n  workflow_dispatch:\n  push:\n   branches: [nope]\n'],
		['4-space triggers', 'on:\n    workflow_dispatch:\n    push:\n        paths-ignore:\n          - \'**\'\n'],
		['an inline flow-mapping filter', 'on:\n  workflow_dispatch:\n  push: {branches: [nope]}\n'],
		['a column-0 comment before the schedule', "on:\n  push:\n# weekly\n  schedule:\n    - cron: '1 1 * * 1'\n"],
		['an unreadable trigger line', "on:\n  push:\n  ? schedule\n"],
		['a trigger-level dedent', 'on:\n    push:\n  workflow_dispatch:\n'],
		['an unreadable line at the filter level', 'on:\n  workflow_dispatch:\n  push:\n    - nope\n'],
		['a filter-level dedent', 'on:\n  workflow_dispatch:\n  push:\n      tags: [v1]\n    branches: [nope]\n'],
	]) {
		injections.push([`LSR-7 ${shape}`, { ...base, '.github/workflows/nightly.yml': `${on}jobs:\n  a:\n    steps:\n      - run: x\n` }, /workflow:nightly .* add it to/]);
	}
	// LSR-9: a flow collection or quoted scalar that continues on the next line.
	for (const [shape, on] of [
		['a two-line branches-ignore', 'on:\n  workflow_dispatch:\n  push:\n    branches-ignore: [foo,\n                      main]\n'],
		['a two-line paths-ignore', "on:\n  workflow_dispatch:\n  push:\n    paths-ignore: ['docs/**',\n      '**']\n"],
		['a two-line on: list', 'on: [push,\n  schedule]\n'],
		['a quoted default continued at column 0', "on:\n  push:\n  workflow_dispatch:\n    inputs:\n      x:\n        default: \"a\nb\"\n  schedule:\n    - cron: '1 1 * * 1'\n"],
		['a tagged quoted default continued at column 0', "on:\n  push:\n  workflow_dispatch:\n    inputs:\n      x:\n        default: !!str \"a\nb\"\n  schedule:\n    - cron: '1 1 * * 1'\n"],
	]) {
		injections.push([`LSR-9 ${shape}`, { ...base, '.github/workflows/nightly.yml': `${on}jobs:\n  a:\n    steps:\n      - run: x\n` }, /workflow:nightly .* add it to/]);
	}
	// LSR-11/12: an item the scanner doesn't positively read counts against the workflow.
	for (const [shape, filter] of [
		['a folded block-scalar item', '    branches-ignore:\n      - >-\n        main\n'],
		['a literal block-scalar item', '    branches-ignore:\n      - |-\n        main\n'],
		['a block-scalar paths-ignore item', '    paths-ignore:\n      - >-\n        **\n'],
		['a bare dash with the value below', '    branches-ignore:\n      -\n        main\n'],
		['a plain item continued on the next line', '    branches-ignore:\n      - foo\n        main\n'],
		['an empty branches-ignore', '    branches-ignore:\n'],
		['an anchored inline list', '    branches-ignore: &b [main]\n'],
		['an anchored two-line list', '    branches-ignore: &b [foo,\n                         main]\n'],
		['an escaped double-quoted item', '    branches-ignore: ["ma\\u0069n"]\n'],
		['an escaped double-quoted block item', '    branches-ignore:\n      - "ma\\x69n"\n'],
	]) {
		injections.push([`LSR-11 ${shape}`, { ...base, '.github/workflows/nightly.yml': `on:\n  workflow_dispatch:\n  push:\n${filter}jobs:\n  a:\n    steps:\n      - run: x\n` }, /workflow:nightly .* add it to/]);
	}
	// LSR-15: the `on:` line must be the real top-level key.
	for (const [shape, yml] of [
		['a decoy on: inside an open flow mapping', 'env: {A: a,\n"on": push,\nB: b}\non:\n  push:\n    branches: [nope]\n'],
		['a decoy on: inside an open quoted scalar', 'env:\n  NOTE: "x\non: push"\non:\n  push:\n    branches: [nope]\n'],
		['a duplicate top-level on:', 'on: push\non:\n  workflow_dispatch:\n'],
		['the only on: is inside an open value', 'env: {A: a,\n"on": push,\nB: b}\n'],
	]) {
		injections.push([`LSR-15 ${shape}`, { ...base, '.github/workflows/nightly.yml': `${yml}jobs:\n  a:\n    steps:\n      - run: x\n` }, /workflow:nightly .* add it to/]);
	}
	// LSR-13/14: filters are judged by what they mean, and what the gate doesn't model counts against.
	for (const [shape, trig] of [
		['branches-ignore m*', "  push:\n    branches-ignore: ['m*']\n"],
		['branches-ignore main*', "  push:\n    branches-ignore: ['main*']\n"],
		['branches-ignore ma?n', "  push:\n    branches-ignore: ['ma?n']\n"],
		['paths-ignore **/**', "  push:\n    paths-ignore: ['**/**']\n"],
		['paths-ignore covering every tracked file', "  push:\n    paths-ignore: ['tabd/**', 'test/**', 'extensions/**', '.github/**', 'build/**', 'docs/**', 'sandbox/**', 'broker/**']\n"],
		['branches with a negation', "  push:\n    branches: ['**', '!main']\n"],
		['tags only', '  push:\n    tags: [nope]\n'],
		['tags-ignore only', "  push:\n    tags-ignore: ['v*']\n"],
		['pull_request with non-default types', '  pull_request:\n    types: [locked]\n'],
		['an unknown key under push', '  push:\n    nope: [x]\n'],
	]) {
		injections.push([`LSR-13 ${shape}`, { ...base, '.github/workflows/nightly.yml': `on:\n  workflow_dispatch:\n${trig}jobs:\n  a:\n    steps:\n      - run: x\n` }, /workflow:nightly .* add it to/]);
	}
	injections.push(['LSR-5 a .yaml twin of a registered .yml workflow', { ...base, '.github/workflows/weekly.yaml': "on:\n  schedule:\n    - cron: '2 2 * * 2'\njobs:\n  r:\n    steps:\n      - run: echo\n" }, /weekly\.yaml and \.github\/workflows\/weekly\.yml are both subject workflow:weekly/]);
	{ // 4. an array nobody reads (seclabTaintEscapes): only test-reached code writes it
		const r = reg();
		r.exempt = r.exempt.filter(x => x.subject !== 'tabd/src/rpc.ts#escapes');
		injections.push(['unread array', withReg(r), /exports escapes, but nothing that runs reaches it/]);
	}
	{ // 5. a scheduled workflow nobody ran (deps-updates)
		const r = reg();
		r.subjects = r.subjects.filter(s => s.id !== 'workflow:weekly');
		injections.push(['scheduled job never run', withReg(r), /workflow:weekly .* add it to/]);
	}
	{ // a scheduled workflow that also runs on push still needs evidence of a scheduled-class run
		injections.push(['scheduled and push, never run on schedule', { ...base, '.github/workflows/alarm.yml': 'on:\n  schedule:\n    - cron: \'1 1 * * 1\'\n  push:\njobs:\n  a:\n    steps:\n      - run: x\n' }, /workflow:alarm .* add it to/]);
	}
	{ // and a ci job that never checks its marks
		injections.push(['marks step removed', { ...base, '.github/workflows/ci.yml': 'on:\n  push:\njobs:\n  oci:\n    steps:\n      - run: ./seclab test containment\n' }, /must end with exactly/]);
	}
	{ // a name inside a string is not a use
		const r = reg();
		r.exempt = r.exempt.filter(x => x.subject !== 'tabd/src/scan.ts#msgOnly');
		injections.push(['string mention', withReg(r), /exports msgOnly, but nothing/]);
	}
	// Review KKK: each way the first version could be satisfied falsely.
	const ciWith = (job: string) => ({ ...base, '.github/workflows/ci.yml': job });
	const marksStep = '      - name: marks\n        run: ./seclab liveness marks ci.yml#oci "$SECLAB_LIVENESS_LOG"\n';
	injections.push(
		['KKK-1 job if: false', ciWith(`on:\n  push:\njobs:\n  oci:\n    if: \${{ false }}\n    steps:\n      - run: x\n${marksStep}`), /must have no if: or continue-on-error/],
		['KKK-1 marks step || true', ciWith('on:\n  push:\njobs:\n  oci:\n    steps:\n      - run: x\n      - name: marks\n        run: ./seclab liveness marks ci.yml#oci "$SECLAB_LIVENESS_LOG" || true\n'), /must end with exactly/],
		['KKK-1 marks step continue-on-error', ciWith(`on:\n  push:\njobs:\n  oci:\n    steps:\n      - run: x\n${marksStep}        continue-on-error: true\n`), /must end with exactly/],
		['CR-1 ci job needs a skipped job', ciWith(`on:\n  push:\njobs:\n  gate:\n    if: false\n    steps:\n      - run: x\n  oci:\n    needs: gate\n    steps:\n      - run: x\n${marksStep}`), /has `needs:`/],
		['CR-1 ci job quoted if', ciWith(`on:\n  push:\njobs:\n  oci:\n    "if": false\n    steps:\n      - run: x\n${marksStep}`), /job-level if/],
		['KKK-1 dispatch-only ci job', ciWith(`on:\n  workflow_dispatch:\njobs:\n  oci:\n    steps:\n      - run: x\n${marksStep}`), /must run on push or pull_request/],
		['KKK-7 push filtered off main', ciWith(`on:\n  push:\n    branches: [nope]\njobs:\n  oci:\n    steps:\n      - run: x\n${marksStep}`), /workflow:ci .* add it to/],
		['MMM-1 paths matching no file', ciWith(`on:\n  push:\n    paths: [no/such/path/**]\njobs:\n  oci:\n    steps:\n      - run: x\n${marksStep}`), /workflow:ci .* add it to/],
		['MMM-1 paths-ignore everything (block list)', ciWith(`on:\n  push:\n    paths-ignore:\n      - '**'\njobs:\n  oci:\n    steps:\n      - run: x\n${marksStep}`), /must run on push or pull_request/],
		['KKK-2 mark only in a string', { ...base, 'test/run.ts': "import { liveMark } from './liveness.ts';\nconst s = \"liveMark('evil-ran')\";\n" }, /never calls liveMark\('evil-ran'\) in code/],
		['KKK-2 mark in another file', { ...base, 'test/run.ts': '\n', 'test/other.ts': "import { liveMark } from './liveness.ts';\nliveMark('evil-ran');\n" }, /never calls liveMark\('evil-ran'\) in code/],
		['KKK-5 record mentions the id in passing', { ...base, 'docs/proof.md': 'hook:v/h never ran\n' }, /has no "- \*\*`hook:v\/h`:\*\* …" evidence line/],
	);
	{ // KKK-3: an entry hatch for something no host calls
		const r = reg();
		r.entry = [...(r.entry ?? []), { subject: 'tabd/src/rpc.ts#record', calledBy: 'nothing really', declaredIn: 'docs/proof.md' }];
		r.exempt = r.exempt.filter(x => x.subject !== 'tabd/src/rpc.ts#record');
		injections.push(['KKK-3 fake entry', withReg(r), /only an extension's activate\/deactivate/]);
	}
	{ // KKK-6: an object key and a member access are not uses
		const r = reg();
		r.exempt = r.exempt.filter(x => x.subject !== 'extensions/e/src/boot.ts#keyOnly');
		injections.push(['KKK-6 key and member only', withReg(r), /exports keyOnly, but nothing/]);
	}
	for (const [name, tree, want] of injections) {
		const got = await run(tree);
		if (!got.errors.some(e => want.test(e))) {
			throw new Error(`self-test: injected "${name}" not caught; got:\n${got.errors.join('\n') || '(no errors)'}`);
		}
	}
	// LSR-9 controls: what reads in full stays readable (a fail-closed rule that fires on ordinary
	// workflows would bury the real cases in subjects nobody can evidence).
	for (const [shape, yml, want] of [
		['an apostrophe in a plain scalar', "on:\n  push:\n  workflow_dispatch:\n    inputs:\n      x:\n        description: don't [stop\n", 'push,workflow_dispatch'],
		['a block scalar with brackets', "on:\n  push:\n  workflow_dispatch:\n    inputs:\n      x:\n        description: |\n          a [b {c\n          'd\n", 'push,workflow_dispatch'],
		['a one-line filter with a comment', "on:\n  push:\n    branches: [main] # [not\n", 'push'],
		['an odd bracket and quote in a comment', "on:\n  push:\n    branches: [main] # see: [x, don: 't\n", 'push'],
		['plain and quoted block items', "on:\n  push:\n    branches:\n      - main\n      - 'release/**'\n      - \"v*\" # tags\n", 'push'],
		['an include glob covering main, with tags', "on:\n  push:\n    branches: ['ma*']\n    tags: ['v*']\n  pull_request:\n    types: [opened, labeled]\n", 'push,pull_request'],
		['an ignore list that misses main', "on:\n  push:\n    branches-ignore: ['dependabot/**', 'mainline']\n", 'push'],
		['a quoted list on one line', "on: ['push', \"pull_request\"]\n", 'push,pull_request'],
	] as const) {
		const got = triggers(yml).join(',');
		if (got !== want) {
			throw new Error(`self-test: LSR-9 control "${shape}": got ${got}, want ${want}`);
		}
	}
	// LSR-6: tombstones are append-only against the base register; `restored` is the only way back.
	{
		const r = reg();
		r.removed = [];
		const got = await run(withReg(r), reg());
		if (!got.errors.some(e => /removed tabd\/src\/zombie\.ts#resurrected: dropped, but tombstones are append-only/.test(e))) {
			throw new Error(`self-test: injected "LSR-6 a tombstone dropped against the base" not caught; got:\n${got.errors.join('\n') || '(no errors)'}`);
		}
		const back = reg();
		back.removed = [{ ...back.removed![0], restored: 'synthetic: brought back on purpose' }];
		back.exempt.push({ subject: 'tabd/src/zombie.ts#resurrected', consumer: null, reason: 'brought back on purpose' });
		const ok = await run(withReg(back, { 'tabd/src/zombie.ts': 'export function resurrected() {}\n' }), reg());
		if (ok.errors.length) {
			throw new Error(`self-test: a restored tombstone with its exemption back should pass; got:\n${ok.errors.join('\n')}`);
		}
		// LSR-8: armed with no exemption (pre-armed, or left on after the exemption went).
		const armed = reg();
		armed.removed = [{ ...armed.removed![0], restored: 'synthetic: armed ahead of time' }];
		const inert = await run(withReg(armed), reg());
		if (!inert.errors.some(e => /removed tabd\/src\/zombie\.ts#resurrected: says restored, but nothing exempts it/.test(e))) {
			throw new Error(`self-test: injected "LSR-8 a restored tombstone with no exemption" not caught; got:\n${inert.errors.join('\n') || '(no errors)'}`);
		}
	}
	const r = JSON.parse(base['build/liveness/register.json']) as Register;
	const marks: Array<[string, string | undefined, boolean]> = [['evil-ran\n', 'evil-ran\n', true], ['missing mark', 'other\n', false], ['no log', undefined, false]];
	for (const [name, log, ok] of marks) {
		if ((checkMarks(r, 'ci.yml#oci', log).length === 0) !== ok) {
			throw new Error(`self-test: marks "${name}" wrong`);
		}
	}
	if (!checkMarks(r, 'ci.yml#other', 'x').length) {
		throw new Error('self-test: a marks step for a job nobody names passed');
	}
	// verify-runs against a fake API: the good run passes; each mismatch fails; a missing job
	// fails (artifacts are never consulted: they expire within days); an aging run is a note
	// ahead of the retention horizon; a deleted run is an error while recent, a note once past it.
	const now = Date.parse('2026-11-09T00:00:00Z');
	const good = { path: '.github/workflows/weekly.yml', event: 'workflow_dispatch', conclusion: 'success', head_sha: 'a'.repeat(40), created_at: '2026-11-01T10:00:00Z' };
	const jobsOk = { jobs: [{ name: 'reh (test variant)', conclusion: 'success' }] };
	const runCases: Array<[string, Record<string, unknown> | undefined, string, 'ok' | 'error' | 'note', string?, Record<string, unknown>?]> = [
		['good run', good, '2026-11-01', 'ok'],
		['other workflow', { ...good, path: '.github/workflows/ci.yml' }, '2026-11-01', 'error'],
		['push event', { ...good, event: 'push' }, '2026-11-01', 'error'],
		['failed', { ...good, conclusion: 'failure' }, '2026-11-01', 'error'],
		['other sha', { ...good, head_sha: 'b'.repeat(40) }, '2026-11-01', 'error'],
		['deleted, recent', undefined, '2026-11-01', 'error'],
		['deleted, expired', undefined, '2026-07-01', 'note'],
		['aging, still there', { ...good, created_at: '2026-08-15T10:00:00Z' }, '2026-08-15', 'note'],
		['named job present', good, '2026-11-01', 'ok', 'reh (test variant)', jobsOk],
		['named job missing', good, '2026-11-01', 'error', 'reh (test variant)', { jobs: [{ name: 'build', conclusion: 'success' }] }],
		['named job failed', good, '2026-11-01', 'error', 'reh (test variant)', { jobs: [{ name: 'reh (test variant)', conclusion: 'failure' }] }],
	];
	for (const [name, body, date, want, job, jobs] of runCases) {
		const reg1: Register = { exempt: [], subjects: [{ id: 'workflow:weekly', runBy: 'x', evidence: [{ run: 1, workflow: 'weekly.yml', sha: 'a'.repeat(40), date, ...(job ? { job } : {}) }] }] };
		const got = await verifyRuns(reg1, async p => p.includes('/artifacts') ? { status: 200, body: { artifacts: [] } }
			: p.includes('/jobs') ? { status: 200, body: jobs ?? { jobs: [] } }
			: body ? { status: 200, body } : { status: 404 }, now);
		const kind = got.errors.length ? 'error' : got.notes.length ? 'note' : 'ok';
		if (kind !== want) {
			throw new Error(`self-test: verify-runs "${name}": ${kind}, want ${want}`);
		}
		// The weekly refresh fails on anything the required check only notes.
		const refreshed = refreshReport(got);
		if ((refreshed.errors.length > 0) !== (want !== 'ok') || refreshed.notes.length) {
			throw new Error(`self-test: verify-runs --refresh "${name}": ${refreshed.errors.length} error(s), want ${want === 'ok' ? 'none' : 'some'}`);
		}
	}
	// Records of runs CI can't do: due again after 30 days (a note; the weekly refresh fails).
	const recordCases: Array<[string, string, 'ok' | 'note']> = [['fresh record', '2026-11-01', 'ok'], ['stale record', '2026-09-01', 'note']];
	for (const [name, date, want] of recordCases) {
		const reg1: Register = { exempt: [], subjects: [{ id: 'fixture:x', runBy: 'a local harness', evidence: [{ record: 'docs/proof.md', date }] }] };
		const got = await verifyRuns(reg1, async () => ({ status: 404 }), now);
		const kind = got.errors.length ? 'error' : got.notes.length ? 'note' : 'ok';
		if (kind !== want || (refreshReport(got).errors.length > 0) !== (want === 'note')) {
			throw new Error(`self-test: verify-runs "${name}": ${kind}, want ${want}`);
		}
	}
	{ // an undated, impossible or future record date is refused offline (NNN-6)
		for (const date of [undefined, '2026-13-45', '2999-01-01']) {
			const r = reg();
			r.subjects = r.subjects.map(s => s.id === 'hook:v/h' ? { ...s, evidence: [{ record: 'docs/proof.md', ...(date ? { date } : {}) }] } : s);
			const got = await run(withReg(r));
			if (!got.errors.some(e => /record evidence needs the run's date/.test(e))) {
				throw new Error(`self-test: a record dated ${date} was accepted`);
			}
		}
	}
	console.log(`liveness self-test: ok (control clean; ${injections.length + 3} injections, ${marks.length + 1} mark cases, ${runCases.length} run and ${recordCases.length} record cases caught)`);
}

// ---- main ---------------------------------------------------------------------------------

if (import.meta.main) {
	const [cmd, ...rest] = process.argv.slice(2);
	const repo = process.cwd();
	const read = (f: string) => fs.readFileSync(path.join(repo, f), 'utf8');
	const report = (r: Report, ok: string) => {
		for (const n of r.notes) {
			console.log(`note: ${n}`);
		}
		if (r.errors.length) {
			for (const e of r.errors) {
				console.error(`liveness: ${e}`);
			}
			process.exit(1);
		}
		console.log(ok);
	};
	if (cmd === '--self-test') {
		await selfTest();
	} else if (cmd === 'check' && rest.length === 3 && rest[0] === '-' && rest[1] === '--base') {
		// The base register (main's, or the push's previous head's) is required, so the tombstone
		// rule can't be skipped by omission; an empty file means the base predates the register.
		const baseText = fs.readFileSync(rest[2], 'utf8');
		const base = baseText.trim() ? JSON.parse(baseText) as Register : null;
		const files = fs.readFileSync(0, 'utf8').split('\0').filter(Boolean).filter(f => fs.existsSync(path.join(repo, f)));
		const links = new Map<string, string>();
		for (const f of files) {
			if (fs.lstatSync(path.join(repo, f)).isSymbolicLink()) {
				links.set(f, path.posix.normalize(path.posix.join(path.posix.dirname(f), fs.readlinkSync(path.join(repo, f)))));
			}
		}
		report(await check(files.filter(f => !links.has(f)), read, { links, base }), 'liveness: ok (Actions runs are verified by verify-runs)');
	} else if (cmd === 'verify-runs' && (rest.length === 0 || (rest.length === 1 && rest[0] === '--refresh'))) {
		// --refresh (the weekly liveness-refresh workflow): evidence near or past the retention
		// horizon fails, so it's re-run before it lapses; the required check only notes it. The
		// banner lets the workflow prove the flag arrived (MMM-2: a lost flag would fail open).
		if (rest[0] === '--refresh') {
			console.log('liveness: refresh mode');
		}
		const r = await verifyRuns(JSON.parse(read(REGISTER)) as Register, githubApi());
		report(rest[0] === '--refresh' ? refreshReport(r) : r, 'liveness: recorded Actions runs verified');
	} else if (cmd === 'marks' && rest.length === 2) {
		const log = fs.existsSync(rest[1]) ? fs.readFileSync(rest[1], 'utf8') : undefined;
		report({ errors: checkMarks(JSON.parse(read(REGISTER)) as Register, rest[0], log), notes: [] }, `liveness marks ${rest[0]}: ok`);
	} else {
		console.error('usage: liveness.ts check - --base FILE | verify-runs | marks FILE.yml#JOB LOG | --self-test');
		process.exit(2);
	}
}
