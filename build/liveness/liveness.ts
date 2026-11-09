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
//            exemption for something live is stale and fails.
// Runtime half (register.json `subjects`, matched exactly against what the tree contains):
//   workflow every workflow that never runs on push or pull_request (scheduled, dispatch-only);
//   hook     every test-only hook in test/builds/variants.json;
//   fixture  every child of a test `fixtures` dir, and every test extension (a dir with a
//            package.json under test/);
//   each with what runs it and at least one piece of evidence:
//     run    a GitHub Actions run of `workflow`; with --verify-runs (CI) it must exist, be a
//            successful dispatch or scheduled run of that workflow, and carry `artifact` if named.
//     ci     a CI job (`file.yml#job`) whose last step is `./seclab liveness marks` for that job,
//            and a `mark` the runner records with liveMark (test/liveness.ts) when it saw the
//            subject run. That step fails the job when a mark is missing.
//     record a doc naming the subject id: only for runs CI can't do (macOS, sbx). Listed on
//            every run.
//
// Usage (through ./seclab liveness, which feeds `git ls-files -z` on stdin):
//        node build/liveness/liveness.ts check - [--verify-runs]
//        node build/liveness/liveness.ts marks FILE.yml#JOB LOGFILE
//        node build/liveness/liveness.ts --self-test

import * as fs from 'node:fs';
import * as path from 'node:path';

export interface Exempt { subject: string; consumer: string | null; reason: string }
/** A declaration a host calls (VS Code calls `activate`): live, and so is what it reaches. */
export interface Entry { subject: string; calledBy: string; declaredIn: string }
export interface Evidence { run?: number; workflow?: string; artifact?: string; ci?: string; mark?: string; record?: string }
export interface Subject { id: string; runBy: string; evidence: Evidence[] }
export interface Register { entry?: Entry[]; exempt: Exempt[]; subjects: Subject[] }

const REGISTER = 'build/liveness/register.json';
// Code that runs: product sources, and the tools CI or an operator runs (doc generators, log CLI).
const TS_ROOTS = ['tabd/src/', 'tabd/tools/', 'extensions/seclab-tab-manager/src/'];
const PY_ROOTS = ['broker/seclab_broker/', 'broker/tools/'];
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

interface Decl { name: string; exported: boolean; body: string; file: string }
interface Parsed { decls: Decl[]; roots: string; imports: Set<string> }

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
	return { decls, roots, imports: importsOf(file, text, have, links) };
}

const word = (name: string) => new RegExp(`(?<![\\w$])${name.replace(/\$/g, '\\$')}(?![\\w$])`);

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
			if (!live.has(key(t)) && t.body !== from.body && word(t.name).test(from.body)) {
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

/** Trigger names of a workflow (`on:` as a map, a list or a scalar). */
export function triggers(yml: string): string[] {
	const lines = yml.split('\n');
	const i = lines.findIndex(l => /^(?:on|"on"|'on'):/.test(l));
	if (i < 0) {
		return [];
	}
	const inline = lines[i].replace(/^[^:]+:\s*/, '').replace(/#.*/, '').trim();
	if (inline) {
		return inline.replace(/^\[|\]$/g, '').split(',').map(s => s.trim()).filter(Boolean);
	}
	const out: string[] = [];
	for (const l of lines.slice(i + 1)) {
		if (/^\S/.test(l)) {
			break;
		}
		const m = /^ {2}([A-Za-z_]+):/.exec(l) ?? /^ {2}- ([A-Za-z_]+)\s*$/.exec(l);
		if (m) {
			out.push(m[1]);
		}
	}
	return out;
}

/** The steps' `run:` texts of one job, in order (block scalars joined). */
export function jobSteps(yml: string, job: string): string[] | undefined {
	const lines = yml.split('\n');
	const start = lines.findIndex(l => l === `  ${job}:`);
	if (start < 0 || !lines.slice(0, start).some(l => l === 'jobs:')) {
		return undefined;
	}
	const steps: string[] = [];
	let cur: string[] | undefined;
	let inRun = false;
	for (const l of lines.slice(start + 1)) {
		if (/^ {2}\S/.test(l) || /^\S/.test(l)) {
			break;
		}
		if (/^ {6}- /.test(l)) {
			if (cur) {
				steps.push(cur.join('\n'));
			}
			cur = [];
			inRun = false;
		}
		const m = /^ {6}(?:- )? {0,2}run:\s*(.*)$/.exec(l);
		if (m && cur) {
			inRun = true;
			if (!/^[|>][-+]?$/.test(m[1].trim())) {
				cur.push(m[1].trim());
			}
		} else if (inRun && cur && /^ {10}\S/.test(l)) {
			cur.push(l.trim());
		} else if (/^ {8}\S/.test(l)) {
			inRun = false;
		}
	}
	if (cur) {
		steps.push(cur.join('\n'));
	}
	return steps;
}

// ---- discovery ----------------------------------------------------------------------------

/** Every subject the tree contains that only matters if something runs it. */
export function discover(files: string[], read: (f: string) => string): Map<string, string> {
	const out = new Map<string, string>();
	for (const f of files.filter(f => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(f))) {
		const t = triggers(read(f));
		if (!t.includes('push') && !t.includes('pull_request')) {
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

export async function check(files: string[], read: (f: string) => string, opts: { verifyRuns?: (e: Evidence) => Promise<string | undefined>; links?: Map<string, string> } = {}): Promise<Report> {
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
		if ([...TS_ROOTS, ...PY_ROOTS].some(r => f.startsWith(r)) && langOf(f)) {
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
		if (!sources.has(file) || !name || !new RegExp(`^export\\s+(?:async\\s+)?function\\s+${name}\\b`, 'm').test(sources.get(file)!)) {
			errors.push(`entry ${x.subject}: no exported function ${name} in ${file}`);
			continue;
		}
		// The host finds the entry through its manifest: it must name the entry's module.
		const stem = path.posix.basename(file).replace(/\.\w+$/, '');
		if (!has.has(x.declaredIn) || !word(stem).test(read(x.declaredIn))) {
			errors.push(`entry ${x.subject}: ${x.declaredIn} does not name ${stem}`);
			continue;
		}
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
	for (const x of reg.exempt ?? []) {
		if (!x || typeof x.subject !== 'string' || typeof x.reason !== 'string' || !x.reason.trim() || !('consumer' in x)) {
			errors.push(`exempt ${JSON.stringify(x)}: needs subject, consumer (a path or null) and reason`);
			continue;
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
		if (!word(sym).test(codeOnly(read(x.consumer), langOf(x.consumer) ?? 'sh', true))) {
			errors.push(`exempt ${x.subject}: consumer ${x.consumer} never uses ${sym} (comments don't count). The exemption claims something untrue.`);
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
		for (const e of s.evidence) {
			const kinds = ['run', 'ci', 'record'].filter(k => k in e);
			if (kinds.length !== 1) {
				errors.push(`subject ${s.id}: each evidence is exactly one of run, ci, record`);
				continue;
			}
			if (e.run !== undefined) {
				if (!Number.isSafeInteger(e.run) || e.run <= 0 || typeof e.workflow !== 'string' || !has.has(`.github/workflows/${e.workflow}`)) {
					errors.push(`subject ${s.id}: run evidence needs a run id and an existing workflow file`);
				} else if (opts.verifyRuns) {
					const bad = await opts.verifyRuns(e);
					if (bad) {
						errors.push(`subject ${s.id}: run ${e.run}: ${bad}`);
					}
				}
			} else if (e.ci !== undefined) {
				const [wf, job] = e.ci.split('#');
				const yml = has.has(`.github/workflows/${wf}`) ? read(`.github/workflows/${wf}`) : undefined;
				const steps = yml && job ? jobSteps(yml, job) : undefined;
				if (!steps) {
					errors.push(`subject ${s.id}: ci evidence ${e.ci}: no such workflow job`);
				} else if (!new RegExp(`^\\./seclab liveness marks ${e.ci.replace(/[.#]/g, '\\$&')} `).test(steps.at(-1) ?? '')) {
					errors.push(`subject ${s.id}: ci job ${e.ci} must end with \`./seclab liveness marks ${e.ci} <log>\`, or nothing checks its marks`);
				}
				if (typeof e.mark !== 'string' || !/^[a-z0-9][a-z0-9:/._-]{2,120}$/.test(e.mark)) {
					errors.push(`subject ${s.id}: ci evidence needs a mark ([a-z0-9:/._-])`);
				} else if (!files.some(f => /^(?:test|tabd\/test)\//.test(f) && langOf(f) === 'ts' && codeOnly(read(f), 'ts').includes(`liveMark('${e.mark}'`))) {
					errors.push(`subject ${s.id}: no runner calls liveMark('${e.mark}')`);
				}
			} else if (e.record !== undefined) {
				if (!/^docs\/.+\.md$/.test(e.record) || !has.has(e.record)) {
					errors.push(`subject ${s.id}: record ${e.record} is not a doc in docs/`);
				} else if (!read(e.record).includes(s.id)) {
					errors.push(`subject ${s.id}: record ${e.record} never names ${s.id}`);
				} else if (!s.evidence.some(x => x.run !== undefined || x.ci !== undefined)) {
					notes.push(`record only: ${s.id} (${e.record})`);
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

async function verifyRun(e: Evidence): Promise<string | undefined> {
	const repo = process.env.GITHUB_REPOSITORY;
	const token = process.env.GITHUB_TOKEN;
	if (!repo || !token) {
		return 'cannot verify: GITHUB_REPOSITORY and GITHUB_TOKEN are required with --verify-runs';
	}
	const api = async (p: string) => {
		const r = await fetch(`https://api.github.com/repos/${repo}/actions/runs/${p}`, { headers: { accept: 'application/vnd.github+json', authorization: `Bearer ${token}` } });
		if (!r.ok) {
			throw new Error(`HTTP ${r.status}`);
		}
		return r.json() as Promise<Record<string, unknown>>;
	};
	try {
		const run = await api(String(e.run));
		if (run.path !== `.github/workflows/${e.workflow}`) {
			return `is a run of ${String(run.path)}, not ${e.workflow}`;
		}
		if (run.event !== 'workflow_dispatch' && run.event !== 'schedule') {
			return `was triggered by ${String(run.event)}, not dispatch or schedule`;
		}
		if (run.conclusion !== 'success') {
			return `concluded ${String(run.conclusion)}`;
		}
		if (e.artifact) {
			const a = await api(`${e.run}/artifacts?per_page=100`) as { artifacts?: Array<{ name?: string }> };
			if (!a.artifacts?.some(x => x.name === e.artifact)) {
				return `has no artifact ${e.artifact}`;
			}
		}
	} catch (err) {
		return `lookup failed: ${(err as Error).message}`;
	}
	return undefined;
}

// ---- self-test ----------------------------------------------------------------------------

/**
 * A clean synthetic tree passes, and each of the five recorded failures, injected alone into a
 * fresh copy, fails with its own message. The control runs first and must pass: a prover that
 * fails everything is as broken as one that passes everything.
 */
async function selfTest(): Promise<void> {
	const base: Record<string, string> = {
		'.github/workflows/ci.yml': 'on:\n  push:\njobs:\n  oci:\n    steps:\n      - run: ./seclab test containment\n      - name: marks\n        run: ./seclab liveness marks ci.yml#oci "$LOG"\n',
		'.github/workflows/weekly.yml': "on:\n  schedule:\n    - cron: '1 1 * * 1'\n  workflow_dispatch:\njobs:\n  r:\n    steps:\n      - run: echo\n",
		'test/builds/variants.json': '{"v":{"hooks":[{"id":"h","patch":"test/h.patch"}]}}',
		'test/h.patch': '',
		'test/x/fixtures/evil/a.txt': '',
		'test/run.ts': "import { liveMark } from './liveness.ts';\nliveMark('evil-ran');\n",
		'docs/proof.md': 'hook:v/h ran in run 7\n',
		'tabd/src/main.ts': "import { start } from './sup.ts';\nimport { onDecision } from './rpc.ts';\nstart();\nonDecision(() => {});\n",
		'tabd/src/sup.ts': "import { mint } from './scan.ts';\nexport function start() { helper(); }\nfunction helper() { const glob = '/**'; mint(); /* a comment */ }\n",
		'tabd/src/scan.ts': "export function mint() {}\nexport function msgOnly() {}\nexport const note = `uses ${mint.name} but msgOnly only in text`;\n",
		'tabd/src/rpc.ts': 'const listeners = [];\nexport function onDecision(f) { listeners.push(f); }\nexport const escapes = [];\nexport function record(x) { escapes.push(x); }\n',
		'tabd/test/rpc.test.ts': "import { record } from '../src/rpc.ts';\nrecord(1);\n",
		'sandbox/rootfs/opt/seclab/bin/seclab-x': '#!/bin/sh\n',
		'tabd/src/drivers.ts': "export const X = '/opt/seclab/bin/seclab-x';\n",
		'build/liveness/register.json': JSON.stringify({
			exempt: [
				{ subject: 'tabd/src/rpc.ts#escapes', consumer: null, reason: 'nothing reads it yet' },
				{ subject: 'tabd/src/rpc.ts#record', consumer: 'tabd/test/rpc.test.ts', reason: 'test only' },
				{ subject: 'tabd/src/drivers.ts#X', consumer: null, reason: 'synthetic' },
				{ subject: 'tabd/src/scan.ts#msgOnly', consumer: null, reason: 'synthetic: named only inside a string' },
				{ subject: 'tabd/src/scan.ts#note', consumer: null, reason: 'synthetic' },
			],
			subjects: [
				{ id: 'workflow:weekly', runBy: 'schedule', evidence: [{ run: 1, workflow: 'weekly.yml' }] },
				{ id: 'hook:v/h', runBy: 'harness', evidence: [{ record: 'docs/proof.md' }] },
				{ id: 'fixture:test/x/fixtures/evil', runBy: 'test/run.ts', evidence: [{ ci: 'ci.yml#oci', mark: 'evil-ran' }] },
			],
		}),
	};
	const run = (tree: Record<string, string>) => check(Object.keys(tree).sort(), f => {
		if (!(f in tree)) {
			throw new Error(`ENOENT ${f}`);
		}
		return tree[f];
	});
	const control = await run(base);
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
		injections.push(['probe never run', { ...base, 'test/run.ts': "import { liveMark } from './liveness.ts';\n// liveMark('evil-ran');\n" }, /no runner calls liveMark\('evil-ran'\)/]);
	}
	{ // 3. a listener API with no listener, behind an exemption claiming one (seclabOnDecision)
		const r = reg();
		r.exempt.push({ subject: 'tabd/src/rpc.ts#onDecision', consumer: 'tabd/src/main.ts', reason: 'the Tab Manager subscribes' });
		injections.push(['false exemption', withReg(r, { 'tabd/src/main.ts': "import { start } from './sup.ts';\n// onDecision is subscribed elsewhere\nstart();\n" }), /consumer tabd\/src\/main\.ts never uses onDecision/]);
	}
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
	{ // and a ci job that never checks its marks
		injections.push(['marks step removed', { ...base, '.github/workflows/ci.yml': 'on:\n  push:\njobs:\n  oci:\n    steps:\n      - run: ./seclab test containment\n' }, /must end with `\.\/seclab liveness marks/]);
	}
	{ // a name inside a string is not a use
		const r = reg();
		r.exempt = r.exempt.filter(x => x.subject !== 'tabd/src/scan.ts#msgOnly');
		injections.push(['string mention', withReg(r), /exports msgOnly, but nothing/]);
	}
	for (const [name, tree, want] of injections) {
		const got = await run(tree);
		if (!got.errors.some(e => want.test(e))) {
			throw new Error(`self-test: injected "${name}" not caught; got:\n${got.errors.join('\n') || '(no errors)'}`);
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
	console.log(`liveness self-test: ok (control clean; ${injections.length} injections and ${marks.length + 1} mark cases caught)`);
}

// ---- main ---------------------------------------------------------------------------------

if (import.meta.main) {
	const [cmd, ...rest] = process.argv.slice(2);
	const repo = process.cwd();
	const read = (f: string) => fs.readFileSync(path.join(repo, f), 'utf8');
	if (cmd === '--self-test') {
		await selfTest();
	} else if (cmd === 'check' && rest[0] === '-') {
		const files = fs.readFileSync(0, 'utf8').split('\0').filter(Boolean).filter(f => fs.existsSync(path.join(repo, f)));
		const links = new Map<string, string>();
		for (const f of files) {
			if (fs.lstatSync(path.join(repo, f)).isSymbolicLink()) {
				links.set(f, path.posix.normalize(path.posix.join(path.posix.dirname(f), fs.readlinkSync(path.join(repo, f)))));
			}
		}
		const { errors, notes } = await check(files.filter(f => !links.has(f)), read, { links, ...(rest.includes('--verify-runs') ? { verifyRuns: verifyRun } : {}) });
		for (const n of notes) {
			console.log(`note: ${n}`);
		}
		if (errors.length) {
			for (const e of errors) {
				console.error(`liveness: ${e}`);
			}
			process.exit(1);
		}
		console.log(`liveness: ok${rest.includes('--verify-runs') ? ' (runs verified)' : ' (runs not verified offline)'}`);
	} else if (cmd === 'marks' && rest.length === 2) {
		const log = fs.existsSync(rest[1]) ? fs.readFileSync(rest[1], 'utf8') : undefined;
		const errs = checkMarks(JSON.parse(read(REGISTER)) as Register, rest[0], log);
		if (errs.length) {
			for (const e of errs) {
				console.error(`liveness: ${e}`);
			}
			process.exit(1);
		}
		console.log(`liveness marks ${rest[0]}: ok`);
	} else {
		console.error('usage: liveness.ts check - [--verify-runs] | marks FILE.yml#JOB LOG | --self-test');
		process.exit(2);
	}
}
