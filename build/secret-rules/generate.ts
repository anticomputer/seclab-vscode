// Generates the secret-scanning rule table that a tab's configuration snapshot is checked against
// (patch 0036, EDR configuration-snapshot). Source: gitleaks' own default config
// (config/gitleaks.toml) at the commit pinned in build/tools/tools.json, translated from Go RE2 to
// V8 regular expressions. It is pure data: no gitleaks code runs in the editor.
//   node build/secret-rules/generate.ts TOML > rules.ts
// Translation (each checked: every emitted pattern must compile in V8, or the run fails):
//   (?i) anywhere -> the `i` flag on the whole pattern (broader matching: fails closed);
//   (?P<name>     -> (?<name>;
//   \z            -> $ (no `m` flag, so end of input);
//   [:alnum:] and the other POSIX classes -> their ranges;
//   rules bound to a file path are skipped (a setting has no file name).
// Allowlist entries that match their own rule's pattern are literal example tokens: they are left
// out, so the repo never holds a value in a real token format and the scanner only gets stricter.

import * as fs from 'node:fs';

interface Allow { target: string; condition: string; regexes: string[]; stopwords: string[]; paths: boolean }
interface Rule { id: string; regex?: string; group: number; entropy: number; keywords: string[]; allow: Allow[]; path: boolean }

const toml = fs.readFileSync(process.argv[2], 'utf8');
const KNOWN = new Set(['id', 'description', 'regex', 'secretGroup', 'entropy', 'keywords', 'path', 'paths', 'regexes', 'regexTarget', 'stopwords', 'condition', 'title', 'minVersion', 'tags']);

// The subset of TOML gitleaks' generated config uses: tables, [[arrays of tables]], strings
// ('''raw''' and "basic"), numbers and string arrays. Anything else fails the run.
type Value = string | number | string[];
const sections: Array<{ header: string; fields: Record<string, Value> }> = [{ header: '', fields: {} }];
const lines = toml.split('\n');
const str = (s: string): string => {
	if (s.startsWith("'''") && s.endsWith("'''") && s.length >= 6) {
		return s.slice(3, -3);
	}
	if (s.startsWith('"')) {
		return JSON.parse(s);
	}
	throw new Error(`unsupported value ${s.slice(0, 60)}`);
};
for (let i = 0; i < lines.length; i++) {
	const line = lines[i].trim();
	if (!line || line.startsWith('#')) {
		continue;
	}
	if (line.startsWith('[')) {
		sections.push({ header: line, fields: {} });
		continue;
	}
	const m = /^([A-Za-z]+) = (.*)$/.exec(line);
	if (!m || !KNOWN.has(m[1])) {
		throw new Error(`line ${i + 1}: unsupported ${line.slice(0, 60)}`);
	}
	const [, key, raw] = m;
	let value: Value;
	if (raw === '[') {
		const items: string[] = [];
		for (i++; lines[i].trim() !== ']'; i++) {
			const parts = lines[i].trim().match(/'''.*?'''|"(?:[^"\\]|\\.)*"/g);
			if (!parts) {
				throw new Error(`line ${i + 1}: unsupported array item`);
			}
			items.push(...parts.map(str));
		}
		value = items;
	} else if (raw.startsWith('[')) {
		value = (raw.match(/'''.*?'''|"(?:[^"\\]|\\.)*"/g) ?? []).map(str);
	} else if (/^-?\d+(\.\d+)?$/.test(raw)) {
		value = Number(raw);
	} else {
		value = str(raw);
	}
	sections[sections.length - 1].fields[key] = value;
}

const POSIX: Record<string, string> = { alnum: 'A-Za-z0-9', alpha: 'A-Za-z', digit: '0-9', xdigit: '0-9A-Fa-f', upper: 'A-Z', lower: 'a-z', word: '\\w', space: '\\s' };
const translate = (re: string): { source: string; flags: string } => {
	const flags = re.includes('(?i)') ? 'i' : '';
	let source = re.replace(/\(\?i\)/g, '').replace(/\(\?P</g, '(?<').replace(/\\z/g, '$')
		// RE2's POSIX classes (only valid inside a bracket expression): V8 would read them as literals.
		.replace(/\[:([a-z]+):\]/g, (_, name: string) => {
			if (!POSIX[name]) {
				throw new Error(`unsupported POSIX class [:${name}:]`);
			}
			return POSIX[name];
		});
	// A pure literal pattern would match its own text in this file, so secret scanners (and our
	// pre-push gitleaks) would flag the rule table itself. `\x2d` is the same pattern.
	if (/^[\w-]+$/.test(source) && new RegExp(source, flags).test(source)) {
		source = source.replace(/-/g, '\\x2d');
	}
	new RegExp(source, flags); // throws on anything V8 can't compile
	return { source, flags };
};

const rules: Rule[] = [];
let global: Allow = { target: 'secret', condition: 'OR', regexes: [], stopwords: [], paths: false };
for (const s of sections) {
	const f = s.fields;
	if (s.header === '[[rules]]') {
		rules.push({
			id: String(f.id), regex: f.regex as string | undefined, group: Number(f.secretGroup ?? 0),
			entropy: Number(f.entropy ?? 0), keywords: ((f.keywords as string[] | undefined) ?? []).map(k => k.toLowerCase()), allow: [], path: f.path !== undefined,
		});
	} else if (s.header === '[[rules.allowlists]]') {
		rules[rules.length - 1].allow.push({ target: String(f.regexTarget ?? 'secret'), condition: String(f.condition ?? 'OR'), regexes: (f.regexes as string[]) ?? [], stopwords: (f.stopwords as string[]) ?? [], paths: !!f.paths || !!f.path });
	} else if (s.header === '[allowlist]') {
		global = { target: 'secret', condition: 'OR', regexes: (f.regexes as string[]) ?? [], stopwords: (f.stopwords as string[]) ?? [], paths: false };
	} else if (s.header !== '') {
		throw new Error(`unsupported table ${s.header}`);
	}
}

const out: unknown[] = [];
let skipped = 0;
let examples = 0;
for (const r of rules) {
	// A rule with a `path` only applies to files whose name matches (.tf, .php, .yaml...), and a
	// settings value is never such a file.
	if (!r.regex || r.path) {
		skipped++;
		continue;
	}
	const t = translate(r.regex);
	const self = new RegExp(t.source, t.flags);
	// An AND allowlist that needs a path can never hold for a setting (no path): left out.
	const allow = r.allow.filter(a => !(a.condition === 'AND' && a.paths)).map(a => {
		const regexes = a.regexes.filter(x => {
			const literal = x.replace(/^\^|\$$/g, '');
			const isExample = /^[\w+/=.-]{16,}$/.test(literal) && self.test(` ${literal} `);
			examples += isExample ? 1 : 0;
			return !isExample;
		}).map(translate);
		return { target: a.target, and: a.condition === 'AND', regexes, stopwords: a.stopwords.map(w => w.toLowerCase()) };
	}).filter(a => a.regexes.length || a.stopwords.length);
	out.push({ id: r.id, ...t, group: r.group, entropy: r.entropy, keywords: r.keywords, allow });
}
const tools = JSON.parse(fs.readFileSync(new URL('../tools/tools.json', import.meta.url), 'utf8')).gitleaks;
process.stdout.write(`/*---------------------------------------------------------------------------------------------
 *  seclab: GENERATED by build/secret-rules/generate.ts from gitleaks v${tools.version} (${tools.commit})
 *  config/gitleaks.toml (MIT). Do not edit. ${out.length} rules; ${skipped} path-bound rule(s) skipped (settings have no file name);
 *  ${examples} example token(s) left out of allowlists.
 *--------------------------------------------------------------------------------------------*/

export interface SeclabSecretRule {
	readonly id: string;
	readonly source: string;
	readonly flags: string;
	readonly group: number;
	readonly entropy: number;
	readonly keywords: readonly string[];
	readonly allow: readonly { readonly target: string; readonly and: boolean; readonly regexes: readonly { readonly source: string; readonly flags: string }[]; readonly stopwords: readonly string[] }[];
}

export const SECLAB_SECRET_RULES: readonly SeclabSecretRule[] = ${JSON.stringify(out, null, '\t')};

export const SECLAB_SECRET_GLOBAL_ALLOW: { readonly regexes: readonly { readonly source: string; readonly flags: string }[]; readonly stopwords: readonly string[] } = ${JSON.stringify({ regexes: global.regexes.map(translate), stopwords: global.stopwords.map(w => w.toLowerCase()) }, null, '\t')};
`);
