// docs-check (EDR docs-check): keep the docs in lock-step with the code. No dependencies;
// runs in a network-less node container. Modes:
//   node build/docs/docs-check.ts check        verify everything below (exit 1 on drift)
//   node build/docs/docs-check.ts write        regenerate the record indexes in place
//   node build/docs/docs-check.ts commands     print the `<!-- ci: run -->` shell blocks
//   node build/docs/docs-check.ts paired FILE  FILE: changed paths, then a line "--", then
//                                              commit messages; fail on unpaired doc changes
// Checks:
//   1. Records (docs/adr, docs/edr, docs/security-reviews): YYYYMMDD-slug.md names, a
//      title, a Date matching the name, a Status (ADR/EDR), supersede links both ways; the
//      README indexes are GENERATED from them (between <!-- index:begin/end --> markers).
//   2. Every relative link in tracked markdown resolves; GitHub permalinks are pinned to a
//      40-hex SHA (never /blob/main/ or another branch).
//   3. ARCHITECTURE.md links every accepted ADR, never a superseded ADR as current, and
//      every `seclab-*` component it names exists in the tree.

import * as fs from 'node:fs';
import * as path from 'node:path';

const repo = path.resolve(import.meta.dirname, '../..');
const SKIP = new Set(['.git', '.work', 'node_modules', 'vscode', '.venv', '__pycache__', 'out', 'dist']);
const problems: string[] = [];
const bad = (where: string, what: string) => problems.push(`${where}: ${what}`);

function walk(dir: string, pick: (p: string) => boolean, acc: string[] = []): string[] {
	for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
		if (SKIP.has(e.name)) {
			continue;
		}
		const p = path.join(dir, e.name);
		if (e.isDirectory()) {
			walk(p, pick, acc);
		} else if (e.isFile() && pick(p)) {
			acc.push(p);
		}
	}
	return acc;
}
const rel = (p: string) => path.relative(repo, p);

// ---- 1. records and generated indexes ---------------------------------------------------

interface Rec { file: string; name: string; title: string; date: string; status: string; keyword: string; supersededBy: string[]; supersedes: string[]; scope: string; open: string }
const KINDS = ['adr', 'edr', 'security-reviews'] as const;

function field(text: string, name: string): string {
	return new RegExp(`^- \\*\\*${name}:\\*\\*\\s*(.*)$`, 'mi').exec(text)?.[1]?.trim() ?? '';
}
function links(s: string): string[] {
	return [...s.matchAll(/\]\(([^)#\s]+\.md)(?:#[^)]*)?\)/g)].map(m => path.posix.basename(m[1]));
}
function readRecords(kind: typeof KINDS[number]): Rec[] {
	const dir = path.join(repo, 'docs', kind);
	// FINDINGS.md is the generated findings register view, and owner-acceptances.md holds the project
	// owner's decisions on findings (build/docs/findings.ts); neither is a review record.
	return fs.readdirSync(dir).filter(f => f.endsWith('.md') && f !== 'README.md' && !(kind === 'security-reviews' && (f === 'FINDINGS.md' || f === 'owner-acceptances.md'))).sort().map(f => {
		const where = `docs/${kind}/${f}`;
		const text = fs.readFileSync(path.join(dir, f), 'utf8');
		if (!/^\d{8}-[a-z0-9]+(-[a-z0-9]+)*\.md$/.test(f)) {
			bad(where, 'name must be YYYYMMDD-short-slug.md');
		}
		const title = /^# (.+)$/m.exec(text)?.[1]?.trim() ?? '';
		if (!title) {
			bad(where, 'missing "# Title"');
		}
		const date = field(text, 'Date').slice(0, 10);
		if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
			bad(where, 'missing "- **Date:** YYYY-MM-DD"');
		} else if (date.replace(/-/g, '') !== f.slice(0, 8)) {
			bad(where, `Date ${date} doesn't match the file name`);
		}
		const status = field(text, 'Status');
		let keyword = '';
		if (kind !== 'security-reviews') {
			keyword = /^(proposed|accepted|deprecated|superseded)/i.exec(status)?.[1]?.toLowerCase() ?? '';
			if (!keyword) {
				bad(where, 'Status must start with proposed | accepted | superseded-by … | deprecated');
			}
		}
		// "superseded-by X" (whole record) or "... is superseded by X" (part of it).
		const supersededBy = /supersed(ed)?[- ]by/i.test(status) ? links(status.slice(status.search(/supersed(ed)?[- ]by/i))) : [];
		const supersedes = links(field(text, 'Supersedes')).concat(/^- \*\*Status:\*\*.*\bsupersedes\b/im.test(text) ? links(status.slice(status.search(/supersedes/i))) : []);
		return { file: f, name: f.replace(/\.md$/, ''), title, date, status, keyword, supersededBy, supersedes, scope: field(text, 'Scope'), open: field(text, 'Open high\\/critical') };
	});
}

const records = Object.fromEntries(KINDS.map(k => [k, readRecords(k)])) as Record<typeof KINDS[number], Rec[]>;
const allRecs = new Map<string, { kind: string; rec: Rec; text: string }>();
for (const k of KINDS) {
	for (const r of records[k]) {
		allRecs.set(r.file, { kind: k, rec: r, text: fs.readFileSync(path.join(repo, 'docs', k, r.file), 'utf8') });
	}
}
// Supersede links must work in both directions.
for (const [file, { kind, rec }] of allRecs) {
	for (const target of rec.supersededBy) {
		const t = allRecs.get(target);
		if (!t) {
			bad(`docs/${kind}/${file}`, `superseded by a missing record ${target}`);
		} else if (!t.text.includes(file)) {
			bad(`docs/${t.kind}/${target}`, `supersedes ${file} but doesn't link back to it`);
		}
	}
	for (const target of rec.supersedes) {
		const t = allRecs.get(target);
		if (!t) {
			bad(`docs/${kind}/${file}`, `supersedes a missing record ${target}`);
		} else if (!/supersed/i.test(t.rec.status) || !t.text.includes(file)) {
			bad(`docs/${t.kind}/${target}`, `is superseded by ${file}, but its Status doesn't say so with a link`);
		}
	}
}

const cell = (s: string) => s.replace(/\|/g, '\\|').replace(/\s+/g, ' ').trim();
function statusCell(r: Rec): string {
	if (r.keyword === 'superseded' || (r.supersededBy.length && r.keyword !== 'accepted')) {
		return `superseded-by ${r.supersededBy.map(b => `[${b.replace(/\.md$/, '')}](${b})`).join(', ')}`;
	}
	return r.keyword + (r.supersededBy.length ? ` (partly superseded by ${r.supersededBy.map(b => `[${b.replace(/\.md$/, '')}](${b})`).join(', ')})` : '');
}
function indexTable(kind: typeof KINDS[number]): string {
	const rows = records[kind];
	if (kind === 'security-reviews') {
		return ['| Date | Review | Scope | Open high/critical |', '|---|---|---|---|',
			...rows.map(r => `| ${r.date} | [${cell(r.title.replace(/^Security review:\s*/i, ''))}](${r.file}) | ${cell(r.scope.replace(/`/g, '') || 'see record').slice(0, 90)} | ${cell(r.open || 'see record')} |`)].join('\n');
	}
	return ['| Date | Record | Status |', '|---|---|---|', ...rows.map(r => `| ${r.date} | [${cell(r.title)}](${r.file}) | ${statusCell(r)} |`)].join('\n');
}
const BEGIN = '<!-- index:begin (generated by build/docs/docs-check.ts write; do not edit) -->';
const END = '<!-- index:end -->';
function regenerate(kind: typeof KINDS[number], write: boolean): void {
	const file = path.join(repo, 'docs', kind, 'README.md');
	let text = fs.readFileSync(file, 'utf8');
	if (write && !text.includes(BEGIN)) {
		// One-time migration: wrap the hand-maintained "| Date |" table in markers.
		const lines = text.split('\n');
		const s = lines.findIndex(l => l.startsWith('| Date |'));
		if (s >= 0) {
			let e = s;
			while (e + 1 < lines.length && lines[e + 1].startsWith('|')) {
				e++;
			}
			lines.splice(s, e - s + 1, BEGIN, ...lines.slice(s, e + 1), END);
			text = lines.join('\n');
			fs.writeFileSync(file, text);
		}
	}
	const a = text.indexOf(BEGIN);
	const b = text.indexOf(END);
	if (a < 0 || b < a) {
		bad(rel(file), `missing index markers (${BEGIN} … ${END})`);
		return;
	}
	const next = `${text.slice(0, a)}${BEGIN}\n${indexTable(kind)}\n${text.slice(b)}`;
	if (next !== text) {
		if (write) {
			fs.writeFileSync(file, next);
		} else {
			bad(rel(file), 'index is stale: run `./seclab docs write`');
		}
	}
}

// ---- 2. links -------------------------------------------------------------------------------

const mdFiles = walk(repo, p => p.endsWith('.md'));
const PIN = /^https:\/\/(?:github\.com\/[^/]+\/[^/]+\/(?:blob|tree|blame|raw)|raw\.githubusercontent\.com\/[^/]+\/[^/]+)\/([^/]+)\//;
for (const f of mdFiles) {
	const text = fs.readFileSync(f, 'utf8').replace(/```[\s\S]*?```/g, '').replace(/`[^`\n]*`/g, ''); // links in code are examples
	const targets = [...text.matchAll(/\]\(([^)\s]+)\)/g), ...text.matchAll(/^\s{0,3}\[[^\]]+\]:\s*(\S+)/gm), ...text.matchAll(/<a\s[^>]*href=["']([^"']+)["']/gi)].map(m => m[1]);
	for (const target of targets) {
		if (/^(https?:|mailto:|#)/.test(target)) {
			const gh = PIN.exec(target);
			if (gh && !/^[0-9a-f]{40}$/.test(gh[1])) {
				bad(rel(f), `GitHub link not pinned to a commit SHA: ${target}`);
			}
			continue;
		}
		const p = path.resolve(path.dirname(f), decodeURIComponent(target.split('#')[0]));
		if (!fs.existsSync(p)) {
			bad(rel(f), `broken relative link: ${target}`);
		}
	}
}

// ---- 3. ARCHITECTURE.md consistency -------------------------------------------------------

const archFile = path.join(repo, 'docs', 'ARCHITECTURE.md');
const arch = fs.readFileSync(archFile, 'utf8');
for (const r of records.adr) {
	const linked = arch.includes(`adr/${r.file}`);
	if (r.keyword === 'accepted' && !linked) {
		bad('docs/ARCHITECTURE.md', `doesn't link accepted ADR ${r.file}`);
	}
	if (r.keyword === 'superseded' && linked) {
		for (const line of arch.split('\n').filter(l => l.includes(`adr/${r.file}`))) {
			if (!/supersed/i.test(line)) {
				bad('docs/ARCHITECTURE.md', `links superseded ADR ${r.file} as current: ${line.trim().slice(0, 100)}`);
			}
		}
	}
}
const treeText = walk(repo, p => !p.endsWith('.md') && !p.includes(`${path.sep}docs${path.sep}`) && fs.statSync(p).size < 1 << 20)
	.map(p => { try { return fs.readFileSync(p, 'utf8'); } catch { return ''; } }).join('\n');
for (const name of new Set([...arch.matchAll(/`(seclab-[a-z][a-z-]*[a-z])`/g)].map(m => m[1]))) {
	if (!treeText.includes(name)) {
		bad('docs/ARCHITECTURE.md', `names component \`${name}\`, which doesn't exist in the tree`);
	}
}

// ---- modes ----------------------------------------------------------------------------------

const [mode, arg] = process.argv.slice(2);
if (mode === 'commands') {
	// Runnable blocks: a fenced ```sh block directly preceded by <!-- ci: run -->. A marker
	// that doesn't introduce such a block, or no blocks at all, fails (no silent skip).
	let blocks = 0;
	for (const f of ['AGENTS.md', 'README.md', 'test/README.md', 'patches/README.md'].map(p => path.join(repo, p)).filter(p => fs.existsSync(p))) {
		const text = fs.readFileSync(f, 'utf8');
		const markers = (text.match(/<!-- ci: run -->/g) ?? []).length;
		const found = [...text.matchAll(/<!-- ci: run -->[ \t]*\r?\n```(?:sh|bash|shell)[ \t]*\r?\n([\s\S]*?)```/g)];
		if (found.length !== markers) {
			console.error(`docs-check: ${rel(f)} has ${markers} "ci: run" marker(s) but ${found.length} runnable block(s) directly after them`);
			process.exit(1);
		}
		for (const m of found) {
			blocks++;
			console.log(`echo '== ${rel(f)}'\nset -e\n${m[1].replace(/\r/g, '')}`);
		}
	}
	if (blocks === 0) {
		console.error('docs-check: no "ci: run" blocks found (AGENTS.md must have at least one)');
		process.exit(1);
	}
	process.exit(0);
}
if (mode === 'paired') {
	const [changedText, trailers = ''] = fs.readFileSync(arg, 'utf8').split('\n--\n');
	const changed = changedText.split('\n').filter(Boolean);
	// Only real git trailers count (the wrapper extracts them with %(trailers:key=...)).
	const trailer = trailers.split('\n').some(l => l.trim().length >= 4);
	// code path -> docs that must change with it
	const PAIRS: Array<[RegExp, RegExp, string]> = [
		[/^tabd\/src\/(supervisor|frames|client|protocol)\.ts$/, /^docs\/tabd\/PROTOCOL\.md$/, 'tabd protocol'],
		[/^tabd\/src\/drivers\//, /^docs\/(adr|edr)\/|^docs\/ARCHITECTURE\.md$/, 'sandbox providers'],
		[/^patches\//, /^docs\/(adr|edr)\/|^patches\/README\.md$/, 'patch queue'],
		[/^build\/product\//, /^docs\/(adr|edr)\//, 'product.json policy'],
		[/^broker\/schema\//, /^docs\/broker-protocol\.md$/, 'broker protocol schema'],
	];
	for (const [code, docs, what] of PAIRS) {
		if (changed.some(c => code.test(c)) && !changed.some(c => docs.test(c)) && !trailer) {
			bad('paired-docs', `${what} changed without its docs (${docs.source}); add them, or a "docs-not-needed: <reason>" commit trailer`);
		}
	}
} else {
	for (const k of KINDS) {
		regenerate(k, mode === 'write');
	}
}
for (const p of problems) {
	console.log(p);
}
console.log(problems.length ? `docs-check: ${problems.length} problem(s)` : `docs-check: ok (${mode ?? 'check'})`);
process.exit(problems.length ? 1 : 0);
