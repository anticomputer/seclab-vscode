// The security findings register (EDR security-findings-register). Review records in
// docs/security-reviews/ are append-only and each round wrote its own shape; this is the one
// current-state view of every finding. Source: docs/security-reviews/findings.json; the
// generated view: docs/security-reviews/FINDINGS.md. No dependencies; runs in a network-less
// node container. Modes:
//   node build/docs/findings.ts check       verify the register against the records (exit 1)
//   node build/docs/findings.ts write       regenerate FINDINGS.md
//   node build/docs/findings.ts commits     print "<key> <commit>" for every landed `fixed`
//                                           entry (the wrapper checks ancestry with git)
//   node build/docs/findings.ts baseline    print the baseline highs (markdown)
//   node build/docs/findings.ts extract [DIR]  print what the extractor finds in DIR (JSON)
//   node build/docs/findings.ts --self-test inject every defect the check claims to catch
// Findings are extracted from the records: every row of a table whose header has a column
// starting "Sev" (anchor: its first cell), every `### CRITICAL|HIGH|MEDIUM|LOW|INFO …` heading
// and every list item that starts with a bold severity (anchor: the heading or bold text). An
// anchor seen before in the same record gets `#n` (its occurrence), so appending a round never
// renames an earlier finding. Shapes the extractor can't read fail (a table with no Sev column,
// an HTML table, an unbalanced code fence, a stray file or directory), and so does a record that
// yields no finding unless the register lists it under `noFindings` (review QQQ-4).
// With --base (the register at the merge base, from git): a finding that is new relative to it
// needs a unique explicit ID (`ABC-1`) and a severity word, and the baseline may only shrink
// (QQQ-5, QQQ-6).

import * as fs from 'node:fs';
import * as path from 'node:path';

const REVIEWS = 'docs/security-reviews';
const REGISTER = `${REVIEWS}/findings.json`;
const VIEW = `${REVIEWS}/FINDINGS.md`;
const SEVS = ['critical', 'high', 'medium', 'low', 'info'] as const;
type Sev = typeof SEVS[number];
const STATUSES = ['fixed', 'fixed-untested', 'accepted-residual', 'deferred', 'open', 'false-positive'] as const;
type Status = typeof STATUSES[number];

interface Extracted { record: string; anchor: string; sevs: Sev[]; round: string; line: number; text: string; placeholder: boolean }
interface Ref { file: string; quote: string }
interface Finding {
	record: string | null; anchor: string; branch?: string; round?: string; severity: Sev; severityNote?: string;
	summary: string; component: string; owner: string; status: Status;
	commit?: string; test?: { file: string; name: string }; acceptedBy?: 'owner' | 'agent'; rationale?: string;
	ref?: Ref; followUp?: string; gap?: string; note?: string; manual?: Ref; wasKey?: string;
}
interface Owner { session: string; branch: string | null; scope: string }
interface Register { $comment?: string; owners: Record<string, Owner>; baseline: string[]; noFindings: string[]; manualOnly: string[]; findings: Finding[] }

// A tiny file view so the self-test can run the real check over an in-memory tree.
interface Tree { exists(p: string): boolean; read(p: string): string; list(dir: string): string[] }
const diskTree = (root: string): Tree => ({
	exists: p => fs.existsSync(path.join(root, p)),
	read: p => fs.readFileSync(path.join(root, p), 'utf8'),
	list: dir => fs.existsSync(path.join(root, dir)) ? fs.readdirSync(path.join(root, dir)).sort() : [],
});

// ---- extraction -------------------------------------------------------------------------------

const PLACEHOLDER = /^(|[-—–]+|\(.*\)|new|self|n\/a|residual)$/i;
const SEV_LEAD = '(?:CRITICAL|HIGH|MEDIUM|LOW|INFO)(?![\\w-])';
// A heading leading with a severity word, in any case, is a finding. A false match (`### Low
// hanging fruit`) only asks for a registration, which is the safe direction (review TTT-4).
const SEV_HEADING = new RegExp(`^\\**${SEV_LEAD}`, 'i');
function sevWords(s: string): Sev[] {
	const out: Sev[] = [];
	for (const m of s.toLowerCase().matchAll(/\b(critical|high|medium|med|low|info|informational)\b/g)) {
		const v = (m[1] === 'med' ? 'medium' : m[1] === 'informational' ? 'info' : m[1]) as Sev;
		if (!out.includes(v)) {
			out.push(v);
		}
	}
	return out;
}
const clean = (s: string) => s.replace(/\*\*/g, '').replace(/`/g, '').replace(/\s+/g, ' ').trim();
function cells(line: string): string[] {
	const t = line.trim().replace(/^\|/, '').replace(/(?<!\\)\|$/, '');
	return t.split(/(?<!\\)\|/).map(c => c.trim());
}
// A GFM delimiter row: `|---|:-:|`, `--- | ---`, one dash or more per cell; it must hold a pipe,
// so a setext underline or thematic break under a line with a `|` isn't a table (SSS-8).
const DELIM = /^\s*\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?\s*$/;
const NO_FINDING = /\b(no (vulnerabilit|finding|issue)|none found|^none\b)/i;
// A record with no finding says so on a line of its own, outside code fences (SSS-5, TTT-4).
const SAYS_NONE = /^\s*(#+\s*)?(findings:?\s*)?(none|no findings|no (vulnerabilities|findings|issues) (found|remain))\.?\s*$/im;
const stripFences = (raw: string) => raw.replace(/^\s*(```|~~~)[^\n]*\n[\s\S]*?^\s*\1[^\n]*$/gm, m => m.replace(/[^\n]/g, ''));

function extract(record: string, text: string): { items: Extracted[]; problems: string[] } {
	const problems: string[] = [];
	const where = (i: number) => `${REVIEWS}/${record}:${i + 1}`;
	const raw = text.replace(/\r\n?/g, '\n');
	if (((raw.match(/^\s*(```|~~~)/gm) ?? []).length) % 2) {
		problems.push(`${REVIEWS}/${record}: unbalanced code fence; the extractor can't tell findings from examples`);
	}
	if (/<table\b/i.test(raw)) {
		problems.push(`${REVIEWS}/${record}: HTML table; findings go in a markdown table with a Sev column`);
	}
	// Fenced code is an example, never a finding; keep line numbers.
	const lines = stripFences(raw).split('\n');
	const out: Extracted[] = [];
	const seen = new Map<string, number>();
	const add = (rawAnchor: string, sevs: Sev[], round: string, i: number, body: string, noIdColumn: boolean) => {
		const base = clean(rawAnchor);
		const n = (seen.get(base) ?? 0) + 1;
		seen.set(base, n);
		out.push({ record, anchor: n === 1 ? base : `${base}#${n}`, sevs, round, line: i + 1, text: body.trim().slice(0, 4000), placeholder: noIdColumn || PLACEHOLDER.test(base) || n > 1 });
	};
	let round = '';
	for (let i = 0; i < lines.length; i++) {
		const l = lines[i];
		const h = /^(#{2,6})\s+(.*)$/.exec(l);
		if (h) {
			if (h[1] === '##') {
				round = clean(h[2]);
			}
			if (h[1].length >= 3 && SEV_HEADING.test(h[2])) {
				let j = i + 1;
				while (j < lines.length && !/^#{1,6}\s/.test(lines[j])) {
					j++;
				}
				add(h[2], sevWords(h[2].split(/[:,(]/)[0]), round, i, lines.slice(i, j).join('\n'), false);
			}
			continue;
		}
		const li = new RegExp(`^\\s*(?:\\d+\\.|[-*+])\\s+\\*\\*(${SEV_LEAD}[^*]*)\\*\\*`, 'i').exec(l);
		if (li) {
			let j = i + 1;
			while (j < lines.length && lines[j].trim() !== '' && !/^\s*(?:\d+\.|[-*+])\s|^#/.test(lines[j])) {
				j++;
			}
			add(li[1], sevWords(li[1].split(/[:,(]/)[0]), round, i, lines.slice(i, j).join('\n'), false);
			continue;
		}
		if (!l.includes('|') || !DELIM.test(lines[i + 1] ?? '') || !/-/.test(lines[i + 1] ?? '') || !(lines[i + 1] ?? '').includes('|')) {
			continue;
		}
		const head = cells(l).map(c => clean(c).toLowerCase());
		const sevIdx = head.findIndex(c => c.startsWith('sev'));
		// A table shaped like findings (an ID column, or a finding/issue column) without a Sev
		// column would hide its rows; other tables (results, inventories) are fine.
		if (sevIdx < 0 && (/^(#|id)$/.test(head[0] ?? '') || head.some(c => /finding|issue|vulnerab/.test(c)))) {
			problems.push(`${where(i)}: a findings table with no Sev column; add one so its rows are registered`);
		}
		let j = i + 2;
		for (; j < lines.length && lines[j].includes('|') && lines[j].trim() !== ''; j++) {
			if (sevIdx < 0) {
				continue;
			}
			const c = cells(lines[j]);
			// "No vulnerabilities found" rows: nothing but dashes around one note that says so.
			const filled = c.filter(x => !/^[-—–\s]*$/.test(clean(x)));
			if (filled.length <= 1 && filled.every(x => NO_FINDING.test(clean(x)))) {
				continue;
			}
			// A Sev-first table has no ID column: its first other cell anchors the row (TTT-9).
			add(sevIdx === 0 ? (c[1] ?? '') : c[0], sevWords(c[sevIdx] ?? ''), round, j, lines[j], sevIdx === 0);
		}
		i = j - 1;
	}
	return { items: out, problems };
}

const KNOWN_FILES = new Set(['README.md', 'FINDINGS.md', 'findings.json', 'owner-acceptances.md']);
const IGNORED_DOTFILES = new Set(['.DS_Store', '.gitkeep', '.gitignore']);
const isRecordName = (f: string) => /^\d{8}-[a-z0-9]+(-[a-z0-9]+)*\.md$/.test(f);
function recordFiles(tree: Tree): string[] {
	return tree.list(REVIEWS).filter(isRecordName);
}

// ---- schema -----------------------------------------------------------------------------------

const keyOf = (f: Finding) => `${f.record ?? 'register'}#${f.anchor}`;
const FIELDS = new Set(['record', 'anchor', 'branch', 'round', 'severity', 'severityNote', 'summary', 'component', 'owner', 'status', 'commit', 'test', 'acceptedBy', 'rationale', 'ref', 'followUp', 'gap', 'note', 'manual', 'wasKey']);
const nonEmpty = (v: unknown) => typeof v === 'string' && v.trim().length > 0;
const isRef = (v: unknown): v is Ref => !!v && typeof v === 'object' && nonEmpty((v as Ref).file) && nonEmpty((v as Ref).quote) && Object.keys(v).every(k => k === 'file' || k === 'quote');
// Cited paths are repo-relative and plain (they're rendered into links), and never the register
// or its view, which would let an entry cite itself (review QQQ-2).
const SELF = new Set([REGISTER, VIEW]);
function pathProblem(p: string): string | undefined {
	if (!/^[A-Za-z0-9._@+-]+(\/[A-Za-z0-9._@+-]+)*$/.test(p) || p.split('/').some(s => s === '..' || s === '.')) {
		return `${p} must be a plain repo-relative path`;
	}
	return SELF.has(p) ? `${p} is the register itself; cite the record, ADR, EDR or test` : undefined;
}
// A regression test lives in a test file, or is a case inside a checker's own self-test: the
// `selfTest`/`self_test` function or the top-level `--self-test` branch, up to where it ends
// (QQQ-3, SSS-3, TTT-3). A mention of --self-test in a header doesn't make the file a test.
// Docs and workflows are never tests.
const TEST_PATH = /(^|\/)(test|tests)\/|\.test\.(ts|mts|js|mjs)$|(^|\/)test_[^/]+\.py$|_test\.py$/;
const NOT_A_TEST = /\.md$|^docs\/|^\.github\//;
// Exact self-test identifiers only (`selfTestRegions` isn't one), and a brace or `fi` region must
// end: one that runs to EOF is discarded, except Python's, which ends by indentation (UUU-5).
const SELF_TEST_START: Array<[RegExp, RegExp, boolean]> = [
	[/^(export\s+)?(async\s+)?function\s+selfTest\s*\(/, /^\}/, false], // TS/JS function
	[/^if\s*\(.*--self-test.*\{\s*$/, /^\}/, false], // TS/JS top-level branch
	[/^def\s+self_test\s*\(/, /^[^\s#]/, true], // Python function: ends at the next top-level line
	[/^(\w+_)?self_test\s*\(\)\s*\{/, /^\}/, false], // shell function
	[/^if\s+\[.*--self-test.*\];?\s*then/, /^fi\b/, false], // shell top-level branch
];
// Block comments (TS/JS) and triple-quoted strings (Python) that start a line can't open or close
// a region: they're blanked (newlines and offsets kept) before starts and ends are looked for
// (VVV-5). Only line-leading ones, so a `/*` inside a string literal can't blank a region's end
// (WWW-4). Names are still matched in the real text: a test name is usually a string.
const blank = (m: string) => m.replace(/[^\n]/g, ' ');
const maskForRegions = (text: string, file: string) => /\.py$/.test(file) ? text.replace(/^[ \t]*("""|''')[\s\S]*?\1/gm, blank)
	: /\.(m?[jt]s)$/.test(file) ? text.replace(/^[ \t]*\/\*[\s\S]*?\*\//gm, blank) : text;
function selfTestRegions(text: string, file: string): Array<[number, number]> {
	const lines = maskForRegions(text, file).split('\n');
	const offsets: number[] = [];
	lines.reduce((o, l) => (offsets.push(o), o + l.length + 1), 0);
	const out: Array<[number, number]> = [];
	for (let i = 0; i < lines.length; i++) {
		const kind = SELF_TEST_START.find(([start]) => start.test(lines[i]));
		if (kind) {
			let j = i + 1;
			while (j < lines.length && !kind[1].test(lines[j])) {
				j++;
			}
			if (j < lines.length || kind[2]) {
				out.push([offsets[i], j < lines.length ? offsets[j] : text.length]);
			}
			i = j;
		}
	}
	return out;
}
function testProblem(file: string, text: string, name: string): string | undefined {
	if (NOT_A_TEST.test(file)) {
		return `${file} is a doc or a workflow, not a test; cite the test, or mark the entry fixed-untested`;
	}
	if (TEST_PATH.test(file)) {
		return undefined;
	}
	const at = text.indexOf(name);
	return selfTestRegions(text, file).some(([a, b]) => at >= a && at + name.length <= b) ? undefined
		: `${file} is neither a test file nor has this case inside its self-test; cite the test, or mark the entry fixed-untested`;
}
const MIN_TEST_NAME = 12;
// An owner acceptance is a row in OWNER_FILE, written by the coordinator on an explicit owner
// decision: the finding's full key, the date, the scope, the closing condition and "accepted by
// the project owner". No quote of any conversation: committed records never capture one.
const OWNER_FILE = `${REVIEWS}/owner-acceptances.md`;
const OWNER_DECISION = 'accepted by the project owner';
const FP_REF = /^docs\/security-reviews\/\d{8}-[a-z0-9-]+\.md$/;
// Commit citations the register itself makes (review YYY): every fix commit, whatever its shape,
// and hex runs in its own prose and component. Each must be a commit on HEAD's history or main's,
// or on the one origin branch the entry names (`branch`, else its owner's declared branch) (checked on the host, which resolves
// the object itself so no ref can shadow it). Nothing is tolerated by hand. The only exemptions
// are fixed rules: a prefix of the pinned upstream Code-OSS commit (upstream.lock) in prose, and a
// round label's token that its record carries verbatim (the record's own historical citation;
// records are append-only), listed in FINDINGS.md. Quotes and test names copy committed text
// verbatim (their presence is checked) and aren't the register's citations.
const SHA_PROSE = ['note', 'gap', 'followUp', 'rationale', 'summary', 'severityNote', 'component'] as const;
const HEX_RUN = /(?<![0-9A-Za-z_])[0-9A-Fa-f]{7,}(?![0-9A-Za-z_])/g;
const DATE8 = /^20\d\d(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])$/;
interface Citation { token: string; tolerated: boolean; branch: string | null; touched: boolean; use: string }
interface Citations { cite: Citation[]; historical: Array<{ token: string; use: string }>; problems: string[] }
function upstreamSha(tree: Tree): string | undefined {
	const m = tree.exists('upstream.lock') ? /^UPSTREAM_SHA=([0-9a-f]{40})\s*$/m.exec(tree.read('upstream.lock')) : null;
	return m?.[1];
}
// The branch an entry's work lives on until it lands: its own, else its owner's declared one.
const entryBranch = (reg: Register, f: Finding): string | null => f.branch ?? reg.owners[f.owner]?.branch ?? null;
// An entry this change adds or modifies, relative to the base register (no base: every entry).
// Only such an entry's citations must resolve; a citation that rotted in an untouched entry, when
// another session's branch rebased, is a warning, not this change's failure (review ZZZ).
// An entry's resolution scope counts as part of it: an owner's branch that changed touches every
// entry inheriting it (ZZZ-1).
function touchedKeys(reg: Register, base?: Register): Set<string> {
	const was = new Map((base?.findings ?? []).map(f => [keyOf(f), f]));
	return new Set(reg.findings.filter(f => {
		const w = base ? was.get(keyOf(f)) : undefined;
		return !base || !w || JSON.stringify(w) !== JSON.stringify(f) || entryBranch(base, w) !== entryBranch(reg, f);
	}).map(keyOf));
}
function citations(tree: Tree, reg: Register, base?: Register): Citations {
	const out: Citations = { cite: [], historical: [], problems: [] };
	const up = upstreamSha(tree);
	const touched = touchedKeys(reg, base);
	const seen = new Map<string, Citation>();
	const add = (c: Citation) => {
		const k = `${c.token}\t${c.tolerated}\t${c.branch}`;
		const had = seen.get(k);
		if (!had) {
			seen.set(k, c);
			out.cite.push(c);
		} else if (c.touched && !had.touched) {
			had.touched = true;
			had.use = c.use;
		}
	};
	for (const f of reg.findings) {
		const branch = entryBranch(reg, f);
		const t0 = touched.has(keyOf(f));
		if (typeof f.commit === 'string') {
			add({ token: f.commit.toLowerCase(), tolerated: false, branch, touched: t0, use: `${keyOf(f)} commit` });
		}
		const recText = f.record && tree.exists(`${REVIEWS}/${f.record}`) ? tree.read(`${REVIEWS}/${f.record}`) : undefined;
		for (const k of ['round', ...SHA_PROSE] as const) {
			const v = (f as unknown as Record<string, unknown>)[k];
			for (const raw of typeof v === 'string' ? v.match(HEX_RUN) ?? [] : []) {
				const t = raw.toLowerCase();
				const use = `${keyOf(f)} ${k}`;
				if (t.length > 40) {
					out.problems.push(`${use}: a hex run of ${t.length} characters isn't a commit citation; quote a digest in a ref, not in prose`);
				} else if (/^[0-9]+$/.test(t) && DATE8.test(t)) {
					continue;
				} else if (k === 'round' && recText !== undefined && new RegExp(`(?<![0-9A-Za-z_])${raw}(?![0-9A-Za-z_])`).test(recText)) {
					out.historical.push({ token: t, use });
				} else {
					add({ token: t, tolerated: !!up && up.startsWith(t), branch, touched: t0, use });
				}
			}
		}
	}
	return out;
}

// `./seclab findings remap --branch B`: the host finds each rotted citation's equivalent on B and
// passes "<old>\t<new>" pairs; only B's entries are rewritten (fix commits and prose, never a
// round label, which is its record's own), and each old token must be a whole hex run.
function remapBranch(reg: Register, branch: string, pairs: Array<[string, string]>): { reg: Register; changed: string[] } {
	const changed: string[] = [];
	const ok = (t: string) => /^[0-9a-f]{7,40}$/.test(t);
	const map = new Map(pairs.filter(([o, n]) => ok(o) && ok(n)));
	const swap = (v: string) => v.replace(HEX_RUN, m => map.get(m.toLowerCase()) ?? m);
	for (const f of reg.findings) {
		if (entryBranch(reg, f) !== branch) {
			continue;
		}
		for (const k of ['commit', ...SHA_PROSE] as const) {
			const rec = f as unknown as Record<string, unknown>;
			const v = rec[k];
			if (typeof v === 'string' && swap(v) !== v) {
				rec[k] = swap(v);
				changed.push(`${keyOf(f)} ${k}`);
			}
		}
	}
	return { reg, changed };
}

function schemaProblems(reg: Register): string[] {
	const p: string[] = [];
	if (!reg || typeof reg !== 'object' || !Array.isArray(reg.findings) || !Array.isArray(reg.baseline) || !Array.isArray(reg.noFindings) || !Array.isArray(reg.manualOnly) || !reg.owners || typeof reg.owners !== 'object') {
		return ['register must have owners {}, baseline [], noFindings [], manualOnly [] and findings []'];
	}
	for (const k of Object.keys(reg)) {
		if (!['$comment', 'owners', 'baseline', 'noFindings', 'manualOnly', 'findings'].includes(k)) {
			p.push(`unknown top-level field ${k}`);
		}
	}
	for (const r of [...reg.noFindings, ...reg.manualOnly]) {
		if (typeof r !== 'string' || !isRecordName(r)) {
			p.push(`noFindings/manualOnly: ${String(r)} is not a review record name`);
		}
	}
	const BRANCH = /^[A-Za-z0-9._/-]+$/;
	for (const [id, o] of Object.entries(reg.owners)) {
		if (!nonEmpty(o?.session) || !nonEmpty(o?.scope) || !(o.branch === null || (typeof o.branch === 'string' && BRANCH.test(o.branch)))) {
			p.push(`owner ${id}: needs session, scope and branch (a branch name or null)`);
		}
	}
	const keys = new Set<string>();
	reg.findings.forEach((f, i) => {
		const at = `findings[${i}]${nonEmpty(f?.anchor) ? ` (${keyOf(f)})` : ''}`;
		if (!f || typeof f !== 'object') {
			p.push(`${at}: not an object`);
			return;
		}
		for (const k of Object.keys(f)) {
			if (!FIELDS.has(k)) {
				p.push(`${at}: unknown field ${k}`);
			}
		}
		if (!(f.record === null || (typeof f.record === 'string' && /^\d{8}-[a-z0-9-]+\.md$/.test(f.record)))) {
			p.push(`${at}: record must be a review file name, or null (an incident or residual recorded elsewhere)`);
		}
		for (const k of ['anchor', 'summary', 'component', 'owner'] as const) {
			if (!nonEmpty(f[k])) {
				p.push(`${at}: ${k} is required`);
			}
		}
		if (!SEVS.includes(f.severity)) {
			p.push(`${at}: severity must be one of ${SEVS.join(', ')}`);
		}
		if (!STATUSES.includes(f.status)) {
			p.push(`${at}: status must be one of ${STATUSES.join(', ')}`);
		}
		if (nonEmpty(f.owner) && !reg.owners[f.owner]) {
			p.push(`${at}: unknown owner ${f.owner}`);
		}
		if (f.branch !== undefined && !(typeof f.branch === 'string' && BRANCH.test(f.branch))) {
			p.push(`${at}: branch must be a branch name`);
		}
		if (f.commit !== undefined && !/^[0-9a-f]{7,40}$/.test(f.commit)) {
			p.push(`${at}: commit must be a hex SHA`);
		}
		for (const k of ['ref', 'manual'] as const) {
			if (f[k] !== undefined && !isRef(f[k])) {
				p.push(`${at}: ${k} must be { file, quote }`);
			} else if (f[k]) {
				const pp = pathProblem(f[k]!.file);
				if (pp) {
					p.push(`${at}: ${k}: ${pp}`);
				}
			}
		}
		if (f.test && typeof f.test === 'object' && nonEmpty(f.test.file) && nonEmpty(f.test.name)) {
			const pp = pathProblem(f.test.file);
			if (pp) {
				p.push(`${at}: test: ${pp}`);
			}
			if (f.test.name.trim().length < MIN_TEST_NAME) {
				p.push(`${at}: test.name must be at least ${MIN_TEST_NAME} characters, enough to name one case`);
			}
		}
		if (f.status === 'false-positive' && f.ref && f.acceptedBy !== 'owner' && !FP_REF.test(f.ref.file)) {
			p.push(`${at}: a false positive cites the review record that concluded it (or is the owner's decision)`);
		}
		if (f.record === null && !f.ref) {
			p.push(`${at}: an entry with no review record needs ref { file, quote } naming where it is recorded`);
		}
		switch (f.status) {
			case 'fixed':
				if (!f.commit || !f.test || !nonEmpty(f.test.file) || !nonEmpty(f.test.name)) {
					p.push(`${at}: fixed needs commit and test { file, name } (no test: fixed-untested)`);
				}
				break;
			case 'fixed-untested':
				if (!nonEmpty(f.gap)) {
					p.push(`${at}: fixed-untested needs gap (the missing regression test)`);
				}
				break;
			case 'accepted-residual':
				if (f.acceptedBy !== 'owner' && f.acceptedBy !== 'agent') {
					p.push(`${at}: accepted-residual needs acceptedBy owner|agent`);
				}
				// The owner's acceptance is its row in owner-acceptances.md; an agent's cites a record.
				if (!nonEmpty(f.rationale) || (f.acceptedBy === 'agent' && !f.ref)) {
					p.push(`${at}: accepted-residual needs rationale, and ref { file, quote } when an agent accepted it`);
				}
				break;
			case 'deferred':
				if (!nonEmpty(f.followUp)) {
					p.push(`${at}: deferred needs followUp`);
				}
				break;
			case 'open':
				if (!nonEmpty(f.gap)) {
					p.push(`${at}: open needs gap (what is missing)`);
				}
				break;
			case 'false-positive':
				if (!nonEmpty(f.rationale) || (f.acceptedBy !== 'owner' && !f.ref)) {
					p.push(`${at}: false-positive needs rationale, and ref { file, quote } unless the owner decided it`);
				}
				break;
		}
		if (f.status !== 'accepted-residual' && f.status !== 'false-positive' && f.acceptedBy !== undefined) {
			p.push(`${at}: acceptedBy only applies to accepted-residual and false-positive`);
		}
		if (f.status === 'false-positive' && f.acceptedBy !== undefined && f.acceptedBy !== 'owner') {
			p.push(`${at}: a false positive's acceptedBy can only be owner`);
		}
		if (f.wasKey !== undefined && !(typeof f.wasKey === 'string' && /^[^#\s]+#\S/.test(f.wasKey))) {
			p.push(`${at}: wasKey must be the finding's earlier key (record#anchor)`);
		}
		if (f.status !== 'fixed' && f.test !== undefined) {
			p.push(`${at}: test only applies to fixed`);
		}
		if (nonEmpty(f.anchor)) {
			const k = keyOf(f);
			if (keys.has(k)) {
				p.push(`${at}: duplicate key`);
			}
			keys.add(k);
		}
	});
	const seenBase = new Set<string>();
	for (const b of reg.baseline) {
		if (typeof b !== 'string' || seenBase.has(b)) {
			p.push(`baseline: ${String(b)} is not a unique key`);
		}
		seenBase.add(b);
	}
	return p;
}

// ---- the check --------------------------------------------------------------------------------

const RANK: Record<Sev, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const isHigh = (f: Finding) => RANK[f.severity] >= RANK.high;
// An entry on a branch is never compliant: its evidence isn't on this tree (review QQQ-1).
function compliant(f: Finding): boolean {
	return !f.branch && (f.status === 'fixed'
		|| (f.status === 'accepted-residual' && f.acceptedBy === 'owner')
		|| (f.status === 'false-positive' && (f.acceptedBy === 'owner' || (!!f.ref && FP_REF.test(f.ref.file)))));
}
const normWs = (s: string) => s.replace(/\s+/g, ' ').trim();
// owner-acceptances.md: one markdown table, `| Finding | Date | Scope | Closing condition |
// Decision |`, one row per accepted finding, keyed by its full key (exact cell match, so `#2`
// isn't `#2.1` and an ID two records share is never ambiguous; a `|` in a key is written `\|`).
// Quotation marks are refused outside the key cell: the file states decisions, it never quotes a
// conversation. That scan is a tripwire for the obvious form only; the rule is no conversation
// content at all (XXX-3). The file must render exactly what the gate reads, since review of the
// rendered file is the control (XXX-1): no HTML, comments, fences, blockquotes or indented
// tables, one header, and no table line outside it.
interface OwnerRow { date: string; scope: string; closing: string; line: number }
const OWNER_HEAD = /^\|\s*Finding\s*\|\s*Date\s*\|\s*Scope\s*\|\s*Closing condition\s*\|\s*Decision\s*\|\s*$/;
const QUOTES = /["“”«»„‘’‚‹›＂]/;
function parseOwnerFile(text: string): { rows: Map<string, OwnerRow>; problems: string[] } {
	const rows = new Map<string, OwnerRow>();
	const problems: string[] = [];
	const at = (i: number) => `${OWNER_FILE}:${i + 1}`;
	const lines = text.replace(/\r\n?/g, '\n').split('\n');
	const heads = lines.flatMap((l, i) => OWNER_HEAD.test(l) ? [i] : []);
	const head = heads.length === 1 ? heads[0] : -1;
	if (heads.length > 1) {
		problems.push(`${OWNER_FILE}: ${heads.length} acceptance tables; there is exactly one`);
	}
	let end = head;
	if (head >= 0 && DELIM.test(lines[head + 1] ?? '') && cells(lines[head + 1]).length === 5) {
		end = head + 2;
		while (end < lines.length && lines[end].startsWith('|')) {
			end++;
		}
	} else if (heads.length <= 1) {
		problems.push(`${OWNER_FILE}: needs the table | Finding | Date | Scope | Closing condition | Decision |`);
	}
	lines.forEach((l, i) => {
		const inRows = head >= 0 && i >= head + 2 && i < end;
		if (/<!--|-->|<\/?[A-Za-z]|^\s*(```|~~~)|^\s*>/.test(l)) {
			problems.push(`${at(i)}: HTML, a comment, a fence or a blockquote; the file must render exactly what the gate reads`);
		}
		if (!inRows && i !== head && i !== head + 1 && /^\s*\|/.test(l)) {
			problems.push(`${at(i)}: a table line outside the one acceptance table`);
		}
		if (QUOTES.test(inRows ? cells(l).slice(1).join('|') : l)) {
			problems.push(`${at(i)}: quotation marks; an acceptance states the decision, it never quotes a conversation`);
		}
	});
	for (let i = head + 2; head >= 0 && i < end; i++) {
		const c = cells(lines[i]).map(x => x.replace(/^`|`$/g, '').trim());
		c[0] = (c[0] ?? '').replace(/\\\|/g, '|');
		const [key, date, scope, closing, decision] = c;
		if (c.length !== 5 || !/^\d{4}-\d{2}-\d{2}$/.test(date ?? '') || !nonEmpty(scope) || !nonEmpty(closing) || decision !== OWNER_DECISION) {
			problems.push(`${at(i)}: a row is | record.md#anchor | YYYY-MM-DD | scope | closing condition | ${OWNER_DECISION} |`);
		} else if (rows.has(key)) {
			problems.push(`${at(i)}: ${key} has a row already`);
		} else {
			rows.set(key, { date, scope, closing, line: i + 1 });
		}
	}
	return { rows, problems };
}
// What the change under check writes (from git): the files, and their text at the base. An owner
// acceptance closes a high only once its row has landed, in an earlier change than the closure
// (UUU-4); an unrelated later edit to the file doesn't reopen it (VVV-3). `ownerBefore` is the
// owner file at the base whatever the changed list says (null: absent there): "touched" is decided
// by content, so a path the list doesn't name (a symlink) can't hide an edit (XXX-7).
interface Change { files: Set<string>; before: Map<string, string>; ownerBefore?: string | null }
interface Ctx { change?: Change; owner?: Map<string, OwnerRow> }
// The row that accepts f: under its key, or under its validated wasKey while a rename lands (XXX-5).
function ownerRowKey(f: Finding, rows: Map<string, OwnerRow> | undefined): string | undefined {
	return rows?.has(keyOf(f)) ? keyOf(f) : f.wasKey && rows?.has(f.wasKey) ? f.wasKey : undefined;
}
function ownerRowLanded(tree: Tree, f: Finding, change?: Change): boolean {
	if (!change) {
		return true;
	}
	const now = tree.exists(OWNER_FILE) ? tree.read(OWNER_FILE) : null;
	const before = change.ownerBefore !== undefined ? change.ownerBefore : change.before.get(OWNER_FILE) ?? null;
	const touched = change.files.has(OWNER_FILE) || (change.ownerBefore !== undefined && before !== now);
	if (!touched) {
		return true;
	}
	const rows = before === null ? undefined : parseOwnerFile(before).rows;
	return ownerRowKey(f, rows) !== undefined;
}
function compliantIn(tree: Tree, f: Finding, ctx: Ctx = {}): boolean {
	if (!compliant(f) || f.status === 'fixed' || !isHigh(f)) {
		return compliant(f);
	}
	// A high is closed by the owner, never by an agent: its row is in the file, and landed first.
	return f.acceptedBy === 'owner' && ownerRowKey(f, ctx.owner) !== undefined && ownerRowLanded(tree, f, ctx.change);
}
function refProblem(tree: Tree, r: Ref, what: string): string | undefined {
	if (!tree.exists(r.file)) {
		return `${what} file ${r.file} doesn't exist`;
	}
	const norm = (s: string) => s.replace(/\s+/g, ' ');
	return norm(tree.read(r.file)).includes(norm(r.quote)) ? undefined : `${what} quote not found in ${r.file}: "${r.quote.slice(0, 80)}"`;
}

function check(tree: Tree, reg: Register, renderedView?: string, base?: Register, change?: Change): string[] {
	const p = schemaProblems(reg);
	if (p.length) {
		return p;
	}
	const byKey = new Map(reg.findings.map(f => [keyOf(f), f]));
	const inTree = new Set(recordFiles(tree));
	for (const f of tree.list(REVIEWS)) {
		// Known housekeeping dotfiles only; anything else, dotted or not, must be a record (SSS-8, TTT-8).
		if (!IGNORED_DOTFILES.has(f) && !KNOWN_FILES.has(f) && !isRecordName(f)) {
			p.push(`${REVIEWS}/${f}: unexpected entry; records are ${REVIEWS}/YYYYMMDD-slug.md (no subdirectories)`);
		}
	}
	const baseKeys = base ? new Set(base.findings.map(keyOf)) : undefined;
	const extracted = new Map<string, Extracted>();
	const yielded = new Set<string>();
	for (const file of inTree) {
		const { items, problems } = extract(file, tree.read(`${REVIEWS}/${file}`));
		p.push(...problems);
		for (const e of items) {
			const k = `${file}#${e.anchor}`;
			extracted.set(k, e);
			yielded.add(file);
			// New since the merge base: an explicit unique ID and a severity word (QQQ-5, QQQ-7).
			if (baseKeys && !baseKeys.has(k)) {
				if (e.placeholder || !/^[A-Z][A-Z0-9]*-\d+[a-z]?$/.test(e.anchor)) {
					p.push(`${REVIEWS}/${file}:${e.line}: new finding "${e.anchor}" needs a unique explicit ID (ROUND-n) in a findings table`);
				}
				if (!e.sevs.length) {
					p.push(`${REVIEWS}/${file}:${e.line}: new finding "${e.anchor}" needs a severity (Critical, High, Medium, Low or Info)`);
				}
			}
		}
	}
	const manualFor = new Set<string>();
	for (const f of reg.findings) {
		if (f.record !== null && f.manual) {
			manualFor.add(f.record);
		}
	}
	// A record yields findings the extractor reads, or is listed: `manualOnly` (its findings are
	// prose, registered by hand; no new record may join) or `noFindings` (the record must say it
	// has none) (SSS-5).
	for (const file of inTree) {
		if (yielded.has(file)) {
			continue;
		}
		if (manualFor.has(file) ? !reg.manualOnly.includes(file) : !reg.noFindings.includes(file)) {
			p.push(`${REVIEWS}/${file}: no finding the extractor can read; ${manualFor.has(file) ? 'list it under manualOnly (its findings are registered by hand)' : 'register its findings, or list it under noFindings if it says it has none'}`);
		}
	}
	for (const [list, name] of [[reg.noFindings, 'noFindings'], [reg.manualOnly, 'manualOnly']] as const) {
		for (const file of list) {
			if (yielded.has(file)) {
				p.push(`${name}: ${file} has extracted findings; remove it`);
			} else if (!inTree.has(file)) {
				p.push(`${name}: ${file} is not in ${REVIEWS}`);
			} else if (name === 'noFindings' && (manualFor.has(file) || !SAYS_NONE.test(stripFences(tree.read(`${REVIEWS}/${file}`))))) {
				p.push(`noFindings: ${file} doesn't say it has no findings${manualFor.has(file) ? ' (it has manual entries)' : ''}`);
			} else if (name === 'manualOnly' && !manualFor.has(file)) {
				p.push(`manualOnly: ${file} has no manual entries`);
			}
			if (name === 'manualOnly' && base && base.findings.length && !(base.manualOnly ?? []).includes(file)) {
				p.push(`manualOnly: ${file} is new since the merge base; a new record puts its findings in a table (README)`);
			}
		}
	}
	for (const [k, e] of extracted) {
		const f = byKey.get(k);
		if (!f) {
			p.push(`${REVIEWS}/${e.record}:${e.line}: finding "${e.anchor}" is not in the register (${REGISTER})`);
		} else if (f.branch) {
			continue; // its record is here: reported below as "drop branch"
		} else if (!e.sevs.length && !nonEmpty(f.severityNote)) {
			p.push(`${k}: the record gives no severity word, so the register's ${f.severity} needs a severityNote saying why (SSS-6)`);
		} else if (e.sevs.length && !e.sevs.includes(f.severity) && !(RANK[f.severity] > Math.max(...e.sevs.map(s => RANK[s])))) {
			p.push(`${k}: severity ${f.severity} isn't what the record says (${e.sevs.join('/')}); a register may raise a severity, never lower it`);
		} else if (e.sevs.length > 1 && f.severity !== e.sevs.reduce((a, b) => RANK[a] >= RANK[b] ? a : b) && !nonEmpty(f.severityNote)) {
			p.push(`${k}: the record gives ${e.sevs.join('/')}; below the highest needs severityNote`);
		}
	}
	// Everything an entry cites must be on this tree. An entry for a branch-only record (or one
	// citing branch-only text) is held to it when it lands: as soon as its record finding (or,
	// with no record, its ref) is on this tree it must drop `branch`, and then every citation is
	// checked (QQQ-1). Until then a branch entry can't satisfy the ratchet (`compliant`).
	for (const f of reg.findings) {
		const k = keyOf(f);
		const missing: string[] = [];
		let landed = false;
		if (f.record !== null) {
			if (f.manual) {
				if (f.manual.file !== `${REVIEWS}/${f.record}`) {
					p.push(`${k}: manual.file must be the record`);
				} else if (!inTree.has(f.record)) {
					missing.push(`record ${f.record} is not in ${REVIEWS}`);
				} else {
					const r = refProblem(tree, f.manual, 'manual');
					if (r) {
						missing.push(r);
					} else {
						landed = true;
					}
				}
			} else if (!extracted.has(k)) {
				missing.push(inTree.has(f.record) ? 'stale; the record has no such finding (extracted anchors only, or use manual)' : `record ${f.record} is not in ${REVIEWS}`);
			} else {
				landed = true;
			}
		}
		if (f.status === 'fixed' && f.test) {
			if (!tree.exists(f.test.file)) {
				missing.push(`regression test file ${f.test.file} doesn't exist`);
			} else {
				const text = tree.read(f.test.file);
				const n = text.split(f.test.name).length - 1;
				if (n === 0) {
					missing.push(`regression test "${f.test.name}" not found in ${f.test.file}`);
				} else if (n > 1) {
					missing.push(`regression test "${f.test.name}" occurs ${n} times in ${f.test.file}; name one case`);
				}
				const tp = testProblem(f.test.file, text, f.test.name);
				if (tp) {
					missing.push(tp);
				}
			}
		}
		if (f.ref) {
			const m = refProblem(tree, f.ref, 'ref');
			if (m) {
				missing.push(m);
			} else if (f.record === null) {
				landed = true;
			}
		}
		if (!f.branch) {
			missing.forEach(m => p.push(`${k}: ${m}`));
		} else if (landed) {
			p.push(`${k}: its ${f.record === null ? 'ref' : 'record finding'} is on this tree now; drop "branch" (${f.branch}) and bring its evidence with it`);
		}
	}
	// The ratchet: a high or critical is fixed, accepted by the user, or a reviewed false
	// positive, the last two by name (SSS-4). Today's exceptions sit in the baseline, which only
	// shrinks. With --base, the merge base's register is conserved: a key it had can't add to the
	// baseline, vanish, drop in severity, or leave the baseline while still open (QQQ-6, SSS-1).
	const baseline = new Set(reg.baseline);
	// wasKey (TTT-6, UUU-2, UUU-3): a moved finding names the key it had. That key must be gone
	// from this register, named by one entry only, and in the merge base's register; the entry
	// claiming it must itself be new since the base. So wasKey can't hide a live finding, launder
	// a removal onto an unrelated compliant entry, or carry a new high into the baseline.
	const baseKeySet = base ? new Set(base.findings.map(keyOf)) : undefined;
	const claims = new Map<string, Finding[]>();
	for (const f of reg.findings) {
		if (f.wasKey) {
			claims.set(f.wasKey, [...(claims.get(f.wasKey) ?? []), f]);
		}
	}
	const moved = new Map<string, Finding>();
	for (const [w, fs_] of claims) {
		const where = `wasKey ${w}`;
		if (fs_.length > 1) {
			p.push(`${where}: claimed by ${fs_.length} entries (${fs_.map(keyOf).join(', ')}); a finding moves once`);
		} else if (byKey.has(w)) {
			p.push(`${where}: that finding still exists; wasKey names a finding that moved away`);
		} else if (baseKeySet && !baseKeySet.has(w)) {
			p.push(`${where}: not in the merge base's register`);
		} else if (baseKeySet && baseKeySet.has(keyOf(fs_[0]))) {
			p.push(`${where}: ${keyOf(fs_[0])} was already in the merge base's register, so it isn't the moved finding`);
		} else {
			// A move keeps the finding: same summary, component and owner as the base entry (VVV-2),
			// so a new finding can't take a deleted one's place in the register or the baseline.
			const was = base?.findings.find(bf => keyOf(bf) === w);
			if (was && (was.summary !== fs_[0].summary || was.component !== fs_[0].component || was.owner !== fs_[0].owner)) {
				p.push(`${where}: ${keyOf(fs_[0])} isn't the same finding (a move keeps summary, component and owner)`);
			} else {
				moved.set(w, fs_[0]);
			}
		}
	}
	// The owner's acceptances: rows must parse and name a registered finding (or one's validated
	// wasKey while a rename lands: XXX-5), and each owner entry has its row. A row may precede its
	// entry's acceptedBy owner: that is the required order (the row first, the closure later).
	const ownerParsed = tree.exists(OWNER_FILE) ? parseOwnerFile(tree.read(OWNER_FILE)) : { rows: new Map<string, OwnerRow>(), problems: [] };
	p.push(...ownerParsed.problems);
	for (const [k, row] of ownerParsed.rows) {
		if (!byKey.has(k) && !reg.findings.some(f => f.wasKey === k && moved.get(k) === f)) {
			p.push(`${OWNER_FILE}:${row.line}: ${k} isn't in the register`);
		}
	}
	for (const f of reg.findings) {
		if (f.acceptedBy === 'owner' && ownerRowKey(f, ownerParsed.rows) === undefined) {
			p.push(`${keyOf(f)}: acceptedBy owner, but ${OWNER_FILE} has no row for it`);
		}
	}
	// Citation shapes the host can't judge (an over-long hex run) fail here (YYY-1).
	p.push(...citations(tree, reg).problems);
	const ctx: Ctx = { change, owner: ownerParsed.rows };
	for (const b of reg.baseline) {
		const f = byKey.get(b);
		if (!f) {
			p.push(`baseline: ${b} has no register entry`);
		} else if (!isHigh(f)) {
			p.push(`baseline: ${b} is ${f.severity}; only high/critical belong in the baseline`);
		} else if (compliantIn(tree, f, ctx)) {
			p.push(`baseline: ${b} is ${f.status}${f.acceptedBy ? ` (${f.acceptedBy})` : ''} now; remove it from the baseline`);
		}
		if (base && !base.baseline.includes(b) && !(f?.wasKey && moved.get(f.wasKey) === f && base.baseline.includes(f.wasKey))) {
			p.push(`baseline: ${b} is new; the baseline only shrinks (fix it with a test, or get the owner's acceptance)`);
		}
	}
	if (base) {
		for (const bf of base.findings) {
			const k = keyOf(bf);
			const f = byKey.get(k) ?? moved.get(k);
			if (!f) {
				p.push(`${k}: in the merge base's register but gone; a finding is never removed (records are append-only; a moved finding names its earlier key in wasKey)`);
			} else if (SEVS.includes(bf.severity) && RANK[f.severity] < RANK[bf.severity]) {
				p.push(`${k}: severity dropped from ${bf.severity} to ${f.severity} since the merge base; a register never lowers a severity (a review that rates it lower is a false positive or an owner acceptance)`);
			}
		}
		for (const b of base.baseline) {
			const f = byKey.get(b) ?? moved.get(b);
			if (f && !baseline.has(keyOf(f)) && !compliantIn(tree, f, ctx)) {
				p.push(`baseline: ${b} left the baseline but is ${f.status}; it leaves only when fixed with a test or accepted by the owner`);
			}
		}
	}
	for (const f of reg.findings) {
		if (isHigh(f) && !compliantIn(tree, f, ctx) && !baseline.has(keyOf(f))) {
			const why = f.branch ? `${f.status} on branch ${f.branch} (not on this tree)`
				: f.acceptedBy === 'owner' && ownerParsed.rows.has(keyOf(f)) ? `${f.status}, by a row ${OWNER_FILE} gains in this change (land the owner's row first)`
				: f.status === 'accepted-residual' || f.status === 'false-positive' ? `${f.status} by an agent only` : f.status;
			p.push(`${keyOf(f)}: ${f.severity} finding is ${why}; it must be fixed with a regression test or accepted by the owner (the baseline only shrinks)`);
		}
	}
	if (renderedView !== undefined && (!tree.exists(VIEW) || tree.read(VIEW) !== renderedView)) {
		p.push(`${VIEW} is stale: run \`./seclab docs write\``);
	}
	return p;
}

// ---- the generated view -----------------------------------------------------------------------

// Register text is data: one table cell, no HTML, no links of its own (QQQ-8, RRR-3).
// Register text is data: one table cell, no HTML, no links of its own (QQQ-8, RRR-3). Backslashes
// first, so `\[x\](url)` and `\|` can't turn an escape into a live link or cell (SSS-7).
const esc = (s: string) => s.replace(/\s+/g, ' ').trim().replace(/\\/g, '\\\\')
	.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/([[\]`])/g, '\\$1').replace(/\|/g, '\\|')
	// GFM autolinks a bare URL or www. name; break them so register text never links (TTT-10).
	.replace(/:\/\//g, ':&#47;/').replace(/\bwww\./gi, 'www&#46;');
const recLink = (f: Finding) => f.record === null ? (f.branch ? `\`${f.ref?.file ?? ''}\` (branch \`${f.branch}\`)` : `[${f.ref?.file ?? ''}](../../${f.ref?.file ?? ''})`) : f.branch ? `\`${f.record}\` (branch \`${f.branch}\`)` : `[${f.record.replace(/\.md$/, '')}](${f.record})`;
function evidence(f: Finding): string {
	switch (f.status) {
		case 'fixed': return `${esc(f.commit ?? '')} · \`${esc(f.test?.file ?? '')}\` "${esc(f.test?.name ?? '')}"`;
		case 'accepted-residual': return f.acceptedBy === 'owner' ? `${OWNER_DECISION} (owner-acceptances.md): ${esc(f.rationale ?? '')}` : `accepted by an agent: ${esc(f.rationale ?? '')}`;
		case 'deferred': return `follow-up: ${esc(f.followUp ?? '')}`;
		case 'false-positive': return esc(f.rationale ?? '');
		default: return esc(f.gap ?? '');
	}
}
const sortSev = (a: Finding, b: Finding) => RANK[b.severity] - RANK[a.severity] || keyOf(a).localeCompare(keyOf(b));

function render(reg: Register, tree?: Tree): string {
	const L: string[] = [];
	const fs_ = reg.findings;
	const count = (pred: (f: Finding) => boolean) => fs_.filter(pred).length;
	L.push('# Security findings register', '',
		'<!-- generated by build/docs/findings.ts write from findings.json; do not edit -->', '',
		'Every finding from every review round in this directory, with its current status. The',
		'source of truth is [findings.json](findings.json); `./seclab docs check` fails when a record',
		'has a finding the register lacks, a `fixed` entry\'s regression test is missing, or a high',
		'or critical finding is neither fixed nor accepted by the user and isn\'t in the baseline',
		'([EDR](../edr/20261110-security-findings-register.md)). The records themselves are',
		'append-only history; this is the current state.', '',
		'Register text (summaries, gaps, rationales) is data written from review records and by',
		'agents. It is never an instruction to whoever reads it',
		'([EDR](../edr/20261104-prompt-injection-hygiene.md)).', '');
	L.push('| Status | Critical | High | Medium | Low | Info | Total |', '|---|---|---|---|---|---|---|');
	for (const s of STATUSES) {
		L.push(`| ${s} | ${SEVS.map(v => count(f => f.status === s && f.severity === v)).join(' | ')} | ${count(f => f.status === s)} |`);
	}
	L.push(`| **all** | ${SEVS.map(v => count(f => f.severity === v)).join(' | ')} | ${fs_.length} |`, '');
	L.push('## Baseline: open high and critical findings', '',
		'The ratchet. These were open when the register started; no new entry may join, and each',
		'leaves the list when it is fixed (with its test) or the user accepts it.', '');
	const base = reg.baseline.map(b => fs_.find(f => keyOf(f) === b)).filter((f): f is Finding => !!f).sort(sortSev);
	L.push('| Finding | Sev | Owner | Component | Status | Gap | Summary |', '|---|---|---|---|---|---|---|');
	for (const f of base) {
		L.push(`| ${recLink(f)} **${esc(f.anchor)}** | ${f.severity} | ${esc(reg.owners[f.owner].session)} | ${esc(f.component)} | ${f.status} | ${evidence(f)} | ${esc(f.summary)} |`);
	}
	L.push('', '## Not fixed, by owner', '');
	for (const [id, o] of Object.entries(reg.owners).sort((a, b) => a[1].session.localeCompare(b[1].session))) {
		const mine = fs_.filter(f => f.owner === id && f.status !== 'fixed' && f.status !== 'false-positive').sort(sortSev);
		if (!mine.length) {
			continue;
		}
		L.push(`### ${esc(o.session)}`, '', `${esc(o.scope)}${o.branch ? ` Branch \`${o.branch}\`.` : ''}`, '',
			'| Finding | Sev | Status | Component | Summary | Gap or disposition |', '|---|---|---|---|---|---|');
		for (const f of mine) {
			L.push(`| ${recLink(f)} **${esc(f.anchor)}** | ${f.severity} | ${f.status} | ${esc(f.component)} | ${esc(f.summary)} | ${evidence(f)} |`);
		}
		L.push('');
	}
	const cit = tree ? citations(tree, reg) : undefined;
	const exempt = cit ? [...cit.cite.filter(c => c.tolerated).map(c => ({ token: c.token, use: c.use, why: 'a prefix of the pinned upstream Code-OSS commit (upstream.lock)' })),
		...cit.historical.map(h => ({ token: h.token, use: h.use, why: 'copied as written from its append-only record\'s round heading' }))] : [];
	if (exempt.length) {
		const byTok = new Map<string, { why: string; uses: string[] }>();
		for (const e of exempt) {
			const x = byTok.get(e.token) ?? { why: e.why, uses: [] };
			x.uses.push(e.use);
			byTok.set(e.token, x);
		}
		L.push('## Hex citations that aren\'t checked as live commits', '',
			'Every other commit the register cites is on main\'s history, or on the branch its entry names. These are exempt by fixed rule (EDR 20261110-security-findings-register).', '',
			'| Token | Rule | Cited by |', '|---|---|---|',
			...[...byTok].sort((a, b) => a[0].localeCompare(b[0])).map(([t, x]) => `| \`${t}\` | ${x.why} | ${x.uses.length} ${x.uses.length === 1 ? 'entry' : 'entries'}: ${esc(x.uses.slice(0, 3).join('; '))}${x.uses.length > 3 ? '; …' : ''} |`), '');
	}
	L.push('## All findings, by record', '');
	const groups = new Map<string, Finding[]>();
	for (const f of fs_) {
		const g = f.record ?? 'register';
		groups.set(g, [...(groups.get(g) ?? []), f]);
	}
	for (const g of [...groups.keys()].sort()) {
		const first = groups.get(g)![0];
		L.push(`### ${g === 'register' ? 'Not from a review record (incidents, residuals recorded elsewhere)' : recLink(first)}`, '',
			'| Finding | Sev | Status | Summary | Evidence |', '|---|---|---|---|---|');
		for (const f of groups.get(g)!) {
			L.push(`| ${esc(f.anchor)}${f.wasKey ? ` (was ${esc(f.wasKey)})` : ''} | ${f.severity} | ${f.status} | ${esc(f.summary)} | ${evidence(f)} |`);
		}
		L.push('');
	}
	return L.join('\n');
}

function baselineText(reg: Register): string {
	const rows = reg.baseline.map(b => reg.findings.find(f => keyOf(f) === b)).filter((f): f is Finding => !!f).sort(sortSev);
	return [`## Security findings baseline: ${reg.baseline.length} open high/critical`, '',
		'| Finding | Sev | Owner | Component | Status | Gap |', '|---|---|---|---|---|---|',
		...rows.map(f => `| ${esc(keyOf(f))} | ${f.severity} | ${esc(reg.owners[f.owner].session)} | ${esc(f.component)} | ${f.status} | ${evidence(f)} |`), ''].join('\n');
}
// The baseline rules alone (the weekly listing): every key resolves, is high and is still open,
// by the same predicate the gate uses (TTT-5). It has no change to judge, so the landing-order
// rule isn't applied: the listing is advisory, and ./seclab docs check is the gate (XXX-8).
function baselineProblems(tree: Tree, reg: Register): string[] {
	const byKey = new Map(reg.findings.map(f => [keyOf(f), f]));
	return reg.baseline.flatMap(b => {
		const f = byKey.get(b);
		return !f ? [`baseline: ${b} has no register entry`] : !isHigh(f) ? [`baseline: ${b} is ${f.severity}`] : compliantIn(tree, f, { owner: tree.exists(OWNER_FILE) ? parseOwnerFile(tree.read(OWNER_FILE)).rows : undefined }) ? [`baseline: ${b} is ${f.status} now; remove it`] : [];
	});
}

// ---- self-test --------------------------------------------------------------------------------

function selfTest(): number {
	const rec = (date: string, body: string) => `# Security review: t\n\n- **Date:** ${date}\n\n${body}\n`;
	const table = '| # | Sev | Area | Finding | Disposition | Fix |\n|---|---|---|---|---|---|\n';
	const EDR = 'docs/edr/20261101-x.md';
	const USERQ = 'Decision record: residual A-1 stays until the fix lands.';
	const ownerTable = (...rows: string[]) => `# Owner acceptances\n\n| Finding | Date | Scope | Closing condition | Decision |\n|---|---|---|---|---|\n${rows.map(r => `${r}\n`).join('')}`;
	const ownerRow = (key: string) => `| ${key} | 2026-11-12 | residual stays | the fix lands | accepted by the project owner |`;
	const base = (): Map<string, string> => new Map([
		[`${REVIEWS}/20261101-a.md`, rec('2026-11-01', `## Round A\n${table}| A-1 | **High** | x | bad | Fixed | f |\n| — | Residual | x | r | Accepted | r |\n| — | Low | x | r2 | Accepted | r |\n\n## Round B\n### MEDIUM (9/10): prose finding\nbody\n`)],
		['tabd/test/unit.test.ts', "test('rejects the bad thing', () => {});\n"],
		[EDR, `${USERQ}\nonly on main\n`],
	]);
	const reg = (): Register => ({
		owners: { o: { session: 'Owner', branch: 'b', scope: 'things' } },
		baseline: [],
		noFindings: [],
		manualOnly: [],
		findings: [
			{ record: '20261101-a.md', anchor: 'A-1', severity: 'high', summary: 's', component: 'c', owner: 'o', status: 'fixed', commit: 'abcdef1', test: { file: 'tabd/test/unit.test.ts', name: 'rejects the bad thing' } },
			{ record: '20261101-a.md', anchor: '—', severity: 'low', severityNote: 'a residual; the record gives no severity', summary: 's', component: 'c', owner: 'o', status: 'accepted-residual', acceptedBy: 'agent', rationale: 'r', ref: { file: `${REVIEWS}/20261101-a.md`, quote: '| r |' } },
			{ record: '20261101-a.md', anchor: '—#2', severity: 'low', summary: 's', component: 'c', owner: 'o', status: 'open', gap: 'g' },
			{ record: '20261101-a.md', anchor: 'MEDIUM (9/10): prose finding', severity: 'medium', summary: 's', component: 'c', owner: 'o', status: 'deferred', followUp: 'f' },
		],
	});
	const mkTree = (files: Map<string, string>): Tree => ({ exists: p => files.has(p) || [...files.keys()].some(k => k.startsWith(`${p}/`)), read: p => files.get(p) ?? '', list: d => [...new Set([...files.keys()].filter(k => k.startsWith(`${d}/`)).map(k => k.slice(d.length + 1).split('/')[0]))].sort() });
	const run = (files: Map<string, string>, r: Register, view = true, baseReg?: Register, change?: Change) => {
		const tree = mkTree(files);
		const ok = schemaProblems(r).length === 0;
		if (view && ok) {
			files.set(VIEW, render(r, tree));
		}
		return check(tree, r, ok ? render(r, tree) : undefined, baseReg, change);
	};
	let failed = 0;
	const expect = (name: string, problems: string[], pattern: RegExp | null) => {
		const ok = pattern === null ? problems.length === 0 : problems.some(x => pattern.test(x));
		console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${ok ? '' : `\n     got: ${JSON.stringify(problems)}`}`);
		failed += ok ? 0 : 1;
	};
	expect('control: a consistent register passes', run(base(), reg()), null);
	{
		const f = base();
		f.set(`${REVIEWS}/20261101-a.md`, f.get(`${REVIEWS}/20261101-a.md`)!.replace('| r2 | Accepted | r |\n', '| r2 | Accepted | r |\n| A-2 | Low | x | new | Fixed | f |\n'));
		expect('a finding in a record but not in the register fails', run(f, reg()), /"A-2" is not in the register/);
		f.set(`${REVIEWS}/20261101-a.md`, f.get(`${REVIEWS}/20261101-a.md`)!.replace('| A-2 |', '| — |'));
		expect('an appended placeholder row gets the next occurrence and must be registered', run(f, reg()), /"—#3" is not in the register/);
	}
	{
		const f = base();
		f.set(`${REVIEWS}/20261101-a.md`, f.get(`${REVIEWS}/20261101-a.md`)! + '\n### HIGH: a new prose finding\n');
		expect('a new prose severity heading must be registered', run(f, reg()), /"HIGH: a new prose finding" is not in the register/);
	}
	{
		const f = base();
		f.set(`${REVIEWS}/20261101-a.md`, f.get(`${REVIEWS}/20261101-a.md`)! + '\n1. **HIGH, a numbered prose finding.** body\n');
		expect('a new bold-severity list item must be registered', run(f, reg()), /"HIGH, a numbered prose finding\." is not in the register/);
	}
	{
		const f = base();
		f.delete('tabd/test/unit.test.ts');
		expect('a fixed entry whose test file is missing fails', run(f, reg()), /regression test file tabd\/test\/unit\.test\.ts doesn't exist/);
	}
	{
		const f = base();
		f.set('tabd/test/unit.test.ts', "test('something else', () => {});\n");
		expect('a fixed entry whose named test is missing fails', run(f, reg()), /regression test "rejects the bad thing" not found/);
	}
	{
		const r = reg();
		Object.assign(r.findings[0], { status: 'open', gap: 'g' });
		delete r.findings[0].commit;
		delete r.findings[0].test;
		expect('an open high outside the baseline fails', run(base(), r), /high finding is open/);
		r.baseline.push('20261101-a.md#A-1');
		expect('control: the same open high in the baseline passes', run(base(), r), null);
	}
	{
		// Owner acceptances: a row in owner-acceptances.md, keyed by the full key, landed first.
		const r = reg();
		Object.assign(r.findings[0], { status: 'accepted-residual', acceptedBy: 'agent', rationale: 'r', ref: { file: EDR, quote: USERQ } });
		delete r.findings[0].commit;
		delete r.findings[0].test;
		expect('a high accepted only by an agent fails', run(base(), r), /accepted-residual by an agent only/);
		r.findings[0].acceptedBy = 'owner';
		delete r.findings[0].ref;
		expect('an owner acceptance with no row in owner-acceptances.md fails', run(base(), r), /acceptedBy owner, but docs\/security-reviews\/owner-acceptances\.md has no row for it/);
		const ow = base();
		ow.set(OWNER_FILE, ownerTable(ownerRow('20261101-a.md#A-1')));
		expect('control: a high accepted by the owner with its row passes', run(ow, r), null);
		expect('an owner row added in this same change does not close it (UUU-4)', run(ow, r, true, undefined, { files: new Set([OWNER_FILE]), before: new Map() }), /land the owner's row first/);
		expect('control: a later unrelated edit to owner-acceptances.md keeps it closed (VVV-3)', run(ow, r, true, undefined, { files: new Set([OWNER_FILE]), before: new Map([[OWNER_FILE, ownerTable(ownerRow('20261101-a.md#A-1'))]]) }), null);
		const other = base();
		other.set(OWNER_FILE, ownerTable(ownerRow('20261101-a.md#A-10')));
		expect('an owner row for another finding does not close this one', run(other, r), /has no row for it/);
		const sib = base();
		sib.set(`${REVIEWS}/20261101-a.md`, sib.get(`${REVIEWS}/20261101-a.md`)!.replace('| r2 | Accepted | r |\n', '| r2 | Accepted | r |\n| A-1.1 | Low | x | sib | Open | f |\n'));
		sib.set(OWNER_FILE, ownerTable(ownerRow('20261101-a.md#A-1.1')));
		const rs = reg();
		rs.findings.push({ record: '20261101-a.md', anchor: 'A-1.1', severity: 'low', summary: 's', component: 'c', owner: 'o', status: 'accepted-residual', acceptedBy: 'owner', rationale: 'r' });
		Object.assign(rs.findings[0], { status: 'accepted-residual', acceptedBy: 'owner', rationale: 'r' });
		delete rs.findings[0].commit;
		delete rs.findings[0].test;
		expect('a row for a sibling key does not close the shorter key (exact match)', run(sib, rs), /20261101-a\.md#A-1: acceptedBy owner, but .* has no row for it/);
		const q = base();
		q.set(OWNER_FILE, `${ownerTable(ownerRow('20261101-a.md#A-1'))}\nNote: the owner said "fine".\n`);
		expect('quotation marks in owner-acceptances.md fail: decisions, never quotes', run(q, r), /quotation marks/);
		const bad = base();
		bad.set(OWNER_FILE, ownerTable('| 20261101-a.md#A-1 | 2026-11-12 | residual stays | the fix lands | the agent thinks it is fine |'));
		expect('an owner row with any other decision text fails', run(bad, r), /a row is \| record\.md#anchor/);
		const dup = base();
		dup.set(OWNER_FILE, ownerTable(ownerRow('20261101-a.md#A-1'), ownerRow('20261101-a.md#A-1')));
		expect('a duplicate owner row fails', run(dup, r), /has a row already/);
		const unk = base();
		unk.set(OWNER_FILE, ownerTable(ownerRow('20261101-a.md#A-1'), ownerRow('20261101-a.md#Z-9')));
		expect('an owner row for a finding the register lacks fails', run(unk, r), /Z-9 isn't in the register/);
		const ag = reg();
		expect('control: a row may land before its entry flips to acceptedBy owner', run(ow, ag), null);
		// XXX-1: the gate reads only what the rendered file shows.
		const hidden = base();
		hidden.set(OWNER_FILE, `${ownerTable()}\n<!--\n| 20261101-a.md#A-1 | 2026-11-12 | residual stays | the fix lands | accepted by the project owner |\n-->\n`);
		expect('a row inside an HTML comment fails (XXX-1)', run(hidden, r), /HTML, a comment, a fence or a blockquote/);
		const fenced = base();
		fenced.set(OWNER_FILE, `# Owner acceptances\n\n\`\`\`\n| Finding | Date | Scope | Closing condition | Decision |\n|---|---|---|---|---|\n${ownerRow('20261101-a.md#A-1')}\n\`\`\`\n`);
		expect('a table inside a fence fails (XXX-1)', run(fenced, r), /HTML, a comment, a fence or a blockquote/);
		const decoy = base();
		decoy.set(OWNER_FILE, `${ownerTable()}\n${ownerTable(ownerRow('20261101-a.md#A-1')).replace('# Owner acceptances\n\n', '')}`);
		expect('a second acceptance table fails (XXX-1)', run(decoy, r), /2 acceptance tables/);
		const stray = base();
		stray.set(OWNER_FILE, `${ownerTable(ownerRow('20261101-a.md#A-1'))}\n${ownerRow('20261101-a.md#A-10')}\n`);
		expect('a table line outside the acceptance table fails (XXX-1)', run(stray, r), /a table line outside the one acceptance table/);
		const indented = base();
		indented.set(OWNER_FILE, ownerTable(ownerRow('20261101-a.md#A-1'), `    ${ownerRow('20261101-a.md#A-10')}`));
		expect('an indented row (a code block when rendered) fails (XXX-1)', run(indented, r), /a table line outside the one acceptance table/);
		const narrow = base();
		narrow.set(OWNER_FILE, ownerTable(ownerRow('20261101-a.md#A-1')).replace('|---|---|---|---|---|', '|---|---|---|---|'));
		expect('a delimiter row that does not match the five columns fails (XXX-1)', run(narrow, r), /needs the table/);
		// XXX-3: the quote scan covers every cell but the key, curly single quotes and blockquotes.
		const curly = base();
		curly.set(OWNER_FILE, ownerTable('| 20261101-a.md#A-1 | 2026-11-12 | ‘fine’ for now | the fix lands | accepted by the project owner |'));
		expect('curly single quotes in a cell fail (XXX-3)', run(curly, r), /quotation marks/);
		const bq = base();
		bq.set(OWNER_FILE, `${ownerTable(ownerRow('20261101-a.md#A-1'))}\n> the owner, in passing\n`);
		expect('a blockquote fails (XXX-3)', run(bq, r), /HTML, a comment, a fence or a blockquote/);
		const qkey = base();
		qkey.set(OWNER_FILE, ownerTable(ownerRow('20261101-a.md#A-1'), ownerRow('20261101-a.md#HIGH, the "x" rule')));
		const qkeyP = run(qkey, r);
		expect('a key with quotation marks is still writable: only its registration fails (XXX-3)', qkeyP, /HIGH, the "x" rule isn't in the register/);
		expect('control: the quote scan skips the key cell (XXX-3)', qkeyP.filter(x => /quotation marks/.test(x)), null);
		// XXX-4: a key with a pipe is written escaped.
		const piped = base();
		piped.set(OWNER_FILE, ownerTable(ownerRow('20261101-a.md#A-1'), ownerRow('20261101-a.md#a\\|b')));
		expect('an escaped pipe in a key reads as a pipe (XXX-4)', run(piped, r), /20261101-a\.md#a\|b isn't in the register/);
		// XXX-7: touched is decided by content, not by the changed-file list.
		const rowNow = ownerTable(ownerRow('20261101-a.md#A-1'));
		expect('a row whose file changed without being listed does not close it (XXX-7)', run(ow, r, true, undefined, { files: new Set(), before: new Map(), ownerBefore: null }), /land the owner's row first/);
		expect('control: an unlisted, unchanged owner file keeps it closed (XXX-7)', run(ow, r, true, undefined, { files: new Set(), before: new Map(), ownerBefore: rowNow }), null);
		const f = base();
		r.findings[0].acceptedBy = 'agent';
		r.findings[0].ref = { file: REGISTER, quote: USERQ };
		expect('a ref to the register itself fails (self-citation)', run(f, r), /is the register itself/);
		r.findings[0].ref = { file: 'docs/edr/../edr/20261101-x.md', quote: USERQ };
		expect('a ref path with .. fails', run(f, r), /must be a plain repo-relative path/);
	}
	{
		const r = reg();
		Object.assign(r.findings[0], { status: 'fixed-untested', gap: 'no test' });
		delete r.findings[0].test;
		expect('a high fixed without a test counts as open', run(base(), r), /high finding is fixed-untested/);
	}
	{
		const r = reg();
		r.baseline.push('20261101-a.md#A-1');
		expect('a fixed baseline entry must leave the baseline', run(base(), r), /is fixed now; remove it from the baseline/);
		r.baseline = ['20261101-a.md#nope'];
		expect('a baseline key with no entry fails', run(base(), r), /baseline: 20261101-a\.md#nope has no register entry/);
		r.baseline = ['20261101-a.md#—'];
		expect('a low in the baseline fails', run(base(), r), /only high\/critical belong in the baseline/);
	}
	{
		const r = reg();
		r.findings[0].severity = 'medium';
		expect('lowering the record\'s severity fails', run(base(), r), /never lower it/);
	}
	{
		const r = reg();
		r.findings.push({ record: '20261101-a.md', anchor: 'A-9', severity: 'low', summary: 's', component: 'c', owner: 'o', status: 'open', gap: 'g' });
		expect('a stale entry (no such finding in its record) fails', run(base(), r), /A-9: stale/);
		r.findings[4].branch = 'b';
		expect('control: the same entry on a branch passes', run(base(), r), null);
	}
	{
		const r = reg();
		r.findings.push({ record: '20261102-b.md', anchor: 'B-1', branch: 'b', severity: 'low', summary: 's', component: 'c', owner: 'o', status: 'fixed', commit: 'abcdef1', test: { file: 'tabd/test/b.test.ts', name: 'branch case number one' } });
		expect('control: a branch-only record and test pass', run(base(), r), null);
		const f = base();
		f.set('tabd/test/b.test.ts', "test('another case', () => {});\n");
		expect('control: a branch entry whose test file exists here without its case passes', run(f, r), null);
		f.set(`${REVIEWS}/20261102-b.md`, rec('2026-11-02', `${table}| B-1 | Low | x | y | Fixed | f |\n`));
		expect('a landed branch record must drop "branch", even before its test lands', run(f, r), /B-1: its record finding is on this tree now; drop "branch"/);
		delete r.findings[4].branch;
		expect('once it drops "branch", its test must be here', run(f, r), /regression test "branch case number one" not found/);
		r.findings[4].severity = 'high';
		r.findings[4].branch = 'b';
		const g = base();
		expect('a fixed high on a branch is not compliant: its evidence isn\'t on this tree (QQQ-1)', run(g, r), /high finding is fixed on branch b \(not on this tree\)/);
		r.baseline.push('20261102-b.md#B-1');
		expect('control: the same branch high in the baseline passes', run(g, r), null);
	}
	{
		const r = reg();
		r.findings.push({ record: null, anchor: 'X-R1', branch: 'b', severity: 'low', summary: 's', component: 'c', owner: 'o', status: 'deferred', followUp: 'f', ref: { file: EDR, quote: 'only on the branch' } });
		expect('control: a branch entry citing branch-only text in a file on this tree passes', run(base(), r), null);
		const f = base();
		f.set(EDR, `${USERQ}\nonly on the branch\n`);
		expect('a branch entry whose ref text has landed must drop "branch"', run(f, r), /X-R1: its ref is on this tree now/);
	}
	{
		const r = reg();
		r.findings[1].owner = 'ghost';
		expect('an unknown owner fails the schema', run(base(), r), /unknown owner ghost/);
	}
	{
		// Commit citations (review YYY): every fix commit, any case, all-digit prose that isn't a
		// date, never quotes or test names; a round token its record carries is historical.
		const UP = 'a717861c07586a53d83b80d742cd3f59b20a6273';
		const files = base();
		files.set('upstream.lock', `UPSTREAM_TAG=1.145.0\nUPSTREAM_SHA=${UP}\n`);
		files.set(`${REVIEWS}/20261101-a.md`, files.get(`${REVIEWS}/20261101-a.md`)!.replace('## Round A', '## Round A (fed0123)'));
		const t = reg();
		t.findings[0].commit = '1234567';
		t.findings[0].note = 'upstream at a717861c; see BEEF123 and 7207391, dated 20261112';
		t.findings[0].round = 'Round A (fed0123; landed 0ddba11)';
		t.findings[0].test = { file: 'tabd/test/unit.test.ts', name: 'rejects 5ca1ab1e the bad thing' };
		t.findings[1].ref = { file: EDR, quote: 'c0ffee12 in a quote' };
		t.findings[1].component = 'c (was 9abcdef)';
		const c = citations(mkTree(files), t);
		const got = c.cite.map(x => `${x.token}${x.tolerated ? '*' : ''}`).sort().join(',');
		const hist = c.historical.map(h => h.token).join(',');
		expect('control: shas mode sees fix commits (all-digit too), any-case, all-digit and component citations, and marks the upstream pin (YYY-1, YYY-2)',
			got === '0ddba11,1234567,7207391,9abcdef,a717861c*,beef123' ? [] : [`got ${got}`], null);
		expect('a round token its record carries is historical, not cited (YYY-6)', hist === 'fed0123' ? [] : [`got ${hist}`], null);
		const noUp = citations(mkTree(base()), t).cite.filter(x => x.tolerated);
		expect('the upstream pin is exempt only with upstream.lock naming it', noUp.length ? [`got ${noUp.map(x => x.token).join(',')}`] : [], null);
		const upCommit = reg();
		upCommit.findings[0].commit = 'a717861c';
		const uc = citations(mkTree(files), upCommit).cite.find(x => x.use.endsWith(' commit') && x.token === 'a717861c');
		expect('a fix commit is never exempt as the upstream pin', uc && !uc.tolerated ? [] : ['exempt'], null);
		const br = reg();
		br.findings[0].branch = 'some-branch';
		const bc = citations(mkTree(files), br).cite.find(x => x.token === 'abcdef1');
		const nob = reg();
		nob.owners.o.branch = null;
		expect('citations carry its branch, and only those: the entry\'s, else its owner\'s declared one', bc?.branch === 'some-branch' && citations(mkTree(files), reg()).cite.every(x => x.branch === 'b') && citations(mkTree(files), nob).cite.every(x => x.branch === null) ? [] : ['wrong branch scope'], null);
		// ZZZ: only an entry this change adds or modifies must have live citations.
		const tb = reg();
		tb.findings[0].note = 'see 0ddba11';
		const ta = JSON.parse(JSON.stringify(tb)) as Register;
		const untouched = citations(mkTree(files), ta, tb).cite.find(x => x.token === '0ddba11');
		expect('control: an entry unchanged since the base is not touched (ZZZ)', untouched && !untouched.touched ? [] : ['touched'], null);
		ta.findings[0].note = 'see 0ddba11 again';
		const edited = citations(mkTree(files), ta, tb).cite.find(x => x.token === '0ddba11');
		expect('an entry this change edits is touched (ZZZ)', edited?.touched ? [] : ['not touched'], null);
		const added = reg();
		added.findings.push({ record: null, anchor: 'INC-9', severity: 'low', summary: 's', component: 'c', owner: 'o', status: 'open', gap: 'g', note: 'see 0ddba11', ref: { file: EDR, quote: 'only on main' } });
		const both = citations(mkTree(files), added, tb).cite.find(x => x.token === '0ddba11');
		expect('a token an added entry shares with an untouched one is touched (ZZZ)', both?.touched && both.use.startsWith('register#INC-9') ? [] : [`got ${JSON.stringify(both)}`], null);
		const ob = JSON.parse(JSON.stringify(tb)) as Register;
		ob.owners.o.branch = 'elsewhere';
		expect('an owner\'s branch change touches the entries that inherit it (ZZZ-1)', citations(mkTree(files), ob, tb).cite.every(x => x.touched) ? [] : ['untouched'], null);
		expect('no base: every entry is touched (ZZZ)', citations(mkTree(files), ta).cite.every(x => x.touched) ? [] : ['untouched'], null);
		// ZZZ: remap rewrites only the named branch's entries, never a round label.
		const rm = reg();
		rm.findings[0].branch = 'br-a';
		Object.assign(rm.findings[0], { commit: 'abcdef1', note: 'see ABCDEF1 and 1234567', round: 'Round A (abcdef1)' });
		rm.findings[1].note = 'see abcdef1';
		const res = remapBranch(rm, 'br-a', [['abcdef1', 'fedcba9'], ['--x', 'fedcba9']]);
		expect('remap rewrites the branch entry\'s commit and prose (ZZZ)', rm.findings[0].commit === 'fedcba9' && rm.findings[0].note === 'see fedcba9 and 1234567' && res.changed.length === 2 ? [] : [`got ${JSON.stringify(rm.findings[0])}`], null);
		expect('remap leaves round labels and other branches alone (ZZZ)', rm.findings[0].round === 'Round A (abcdef1)' && rm.findings[1].note === 'see abcdef1' ? [] : ['rewrote'], null);
		const long = reg();
		long.findings[0].note = `digest ${'ab12'.repeat(11)}`;
		expect('a hex run over 40 characters fails (YYY-1)', run(base(), long), /a hex run of 44 characters isn't a commit citation/);
		const r2 = reg();
		delete (r2.findings[0] as Partial<Finding>).test;
		expect('fixed without a test fails the schema', run(base(), r2), /fixed needs commit and test/);
		const r3 = reg();
		(r3.findings[0] as unknown as Record<string, unknown>).verified = true;
		expect('an unknown field fails the schema', run(base(), r3), /unknown field verified/);
		const r4 = reg();
		r4.findings.push({ ...r4.findings[2] });
		expect('a duplicate key fails the schema', run(base(), r4), /duplicate key/);
		const r5 = reg();
		r5.findings[0].commit = 'HEAD~1';
		expect('a non-hex commit fails the schema', run(base(), r5), /commit must be a hex SHA/);
		const r6 = reg();
		r6.findings[2].acceptedBy = 'owner';
		expect('acceptedBy outside accepted-residual fails the schema', run(base(), r6), /acceptedBy only applies/);
		const r7 = reg();
		r7.findings[2].test = { file: 'tabd/test/unit.test.ts', name: 'rejects the bad thing' };
		expect('test outside fixed fails the schema', run(base(), r7), /test only applies to fixed/);
		const r8 = reg();
		r8.baseline = ['20261101-a.md#A-1', '20261101-a.md#A-1'];
		expect('a repeated baseline key fails the schema', run(base(), r8), /is not a unique key/);
	}
	{
		const r = reg();
		r.findings[0].test = { file: 'tabd/test/unit.test.ts', name: 'rejects' };
		expect('a test name too short to name one case fails (QQQ-3)', run(base(), r), /test\.name must be at least 12 characters/);
		const f = base();
		f.set('tabd/test/unit.test.ts', "test('rejects the bad thing', () => {});\ntest('rejects the bad thing twice', () => {});\n");
		expect('a test name that matches more than one place fails', run(f, reg()), /occurs 2 times/);
		const g = base();
		g.set('build/tool.ts', '// rejects the bad thing\n');
		const r2 = reg();
		r2.findings[0].test = { file: 'build/tool.ts', name: 'rejects the bad thing' };
		expect('a "test" in a file that is neither a test nor a self-tested checker fails', run(g, r2), /neither a test file nor has this case inside its self-test/);
		g.set('build/tool.ts', "expect('rejects the bad thing');\nif (mode === '--self-test') {\n\tselfTest();\n}\n");
		expect('a name that sits before the checker\'s self-test entry fails (SSS-3)', run(g, r2), /nor has this case inside its self-test/);
		g.set('build/tool.ts', "// usage: tool.ts check | --self-test\nfunction check() {\n\tconsole.log('rejects the bad thing');\n}\nfunction selfTest() {\n\texpect('another case here');\n}\n");
		expect('a name below a header mention of --self-test but outside the self-test fails (TTT-3)', run(g, r2), /nor has this case inside its self-test/);
		g.set('build/tool.ts', "// usage: tool.ts check | --self-test\nfunction selfTest(): number {\n\texpect('rejects the bad thing');\n\treturn 0;\n}\nfunction check() {}\n");
		expect('control: a case inside a checker\'s selfTest function passes', run(g, r2), null);
		g.set('build/tool.ts', "function check() {}\nfunction selfTest(): number {\n\texpect('another case here');\n\treturn 0;\n}\nfunction selfTestRegions(text) {\n\t// rejects the bad thing\n}\n");
		expect('a name in a function merely called selfTest-something is not in a self-test (UUU-5)', run(g, r2), /nor has this case inside its self-test/);
		g.set('build/tool.ts', "function check() {}\n/*\nfunction selfTest() {\n*/\nconsole.log('rejects the bad thing');\n");
		expect('a self-test start that never ends opens no region (UUU-5)', run(g, r2), /nor has this case inside its self-test/);
		g.set('build/tool.ts', "/*\nfunction selfTest() {\n*/\nfunction check() {\n\tconsole.log('rejects the bad thing');\n}\n");
		expect('a self-test start inside a block comment opens no region (VVV-5)', run(g, r2), /nor has this case inside its self-test/);
		g.set('build/tool.ts', "function selfTest() {\n\tconst s = '/*';\n}\nfunction check() {\n\tconsole.log('rejects the bad thing');\n\tconst t = '*/';\n}\n");
		expect('a /* inside a string cannot blank a self-test end and stretch the region (WWW-4)', run(g, r2), /nor has this case inside its self-test/);
		g.set('build/tool.py', '"""\ndef self_test():\n"""\ndef check():\n    print("rejects the bad thing")\n');
		r2.findings[0].test = { file: 'build/tool.py', name: 'rejects the bad thing' };
		expect('a self_test start inside a docstring opens no region (VVV-5)', run(g, r2), /nor has this case inside its self-test/);
		r2.findings[0].test = { file: 'build/tool.ts', name: 'rejects the bad thing' };
		g.set('build/tool.py', "def check():\n    pass\n\ndef self_test() -> list[str]:\n    case('rejects the bad thing')\n    return []\n\nif __name__ == '__main__':\n    check()\n");
		r2.findings[0].test = { file: 'build/tool.py', name: 'rejects the bad thing' };
		expect('control: a case inside a Python self_test passes', run(g, r2), null);
		g.set('build/tool.sh', "#!/bin/sh\nif [ \"${1:-}\" = \"--self-test\" ]; then\n\tcase_ok 'rejects the bad thing'\n\texit 0\nfi\necho run\n");
		r2.findings[0].test = { file: 'build/tool.sh', name: 'rejects the bad thing' };
		expect('control: a case inside a shell --self-test branch passes', run(g, r2), null);
		g.set('.github/workflows/ci.yml', "run: ./x --self-test\nname: rejects the bad thing\n");
		r2.findings[0].test = { file: '.github/workflows/ci.yml', name: 'rejects the bad thing' };
		expect('a workflow that mentions --self-test is still not a test (SSS-3)', run(g, r2), /is a doc or a workflow, not a test/);
	}
	{
		const f = base();
		f.set(`${REVIEWS}/20261101-a.md`, f.get(`${REVIEWS}/20261101-a.md`)!.replace('| r2 | Accepted | r |\n', '| r2 | Accepted | r |\n| A-3 | Low/Medium | x | y | Fixed | f |\n'));
		const r = reg();
		r.findings.push({ record: '20261101-a.md', anchor: 'A-3', severity: 'low', summary: 's', component: 'c', owner: 'o', status: 'open', gap: 'g' });
		expect('below the highest of two record severities needs severityNote', run(f, r), /below the highest needs severityNote/);
		r.findings[4].severityNote = 'the re-review rated it low';
		expect('control: with a severityNote it passes', run(f, r), null);
	}
	{
		const f = base();
		f.set(`${REVIEWS}/20261101-a.md`, `${f.get(`${REVIEWS}/20261101-a.md`)!}\nAlso noted: the frobnicator leaks its key.\n`);
		const r = reg();
		r.findings.push({ record: '20261101-a.md', anchor: 'M-1', manual: { file: `${REVIEWS}/20261101-a.md`, quote: 'the frobnicator leaks its key' }, severity: 'low', summary: 's', component: 'c', owner: 'o', status: 'open', gap: 'g' });
		expect('control: a manual entry quoting its record passes', run(f, r), null);
		r.findings[4].manual = { file: `${REVIEWS}/20261101-a.md`, quote: 'the frobnicator is fine' };
		expect('a manual entry whose quote left the record fails', run(f, r), /manual quote not found/);
		r.findings[4].manual = { file: EDR, quote: USERQ };
		expect('a manual entry quoting another file fails', run(f, r), /manual\.file must be the record/);
	}
	{
		// Shape coverage (QQQ-4): each supported form is seen, each unsupported one fails.
		const shapes: Array<[string, string, RegExp]> = [
			['a "Sev/Conf" header', '| ID | Sev/Conf | Finding |\n|---|---|---|\n| S-1 | High/9 | x |\n', /"S-1" is not in the register/],
			['a table without leading pipes', 'ID | Sev | Finding\n--- | --- | ---\nS-1 | High | x\n', /"S-1" is not in the register/],
			['a one-dash delimiter row', '| ID | Sev | Finding |\n|-|-|-|\n| S-1 | High | x |\n', /"S-1" is not in the register/],
			['a mixed-case severity heading', '### High: lower-case heading\nbody\n', /"High: lower-case heading" is not in the register/],
			['a level-5 severity heading', '##### HIGH deep heading\nbody\n', /"HIGH deep heading" is not in the register/],
			['a dash row carrying a finding', '| ID | Sev | Finding |\n|---|---|---|\n| — | — | HIGH: auth bypass |\n', /"—#3" is not in the register/],
			['a findings table with no Sev column', '| ID | Finding |\n|---|---|\n| S-1 | x |\n', /a findings table with no Sev column/],
			['an HTML table', '<table><tr><td>HIGH</td></tr></table>\n', /HTML table/],
			['an unbalanced code fence', '```\n| S-1 | High | x |\n', /unbalanced code fence/],
		];
		for (const [name, body, pattern] of shapes) {
			const f = base();
			f.set(`${REVIEWS}/20261101-a.md`, `${f.get(`${REVIEWS}/20261101-a.md`)!}\n${body}`);
			expect(`extractor: ${name}`, run(f, reg()), pattern);
		}
		const f = base();
		f.set(`${REVIEWS}/20261101-a.md`, `${f.get(`${REVIEWS}/20261101-a.md`)!}\n| ID | Sev | Finding |\n|---|---|---|\n| — | — | No vulnerabilities found. |\n`);
		expect('control: a "no vulnerabilities found" row is not a finding', run(f, reg()), null);
		const h = base();
		h.set(`${REVIEWS}/20261101-a.md`, `${h.get(`${REVIEWS}/20261101-a.md`)!}\n| Case | Result |\n|---|---|\n| plain GET | 403 |\n`);
		expect('control: a results table without a Sev column is not a finding', run(h, reg()), null);
		const g = base();
		g.set(`${REVIEWS}/sub/20261103-c.md`, rec('2026-11-03', `${table}| C-1 | High | x | y | z | w |\n`));
		expect('a subdirectory under the reviews dir fails', run(g, reg()), /docs\/security-reviews\/sub: unexpected entry/);
		const s = base();
		s.set(`${REVIEWS}/notes.md`, '| ID | Sev |\n|---|---|\n| N-1 | High |\n');
		expect('a stray file under the reviews dir fails (SSS-9)', run(s, reg()), /docs\/security-reviews\/notes\.md: unexpected entry/);
		const d = base();
		d.set(`${REVIEWS}/.DS_Store`, 'binary');
		expect('control: a dotfile under the reviews dir is ignored (SSS-8)', run(d, reg()), null);
		const k = base();
		k.set(`${REVIEWS}/20261101-a.md`, `${k.get(`${REVIEWS}/20261101-a.md`)!}\nMore A | B text\n---\n\n\`\`\`\n| F-1 | High | fenced example |\n\`\`\`\n~~~\n### HIGH: in a tilde fence\n~~~\n`);
		expect('control: a setext rule under a pipe and fenced examples are not findings (SSS-8, SSS-9)', run(k, reg()), null);
		const hs = base();
		hs.set(`${REVIEWS}/20261101-a.md`, `${hs.get(`${REVIEWS}/20261101-a.md`)!}\n### High severity issue in the broker\nbody\n`);
		expect('a "### High severity …" heading is a finding (TTT-4)', run(hs, reg()), /"High severity issue in the broker" is not in the register/);
		const sf = base();
		sf.set(`${REVIEWS}/20261101-a.md`, `${sf.get(`${REVIEWS}/20261101-a.md`)!}\n| Sev | Finding | Fix |\n|---|---|---|\n| High | unanchored row | x |\n`);
		expect('a Sev-first table row is anchored by its next cell (TTT-9)', run(sf, reg()), /"unanchored row" is not in the register/);
		const dot = base();
		dot.set(`${REVIEWS}/.20261112-hidden.md`, rec('2026-11-12', `${table}| H-1 | High | x | y | z | w |\n`));
		expect('a dotted record name is an unexpected entry, not ignored (TTT-8)', run(dot, reg()), /\.20261112-hidden\.md: unexpected entry/);
	}
	{
		const f = base();
		f.set(`${REVIEWS}/20261103-c.md`, rec('2026-11-03', '## Findings\nNone.\n'));
		const r = reg();
		expect('a record that yields no finding fails', run(f, r), /20261103-c\.md: no finding the extractor can read/);
		r.noFindings.push('20261103-c.md');
		expect('control: listed under noFindings it passes', run(f, r), null);
		f.set(`${REVIEWS}/20261103-c.md`, rec('2026-11-03', 'Some prose about an issue nobody tabled.\n'));
		expect('a noFindings record that doesn\'t say it has none fails (SSS-5)', run(f, r), /noFindings: 20261103-c\.md doesn't say it has no findings/);
		f.set(`${REVIEWS}/20261103-c.md`, rec('2026-11-03', 'We expected no findings found here, but a token leaked.\n```\nNone.\n```\n'));
		expect('"none" mid-sentence or inside a fence doesn\'t count as saying none (TTT-4)', run(f, r), /noFindings: 20261103-c\.md doesn't say it has no findings/);
		f.set(`${REVIEWS}/20261103-c.md`, rec('2026-11-03', 'Some prose about an issue nobody tabled.\n'));
		r.noFindings = [];
		r.findings.push({ record: '20261103-c.md', anchor: 'C-M1', manual: { file: `${REVIEWS}/20261103-c.md`, quote: 'an issue nobody tabled' }, severity: 'low', summary: 's', component: 'c', owner: 'o', status: 'open', gap: 'g' });
		expect('a record with only manual entries must be listed under manualOnly (SSS-5)', run(f, r), /list it under manualOnly/);
		r.manualOnly.push('20261103-c.md');
		expect('control: listed under manualOnly it passes', run(f, r), null);
		const b = reg();
		b.findings.push({ ...r.findings[4] });
		expect('a record new to manualOnly since the merge base fails', run(f, r, true, b), /manualOnly: 20261103-c\.md is new since the merge base/);
		f.set(`${REVIEWS}/20261103-c.md`, rec('2026-11-03', `${table}| C-1 | Low | x | y | z | w |\n`));
		r.manualOnly = [];
		r.noFindings.push('20261103-c.md');
		r.findings[4] = { record: '20261103-c.md', anchor: 'C-1', severity: 'low', summary: 's', component: 'c', owner: 'o', status: 'open', gap: 'g' };
		expect('a noFindings record that has findings fails', run(f, r), /noFindings: 20261103-c\.md has extracted findings/);
	}
	{
		// --base: what's new since the merge base (QQQ-5, QQQ-6, QQQ-7).
		const f = base();
		f.set(`${REVIEWS}/20261101-a.md`, `${f.get(`${REVIEWS}/20261101-a.md`)!}\n## Round C\n${table}| — | Low | x | appended | Fixed | f |\n| C-2 | Note | x | y | z | w |\n`);
		const r = reg();
		r.findings.push({ record: '20261101-a.md', anchor: '—#3', severity: 'low', summary: 's', component: 'c', owner: 'o', status: 'open', gap: 'g' });
		r.findings.push({ record: '20261101-a.md', anchor: 'C-2', severity: 'info', summary: 's', component: 'c', owner: 'o', status: 'open', gap: 'g' });
		expect('a legacy row with no severity word needs a severityNote (SSS-6)', run(f, r), /C-2: the record gives no severity word/);
		r.findings[5].severityNote = 'a note; nothing to fix';
		expect('control: without --base, legacy shapes are only registered', run(f, r), null);
		expect('a new placeholder ID fails against the base, whatever the record\'s date', run(f, r, true, reg()), /new finding "—#3" needs a unique explicit ID/);
		expect('a new finding with no severity word fails against the base', run(f, r, true, reg()), /new finding "C-2" needs a severity/);
		const r2 = reg();
		Object.assign(r2.findings[0], { status: 'open', gap: 'g' });
		delete r2.findings[0].commit;
		delete r2.findings[0].test;
		r2.baseline.push('20261101-a.md#A-1');
		expect('a key added to the baseline fails against the base (it only shrinks)', run(base(), r2, true, reg()), /baseline: 20261101-a\.md#A-1 is new/);
		expect('control: a key the base already had passes', run(base(), r2, true, r2), null);
		// Conservation against the base (SSS-1).
		const r3 = reg();
		r3.findings[0].severity = 'critical';
		expect('a severity lowered since the merge base fails, even if the record was edited too', run(base(), reg(), true, r3), /severity dropped from critical to high since the merge base/);
		const r4 = reg();
		r4.findings.push({ record: '20261101-a.md', anchor: 'A-7', severity: 'low', summary: 's', component: 'c', owner: 'o', status: 'open', gap: 'g' });
		expect('a finding removed since the merge base fails', run(base(), reg(), true, r4), /A-7: in the merge base's register but gone/);
		const openHigh = () => {
			const x = reg();
			Object.assign(x.findings[0], { status: 'open', gap: 'g' });
			delete x.findings[0].commit;
			delete x.findings[0].test;
			return x;
		};
		const was = openHigh();
		was.baseline = ['20261101-a.md#A-1'];
		const now = openHigh();
		now.findings[0].severity = 'high';
		expect('an open high that left the baseline since the merge base fails', run(base(), now, true, was), /left the baseline but is open/);
		// A finding that moved names its earlier key (TTT-6), under the UUU-2/UUU-3 rules.
		const inc = (anchor: string, sev: Sev = 'low'): Finding => ({ record: null, anchor, severity: sev, summary: 's', component: 'c', owner: 'o', status: 'open', gap: 'g', ref: { file: EDR, quote: 'only on main' } });
		const before = reg();
		before.findings.push(inc('INC-9'));
		const after = reg();
		after.findings.push({ ...inc('INC-10'), wasKey: 'register#INC-9' });
		expect('control: a finding moved under wasKey is conserved', run(base(), after, true, before), null);
		delete after.findings[4].wasKey;
		expect('the same move without wasKey fails', run(base(), after, true, before), /register#INC-9: in the merge base's register but gone/);
		const launder = reg();
		launder.findings[0].wasKey = 'register#INC-9';
		expect('wasKey on an entry the base already had can\'t launder a removal (UUU-2)', run(base(), launder, true, before), /wasKey register#INC-9: 20261101-a\.md#A-1 was already in the merge base's register/);
		const twice = reg();
		twice.findings.push({ ...inc('INC-10'), wasKey: 'register#INC-9' }, { ...inc('INC-11'), wasKey: 'register#INC-9' });
		expect('one earlier key claimed by two entries fails (UUU-2)', run(base(), twice, true, before), /claimed by 2 entries/);
		const live = reg();
		live.findings.push(inc('INC-9'), { ...inc('INC-10'), wasKey: 'register#INC-9' });
		expect('wasKey naming a finding that still exists fails (UUU-2)', run(base(), live, true, before), /that finding still exists/);
		// XXX-5: renaming an owner-accepted high: its landed row under the old key still counts.
		const acc = (anchor: string): Finding => ({ record: null, anchor, severity: 'high', summary: 's', component: 'c', owner: 'o', status: 'accepted-residual', acceptedBy: 'owner', rationale: 'r', ref: { file: EDR, quote: 'only on main' } });
		const wasAcc = reg();
		wasAcc.findings.push(acc('INC-30'));
		const oldRow = ownerTable(ownerRow('register#INC-30'));
		const renamed = reg();
		renamed.findings.push({ ...acc('INC-31'), wasKey: 'register#INC-30' });
		const keep = base();
		keep.set(OWNER_FILE, oldRow);
		expect('control: a renamed owner-accepted high keeps its landed row under wasKey (XXX-5)', run(keep, renamed, true, wasAcc, { files: new Set(), before: new Map(), ownerBefore: oldRow }), null);
		const rekeyed = base();
		rekeyed.set(OWNER_FILE, ownerTable(ownerRow('register#INC-31')));
		expect('control: its row rekeyed in the same change still counts as landed (XXX-5)', run(rekeyed, renamed, true, wasAcc, { files: new Set([OWNER_FILE]), before: new Map([[OWNER_FILE, oldRow]]), ownerBefore: oldRow }), null);
		const noOld = reg();
		noOld.findings.push({ ...acc('INC-31'), wasKey: 'register#INC-30' });
		expect('a rename does not land a row the base never had (XXX-5)', run(rekeyed, noOld, true, wasAcc, { files: new Set([OWNER_FILE]), before: new Map(), ownerBefore: null }), /land the owner's row first/);
		// UUU-3: a new open high can't ride into the baseline on another key's wasKey.
		const wasB = openHigh();
		wasB.baseline = ['20261101-a.md#A-1'];
		const grow = openHigh();
		grow.baseline = ['20261101-a.md#A-1', 'register#INC-12'];
		grow.findings.push({ ...inc('INC-12', 'high'), wasKey: '20261101-a.md#A-1' });
		expect('a new high can\'t join the baseline via wasKey of a live baseline key (UUU-3)', run(base(), grow, true, wasB), /baseline: register#INC-12 is new/);
		// VVV-2: a fresh, unrelated entry can't take a deleted baselined high's place.
		const wasInc = reg();
		wasInc.findings.push(inc('INC-20', 'high'));
		wasInc.baseline = ['register#INC-20'];
		const subst = reg();
		subst.findings.push({ ...inc('INC-21', 'high'), summary: 'an unrelated new finding', wasKey: 'register#INC-20' });
		subst.baseline = ['register#INC-21'];
		expect('wasKey substitution by an unrelated entry fails (VVV-2)', run(base(), subst, true, wasInc), /isn't the same finding/);
		subst.findings[4].summary = 's';
		expect('control: a genuine move keeps its place in the baseline', run(base(), subst, true, wasInc), null);
	}
	{
		const r = reg();
		r.baseline.push('20261101-a.md#gone');
		expect('baseline mode: an unresolved key is a problem', baselineProblems(mkTree(base()), r), /has no register entry/);
		expect('baseline mode: the header counts every key', /baseline: 1 open/.test(baselineText(r)) ? [] : ['header'], null);
		// Escape-aware scan of the rendered view: no raw HTML, no live link, no extra cell (SSS-7).
		const live = (line: string, ch: string) => {
			const at: number[] = [];
			for (let i = 0; i < line.length; i++) {
				if (line[i] === '\\') {
					i++;
				} else if (line[i] === ch) {
					at.push(i);
				}
			}
			return at;
		};
		r.findings[2].gap = '<script>x</script> [link](https://example.invalid) a|b \\[y\\](https://example.invalid/2) c\\|d `e|f` bare https://example.invalid/4 and www.example.invalid';
		r.owners.o.session = 'Owner [x](https://example.invalid/3)';
		const v = render(r);
		const row = v.split('\n').find(l => l.includes('example.invalid/2') && l.startsWith('| ') && l.includes('open')) ?? '';
		const header = v.split('\n').find(l => l.startsWith('| Finding | Sev | Status | Component | Summary |')) ?? '';
		expect('the view has no raw HTML from register text', /<script>/.test(v) ? ['raw html'] : [], null);
		expect('the view has no live link from register text, backslash tricks included', v.split('\n').some(l => live(l, ']').some(i => l.startsWith('(https://example.invalid', i + 1))) ? ['live link'] : [], null);
		expect('a register cell stays one cell, backslash tricks included', live(row, '|').length === live(header, '|').length ? [] : [`${live(row, '|').length} vs ${live(header, '|').length}`], null);
		expect('a bare URL in register text is not autolinked (TTT-10)', /https:\/\/example\.invalid\/4|www\.example/.test(v) ? ['autolink'] : [], null);
	}
	{
		const f = base();
		const r = reg();
		f.set(VIEW, 'hand edited');
		expect('a stale FINDINGS.md fails', run(f, r, false), /FINDINGS\.md is stale/);
	}
	{
		const r = reg();
		r.findings[0].status = 'false-positive';
		Object.assign(r.findings[0], { rationale: 'r', ref: { file: EDR, quote: USERQ } });
		delete r.findings[0].test;
		delete r.findings[0].commit;
		expect('a false positive not concluded by a review record fails', run(base(), r), /a false positive cites the review record/);
		r.findings[0].ref = { file: `${REVIEWS}/20261101-a.md`, quote: '| bad |' };
		expect('a high false positive by an agent fails (TTT-1)', run(base(), r), /false-positive by an agent only/);
		r.findings[0].acceptedBy = 'owner';
		delete r.findings[0].ref;
		const fo = base();
		fo.set(OWNER_FILE, ownerTable(ownerRow('20261101-a.md#A-1')));
		expect('control: a high false positive the owner decided, with its row, passes', run(fo, r), null);
		const low = reg();
		Object.assign(low.findings[2], { status: 'false-positive', rationale: 'r', ref: { file: `${REVIEWS}/20261101-a.md`, quote: '| r2 |' } });
		delete low.findings[2].gap;
		expect('control: a low false positive concluded by its review record passes', run(base(), low), null);
	}
	{
		const r = reg();
		r.findings.push({ record: null, anchor: 'INC-1', severity: 'medium', summary: 's', component: 'c', owner: 'o', status: 'fixed-untested', gap: 'g', ref: { file: EDR, quote: 'only on main' } });
		expect('control: an incident with a ref passes', run(base(), r), null);
		delete r.findings[4].ref;
		expect('an incident without a ref fails', run(base(), r), /no review record needs ref/);
	}
	console.log(failed ? `findings self-test: ${failed} failed` : 'findings self-test: ok');
	return failed ? 1 : 0;
}

// ---- modes ------------------------------------------------------------------------------------

// Output goes through process.exitCode, never process.exit(), which would cut a piped stdout short.
function main(): number {
	const repo = path.resolve(import.meta.dirname, '../..');
	const [mode, arg] = process.argv.slice(2);
	if (mode === '--self-test') {
		return selfTest();
	}
	if (mode === 'extract') {
		const dir = path.resolve(arg ?? path.join(repo, REVIEWS));
		const all = fs.readdirSync(dir).filter(isRecordName).sort().flatMap(f => extract(f, fs.readFileSync(path.join(dir, f), 'utf8')).items);
		process.stdout.write(`${JSON.stringify(all, null, '\t')}\n`);
		return 0;
	}
	const tree = diskTree(repo);
	const reg = JSON.parse(tree.read(REGISTER)) as Register;
	const sp = schemaProblems(reg);
	if (mode === 'write') {
		sp.forEach(x => console.log(x));
		if (sp.length) {
			return 1;
		}
		fs.writeFileSync(path.join(repo, VIEW), render(reg, tree));
		console.log(`findings: wrote ${VIEW}`);
		return 0;
	}
	if (mode === 'commits') {
		sp.forEach(x => console.error(x));
		const lines = sp.length ? [] : reg.findings.filter(f => f.status === 'fixed' && !f.branch && f.commit).map(f => `${keyOf(f)}\t${f.commit}\n`);
		process.stdout.write(lines.join(''));
		return sp.length ? 1 : 0;
	}
	if (mode === 'shas') { // "<token>\t<0|1 upstream>\t<branch or ->\t<0|1 touched>\t<use>"; [--base FILE]
		sp.forEach(x => console.error(x));
		const bf = arg === '--base' ? process.argv[4] : undefined;
		if (arg !== undefined && (arg !== '--base' || !bf || process.argv.length > 5)) {
			console.error('usage: findings.ts shas [--base FILE]');
			return 2;
		}
		const btext = bf ? fs.readFileSync(path.resolve(repo, bf), 'utf8') : '';
		const c = sp.length ? undefined : citations(tree, reg, btext.trim() ? JSON.parse(btext) as Register : undefined);
		process.stdout.write((c?.cite ?? []).map(x => `${x.token}\t${x.tolerated ? 1 : 0}\t${x.branch ?? '-'}\t${x.touched ? 1 : 0}\t${x.use.replace(/[\t\n]/g, ' ')}\n`).join(''));
		if (c) {
			console.error(`findings: ${c.historical.length} round-label citations are their records' own (append-only, listed in FINDINGS.md)`);
		}
		return sp.length || c?.problems.length ? 1 : 0;
	}
	if (mode === 'remap') { // remap BRANCH PAIRS_FILE: rewrites the register in place
		const pairsFile = process.argv[4];
		if (sp.length || !arg || !/^[A-Za-z0-9._/-]+$/.test(arg) || arg.includes('..') || !pairsFile) {
			sp.forEach(x => console.error(x));
			console.error('usage: findings.ts remap BRANCH PAIRS_FILE');
			return 2;
		}
		const pairs = fs.readFileSync(path.resolve(repo, pairsFile), 'utf8').split('\n').filter(Boolean).map(l => l.split('\t') as [string, string]);
		const { changed } = remapBranch(reg, arg, pairs);
		fs.writeFileSync(path.join(repo, REGISTER), `${JSON.stringify(reg, null, '\t')}\n`);
		console.log(`findings: remapped ${changed.length} field(s) in ${arg}'s entries`);
		return 0;
	}
	if (mode === 'baseline') {
		sp.forEach(x => console.error(x));
		if (sp.length) {
			return 1;
		}
		const bp = baselineProblems(tree, reg);
		process.stdout.write(baselineText(reg));
		bp.forEach(x => console.error(x));
		return bp.length ? 1 : 0;
	}
	const opts = process.argv.slice(3);
	const opt = (name: string) => {
		const i = opts.indexOf(name);
		return i >= 0 ? opts[i + 1] : undefined;
	};
	if (mode !== 'check' || opts.length % 2 || opts.some((o, i) => i % 2 === 0 && !['--base', '--changed', '--before'].includes(o)) || opts.some((o, i) => i % 2 === 1 && !o) || (opts.includes('--before') && !opts.includes('--changed'))) {
		console.error('usage: findings.ts check [--base FILE] [--changed FILE [--before DIR]] | write | commits | baseline | extract [DIR] | --self-test');
		return 2;
	}
	// --base: the register at the merge base (written by ./seclab from git; empty when the base
	// predates the register, which skips the new-finding and shrink rules). --changed: the files
	// the change touches, one per line (UUU-4).
	let base: Register | undefined;
	const baseFile = opt('--base');
	if (baseFile) {
		const text = fs.readFileSync(path.resolve(repo, baseFile), 'utf8');
		base = text.trim() ? JSON.parse(text) as Register : undefined;
		console.log(base ? `findings: base register has ${base.findings.length} findings, ${base.baseline.length} in the baseline` : 'findings: no register at the merge base; new-finding and shrink rules skipped');
	}
	const changedFile = opt('--changed');
	const beforeDir = opt('--before');
	let change: Change | undefined;
	if (changedFile) {
		const files = new Set(fs.readFileSync(path.resolve(repo, changedFile), 'utf8').split('\n').filter(Boolean));
		const before = new Map<string, string>();
		for (const f of files) {
			const at = beforeDir && !pathProblem(f) ? path.resolve(repo, beforeDir, f) : undefined;
			if (at && fs.existsSync(at)) {
				before.set(f, fs.readFileSync(at, 'utf8'));
			}
		}
		change = { files, before };
		if (beforeDir) {
			const at = path.resolve(repo, beforeDir, OWNER_FILE);
			change.ownerBefore = fs.existsSync(at) ? fs.readFileSync(at, 'utf8') : null;
		}
	} else {
		console.log('findings: no --changed list; the rule that a decision lands before the closure (UUU-4) is skipped');
	}
	const problems = check(tree, reg, sp.length ? undefined : render(reg, tree), base, change);
	problems.forEach(x => console.log(x));
	const open = sp.length ? 0 : reg.findings.filter(f => f.status !== 'fixed' && f.status !== 'false-positive').length;
	console.log(problems.length ? `findings: ${problems.length} problem(s)` : `findings: ok (${reg.findings.length} findings, ${open} not fixed, ${reg.baseline.length} in the baseline)`);
	return problems.length ? 1 : 0;
}
process.exitCode = main();
