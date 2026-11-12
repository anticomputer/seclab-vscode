// Internal-identifier scan: no tracked file and no run record may contain an identifier on the
// denylist.
//
// The denylist is never in the repo, in clear or hashed (a hash of a short identifier can be
// recovered by a dictionary attack). It lives in a GitHub Actions secret (CI) and in a file
// outside the repo for developers (default ~/.config/seclab/denylist.txt, chmod 600, or
// SECLAB_DENYLIST_FILE): one identifier per line, '#' starts a comment. It reaches this tool
// only as a file, never through argv or the environment of a step that runs anything else.
//
// Text is NFKC-folded and lower-cased, then split into words on anything that is not a letter, a
// digit or an identifier joiner (`-`, `_`, `.`); inside a word, runs of joiners become `-`. An
// entry matches when its words appear in order (windows may span a line break): a one-word entry
// anywhere inside a word at joiner boundaries (`x-y` in `a.x_y.b`), a longer one with its first
// word ending and its last word starting a text word at a joiner boundary and the rest equal. So
// a listed identifier is found however it is cased or joined, inside a URL or a path, but a
// hyphenated entry does not match the same words written as prose with spaces, which can be a
// public product name (grep -F semantics, punctuation-tolerant). See parseList for separators,
// slugs and wrapped words. A finding names the file and line, never the matched text: CI logs are
// public.
//
//   git ls-files -z | node build/check-denylist.ts check - --list FILE [--require-list] [--extra DIR]...
//   node build/check-denylist.ts git-push --git-dir DIR --list FILE --ref NAME TIP [BASE]
//   node build/check-denylist.ts git-tree --git-dir DIR --list FILE --ref NAME SHA
//   node build/check-denylist.ts --self-test
// Without --require-list a missing or empty list skips with a notice (exit 0); with it, that is
// a failure (exit 1). The git modes always require the list. Wrapped by `./seclab lint denylist
// [--self-test]`, the CI steps (build/ci-denylist.sh) and the pre-push hook (build/hooks).
//
// git-push scans what a push publishes for one ref: the ref name, and for every commit in
// TIP --not BASE --remotes=origin its message, the paths it touches and the lines it adds (a
// removed or unchanged line is already public). git-tree scans one commit as it stands: the ref
// name, its message, every path and every blob. Both read the repository only through git
// plumbing with no hooks, filters or textconv, so a pushed tree is data, never code (review
// round 19). A diff line the parser does not recognise is scanned too, never dropped.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { spawnSync } from 'node:child_process';

interface Finding { file: string; line: number }

const repo = path.resolve(import.meta.dirname, '..');
const MAX_TOKENS = 16;
export const MAX_FILE_BYTES = 64 << 20;

interface Word { w: string; sep: string; line: number }

/** Words with the non-whitespace separator before each one and the line it starts on. */
function splitWords(text: string): Word[] {
	// NFKC folds fullwidth and compatibility forms; format characters (zero-width joiners and
	// the like) are dropped so they cannot split a word. Cross-script lookalikes are not
	// folded: this catches accidents, it is not an adversary filter.
	const t = text.normalize('NFKC').replace(/\p{Cf}/gu, '').toLowerCase();
	const out: Word[] = [];
	let line = 1;
	let last = 0;
	let sep = '';
	let joinerEnd = false;
	for (const m of t.matchAll(/[a-z0-9._-]+/g)) {
		const gap = t.slice(last, m.index);
		const breaks = gap.split('\n').length - 1;
		line += breaks;
		last = m.index + m[0].length;
		const w = m[0].replace(/[._-]+/g, '-').replace(/^-+|-+$/g, '');
		// A word wrapped at a joiner (`fake-\npipeline`) is one word (R21-4).
		if (w && joinerEnd && breaks === 1 && /^\s*$/.test(gap) && out.length) {
			out[out.length - 1].w += `-${w}`;
		} else if (w) {
			out.push({ w, sep: sep + gap.replace(/\s+/g, ''), line });
			sep = '';
		} else {
			sep += gap.replace(/\s+/g, '');
		}
		joinerEnd = /[._-]$/.test(m[0]);
	}
	return out;
}

export function tokens(text: string): string[] {
	return splitWords(text).map(x => x.w);
}

/** Marks an entry word that must follow a non-whitespace separator in the text. */
const AFTER_SEP = '\u0001';
/** Path- and key-like separators (`/`, `\`, `:`, `|`, `@`, with quotes for JSON); prose punctuation such as `(` or `,` is not one. */
const PATH_SEP = /^["'`]*[/\\:|@]+["'`]*$/;

/**
 * The entries of a list file's text, as word sequences. A word an entry writes after a
 * non-whitespace separator (`owner/name`) must follow one in the text too (any separator: `/`,
 * `\`, `:`, a JSON quote-colon; R21-3), so the same words as spaced prose don't match. Every
 * multi-word entry is also indexed as one joined word (`owner-name`, a slug of a spaced name;
 * R21-1). A control character in an entry is refused: the list must be plain text (R21-5).
 */
export function parseList(text: string): string[][] {
	const out: string[][] = [];
	for (const raw of text.split('\n').map(l => l.replace(/#.*$/, '').trim()).filter(Boolean)) {
		if (/[\u0000-\u0008\u000b-\u001f\u007f]/.test(raw)) {
			throw new Error('the known-names list holds a control character; save it as plain UTF-8 text');
		}
		const ws = splitWords(raw);
		if (ws.length === 0 || ws.length > MAX_TOKENS) {
			continue;
		}
		out.push(ws.map((x, i) => i > 0 && x.sep ? `${AFTER_SEP}${x.w}` : x.w));
		if (ws.length > 1) {
			out.push([ws.map(x => x.w).join('-')]);
		}
	}
	return out;
}

/** The list file's entries; a missing, unreadable or malformed list is empty, and callers fail closed on empty. */
export function readList(file: string | undefined): string[][] {
	if (!file || !fs.existsSync(file)) {
		return [];
	}
	try {
		return parseList(fs.readFileSync(file, 'utf8'));
	} catch (e) {
		console.error(`denylist: ${printable(String((e as Error).message)).slice(0, 200)}`);
		return [];
	}
}

/**
 * Whether a location mentions an entry in any form: every entry word, in order, in the location's
 * letters and digits with everything else dropped. Over-matches on purpose: it decides whether a
 * location is withheld from output, never whether something is a finding (R21-2).
 */
export function mentionsLoosely(text: string, entries: string[][]): boolean {
	const flat = text.normalize('NFKC').replace(/\p{Cf}/gu, '').toLowerCase().replace(/[^a-z0-9]+/g, '');
	return entries.some(e => {
		const needle = e.map(w => w.replace(AFTER_SEP, '')).join('').replace(/[^a-z0-9]+/g, '');
		return needle.length > 0 && flat.includes(needle);
	});
}

const within = (word: string, part: string) => `-${word}-`.includes(`-${part}-`);
const endsWith = (word: string, part: string) => word === part || word.endsWith(`-${part}`);
const startsWith = (word: string, part: string) => word === part || word.startsWith(`${part}-`);

/** Whether the text words at `at` begin a match of `entry`. */
function matchesAt(words: Word[], at: number, entry: string[]): boolean {
	const n = entry.length;
	if (at + n > words.length) {
		return false;
	}
	if (n === 1) {
		return within(words[at].w, entry[0]);
	}
	for (let k = 1; k < n; k++) {
		const needsSep = entry[k].startsWith(AFTER_SEP);
		const w = needsSep ? entry[k].slice(1) : entry[k];
		if (needsSep && !PATH_SEP.test(words[at + k].sep)) {
			return false;
		}
		if (k < n - 1 ? words[at + k].w !== w : !startsWith(words[at + k].w, w)) {
			return false;
		}
	}
	return endsWith(words[at].w, entry[0]);
}

/** Lines where an entry's words begin (windows may span lines). */
export function scanText(file: string, text: string, entries: string[][]): Finding[] {
	if (entries.length === 0) {
		return [];
	}
	const words = splitWords(text);
	const lines = new Set<number>();
	for (let i = 0; i < words.length; i++) {
		if (!lines.has(words[i].line) && entries.some(e => matchesAt(words, i, e))) {
			lines.add(words[i].line);
		}
	}
	return [...lines].sort((a, b) => a - b).map(line => ({ file, line }));
}

/** Extensions that are always text: one of these the scan could not read is a failure, not a skip. */
export const TEXT_EXT = /\.(?:ts|js|mjs|cjs|json|jsonc|md|txt|sh|py|yml|yaml|toml|html|css|patch|diff|log|csv|xml|plist|jxa|ini|cfg|conf|env)$/i;

type Scanned = { findings: Finding[]; skipped?: string };

function scanFile(rel: string, abs: string, entries: string[][]): Scanned {
	let st: fs.Stats;
	try { st = fs.lstatSync(abs); } catch { return { findings: [], skipped: 'missing' }; }
	if (st.isSymbolicLink()) {
		return { findings: [], skipped: 'symlink' }; // its target, if tracked, is scanned as itself
	}
	if (!st.isFile()) {
		return { findings: [], skipped: 'not a file' };
	}
	if (st.size > MAX_FILE_BYTES) {
		return { findings: [], skipped: 'oversized' };
	}
	const buf = fs.readFileSync(abs);
	if (buf.subarray(0, 8000).includes(0)) {
		return { findings: [], skipped: 'binary' };
	}
	return { findings: scanText(rel, buf.toString('utf8'), entries) };
}

/** A path as printed: no control characters, no workflow-command syntax. */
export function printable(p: string): string {
	return p.replace(/[\u0000-\u001f\u007f]/g, '?').replace(/::/g, ': :').replace(/%/g, '%25');
}

function walk(dir: string): string[] {
	const out: string[] = [];
	for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
		const p = path.join(dir, e.name);
		if (e.isDirectory()) {
			out.push(...walk(p));
		} else if (e.isFile()) {
			out.push(p);
		}
	}
	return out;
}

/** A piece of text to scan; `lines` maps its line i (1-based) to the line it reports; `file` is the path it came from. */
export interface Unit { where: string; text: string; lines?: number[]; file?: string }

export function scanUnits(units: Unit[], entries: string[][]): Finding[] {
	return units.flatMap(u => scanText(u.where, u.text, entries)
		.map(f => ({ file: u.where, line: u.lines ? (u.lines[f.line - 1] ?? 0) : f.line })));
}

const HEADER = /^(?:index |--- |new file mode |deleted file mode |old mode |new mode |Binary files |similarity index |dissimilarity index |rename from |rename to |copy from |copy to |\\ )/;

/**
 * The units of one commit's patch (`git diff-tree -p`): each file's added lines, numbered as in
 * the new file, and each path. Hunk bodies are consumed by their header's counts, so an added
 * line that looks like a header is still an added line. Removed and context lines are already
 * public. Anything else is scanned as an unparsed unit rather than dropped.
 */
export function diffUnits(diff: string, where: string): Unit[] {
	const out: Unit[] = [];
	const other: string[] = [];
	let file = '?';
	let pathDone = true;
	let added: string[] = [];
	let nums: number[] = [];
	let oldLeft = 0;
	let newLeft = 0;
	let n = 0;
	const flush = () => {
		if (added.length) {
			out.push({ where: `${where} ${file}`, text: added.join('\n'), lines: nums, file });
		}
		added = [];
		nums = [];
	};
	// A path is published when the commit writes it (a `+++` side or a new, possibly empty,
	// file); a deleted path is already public.
	const publishPath = () => {
		if (!pathDone) {
			out.push({ where: `${where} (path)`, text: file });
			pathDone = true;
		}
	};
	for (const l of diff.split('\n')) {
		if (oldLeft > 0 || newLeft > 0) {
			const c = l[0];
			if (c === '+') {
				added.push(l.slice(1));
				nums.push(n++);
				newLeft--;
			} else if (c === '-') {
				oldLeft--;
			} else if (c === ' ') {
				n++;
				oldLeft--;
				newLeft--;
			} else if (c !== '\\') {
				other.push(l);
				oldLeft = newLeft = 0;
			}
			continue;
		}
		const m = /^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(l);
		if (m) {
			oldLeft = m[1] === undefined ? 1 : Number(m[1]);
			n = Number(m[2]);
			newLeft = m[3] === undefined ? 1 : Number(m[3]);
		} else if (l.startsWith('diff --git ')) {
			flush();
			file = l.slice('diff --git '.length);
			pathDone = false;
		} else if (l.startsWith('+++ ')) {
			if (l !== '+++ /dev/null') {
				file = l.slice(4).replace(/^b\//, '');
				publishPath();
			}
		} else if (l.startsWith('new file mode ')) {
			publishPath();
		} else if (l !== '' && !HEADER.test(l)) {
			other.push(l);
		}
	}
	flush();
	if (other.length) {
		out.push({ where: `${where} (unparsed diff lines)`, text: other.join('\n') });
	}
	return out;
}

/** git with no user or system config, hooks, filters, textconv or pager; read-only plumbing only. */
export function git(gitDir: string, args: string[], input?: string): Buffer {
	const r = spawnSync('git', ['-c', 'safe.directory=*', '-c', 'core.quotePath=false', '--no-pager', `--git-dir=${gitDir}`, ...args], {
		input,
		maxBuffer: 1 << 30,
		env: { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: '/nonexistent', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0' },
	});
	if (r.status !== 0) {
		throw new Error(`git ${args[0]} failed (exit ${r.status}): ${String(r.stderr).split('\n')[0].slice(0, 200)}`);
	}
	return r.stdout;
}

export const HEX40 = /^[0-9a-f]{40}$/;

export function commitUnits(gitDir: string, sha: string): Unit[] {
	const short = sha.slice(0, 12);
	return [
		{ where: `${short} (message)`, text: git(gitDir, ['log', '-1', '--format=%B', sha]).toString('utf8') },
		...diffUnits(git(gitDir, ['diff-tree', '-p', '-m', '--root', '--no-commit-id', '--text', '--no-renames', '--no-ext-diff', '--no-textconv', '--no-color', sha]).toString('utf8'), short),
	];
}

/** Units for what pushing TIP publishes: every commit not yet on BASE or any origin ref. */
export function pushScanUnits(gitDir: string, tip: string, base?: string): Unit[] {
	const revs = git(gitDir, ['rev-list', tip, ...(base ? [`^${base}`] : []), '--not', '--remotes=origin']).toString('utf8').split('\n').filter(Boolean);
	if (!revs.every(r => HEX40.test(r))) {
		throw new Error('unexpected rev-list output');
	}
	return revs.flatMap(r => commitUnits(gitDir, r));
}

export type Blob = { path: string; data?: Buffer; skipped?: string };

/** Every blob of SHA's tree by path, read with `cat-file --batch` (no filters). */
export function treeBlobs(gitDir: string, sha: string): Blob[] {
	const entries = git(gitDir, ['ls-tree', '-r', '-z', '--full-tree', sha]).toString('utf8').split('\0').filter(Boolean).map(e => {
		const m = /^(\d{6}) (\w+) ([0-9a-f]{40})\t([\s\S]+)$/.exec(e);
		if (!m) {
			throw new Error('unexpected ls-tree output');
		}
		return { type: m[2], oid: m[3], path: m[4] };
	});
	const blobs = entries.filter(e => e.type === 'blob');
	const out: Blob[] = entries.filter(e => e.type !== 'blob').map(e => ({ path: e.path, skipped: e.type }));
	const raw = git(gitDir, ['cat-file', '--batch'], blobs.map(b => b.oid).join('\n') + '\n');
	let at = 0;
	for (const b of blobs) {
		const nl = raw.indexOf(10, at);
		const head = /^([0-9a-f]{40}) blob (\d+)$/.exec(raw.subarray(at, nl).toString('latin1'));
		if (!head || head[1] !== b.oid) {
			throw new Error(`cat-file: unexpected object for ${printable(b.path)}`);
		}
		const size = Number(head[2]);
		const data = raw.subarray(nl + 1, nl + 1 + size);
		at = nl + 1 + size + 1;
		out.push(size > MAX_FILE_BYTES ? { path: b.path, skipped: 'oversized' }
			: data.subarray(0, 8000).includes(0) ? { path: b.path, skipped: 'binary' } : { path: b.path, data });
	}
	return out;
}

function report(findings: Finding[], skipped: Array<{ rel: string; skipped?: string }>, required: boolean, summary: string, entries: string[][]): number {
	// A path that itself holds an identifier is never printed (its own finding says so).
	const shown = (p: string) => scanText('', p, entries).length || mentionsLoosely(p, entries) ? '(a path that holds an identifier, not printed)' : printable(p);
	for (const f of findings) {
		console.error(`denylist: ${shown(f.file)}:${f.line}: holds a denylisted internal identifier (not printed)`);
	}
	// Nothing is dropped silently: every skipped file is named, and a text-type file the scan
	// could not read is a failure when the scan is required (review round 17).
	const unreadText = skipped.filter(s => s.skipped !== 'symlink' && TEXT_EXT.test(s.rel));
	for (const s of skipped) {
		console.log(`denylist: skipped ${shown(s.rel)} (${s.skipped})`);
	}
	if (required && unreadText.length > 0) {
		console.error(`denylist: ${unreadText.length} text file(s) could not be scanned; failing closed`);
	}
	console.log(findings.length ? `denylist: ${findings.length} finding(s); ${summary}` : `denylist: clean (${summary})`);
	return findings.length || (required && unreadText.length > 0) ? 1 : 0;
}

/** git-push / git-tree: the list is always required; any git or parse failure fails closed. */
function gitScan(mode: 'git-push' | 'git-tree', args: string[]): number {
	let gitDir: string | undefined;
	let listFile: string | undefined;
	let ref: string | undefined;
	const revs: string[] = [];
	for (let i = 0; i < args.length; i++) {
		if (args[i] === '--git-dir' && args[i + 1] !== undefined) {
			gitDir = args[++i];
		} else if (args[i] === '--list' && args[i + 1] !== undefined) {
			listFile = args[++i];
		} else if (args[i] === '--ref' && args[i + 1] !== undefined) {
			ref = args[++i];
		} else if (HEX40.test(args[i])) {
			revs.push(args[i]);
		} else {
			console.error(`${mode}: unexpected argument`);
			return 2;
		}
	}
	if (!gitDir || ref === undefined || revs.length < 1 || revs.length > (mode === 'git-push' ? 2 : 1)) {
		console.error(`usage: ${mode} --git-dir DIR --list FILE --ref NAME ${mode === 'git-push' ? 'TIP [BASE]' : 'SHA'}`);
		return 2;
	}
	const entries = readList(listFile);
	if (entries.length === 0) {
		console.error('denylist: no list (or an empty one); this scan is required here, so it fails closed');
		return 1;
	}
	try {
		const refUnit: Unit = { where: '(ref name)', text: ref };
		if (mode === 'git-push') {
			const units = [refUnit, ...pushScanUnits(gitDir, revs[0], revs[1])];
			const commits = new Set(units.map(u => u.where.split(' ')[0])).size - 1;
			return report(scanUnits(units, entries), [], true, `${commits} commit(s), ${entries.length} entr${entries.length === 1 ? 'y' : 'ies'}`, entries);
		}
		const blobs = treeBlobs(gitDir, revs[0]);
		const units: Unit[] = [refUnit, { where: '(message)', text: git(gitDir, ['log', '-1', '--format=%B', revs[0]]).toString('utf8') }];
		for (const b of blobs) {
			units.push({ where: `${b.path} (path)`, text: b.path });
			if (b.data) {
				units.push({ where: b.path, text: b.data.toString('utf8') });
			}
		}
		const skipped = blobs.filter(b => b.skipped).map(b => ({ rel: b.path, skipped: b.skipped }));
		return report(scanUnits(units, entries), skipped, true, `${blobs.length} path(s), ${skipped.length} skipped, ${entries.length} entr${entries.length === 1 ? 'y' : 'ies'}`, entries);
	} catch (e) {
		console.error(`denylist: the scan could not run (${printable(String((e as Error).message)).slice(0, 200)}); failing closed`);
		return 1;
	}
}

function selfTest(): number {
	const bad: string[] = [];
	let cases = 0;
	const expect = (name: string, ok: boolean) => { cases++; if (!ok) { bad.push(name); } };
	// Obviously fake entries: made-up names under the reserved .invalid TLD.
	const entries = parseList([
		'# a comment line',
		'feeds.fake-internal.invalid/fake-path/fake-secret-feed   # trailing comment',
		'fake-pipeline-internal',
		'',
	].join('\n'));
	// Two list lines: the multi-word one is indexed as written and as one joined word (R21-1).
	expect('comments and blank lines are not entries', entries.length === 3);
	const hits = (t: string) => scanText('t', t, entries);
	expect('a listed identifier is found', hits('registry=https://feeds.fake-internal.invalid/fake-path/fake-secret-feed/npm/').length === 1);
	expect('whatever its case and joiners', hits('see FEEDS.Fake_Internal.invalid/fake_path/FAKE-secret-FEED').length === 1);
	expect('a separator the entry names must be there', hits('see feeds.fake-internal.invalid fake-path fake-secret-feed').length === 0);
	expect('across a line break, reported at its first line',
		hits('x\nfeeds.fake-internal.invalid/\nfake-path/fake-secret-feed')[0]?.line === 2);
	expect('a second entry', hits('the fake_pipeline_internal job').length === 1);
	expect('a prefix of an entry is not a match', hits('feeds.fake-internal.invalid/fake-path/fake-secret').length === 0);
	expect('unrelated text is clean', hits('github.com/microsoft/vscode, packages and feeds').length === 0);
	expect('an empty list matches nothing', scanText('t', 'fake-pipeline-internal', []).length === 0);
	expect('a finding carries no text', JSON.stringify(hits('fake-pipeline-internal')) === '[{"file":"t","line":1}]');
	expect('fullwidth and zero-width forms fold to the entry', hits('ｆａｋｅ-pipe\u200bline-internal').length === 1);
	// A hyphenated entry is an identifier: it matches inside dotted or slashed names and in any
	// joiner form, but not the same words as prose, which can be a public product name.
	expect('inside a dotted host', hits('see build.fake-pipeline-internal.example.invalid').length === 1);
	expect('not as spaced prose', hits('the fake pipeline internal job').length === 0);
	expect('not as part of a longer word', hits('fake-pipeline-internals and xfake-pipeline-internal').length === 0);
	expect('an entry written with spaces matches prose', scanText('t', 'Fake  Prose\tName here', parseList('fake prose name')).length === 1);
	// Round 21: each recall regression and the withholding invariant, as measured by the reviewer.
	const spaced = parseList('fake prose name');
	expect('R21-1: a spaced entry matches its slug', ['fake-prose-name', 'fake_prose_name.ts', 'https://x.invalid/fake-prose-name'].every(t => scanText('t', t, spaced).length === 1));
	const slashed = parseList('owner/name');
	expect('R21-3: a named separator matches any separator', ['see owner/name here', 'see owner / name here', 'see owner:name here', 'C:\\x\\owner\\name', '{"owner": "name"}', 'see owner.name here', 'see owner-name here'].every(t => scanText('t', t, slashed).length === 1));
	expect('R21-3: but not the same words as spaced prose or a parenthesis', ['see Owner name here', 'Owner (name extension)', 'owner, name'].every(t => scanText('t', t, slashed).length === 0));
	expect('R21-4: a word wrapped at a joiner', ['the fake-pipeline-\ninternal job', 'the fake-\npipeline-internal job'].every(t => scanText('t', t, entries).length === 1)
		&& scanText('t', 'x\nthe fake-pipeline-\ninternal job', entries)[0]?.line === 2);
	let nul = false;
	try { parseList('foo\u0000bar'); } catch { nul = true; }
	expect('R21-5: a control character in the list is refused', nul);
	const feed = parseList('feeds.fakecorp.invalid/pipeline-x');
	expect('R21-2: a location naming an entry in any form is withheld', ['docs/feeds.fakecorp.invalid/pipeline-x.md', 'docs/feeds.fakecorp.invalid.pipeline-x.md', 'docs/feeds-fakecorp-invalid-pipeline-x.md'].every(p => mentionsLoosely(p, feed)));
	expect('a printed path cannot carry a workflow command', printable('a::stop-commands::x%0A\n.md') === 'a: :stop-commands: :x%250A?.md');

	// Diff parsing: added lines keep their new-file numbers; a removed line is not published;
	// an added line that looks like a header is still added; an unrecognised line is scanned.
	const diff = [
		'diff --git a/f.txt b/f.txt', 'index 1..2 100644', '--- a/f.txt', '+++ b/f.txt',
		'@@ -10,3 +10,4 @@', ' keep', '-fake-pipeline-internal', '+clean', '++++ b/fake-pipeline-internal', ' keep',
		'garbage fake-pipeline-internal',
	].join('\n');
	const du = scanUnits(diffUnits(diff, 'c0ffee'), entries);
	expect('an added line is reported at its new-file line', du.some(f => f.file === 'c0ffee f.txt' && f.line === 12));
	expect('a removed line is not reported', !du.some(f => f.file === 'c0ffee f.txt' && f.line !== 12));
	expect('an unparsed diff line is scanned, not dropped', du.some(f => f.file === 'c0ffee (unparsed diff lines)'));

	// The git modes against a real throwaway repository (container-local temp; the self-test
	// runs with no network). Injected: an identifier in an added line, a message, a path and a
	// ref name; a later removal is clean; no list, an empty list and a bad repo fail closed.
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'denylist-selftest-'));
	try {
		const g = (...a: string[]) => {
			const r = spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'init.defaultBranch=main', '-c', 'commit.gpgsign=false', '-C', tmp, ...a],
				{ env: { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: tmp, GIT_CONFIG_NOSYSTEM: '1' } });
			if (r.status !== 0) {
				throw new Error(`self-test git ${a[0]}: ${r.stderr}`);
			}
			return r.stdout.toString().trim();
		};
		const commit = (msg: string) => { g('add', '-A'); g('commit', '-q', '--allow-empty', '-m', msg); return g('rev-parse', 'HEAD'); };
		g('init', '-q');
		fs.writeFileSync(path.join(tmp, 'a.txt'), 'one\ntwo\n');
		const pub = commit('public base');
		g('update-ref', 'refs/remotes/origin/main', pub);
		fs.writeFileSync(path.join(tmp, 'a.txt'), 'one\ntwo\nsee fake_pipeline_internal here\n');
		const added = commit('add a line');
		const msg = commit('mention FEEDS.fake-internal.invalid/fake-path/fake-secret-feed');
		fs.writeFileSync(path.join(tmp, 'fake-pipeline-internal.md'), 'clean\n');
		const named = commit('a path');
		fs.writeFileSync(path.join(tmp, 'a.txt'), 'one\ntwo\n');
		fs.rmSync(path.join(tmp, 'fake-pipeline-internal.md'));
		const removed = commit('remove both');
		const gd = path.join(tmp, '.git');
		const push = scanUnits(pushScanUnits(gd, named), entries);
		expect('push: an added line', push.some(f => f.file === `${added.slice(0, 12)} a.txt` && f.line === 3));
		expect('push: a commit message', push.some(f => f.file === `${msg.slice(0, 12)} (message)`));
		expect('push: a path', push.some(f => f.file === `${named.slice(0, 12)} (path)`));
		expect('push: commits already on origin are not rescanned', !push.some(f => f.file.startsWith(pub.slice(0, 12))));
		expect('push: a removal publishes nothing new', scanUnits(pushScanUnits(gd, removed, named), entries).length === 0);
		const tree = scanUnits(treeBlobs(gd, named).flatMap(b => [{ where: `${b.path} (path)`, text: b.path }, ...(b.data ? [{ where: b.path, text: b.data.toString('utf8') }] : [])]), entries);
		expect('tree: a blob line', tree.some(f => f.file === 'a.txt' && f.line === 3));
		expect('tree: a path', tree.some(f => f.file === 'fake-pipeline-internal.md (path)'));
		expect('tree: a clean tree is clean', treeBlobs(gd, removed).every(b => !b.data || scanText(b.path, b.data.toString('utf8'), entries).length === 0));
		const listFile = path.join(tmp, 'list.txt');
		fs.writeFileSync(listFile, 'fake-pipeline-internal\n');
		function quiet<T>(f: () => T): T { const [l, e] = [console.log, console.error]; console.log = console.error = () => { }; try { return f(); } finally { [console.log, console.error] = [l, e]; } }
		expect('git-push: a finding fails', quiet(() => gitScan('git-push', ['--git-dir', gd, '--list', listFile, '--ref', 'refs/heads/x', named])) === 1);
		expect('git-push: a ref name fails', quiet(() => gitScan('git-push', ['--git-dir', gd, '--list', listFile, '--ref', 'refs/heads/fake-pipeline-internal', removed, named])) === 1);
		expect('git-push: clean passes', quiet(() => gitScan('git-push', ['--git-dir', gd, '--list', listFile, '--ref', 'refs/heads/x', removed, named])) === 0);
		expect('git-tree: a finding fails', quiet(() => gitScan('git-tree', ['--git-dir', gd, '--list', listFile, '--ref', 'x', named])) === 1);
		expect('git-tree: clean passes', quiet(() => gitScan('git-tree', ['--git-dir', gd, '--list', listFile, '--ref', 'x', removed])) === 0);
		expect('git modes: no list fails closed', quiet(() => gitScan('git-tree', ['--git-dir', gd, '--list', path.join(tmp, 'missing'), '--ref', 'x', removed])) === 1);
		fs.writeFileSync(path.join(tmp, 'empty.txt'), '# only a comment\n');
		expect('git modes: an empty list fails closed', quiet(() => gitScan('git-push', ['--git-dir', gd, '--list', path.join(tmp, 'empty.txt'), '--ref', 'x', removed])) === 1);
		expect('git modes: an unreadable repository fails closed', quiet(() => gitScan('git-tree', ['--git-dir', path.join(tmp, 'nope'), '--list', listFile, '--ref', 'x', removed])) === 1);
		expect('git modes: a non-sha revision is refused', quiet(() => gitScan('git-push', ['--git-dir', gd, '--list', listFile, '--ref', 'x', 'HEAD'])) === 2);
		const printed: string[] = [];
		const keep = [console.log, console.error];
		console.log = console.error = (s: string) => { printed.push(s); };
		try { report([{ file: 'dir/fake-pipeline-internal.md (path)', line: 1 }], [{ rel: 'fake-pipeline-internal.json', skipped: 'binary' }], true, '', entries); } finally { [console.log, console.error] = keep; }
		expect('a path that holds an identifier is never printed', printed.length > 0 && printed.every(s => !tokens(s).some(w => `-${w}-`.includes('-fake-pipeline-internal-'))));
	} finally {
		fs.rmSync(tmp, { recursive: true, force: true });
	}
	console.log(bad.length ? `denylist self-test FAILED: ${bad.join('; ')}` : `denylist self-test: ${cases} cases OK`);
	return bad.length ? 1 : 0;
}

function check(args: string[]): number {
	let listFile: string | undefined;
	let requireList = false;
	let fromStdin = false;
	const extra: string[] = [];
	for (let i = 0; i < args.length; i++) {
		if (args[i] === '-') {
			fromStdin = true;
		} else if (args[i] === '--list' && args[i + 1]) {
			listFile = path.resolve(args[++i]);
		} else if (args[i] === '--require-list') {
			requireList = true;
		} else if (args[i] === '--extra' && args[i + 1]) {
			extra.push(path.resolve(args[++i]));
		} else {
			console.error('check: unknown argument');
			return 2;
		}
	}
	const entries = readList(listFile);
	if (entries.length === 0) {
		if (requireList) {
			console.error('denylist: no list (or an empty one); this scan is required here, so it fails closed');
			return 1;
		}
		console.log('denylist: skipped, no list (set SECLAB_DENYLIST_FILE or ~/.config/seclab/denylist.txt)');
		return 0;
	}
	const files: Array<[string, string]> = [];
	if (fromStdin) {
		for (const rel of fs.readFileSync(0, 'utf8').split('\0').filter(Boolean)) {
			files.push([rel, path.join(repo, rel)]);
		}
	}
	for (const dir of extra) {
		for (const abs of fs.existsSync(dir) ? walk(dir) : []) {
			files.push([path.relative(repo, abs), abs]);
		}
	}
	if (files.length === 0) {
		console.error('check: no files to scan (pipe `git ls-files -z` with `-`, or pass --extra DIR)');
		return 2;
	}
	const scanned = files.map(([rel, abs]) => ({ rel, ...scanFile(rel, abs, entries) }));
	const findings = [...scanned.flatMap(s => s.findings), ...files.flatMap(([rel]) => scanText(`${rel} (path)`, rel, entries))];
	const skipped = scanned.filter(s => s.skipped);
	return report(findings, skipped, requireList, `${files.length} file(s), ${skipped.length} skipped, ${entries.length} entr${entries.length === 1 ? 'y' : 'ies'}`, entries);
}

if (import.meta.main) {
	const [cmd, ...rest] = process.argv.slice(2);
	if (cmd === '--self-test') {
		process.exit(selfTest());
	} else if (cmd === 'check') {
		process.exit(check(rest));
	} else if (cmd === 'git-push' || cmd === 'git-tree') {
		process.exit(gitScan(cmd, rest));
	} else {
		console.error('usage: check-denylist.ts check - --list FILE [--require-list] [--extra DIR]... | git-push|git-tree ... | --self-test');
		process.exit(2);
	}
}
