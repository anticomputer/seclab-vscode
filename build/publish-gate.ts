// Publish gate: allow only what can be shown to be public (EDR 20261112-publish-gate).
//
// The repo is public, so a push to any branch publishes. This runs before the push (the pre-push
// hook, build/hooks) and, as the same code, over main's tree in CI (the `denylist` job of
// workflow-lint.yml, build/ci-denylist.sh). Branches are not scanned with the list in CI.
// Layers, over what a push publishes (git-push: ref name, and for each new commit its message,
// the paths it writes and the lines it adds) or over a whole commit (git-tree):
//   repo     every GitHub repository reference; this tool lists them and the driver
//            (build/hooks/publish-gate.sh) checks each live: only `public` passes
//   host     URL, protocol-relative, email and bare-domain hosts: an allowlisted host or pattern
//   id       GUIDs (whole or truncated) and non-hash-length hex IDs: allowlisted values only
//   path     home paths with a non-placeholder user, agent session-state and worktree paths
//   handle   @handles: allowlisted only (the owner's among them)
//   record   run-record JSON: booleans, numbers, null, canary tokens and token-like literals only
//   allow    the allowlist changes only in a commit of its own whose message states the evidence
//            ("public: <what was checked> YYYY-MM-DD")
//   denylist the known-names list (build/check-denylist.ts), the final layer
// Findings name the layer and location only, never the value: CI logs are public.
//
//   node build/publish-gate.ts git-push --git-dir DIR --list FILE --ref NAME [--exclude-remotes] TIP [BASE]
//   node build/publish-gate.ts git-tree --git-dir DIR --list FILE --ref NAME SHA [--base BASE]
//   node build/publish-gate.ts --self-test
// stdout carries one `repo<TAB>owner/name<TAB>location` line per reference, for the driver;
// stderr the findings. Exit 1 on any finding, 2 on a usage or internal error: both block.

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { commitUnits, git, HEX40, mentionsLoosely, parseList, printable, readList, scanUnits, TEXT_EXT, treeBlobs, type Unit } from './check-denylist.ts';

export const ALLOW_PATH = 'build/publish-allow.json';

export interface Allow {
	hosts: string[];
	ids: string[];
	handles: string[];
	homeNames: string[];
	watchedOwners: string[];
	records: Array<{ path: string; blob: string }>;
	/** Runtime only: the entries a scan matched. */
	used?: Set<string>;
}

export function parseAllow(text: string): Allow {
	const j = JSON.parse(text) as Record<string, unknown>;
	const keys = ['$comment', 'hosts', 'ids', 'handles', 'homeNames', 'watchedOwners', 'records'];
	for (const k of Object.keys(j)) {
		if (!keys.includes(k)) {
			throw new Error(`allowlist: unknown key ${printable(k)}`);
		}
	}
	const strs = (k: string, re: RegExp): string[] => {
		const v = j[k];
		if (!Array.isArray(v) || !v.every(s => typeof s === 'string' && re.test(s))) {
			throw new Error(`allowlist: ${k} must be an array of matching strings`);
		}
		return (v as string[]).map(s => s.toLowerCase());
	};
	const records = j.records;
	if (!Array.isArray(records) || !records.every(r => r && typeof r === 'object' && Object.keys(r).join() === 'path,blob'
		&& typeof r.path === 'string' && typeof r.blob === 'string' && HEX40.test(r.blob))) {
		throw new Error('allowlist: records must be [{path, blob}]');
	}
	return {
		// A wildcard needs two labels after `*.` (R19-10); only the reserved test TLDs may stand alone.
		hosts: strs('hosts', /^\*\.(?:test|example|invalid|localhost)$|^\*\.[a-z0-9-]+(?:\.[a-z0-9-]+)+$|^[a-z0-9.-]+$|^\d{1,3}(?:\.\d{1,3}){3}$|^\[[0-9a-f:.]+\]$/i),
		ids: strs('ids', /^[0-9a-f-]{8,}$/i),
		handles: strs('handles', /^[a-z0-9-]{1,39}$/i),
		homeNames: strs('homeNames', /^[^/\\\s]{1,64}$/),
		watchedOwners: strs('watchedOwners', /^[a-z0-9-]{1,39}$/i),
		records,
	};
}

export type Layer = 'repo' | 'host' | 'id' | 'path' | 'handle' | 'record' | 'allow' | 'denylist' | 'review' | 'unread';
export interface Hit { layer: Layer; where: string; line: number; value: string }

// Text that may record a private conversation (a quote, a paraphrase, an excerpt). It only asks
// for review: product text such as "the user chose deny-new-destinations" is legitimate.
const CONVERSATION = /\bverbatim\b|\b(?:the )?user(?:'s)? (?:said|says|asked|asks|wrote|chose|replied|answered|told|requested|insisted|confirmed|approved|decided|stated|words)\b|\buser input:|\bin (?:the user's|their) (?:own )?words\b/i;
const PROSE_EXT = /\.(?:md|markdown|txt|rst)$/i;
/** Text-type for the tree scan's unread check (R20-3): the scanner's text set, prose, code, or no extension. */
function textLike(p: string): boolean {
	const base = p.slice(p.lastIndexOf('/') + 1);
	return TEXT_EXT.test(p) || PROSE_EXT.test(p) || CODE_EXT.test(p) || /\.(?:jsx|tsx|properties)$/i.test(p) || !base.slice(1).includes('.');
}

// Network schemes only: vscode-remote://seclab+tab, file://, docker:// and the like name no host.
const URL_HOST = /\b(?:https?|wss?|ftps?|sftp|ssh|git|git\+ssh|git\+https?|svn|rsync|ldaps?|smb|telnet|redis|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|amqps?|mqtt):\/\/(?:[^\s/@'"`<>]*@)?(\[[0-9a-f:.]+\]|[a-z0-9.-]+)/gi;
const PROTO_REL = /(?<![\w:/])\/\/([a-z0-9-]+(?:\.[a-z0-9-]+)+)/gi;
const EMAIL = /(?<![\w.+-])[\w.+-]+@([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.[a-z][a-z0-9-]*[a-z0-9])(?![\w-])/gi;
// Bare domains: ending in a TLD that a source identifier rarely ends in. The private-use TLDs need
// three labels; dev, ai, cloud and the like are left to URL hosts (`process.env.dev` is code).
// Catches accidents, not adversaries.
const STRONG_TLD = 'com|net|org|io|gov|edu|xyz';
const WEAK_TLD = 'internal|corp|lan|intranet|test|example|invalid|localhost';
const LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
const BARE = new RegExp(`(?<![\\w.@/:-])((?:${LABEL}\\.)+(?:${STRONG_TLD})|(?:${LABEL}\\.){2,}(?:${WEAK_TLD}))(?![\\w-]|\\.[a-z0-9])`, 'gi');
const IPV4 = /(?<![\w.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\w.])/g;
const TLD_ANY = new RegExp(`\\.(?:${STRONG_TLD}|${WEAK_TLD})$`, 'i');

const GUID = /\b[0-9a-f]{8}-(?:[0-9a-f]{4}(?:-[0-9a-f]{4}(?:-[0-9a-f]{4}(?:-[0-9a-f]{12})?)?)?\b|(?=…|\.\.\.))/gi;
const LONG_HEX = /\b[0-9a-f]{16,}\b/gi;
const HASH_LENGTHS = new Set([40, 64, 128]);

const HOME = /(?<![\w.-])(?:[/](?:Users|home)[/]|\b[A-Za-z]:\\{1,2}Users\\{1,2})([^/\\\s'"`$<>{}()*:;,|]+)/g;
// Built from parts so this source does not match itself; a path needs a separator next to it.
const AGENT_PATH = new RegExp(['session' + '-state', 'copilot' + '-worktrees'].map(s => s.replace('-', '[-_]')).map(s => `[/\\\\]${s}|${s}[/\\\\]`).join('|'), 'gi');

const HANDLE = /(?<![\w.@/:+\-\\])@([a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?)(?![\w-]|[/:(@]|\.\w)/gi;
// Doc-comment tags, Python decorators and CSS at-rules that look like handles.
const NOT_HANDLES = new Set(('param returns return type typedef template deprecated override internal see link linkcode example throws '
	+ 'default defaultvalue since private public protected readonly abstract inheritdoc description property prop callback module '
	+ 'file fileoverview author license version event fires memberof enum namespace function class constructor static this '
	+ 'ts-ignore ts-expect-error ts-nocheck ts-check jsx satisfies remarks alpha beta experimental packagedocumentation '
	+ 'dataclass classmethod staticmethod abstractmethod cached_property overload final pytest fixture contextmanager wraps '
	+ 'media import supports keyframes font-face charset layer apply tailwind container page namespace '
	+ 'sha1 sha256 sha512 latest tsv csv sh json text html uri base64 base64d base32 base32d').split(' '));
const CODE_EXT = /\.(?:ts|tsx|js|mjs|cjs|py|patch|diff)$/i;
const DECORATOR_LINE = /^[+\- ]?\s*@[\w.]+(?:\(.*)?\s*$/;

const REPO_PART = '([a-z0-9-]{1,39})/([a-z0-9._-]{1,100})';
const REPO_FORMS = [
	new RegExp(`(?<![\\w.-])(?:www\\.)?github\\.com[/:]${REPO_PART}`, 'gi'),
	new RegExp(`(?<![\\w.-])api\\.github\\.com/repos/${REPO_PART}`, 'gi'),
	new RegExp(`(?<![\\w.-])(?:raw|codeload)\\.githubusercontent\\.com/${REPO_PART}`, 'gi'),
	new RegExp(`\\buses:\\s*['"]?${REPO_PART}(?:/[^@\\s'"]*)?@`, 'gi'),
	new RegExp(`(?<![\\w./-])${REPO_PART}#\\d+\\b`, 'gi'),
	new RegExp(`(?:--repo[= ]|(?<![\\w-])-R |\\brepo:)${REPO_PART}`, 'gi'),
];
// github.com/<first>/… that is a site page, not an owner.
const NOT_OWNERS = new Set(('orgs settings marketplace features sponsors apps login logout about topics collections enterprise '
	+ 'enterprises pricing security site customer-stories readme users notifications issues pulls search explore codespaces '
	+ 'copilot new organizations account contact team trending advisories github-copilot').split(' '));
const FILE_EXT = /\.(?:md|ts|js|mjs|cjs|json|jsonc|py|sh|ya?ml|txt|html|css|patch|diff|toml|lock)$/i;
// Documentation placeholders: never looked up.
const PLACEHOLDER_REPOS = new Set(['owner/repo', 'org/repo', 'user/repo', 'o/r', 'you/your-repo', 'owner/name']);

function repoName(owner: string, name: string): string | undefined {
	const o = owner.toLowerCase();
	const n = name.toLowerCase().replace(/\.git$/, '').replace(/[.]+$/, '');
	if (!n || NOT_OWNERS.has(o) || FILE_EXT.test(n) || n === '.' || n === '..' || PLACEHOLDER_REPOS.has(`${o}/${n}`)) {
		return undefined;
	}
	return `${o}/${n}`;
}

/** Records an allowlist entry as used (tree mode reports entries that match nothing as stale). */
function hit(allow: Allow, kind: string, entry: string): true {
	allow.used?.add(`${kind}:${entry}`);
	return true;
}

function ipAllowed(ip: string, allow: Allow): boolean {
	const o = ip.split('.').map(Number);
	return o[0] === 127 || ip === '0.0.0.0' || ip === '169.254.169.254'
		|| (o[0] === 192 && o[1] === 0 && o[2] === 2) || (o[0] === 198 && o[1] === 51 && o[2] === 100) || (o[0] === 203 && o[1] === 0 && o[2] === 113)
		|| (allow.hosts.includes(ip) && hit(allow, 'hosts', ip));
}

export function hostAllowed(host: string, allow: Allow): boolean {
	const h = host.toLowerCase().replace(/\.$/, '');
	if (/^\[.*\]$/.test(h)) {
		return h === '[::1]' || h === '[::]' || (allow.hosts.includes(h) && hit(allow, 'hosts', h));
	}
	if (/^\d+(?:\.\d+){3}$/.test(h)) {
		return ipAllowed(h, allow);
	}
	const p = allow.hosts.find(p => p.startsWith('*.') ? h.endsWith(p.slice(1)) : h === p);
	return p !== undefined && hit(allow, 'hosts', p);
}

function idAllowed(v: string, allow: Allow): boolean {
	const a = allow.ids.find(a => a === v || a.startsWith(v));
	return a !== undefined && hit(allow, 'ids', a);
}

/** Allowlist entries no line of the tree used, wildcards included: stale, so a value scrubbed from the tree cannot live on here. */
export function staleEntries(allow: Allow): string[] {
	const out: string[] = [];
	for (const kind of ['hosts', 'ids', 'handles', 'homeNames'] as const) {
		for (const e of allow[kind]) {
			if (!allow.used?.has(`${kind}:${e}`)) {
				out.push(`${kind}:${e}`);
			}
		}
	}
	return out;
}

/** The layer hits on one line (repo hits carry the owner/name; the driver checks them live). */
export function lineHits(text: string, file: string | undefined, allow: Allow): Array<{ layer: Layer; value: string }> {
	const out: Array<{ layer: Layer; value: string }> = [];
	const exempt = file === ALLOW_PATH;
	for (const re of REPO_FORMS) {
		for (const m of text.matchAll(re)) {
			const r = repoName(m[1], m[2]);
			if (r) {
				out.push({ layer: 'repo', value: r });
			}
		}
	}
	if (allow.watchedOwners.length) {
		const watched = new RegExp(`(?<![\\w./@-])(${allow.watchedOwners.map(o => o.replace(/[-]/g, '\\-')).join('|')})/([a-z0-9._-]{1,100})`, 'gi');
		for (const m of text.matchAll(watched)) {
			// "GitHub/AWS formats", "Microsoft/VS Code": prose, not a repository.
			if (/^[A-Z]/.test(m[1]) && /^[A-Z][A-Za-z]*$/.test(m[2])) {
				continue;
			}
			const r = repoName(m[1], m[2]);
			if (r) {
				out.push({ layer: 'repo', value: r });
			}
		}
	}
	if (exempt) {
		return out;
	}
	if ((file === undefined || PROSE_EXT.test(file)) && CONVERSATION.test(text)) {
		out.push({ layer: 'review', value: 'conversation' });
	}
	const hosts = new Set<string>();
	for (const m of text.matchAll(URL_HOST)) {
		hosts.add(m[1]);
	}
	for (const re of [PROTO_REL, EMAIL]) {
		for (const m of text.matchAll(re)) {
			if (re === EMAIL || TLD_ANY.test(m[1])) {
				hosts.add(m[1]);
			}
		}
	}
	for (const m of text.matchAll(BARE)) {
		// In code, a two-label name is usually a property access on a module object; count it only
		// where it opens a string.
		if (file && CODE_EXT.test(file) && m[1].split('.').length < 3 && !/['"`]/.test(text[m.index - 1] ?? '')) {
			continue;
		}
		hosts.add(m[1]);
	}
	for (const m of text.matchAll(IPV4)) {
		hosts.add(m[1]);
	}
	for (const h of hosts) {
		if (h && h !== '.' && !hostAllowed(h, allow)) {
			out.push({ layer: 'host', value: h.toLowerCase() });
		}
	}
	const guidSpans: Array<[number, number]> = [];
	for (const m of text.matchAll(GUID)) {
		guidSpans.push([m.index, m.index + m[0].length]);
		const v = m[0].toLowerCase();
		if (/[a-f]/.test(v) && !idAllowed(v, allow)) {
			out.push({ layer: 'id', value: v });
		}
	}
	for (const m of text.matchAll(LONG_HEX)) {
		const v = m[0].toLowerCase();
		if (!HASH_LENGTHS.has(v.length) && /[a-f]/.test(v) && /\d/.test(v) && !guidSpans.some(([a, b]) => m.index >= a && m.index < b) && !idAllowed(v, allow)) {
			out.push({ layer: 'id', value: v });
		}
	}
	for (const m of text.matchAll(HOME)) {
		if (!(allow.homeNames.includes(m[1].toLowerCase()) && hit(allow, 'homeNames', m[1].toLowerCase()))) {
			out.push({ layer: 'path', value: m[0] });
		}
	}
	for (const m of text.matchAll(AGENT_PATH)) {
		out.push({ layer: 'path', value: m[0] });
	}
	if (!(file && CODE_EXT.test(file) && DECORATOR_LINE.test(text))) {
		for (const m of text.matchAll(HANDLE)) {
			const h = m[1].toLowerCase();
			if (!NOT_HANDLES.has(h) && !/^I[A-Z]/.test(m[1]) && !(allow.handles.includes(h) && hit(allow, 'handles', h))) {
				out.push({ layer: 'handle', value: h });
			}
		}
	}
	return out;
}

export function unitHits(units: Unit[], allow: Allow): Hit[] {
	const out: Hit[] = [];
	for (const u of units) {
		u.text.split('\n').forEach((l, i) => {
			for (const h of lineHits(l, u.file, allow)) {
				out.push({ ...h, where: u.where, line: u.lines ? (u.lines[i] ?? 0) : i + 1 });
			}
		});
	}
	return out;
}

// Run records (committed evidence, traces, measured results): facts only.
export const RECORD = /(?:^|\/)(?:runs|results|traces|evidence|\.seclab-evidence)\/(?:[^/]+\/)*[^/]+\.json$|\.measured\.json$/;
const CANARY = /^seclabcanary_[A-Za-z0-9_]{1,128}$/;
const TOKEN = /^[A-Za-z0-9._:$|=+#-]{0,96}$/;

/** Why a run record is not facts-only, or undefined. */
export function recordProblem(text: string): string | undefined {
	let j: unknown;
	try { j = JSON.parse(text); } catch { return 'not JSON'; }
	const walk = (v: unknown, depth: number): string | undefined => {
		if (depth > 16) {
			return 'nested too deep';
		}
		if (v === null || typeof v === 'boolean' || (typeof v === 'number' && Number.isFinite(v))) {
			return undefined;
		}
		if (typeof v === 'string') {
			return CANARY.test(v) || TOKEN.test(v) ? undefined : 'a free-text string';
		}
		if (Array.isArray(v)) {
			for (const x of v) {
				const p = walk(x, depth + 1);
				if (p) {
					return p;
				}
			}
			return undefined;
		}
		if (typeof v === 'object') {
			for (const [k, x] of Object.entries(v as object)) {
				if (!TOKEN.test(k)) {
					return 'a free-text key';
				}
				const p = walk(x, depth + 1);
				if (p) {
					return p;
				}
			}
			return undefined;
		}
		return 'a non-JSON value';
	};
	return walk(j, 0);
}

function blobAt(gitDir: string, sha: string, file: string): { blob: string; text: string } | undefined {
	const ls = git(gitDir, ['ls-tree', '-z', sha, '--', file]).toString('utf8').split('\0').filter(Boolean)[0];
	const m = ls && /^\d{6} blob ([0-9a-f]{40})\t/.exec(ls);
	if (!m) {
		return undefined;
	}
	return { blob: m[1], text: git(gitDir, ['cat-file', 'blob', m[1]]).toString('utf8') };
}

function recordHits(gitDir: string, sha: string, files: Iterable<string>, allow: Allow): Hit[] {
	const out: Hit[] = [];
	for (const f of files) {
		if (!RECORD.test(f)) {
			continue;
		}
		const b = blobAt(gitDir, sha, f);
		if (!b || allow.records.some(r => r.path === f && r.blob === b.blob)) {
			continue;
		}
		const p = recordProblem(b.text);
		if (p) {
			out.push({ layer: 'record', where: f, line: 0, value: p });
		}
	}
	return out;
}

const EVIDENCE = /^public: .*\b\d{4}-\d{2}-\d{2}\b/m;

/** The allowlist changes only in a commit of its own that states its evidence. */
function allowHits(gitDir: string, revs: string[]): Hit[] {
	const out: Hit[] = [];
	for (const r of revs) {
		const names = new Set(git(gitDir, ['diff-tree', '-r', '-m', '--root', '--no-commit-id', '--name-only', '-z', '--no-renames', r]).toString('utf8').split('\0').filter(Boolean));
		if (!names.has(ALLOW_PATH)) {
			continue;
		}
		const msg = git(gitDir, ['log', '-1', '--format=%B', r]).toString('utf8');
		if (names.size !== 1 || !EVIDENCE.test(msg)) {
			out.push({ layer: 'allow', where: `${r.slice(0, 12)} (allowlist change)`, line: 0, value: names.size !== 1 ? 'not alone' : 'no evidence line' });
		}
	}
	return out;
}

function revList(gitDir: string, tip: string, base: string | undefined, excludeRemotes: boolean): string[] {
	const revs = git(gitDir, ['rev-list', tip, ...(base ? [`^${base}`] : []), ...(excludeRemotes ? ['--not', '--remotes=origin'] : [])])
		.toString('utf8').split('\n').filter(Boolean);
	if (!revs.every(r => HEX40.test(r))) {
		throw new Error('unexpected rev-list output');
	}
	return revs;
}

export interface GateResult { hits: Hit[]; summary: string }

export function gatePush(gitDir: string, ref: string, tip: string, base: string | undefined, excludeRemotes: boolean, entries: string[][]): GateResult {
	const allowText = blobAt(gitDir, tip, ALLOW_PATH);
	if (!allowText) {
		throw new Error(`no ${ALLOW_PATH} at the pushed tip`);
	}
	const allow = parseAllow(allowText.text);
	const revs = revList(gitDir, tip, base, excludeRemotes);
	const units: Unit[] = [{ where: '(ref name)', text: ref }, ...revs.flatMap(r => commitUnits(gitDir, r))];
	// An annotated tag publishes its own message (R19-6).
	if (git(gitDir, ['cat-file', '-t', tip]).toString('utf8').trim() === 'tag') {
		const tag = git(gitDir, ['cat-file', 'tag', tip]).toString('utf8');
		const at = tag.indexOf('\n\n');
		units.push({ where: `${tip.slice(0, 12)} (tag message)`, text: at < 0 ? '' : tag.slice(at + 2) });
	}
	// Run records are checked in every commit that writes them, against that commit's tree: one a
	// later commit deletes is still published (R19-3).
	const records = new Map<string, Hit>();
	for (const r of revs) {
		const names = git(gitDir, ['diff-tree', '-r', '-m', '--root', '--no-commit-id', '--name-only', '-z', '--no-renames', r]).toString('utf8').split('\0').filter(Boolean);
		for (const h of recordHits(gitDir, r, names, allow)) {
			records.set(`${h.where}\0${h.value}\0${r}`, { ...h, where: `${r.slice(0, 12)} ${h.where}` });
		}
	}
	const hits = [
		...unitHits(units, allow),
		...records.values(),
		...allowHits(gitDir, revs),
		...scanUnits(units, entries).map(f => ({ layer: 'denylist' as Layer, where: f.file, line: f.line, value: '' })),
	];
	return { hits, summary: `${revs.length} commit(s)` };
}

export function gateTree(gitDir: string, ref: string, sha: string, base: string | undefined, entries: string[][]): GateResult {
	const allowText = blobAt(gitDir, sha, ALLOW_PATH);
	if (!allowText) {
		throw new Error(`no ${ALLOW_PATH} in the tree`);
	}
	const allow = parseAllow(allowText.text);
	allow.used = new Set();
	const blobs = treeBlobs(gitDir, sha);
	const units: Unit[] = [{ where: '(ref name)', text: ref }, { where: '(message)', text: git(gitDir, ['log', '-1', '--format=%B', sha]).toString('utf8') }];
	for (const b of blobs) {
		units.push({ where: `${b.path} (path)`, text: b.path });
		if (b.data) {
			units.push({ where: b.path, text: b.data.toString('utf8'), file: b.path });
		}
	}
	const hits = [
		...unitHits(units, allow),
		...recordHits(gitDir, sha, blobs.map(b => b.path), allow),
		...(base ? allowHits(gitDir, revList(gitDir, sha, base, false)) : []),
		...scanUnits(units, entries).map(f => ({ layer: 'denylist' as Layer, where: f.file, line: f.line, value: '' })),
	];
	// Nothing is dropped silently (R19-4): a text-type file the scan could not read blocks; other
	// skipped blobs (images, archives) are counted in the summary.
	const skipped = blobs.filter(b => b.skipped && b.skipped !== 'commit');
	for (const b of skipped.filter(b => textLike(b.path))) {
		hits.push({ layer: 'unread', where: b.path, line: 0, value: b.skipped ?? '' });
	}
	const otherSkips = skipped.filter(b => !textLike(b.path)).length;
	// An entry nothing uses must go: otherwise a value scrubbed from the tree lives on here.
	const stale = staleEntries(allow).length + allow.records.filter(r => {
		const b = blobAt(gitDir, sha, r.path);
		return !b || b.blob !== r.blob;
	}).length;
	for (let i = 0; i < stale; i++) {
		hits.push({ layer: 'allow', where: ALLOW_PATH, line: 0, value: 'an entry nothing in the tree uses; remove it' });
	}
	return { hits, summary: `${blobs.length} path(s)${otherSkips ? `, ${otherSkips} binary not scanned` : ''}` };
}

/**
 * Prints findings by layer and location; a location that itself carries a finding is withheld.
 * With `denylistCounts` (CI), known-name hits are a count only: a location would tell a public log
 * which candidate names are listed (review round 19, R19-1).
 * Exit 0: clean (repo references still go to the driver's live check); 1: a blocking finding;
 * 3: only review findings (conversation text), which a person must look at.
 */
export function emit(res: GateResult, allow: Allow | undefined, entries: string[][], write: (fd: 1 | 2, s: string) => void, denylistCounts = false): number {
	const shown = (w: string) => (allow && lineHits(w, undefined, allow).some(h => h.layer !== 'review')) || scanUnits([{ where: '', text: w }], entries).length > 0 || mentionsLoosely(w, entries)
		? '(a location that itself holds a finding, not printed)' : printable(w);
	let blocking = 0;
	let review = 0;
	// CI (denylistCounts): counts per layer, no location at all. Which locations are printed, or
	// withheld, or in what order, would tell a public log which candidates are listed (R19-1, R20-1).
	const perLayer = new Map<string, number>();
	for (const h of res.hits) {
		if (denylistCounts) {
			if (h.layer === 'repo') {
				write(1, `repo\t${h.value}\t(location not printed in CI):0`);
				continue;
			}
			perLayer.set(h.layer, (perLayer.get(h.layer) ?? 0) + 1);
			if (h.layer === 'review') {
				review++;
			} else {
				blocking++;
			}
			continue;
		}
		const where = h.value && h.layer !== 'review' && h.where.toLowerCase().includes(h.value.toLowerCase()) ? '(a location that itself holds a finding, not printed)' : shown(h.where);
		if (h.layer === 'repo') {
			write(1, `repo\t${h.value}\t${where}:${h.line}`);
			continue;
		}
		if (h.layer === 'review') {
			review++;
			write(2, `publish-gate: review: ${where}${h.line ? `:${h.line}` : ''} (may record a private conversation; check it is not a quote, paraphrase or excerpt)`);
			continue;
		}
		blocking++;
		const why = h.layer === 'record' || h.layer === 'allow' || h.layer === 'unread' ? ` (${h.value})` : '';
		write(2, `publish-gate: ${h.layer}: ${where}${h.line ? `:${h.line}` : ''}${why}`);
	}
	for (const [layer, n] of [...perLayer].sort()) {
		write(2, `publish-gate: ${layer}: ${n} finding(s); locations are not printed in CI (run ./seclab lint publish with the list)`);
	}
	write(2, blocking ? `publish-gate: ${blocking} finding(s) in ${res.summary}; blocked`
		: review ? `publish-gate: ${review} line(s) to review in ${res.summary}`
			: `publish-gate: clean apart from the live repo check (${res.summary})`);
	return blocking ? 1 : review ? 3 : 0;
}

/** text: the same layers over stdin (a PR or issue body, a comment, release notes) before it is posted. */
export function gateText(text: string, allow: Allow, entries: string[][]): GateResult {
	const units: Unit[] = [{ where: '(text)', text }];
	return {
		hits: [...unitHits(units, allow), ...scanUnits(units, entries).map(f => ({ layer: 'denylist' as Layer, where: f.file, line: f.line, value: '' }))],
		summary: `${text.split('\n').length} line(s)`,
	};
}

function runText(args: string[]): number {
	let listFile: string | undefined;
	let allowFile: string | undefined;
	for (let i = 0; i < args.length; i++) {
		if (args[i] === '--list' && args[i + 1] !== undefined) {
			listFile = args[++i];
		} else if (args[i] === '--allow' && args[i + 1] !== undefined) {
			allowFile = args[++i];
		} else {
			console.error('text: unexpected argument');
			return 2;
		}
	}
	const entries = readList(listFile);
	if (entries.length === 0 || !allowFile) {
		console.error('publish-gate: text needs --allow and a non-empty known-names list; failing closed');
		return 2;
	}
	try {
		const allow = parseAllow(fs.readFileSync(allowFile, 'utf8'));
		return emit(gateText(fs.readFileSync(0, 'utf8'), allow, entries), allow, entries, (fd, s) => (fd === 1 ? process.stdout : process.stderr).write(s + '\n'));
	} catch (e) {
		console.error(`publish-gate: could not run (${printable(String((e as Error).message)).slice(0, 200)}); failing closed`);
		return 2;
	}
}

function run(mode: 'git-push' | 'git-tree', args: string[]): number {
	let gitDir: string | undefined;
	let listFile: string | undefined;
	let ref: string | undefined;
	let base: string | undefined;
	let excludeRemotes = false;
	let denylistCounts = false;
	const revs: string[] = [];
	for (let i = 0; i < args.length; i++) {
		const a = args[i];
		if (a === '--git-dir' && args[i + 1] !== undefined) {
			gitDir = args[++i];
		} else if (a === '--list' && args[i + 1] !== undefined) {
			listFile = args[++i];
		} else if (a === '--ref' && args[i + 1] !== undefined) {
			ref = args[++i];
		} else if (a === '--base' && HEX40.test(args[i + 1] ?? '')) {
			base = args[++i];
		} else if (a === '--exclude-remotes' && mode === 'git-push') {
			excludeRemotes = true;
		} else if (a === '--denylist-counts') {
			denylistCounts = true;
		} else if (HEX40.test(a)) {
			revs.push(a);
		} else {
			console.error(`${mode}: unexpected argument`);
			return 2;
		}
	}
	if (!gitDir || ref === undefined || revs.length < 1 || revs.length > (mode === 'git-push' ? 2 : 1) || (mode === 'git-push' && base)) {
		console.error('usage: git-push --git-dir DIR --list FILE --ref NAME [--exclude-remotes] TIP [BASE] | git-tree --git-dir DIR --list FILE --ref NAME SHA [--base BASE]');
		return 2;
	}
	const entries = readList(listFile);
	if (entries.length === 0) {
		console.error('publish-gate: no known-names list (or an empty one); it is required, so the gate fails closed');
		return 2;
	}
	try {
		const res = mode === 'git-push' ? gatePush(gitDir, ref, revs[0], revs[1], excludeRemotes, entries) : gateTree(gitDir, ref, revs[0], base, entries);
		const allowText = blobAt(gitDir, revs[0], ALLOW_PATH);
		return emit(res, allowText ? parseAllow(allowText.text) : undefined, entries, (fd, s) => (fd === 1 ? process.stdout : process.stderr).write(s + '\n'), denylistCounts);
	} catch (e) {
		console.error(`publish-gate: could not run (${printable(String((e as Error).message)).slice(0, 200)}); failing closed`);
		return 2;
	}
}

// ---- self-test: every layer is proved by injecting a hit first; values are built at runtime so
// this source holds none of them.

function selfTest(): number {
	const bad: string[] = [];
	let cases = 0;
	const expect = (name: string, ok: boolean) => { cases++; if (!ok) { bad.push(name); } };
	const allow: Allow = {
		hosts: ['github.com', '*.github.com', '*.test', '*.invalid', 'example.com', '*.example.com', 'localhost'],
		ids: [['0123abcd', '0000', '4000', '8000', '000000000001'].join('-')],
		handles: ['anticomputer'],
		homeNames: ['agent', 'someone'],
		watchedOwners: ['github', 'microsoft'],
		records: [],
	};
	const layers = (t: string, file?: string) => lineHits(t, file, allow);
	// Fixture values are joined at runtime, so this source holds none of them.
	const j = (...p: string[]) => p.join('');
	const has = (t: string, layer: Layer, file?: string) => layers(t, file).some(h => h.layer === layer);
	const clean = (t: string, file?: string) => layers(t, file).filter(h => h.layer !== 'repo').length === 0;
	const fakeCorp = ['build', 'corp', 'contoso-fake'].join('.') + '.com';
	const guid = ['9f', 'e2'].join('').repeat(4) + '-' + 'a1b2-c3d4-e5f6-' + 'a7b8'.repeat(3);

	// repo
	const repos = (t: string) => layers(t).filter(h => h.layer === 'repo').map(h => h.value);
	expect('repo: a github.com URL is listed', repos(`see https://github.com/${j('Some-Org', '/', 'Private-Thing')}/blob/x`).join() === j('some-org', '/', 'private-thing'));
	expect('repo: an owner/name#N reference', repos(['fake-org', 'fake-repo'].join('/') + '#12').join() === 'fake-org/fake-repo');
	expect('repo: a bare mention under a watched owner', repos(`the ${j('github', '/', 'fake-internal-thing')} repo`).join() === j('github', '/', 'fake-internal-thing'));
	expect('repo: a uses: pin', repos('uses: actions/checkout@' + 'a'.repeat(40)).join() === 'actions/checkout');
	expect('repo: --repo and repo:', repos(`gh pr list --repo ${j('o1', '/', 'r1')}; q repo:${j('o2', '/', 'r2')}`).sort().join() === [j('o1', '/', 'r1'), j('o2', '/', 'r2')].join());
	expect('repo: a path is not a repo', repos('see docs/research/agentic-surfaces.md#11 and src/vs/base').length === 0);
	expect('repo: docs.github.com pages are not repos', repos('https://docs.github.com/en/rest/users').length === 0);
	expect('repo: .github/workflows is not a watched mention', repos('.github/workflows/x.yml').length === 0);
	expect('repo: Title/Title prose is not a repo', repos('gitleaks GitHub/AWS formats; Microsoft/VS Code-adjacent').length === 0);
	expect('repo: a placeholder is never looked up', repos('gh pr list --repo owner/repo').length === 0);

	// host
	expect('host: an unknown URL host blocks', has(`https://${fakeCorp}/x`, 'host'));
	expect('host: a protocol-relative host blocks', has(`registry=//${fakeCorp}/npm/`, 'host'));
	expect('host: a bare domain blocks', has(`point it at ${fakeCorp} first`, 'host'));
	expect('host: an email domain blocks', has(`mail someone@${fakeCorp}`, 'host'));
	expect('host: an allowlisted host and pattern pass', clean(`https://github.com/${j('x', '/', 'y')} and https://api.github.com and http://a.b.test:8080/`));
	expect('host: loopback and RFC 5737 pass', clean('http://127.0.0.1:9/ 192.0.2.10 http://[::1]:80/'));
	expect('host: another IP blocks', has(`connect to ${[10, 20, 30, 40].join('.')}`, 'host'));
	expect('host: non-network schemes name no host', clean('vscode-remote://seclab+tab/x file:///y docker://sha256'));
	expect('host: property access is not a host', clean('logger.info(x); this.local = y; process.env.dev') && clean('...(cause?.net ? { net: cause.net } : {})', 'x.ts'));
	expect('host: a quoted two-label name in code is a host', has(`const h = '${['contoso-fake', 'com'].join('.')}';`, 'host', 'x.ts'));

	// id
	expect('id: an unknown GUID blocks', has(`feed ${guid}`, 'id'));
	expect('id: a truncated GUID prefix blocks', has(`/x/${guid.slice(0, 8)}-…/y`, 'id'));
	expect('id: an allowlisted GUID and its prefix pass', clean(`v ${allow.ids[0]} and ${allow.ids[0].slice(0, 13)}`));
	expect('id: a non-hash-length hex blocks', has('run-' + 'ab12'.repeat(5), 'id'));
	expect('id: hash-length hex passes', clean('sha ' + 'ab12'.repeat(10) + ' digest ' + 'cd34'.repeat(16)));
	expect('id: a date stamp is not a GUID', clean('20261105-1234 20261112T090000Z'));

	// path
	expect('path: a real-looking home path blocks', has(['', 'Users', 'jdoe-fake', 'x'].join('/'), 'path'));
	expect('path: a Windows home path blocks', has(['C:', 'Users', 'jdoe-fake', 'x'].join('\\'), 'path'));
	expect('path: a placeholder home passes', clean(['', 'home', 'agent', 'x'].join('/') + ' ' + ['', 'Users', 'someone'].join('/')));
	expect('path: an agent session path blocks', has(['x', 'session' + '-state', 'y'].join('/'), 'path'));
	expect('path: the words alone are not a path', clean('session' + '-state semantics'));
	expect('path: an agent worktree path blocks', has(['x', 'copilot' + '-worktrees', 'y'].join('/'), 'path'));

	// handle
	expect('handle: an unknown handle blocks', has('thanks @' + 'fake-person', 'handle'));
	expect('handle: the owner passes', clean('cc @anticomputer'));
	expect('handle: doc tags, DI decorators, npm scopes, emails and pins pass',
		clean('/** @param x @returns y */ @IFileService private a; @types/node t@example.com img@sha256:ab'));
	expect('handle: a decorator line in code passes', clean('@dataclass(frozen=True)', 'x.py') && clean('\t' + j('@', 'someDecorator'), 'x.ts'));

	// record
	expect('record: facts pass', recordProblem(JSON.stringify({ a: true, n: 3, s: 'cmd:x.y', c: 'seclabcanary_abc', z: null, l: [false] })) === undefined);
	expect('record: free text fails', recordProblem(JSON.stringify({ detail: 'read this from somewhere' })) === 'a free-text string');
	expect('record: a path fails', recordProblem(JSON.stringify({ p: ['', 'tmp', 'x'].join('/') })) === 'a free-text string');
	expect('record: a free-text key fails', recordProblem(JSON.stringify({ 'a key with spaces': true })) === 'a free-text key');

	// allowlist file content is exempt from the value layers, not from the repo check
	expect('allow: the allowlist file holds values', clean(`"${fakeCorp}"`, ALLOW_PATH));

	// review: conversation text is flagged in prose and messages, not in code; it does not block
	expect('review: a quote marker in a doc is flagged', has('the user, ' + 'verbatim: "x"', 'review', 'docs/x.md'));
	expect('review: a paraphrase in a commit message is flagged', has('as the user ' + 'asked, we', 'review'));
	expect('review: code is not prose', !has('the user ' + 'chose deny', 'review', 'src/x.ts'));
	const reviewOnly = gateText('The user ' + 'chose deny-new-destinations.', allow, []);
	expect('review: only review findings exit 3', emit(reviewOnly, allow, [], () => { }) === 3);
	const textHit = gateText(`see https://${fakeCorp}/ and the ${['github', 'fake-internal-thing'].join('/')} repo`, allow, []);
	expect('text: the same layers over posted text', textHit.hits.some(h => h.layer === 'host') && textHit.hits.some(h => h.layer === 'repo'));
	expect('text: a blocking finding exits 1', emit(textHit, allow, [], () => { }) === 1);

	// emit never prints a value
	const printed: string[] = [];
	emit({ hits: [{ layer: 'host', where: `docs/${fakeCorp}.md`, line: 3, value: fakeCorp }, { layer: 'repo', where: 'a.md', line: 1, value: 'o/r' }], summary: 't' },
		allow, [], (_fd, s) => printed.push(s));
	expect('emit: no value is printed, and a location holding one is withheld', printed.every(s => !s.includes('contoso')));
	expect('emit: repo references go to the driver', printed.some(s => s === 'repo\to/r\ta.md:1'));
	// R19-1/R20-1: in CI, every layer is a count; no location, withheld or not, reaches the log.
	const ciOut: string[] = [];
	const ciRc = emit({ hits: [
		{ layer: 'denylist', where: 'candidates.md', line: 3, value: '' },
		{ layer: 'unread', where: 'cand-01-guess.csv', line: 0, value: 'binary' },
		{ layer: 'unread', where: 'cand-02-guess.csv', line: 0, value: 'binary' },
		{ layer: 'repo', where: 'cand-03-guess.md', line: 1, value: 'o/r' },
	], summary: 't' }, allow, [], (_fd, s) => ciOut.push(s), true);
	expect('emit: CI prints counts per layer and no location', ciRc === 1 && ciOut.every(s => !s.includes('cand') && !s.includes('candidates'))
		&& ciOut.some(s => s.includes('denylist: 1 finding')) && ciOut.some(s => s.includes('unread: 2 finding')));
	// R19-10: a one-label wildcard is refused; wildcards count toward the stale check.
	let wide = false;
	try { parseAllow(JSON.stringify({ ...allow, hosts: ['*.com'] })); } catch { wide = true; }
	expect('allow: a one-label wildcard is refused', wide);
	const wildAllow: Allow = { ...allow, hosts: ['*.example.com'], used: new Set() };
	expect('allow: an unused wildcard is stale', staleEntries(wildAllow).includes('hosts:*.example.com'));
	hostAllowed('a.example.com', wildAllow);
	expect('allow: a used wildcard is not stale', !staleEntries(wildAllow).includes('hosts:*.example.com'));

	// The git modes on a throwaway repository: each layer injected through a real commit.
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'publish-gate-selftest-'));
	try {
		const g = (...a: string[]) => {
			const r = spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'init.defaultBranch=main', '-c', 'commit.gpgsign=false', '-C', tmp, ...a],
				{ env: { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: tmp, GIT_CONFIG_NOSYSTEM: '1' } });
			if (r.status !== 0) {
				throw new Error(`self-test git ${a[0]}: ${r.stderr}`);
			}
			return r.stdout.toString().trim();
		};
		const write = (f: string, s: string) => { fs.mkdirSync(path.dirname(path.join(tmp, f)), { recursive: true }); fs.writeFileSync(path.join(tmp, f), s); };
		const commit = (msg: string) => { g('add', '-A'); g('commit', '-q', '--allow-empty', '-m', msg); return g('rev-parse', 'HEAD'); };
		g('init', '-q');
		write(ALLOW_PATH, JSON.stringify(allow, null, 1));
		const pub = commit('public: seed checked 2026-11-12');
		g('update-ref', 'refs/remotes/origin/main', pub);
		const gd = path.join(tmp, '.git');
		const entries = parseList('fake-pipeline-internal\n');
		const layersOf = (r: GateResult) => [...new Set(r.hits.filter(h => h.layer !== 'repo').map(h => h.layer))].sort().join();
		write('a.md', 'clean text\n');
		const ok = commit('clean');
		expect('git-push: a clean push has no findings', layersOf(gatePush(gd, 'refs/heads/x', ok, undefined, true, entries)) === '');
		const inject: Array<[Layer, () => string]> = [
			['host', () => { write('h.md', `see https://${fakeCorp}/\n`); return commit('host'); }],
			['id', () => { write('i.md', `${guid}\n`); return commit('id'); }],
			['path', () => { write('p.md', ['', 'Users', 'jdoe-fake'].join('/') + '\n'); return commit('path'); }],
			['handle', () => commit('thanks @' + 'fake-person')],
			['record', () => { write('rpc-filter/probes/runs/x.json', JSON.stringify({ detail: 'free text here' })); return commit('record'); }],
			['allow', () => { write(ALLOW_PATH, JSON.stringify({ ...allow, hosts: [...allow.hosts, fakeCorp] }, null, 1)); write('other.md', 'x\n'); return commit('widen the allowlist'); }],
			['denylist', () => { write('d.md', 'the fake_pipeline_internal job\n'); return commit('d'); }],
		];
		for (const [layer, make] of inject) {
			g('reset', '-q', '--hard', ok);
			const tip = make();
			expect(`git-push: an injected ${layer} hit is found`, layersOf(gatePush(gd, 'refs/heads/x', tip, undefined, true, entries)) === layer);
		}
		g('reset', '-q', '--hard', ok);
		write(ALLOW_PATH, JSON.stringify({ ...allow, hosts: [...allow.hosts, fakeCorp] }, null, 1));
		commit('Allow a host\n\npublic: host resolves publicly, checked 2026-11-12');
		write('h.md', `see https://${fakeCorp}/\n`);
		const cleared = commit('use it');
		expect('allow: a separate evidenced allowlist commit clears a host', layersOf(gatePush(gd, 'refs/heads/x', cleared, undefined, true, entries)) === '');
		g('reset', '-q', '--hard', ok);
		const refHit = gatePush(gd, 'refs/heads/fake-pipeline-internal', ok, undefined, true, entries);
		expect('git-push: a ref name on the list is found', layersOf(refHit) === 'denylist');
		expect('git-push: a removal publishes nothing', (() => { g('reset', '-q', '--hard', ok); write('h.md', `https://${fakeCorp}/\n`); const a = commit('add'); g('update-ref', 'refs/remotes/origin/main', a); fs.rmSync(path.join(tmp, 'h.md')); const b = commit('remove'); return layersOf(gatePush(gd, 'refs/heads/x', b, undefined, true, entries)) === ''; })());
		g('update-ref', 'refs/remotes/origin/main', pub);
		// R19-3: a run record written then deleted within the push is still published.
		g('reset', '-q', '--hard', ok);
		write('x/runs/r.json', JSON.stringify({ detail: 'free text here' }));
		commit('add a record');
		fs.rmSync(path.join(tmp, 'x'), { recursive: true });
		const tidied = commit('tidy it away');
		expect('record: one deleted before the tip still blocks', layersOf(gatePush(gd, 'refs/heads/x', tidied, undefined, true, entries)) === 'record');
		// R19-6: an annotated tag publishes its message.
		g('reset', '-q', '--hard', ok);
		g('tag', '-a', 't1', '-m', 'release notes for the fake_pipeline_internal job');
		const tagObj = g('rev-parse', 't1');
		expect('tag: an annotated tag message is scanned', layersOf(gatePush(gd, 'refs/tags/t1', tagObj, undefined, true, entries)) === 'denylist');
		g('tag', '-d', 't1');
		// R19-11: tree mode with a base checks the allowlist-commit discipline over the range.
		write(ALLOW_PATH, JSON.stringify({ ...allow, hosts: [...allow.hosts, fakeCorp] }, null, 1));
		write('other.md', 'x\n');
		const mixed = commit('widen the allowlist with other changes');
		expect('git-tree: with a base, a mixed allowlist commit blocks', layersOf(gateTree(gd, 'main', mixed, ok, entries)).split(',').includes('allow'));
		g('reset', '-q', '--hard', ok);
		// R19-4: a text-type file the tree scan cannot read blocks; it is never dropped silently.
		fs.writeFileSync(path.join(tmp, 'data.csv'), Buffer.concat([Buffer.from([0]), Buffer.from('fake_pipeline_internal\n')]));
		const nulTip = commit('a NUL-led csv');
		expect('git-tree: an unreadable text-type file blocks', layersOf(gateTree(gd, 'main', nulTip, undefined, entries)).split(',').includes('unread'));
		g('reset', '-q', '--hard', ok);
		for (const name of ['f.rst', 'f.tsx', 'noextension']) {
			fs.writeFileSync(path.join(tmp, name), Buffer.concat([Buffer.from([0]), Buffer.from('x\n')]));
		}
		const moreNul = commit('NUL-led prose, code and an extensionless file');
		expect('git-tree: prose, code and extensionless unreadable files block (R20-3)', gateTree(gd, 'main', moreNul, undefined, entries).hits.filter(h => h.layer === 'unread').length === 3);
		g('reset', '-q', '--hard', ok);
		write('h.md', `https://${fakeCorp}/\n`);
		const treeTip = commit('tree');
		expect('git-tree: the same layers over a whole tree', layersOf(gateTree(gd, 'main', treeTip, undefined, entries)).split(',').includes('host'));
		// Stale entries: a tree whose allowlist holds only what it uses is clean; one more entry is not.
		const usedOnly = { ...allow, hosts: ['*.test'], ids: [], handles: [], homeNames: [], records: [] };
		write(ALLOW_PATH, JSON.stringify(usedOnly, null, 1));
		write('h.md', 'http://a.b.test/\n');
		const tight = commit('public: tight allowlist checked 2026-11-12');
		expect('allow: an allowlist with only used entries is not stale', !layersOf(gateTree(gd, 'main', tight, undefined, entries)).includes('allow'));
		write(ALLOW_PATH, JSON.stringify({ ...usedOnly, hosts: ['*.test', j('old-scrubbed', '.', 'example-fake', '.com')] }, null, 1));
		const staleTip = commit('public: one more entry checked 2026-11-12');
		expect('allow: an entry nothing uses is stale', layersOf(gateTree(gd, 'main', staleTip, undefined, entries)).includes('allow'));
		write(ALLOW_PATH, JSON.stringify(allow, null, 1));
		commit('public: restore checked 2026-11-12');
		write('rpc-filter/probes/runs/old.json', JSON.stringify({ detail: 'legacy free text' }));
		const legacy = commit('legacy record');
		const blob = g('rev-parse', `${legacy}:rpc-filter/probes/runs/old.json`);
		expect('record: an unpinned legacy record fails', layersOf(gateTree(gd, 'main', legacy, undefined, entries)).includes('record'));
		write(ALLOW_PATH, JSON.stringify({ ...allow, records: [{ path: 'rpc-filter/probes/runs/old.json', blob }] }, null, 1));
		const pinned = commit('public: legacy record reviewed 2026-11-12');
		expect('record: a record pinned by blob passes until it changes', !layersOf(gateTree(gd, 'main', pinned, undefined, entries)).includes('record'));
		write('rpc-filter/probes/runs/old.json', JSON.stringify({ detail: 'changed free text' }));
		const changed = commit('change it');
		expect('record: a changed pinned record fails again', layersOf(gateTree(gd, 'main', changed, undefined, entries)).includes('record'));
		const noAllow = (() => { g('rm', '-q', ALLOW_PATH); return commit('drop allowlist'); })();
		let threw = false;
		try { gatePush(gd, 'refs/heads/x', noAllow, undefined, true, entries); } catch { threw = true; }
		expect('git-push: no allowlist at the tip fails closed', threw);
		const quiet = (f: () => number) => { const [o, e] = [process.stdout.write, process.stderr.write]; process.stdout.write = process.stderr.write = (() => true) as never; try { return f(); } finally { process.stdout.write = o; process.stderr.write = e; } };
		expect('run: no list fails closed', quiet(() => run('git-push', ['--git-dir', gd, '--list', path.join(tmp, 'none'), '--ref', 'x', ok])) === 2);
		expect('run: a bad repository fails closed', quiet(() => { fs.writeFileSync(path.join(tmp, 'l'), 'fake-pipeline-internal\n'); return run('git-tree', ['--git-dir', path.join(tmp, 'nope'), '--list', path.join(tmp, 'l'), '--ref', 'x', ok]); }) === 2);
	} finally {
		fs.rmSync(tmp, { recursive: true, force: true });
	}
	console.log(bad.length ? `publish-gate self-test FAILED: ${bad.join('; ')}` : `publish-gate self-test: ${cases} cases OK`);
	return bad.length ? 1 : 0;
}

if (import.meta.main) {
	const [cmd, ...rest] = process.argv.slice(2);
	if (cmd === '--self-test') {
		process.exit(selfTest());
	} else if (cmd === 'git-push' || cmd === 'git-tree') {
		process.exit(run(cmd, rest));
	} else if (cmd === 'text') {
		process.exit(runText(rest));
	} else {
		console.error('usage: publish-gate.ts git-push|git-tree|text ... | --self-test');
		process.exit(2);
	}
}
