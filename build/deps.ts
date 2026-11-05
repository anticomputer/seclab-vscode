// Dependency register (ADR supply-chain-provenance): deps/registry.json is the single source of
// truth for every third-party input we build, run or ship. This tool:
//   node build/deps.ts check [FILELIST|-]   every pin in the tree is registered, every
//                                           registered pin exists, entries are complete,
//                                           exceptions have an EDR, docs/DEPENDENCIES.md current
//   node build/deps.ts write                regenerate docs/DEPENDENCIES.md
//   node build/deps.ts --self-test
// Pins found in the tree: image digests (`name[:tag]@sha256:…`) in any tracked non-Markdown
// file, workflow `uses: owner/repo@<sha>`, UPSTREAM_SHA in upstream.lock, pip requirement
// files, and the apt package set of every Dockerfile `apt-get install`.

import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

const repo = path.resolve(import.meta.dirname, '..');
const REGISTRY = 'deps/registry.json';
const DOC = 'docs/DEPENDENCIES.md';

export const KINDS = ['source', 'oci-image', 'github-action', 'pip-set', 'npm-tree', 'apt-set', 'binary', 'extension', 'host-tool'] as const;
/** The provenance bar (ADR): one of these, or a recorded, user-approved exception. */
export const BARS = ['signed-verified', 'official-pinned', 'built-from-source', 'exception'] as const;

export interface Dep {
	id: string;
	name: string;
	kind: typeof KINDS[number];
	publisher: string;
	/** True when the artifact comes from the project's own org/registry (or a Docker Official Image). */
	official: boolean;
	purpose: string;
	/** Exact pins as they appear in the tree (see header); empty for host tools and transitive trees. */
	pins: string[];
	/** Where it's used (paths). */
	used: string[];
	/** What the publisher provides (signatures, attestations, checksums). */
	provenance: string;
	/** How we verify it, and where that runs. */
	verify: string;
	bar: typeof BARS[number];
	/** ADR/EDR that records the decision (exceptions: an EDR with the user's approval). */
	record: string;
	/** Who bumps it and how. */
	bump: string;
	/** Open gap against the bar, if any (rendered as an audit finding). */
	gap?: string;
}

export interface TreePin {
	pin: string;
	where: string;
}

const IMAGE_PIN = /(?<![\w./-])([a-z0-9][a-z0-9._/-]*(?::[A-Za-z0-9][A-Za-z0-9._-]*)?@sha256:[0-9a-f]{64})/g;
const ACTION_PIN = /^\s*-?\s*uses:\s*['"]?([A-Za-z0-9_.-]+\/[A-Za-z0-9_./-]+@[0-9a-f]{40})/;

/** apt packages a Dockerfile installs (names only, versions stripped), sorted. */
export function aptPackages(text: string): string[] {
	const joined = text.replace(/\\\r?\n/g, ' ');
	const out = new Set<string>();
	for (const m of joined.matchAll(/apt-get\s+install\s+([^&;|\n]*)/g)) {
		for (const t of m[1].trim().split(/\s+/)) {
			if (t && !t.startsWith('-') && !t.startsWith('$')) {
				out.add(t.replace(/=.*$/, ''));
			}
		}
	}
	return [...out].sort();
}

/** Pins in one tracked file. */
export function pinsIn(f: string, text: string): TreePin[] {
	const out: TreePin[] = [];
	if (f.endsWith('.md')) {
		return out; // prose; runnable blocks call ./seclab, whose pins are checked at their source
	}
	text.split('\n').forEach((line, i) => {
		const where = `${f}:${i + 1}`;
		for (const m of line.matchAll(IMAGE_PIN)) {
			out.push({ pin: m[1], where });
		}
		const a = /(^|\/)\.github\//.test(f) ? ACTION_PIN.exec(line) : null;
		if (a) {
			out.push({ pin: a[1], where });
		}
	});
	if (f === 'upstream.lock') {
		const m = /^UPSTREAM_SHA=["']?([0-9a-f]{40})/m.exec(text);
		if (m) {
			out.push({ pin: `upstream:${m[1]}`, where: f });
		}
	}
	if (/(^|\/)requirements[^/]*\.txt$/.test(f)) {
		out.push({ pin: `pip:${f}`, where: f });
	}
	if (/(^|\/)Dockerfile[^/]*$/.test(f)) {
		const pk = aptPackages(text);
		if (pk.length) {
			out.push({ pin: `apt:${f}:${pk.join(',')}`, where: f });
		}
	}
	return out;
}

export function validate(deps: Dep[], tree: TreePin[], exists: (p: string) => boolean): string[] {
	const problems: string[] = [];
	const ids = new Set<string>();
	const registered = new Map<string, string>();
	for (const d of deps) {
		const at = `${REGISTRY} ${d.id ?? '?'}`;
		for (const k of ['id', 'name', 'kind', 'publisher', 'purpose', 'provenance', 'verify', 'bar', 'record', 'bump'] as const) {
			if (typeof d[k] !== 'string' || !(d[k] as string).trim()) {
				problems.push(`${at}: missing ${k}`);
			}
		}
		if (typeof d.official !== 'boolean' || !Array.isArray(d.pins) || !Array.isArray(d.used)) {
			problems.push(`${at}: official/pins/used malformed`);
			continue;
		}
		if (ids.has(d.id)) {
			problems.push(`${at}: duplicate id`);
		}
		ids.add(d.id);
		if (!KINDS.includes(d.kind)) {
			problems.push(`${at}: unknown kind ${d.kind}`);
		}
		if (!BARS.includes(d.bar)) {
			problems.push(`${at}: unknown bar ${d.bar}`);
		}
		if (d.bar === 'exception' && !/^docs\/edr\//.test(d.record)) {
			problems.push(`${at}: an exception needs an EDR record (docs/edr/…) with the user's approval`);
		}
		if (d.bar === 'official-pinned' && !d.official) {
			problems.push(`${at}: official-pinned requires an official publisher`);
		}
		if (d.record && !exists(d.record)) {
			problems.push(`${at}: record ${d.record} does not exist`);
		}
		for (const p of d.pins) {
			if (registered.has(p)) {
				problems.push(`${at}: pin also registered by ${registered.get(p)}: ${p}`);
			}
			registered.set(p, d.id);
		}
		if (d.pins.length === 0 && !['host-tool', 'npm-tree', 'binary', 'extension'].includes(d.kind)) {
			problems.push(`${at}: a ${d.kind} must list its pins`);
		}
	}
	const seen = new Set<string>();
	for (const t of tree) {
		seen.add(t.pin);
		if (!registered.has(t.pin)) {
			problems.push(`${t.where}: unregistered dependency pin ${t.pin.slice(0, 160)} (add it to ${REGISTRY} with an ADR/EDR)`);
		}
	}
	for (const [p, id] of registered) {
		if (!seen.has(p)) {
			problems.push(`${REGISTRY} ${id}: registered pin no longer in the tree: ${p.slice(0, 160)}`);
		}
	}
	return problems;
}

const cell = (s: string) => s.replace(/\|/g, '\\|').replace(/\s+/g, ' ').trim();
const short = (p: string) => p.replace(/@sha256:([0-9a-f]{12})[0-9a-f]{52}/, '@sha256:$1…').replace(/@([0-9a-f]{12})[0-9a-f]{28}$/, '@$1…');

export function render(deps: Dep[]): string {
	const by = (k: string) => deps.filter(d => d.kind === k);
	const out: string[] = [
		'# Dependencies',
		'',
		'<!-- generated by build/deps.ts write from deps/registry.json; do not edit -->',
		'',
		'Every third-party input we build, run or ship, and the host tools we rely on. The policy and',
		'the provenance bar are in [ADR supply-chain provenance](adr/20261104-supply-chain-provenance.md);',
		'`./seclab lint deps` fails if a pin in the tree is missing here, or an entry is stale.',
		'',
		'Bar: **signed-verified** (publisher signature or attestation, verified before use);',
		'**official-pinned** (digest or hash from the project\'s own source, checksums verified where',
		'published); **built-from-source** (by us, from pinned source); **exception** (EDR, user-approved).',
		'',
	];
	const gaps = deps.filter(d => d.gap);
	if (gaps.length) {
		out.push('## Open gaps', '', '| Dependency | Bar | Gap |', '|---|---|---|');
		for (const d of gaps) {
			out.push(`| ${cell(d.name)} | ${d.bar} | ${cell(d.gap ?? '')} |`);
		}
		out.push('');
	}
	for (const k of KINDS) {
		const list = by(k);
		if (!list.length) {
			continue;
		}
		out.push(`## ${k}`, '', '| Dependency | Publisher | Pin | Bar | Provenance | Verified by | Bump | Record |', '|---|---|---|---|---|---|---|---|');
		for (const d of list) {
			const pins = d.pins.length ? d.pins.map(p => `\`${cell(short(p))}\``).join('<br>') : '—';
			out.push(`| **${cell(d.name)}**<br>${cell(d.purpose)} | ${cell(d.publisher)}${d.official ? ' (official)' : ''} | ${pins} | ${d.bar} | ${cell(d.provenance)} | ${cell(d.verify)} | ${cell(d.bump)} | [record](${path.posix.relative('docs', d.record)}) |`);
		}
		out.push('');
	}
	return out.join('\n');
}

function selfTest(): number {
	const pin = `alpine:3.22@sha256:${'a'.repeat(64)}`;
	const sha = 'b'.repeat(40);
	const base: Dep = { id: 'alpine', name: 'alpine', kind: 'oci-image', publisher: 'Docker Official Images', official: true, purpose: 'p', pins: [pin], used: ['x'], provenance: 'p', verify: 'v', bar: 'official-pinned', record: 'docs/adr/x.md', bump: 'b' };
	const tree = [...pinsIn('x.sh', `docker run ${pin} true\n`), ...pinsIn('.github/workflows/a.yml', `  - uses: actions/checkout@${sha} # v7\n`),
		...pinsIn('Dockerfile', `FROM ${pin}\nRUN apt-get install -y --no-install-recommends \\\n  git curl=8.1 \\\n && rm -rf x\n`), ...pinsIn('README.md', pin)];
	const cases: Array<[string, boolean]> = [
		['tree pins', tree.length === 4 && tree.some(t => t.pin === `apt:Dockerfile:curl,git`)],
		['unregistered action and apt set are found', validate([base], tree, () => true).filter(p => /unregistered/.test(p)).length === 2],
		['stale registered pin', validate([{ ...base, pins: [pin, 'gone@sha256:' + 'c'.repeat(64)] }], tree.slice(0, 1), () => true).some(p => /no longer in the tree/.test(p))],
		['exception needs an EDR', validate([{ ...base, bar: 'exception' }], tree.slice(0, 1), () => true).some(p => /needs an EDR/.test(p))],
		['official-pinned needs official', validate([{ ...base, official: false }], tree.slice(0, 1), () => true).some(p => /requires an official/.test(p))],
		['missing record file', validate([base], tree.slice(0, 1), () => false).some(p => /does not exist/.test(p))],
		['clean', validate([base], tree.slice(0, 1), () => true).length === 0],
	];
	const failed = cases.filter(([, ok]) => !ok).map(([n]) => n);
	console.log(failed.length ? `deps self-test FAILED: ${failed.join(', ')}` : `deps self-test: ${cases.length} cases OK`);
	return failed.length ? 1 : 0;
}

const [mode, arg] = process.argv.slice(2);
if (mode === '--self-test') {
	process.exit(selfTest());
}
if (mode !== 'check' && mode !== 'write') {
	console.error('usage: deps.ts check [FILELIST|-] | write | --self-test');
	process.exit(2);
}
const deps = JSON.parse(fs.readFileSync(path.join(repo, REGISTRY), 'utf8')).deps as Dep[];
const doc = render(deps);
if (mode === 'write') {
	fs.writeFileSync(path.join(repo, DOC), doc);
	console.log(`wrote ${DOC}`);
	process.exit(0);
}
const files = (arg ? fs.readFileSync(arg === '-' ? 0 : arg, 'utf8') : execFileSync('git', ['-C', repo, 'ls-files', '-z'], { encoding: 'utf8' }))
	.split('\0').filter(Boolean)
	.filter(f => !/\.(png|jpe?g|gif|svg|patch)$/.test(f) && !f.includes('/fixtures/') && !f.startsWith('rpc-filter/inventory/') && f !== 'build/deps.ts' && f !== 'build/check-pins.ts' && f !== REGISTRY);
const tree: TreePin[] = [];
for (const f of files) {
	try {
		const text = fs.readFileSync(path.join(repo, f), 'utf8');
		if (!text.includes('\0')) {
			tree.push(...pinsIn(f, text));
		}
	} catch { /* deleted in the worktree */ }
}
const problems = validate(deps, tree, p => fs.existsSync(path.join(repo, p)));
// Artifacts derived from the upstream source must name the SHA the build uses (review CC-2):
// otherwise an upstream.lock bump with a stale RPC inventory/policy passes every gate.
const lockSha = /^UPSTREAM_SHA=["']?([0-9a-f]{40})/m.exec(fs.readFileSync(path.join(repo, 'upstream.lock'), 'utf8'))?.[1];
for (const f of ['rpc-filter/inventory/inventory.json', 'rpc-filter/policy/policy.json', 'rpc-filter/policy/coverage.json']) {
	try {
		const sha = (JSON.parse(fs.readFileSync(path.join(repo, f), 'utf8')) as { upstream_sha?: string }).upstream_sha;
		if (sha !== lockSha) {
			problems.push(`${f}: upstream_sha ${sha} != upstream.lock ${lockSha} (regenerate it from the pinned source)`);
		}
	} catch (e) {
		problems.push(`${f}: unreadable (${(e as Error).message})`);
	}
}
let current = '';
try {
	current = fs.readFileSync(path.join(repo, DOC), 'utf8');
} catch { /* missing */ }
if (current !== doc) {
	problems.push(`${DOC} is out of date: run ./seclab docs write`);
}
for (const p of problems) {
	console.log(p);
}
console.log(problems.length ? `deps: ${problems.length} problem(s)` : `deps: ok (${deps.length} entries, ${new Set(tree.map(t => t.pin)).size} pins in ${files.length} files)`);
process.exit(problems.length ? 1 : 0);
