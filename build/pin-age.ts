// The 7-day rule (EDR pin-age-cooldown): no pin in the dependency register may be younger than
// the feed's hold on new versions, so a local build through CFS never waits on a pin and nothing
// lands that hasn't been public for a week. Network; runs in CI's lint job.
//   node build/pin-age.ts [--days N] [--verbose] [--npm-dates FILE] [--list-npm] [-]
//     (`-`: `git ls-files -z` on stdin; --npm-dates: {"name@version": iso} resolved through CFS)
// Every register pin is dated, or exempt with its reason printed (Debian apt/debs; an entry's
// recorded `ageExempt`); an unknown date fails.
//   upstream:<sha>, git:<url>@<sha>, actions        commit date (GitHub)
//   tool:<name>:<arch>@sha256, asset:ripgrep-v…     GitHub release publish date
//   images                                          image config `created` (linux/amd64)
//   pip:<file>                                      every `==` pin: first upload to PyPI
//   npm installs of name@x.y.z in tracked Dockerfiles   npm publish time (CFS packument locally,
//                                                       the public registry in CI only)
// The Code-OSS npm tree and the runtimes in upstream's product.json are dated by the upstream
// commit's age (a lockfile can't name a version published after it was committed); the
// upstream commit itself is exempt (it isn't fetched through CFS, and the local CFS fetch fails
// on any lockfile entry CFS won't serve).

import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { ageDays, commitDate, COOLDOWN_DAYS, imageDate, npmDatePublic, pypiDate, releaseDate } from './release-dates.ts';

const repo = path.resolve(import.meta.dirname, '..');
const daysArg = process.argv.indexOf('--days');
const minDays = daysArg > 0 ? Number(process.argv[daysArg + 1]) : COOLDOWN_DAYS;
if (!(minDays >= 0)) {
	console.error('usage: pin-age.ts [--days N]');
	process.exit(2);
}

interface Dep { id: string; kind: string; pins: string[]; track?: { github?: string }; ageExempt?: { reason: string } }
const deps = (JSON.parse(fs.readFileSync(path.join(repo, 'deps/registry.json'), 'utf8')) as { deps: Dep[] }).deps;
const tools = JSON.parse(fs.readFileSync(path.join(repo, 'build/tools/tools.json'), 'utf8')) as Record<string, { url?: string }>;

interface Item { dep: string; what: string; date: () => Promise<string> }
const items: Item[] = [];
const exempt: string[] = [];

/** Requirement pins (`name==version`) in a pip requirements file; continuation and option lines skipped. */
export function pipPins(text: string): Array<[string, string]> {
	const out: Array<[string, string]> = [];
	for (const raw of text.split('\n')) {
		const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([A-Za-z0-9.!+_-]+)/.exec(raw.trim());
		if (m) {
			out.push([m[1], m[2]]);
		}
	}
	return out;
}

for (const d of deps) {
	if (d.ageExempt) {
		exempt.push(`${d.id}: ${d.ageExempt.reason}`);
		continue;
	}
	for (const p of d.pins) {
		let m: RegExpExecArray | null;
		if ((m = /^upstream:([0-9a-f]{40})$/.exec(p))) {
			const sha = m[1];
			items.push({ dep: d.id, what: p, date: () => commitDate(d.track?.github ?? 'microsoft/vscode', sha) });
		} else if ((m = /^git:https:\/\/github\.com\/([^/]+\/[^/]+?)(?:\.git)?@([0-9a-f]{40})$/.exec(p))) {
			const [, r, sha] = m;
			items.push({ dep: d.id, what: p, date: () => commitDate(r, sha) });
		} else if ((m = /^tool:([a-z0-9-]+):[a-z0-9]+@sha256:[0-9a-f]{64}$/.exec(p))) {
			const u = /^https:\/\/github\.com\/([^/]+\/[^/]+)\/releases\/download\/([^/]+)\//.exec(tools[m[1]]?.url ?? '');
			if (!u) {
				items.push({ dep: d.id, what: p, date: () => Promise.reject(new Error('tool has no GitHub release URL')) });
			} else {
				items.push({ dep: d.id, what: `${m[1]} ${u[2]}`, date: () => releaseDate(u[1], u[2]) });
			}
		} else if ((m = /^asset:ripgrep-(v[0-9.]+)-/.exec(p))) {
			const tag = m[1];
			items.push({ dep: d.id, what: `ripgrep-prebuilt ${tag}`, date: () => releaseDate('microsoft/ripgrep-prebuilt', tag) });
		} else if ((m = /^([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)(?:\/[A-Za-z0-9_./-]+)?@([0-9a-f]{40})$/.exec(p))) {
			// Actions: the pinned commit's date. A lower bound on the release's age; Dependabot's
			// cooldown covers the release date.
			const [, r, sha] = m;
			items.push({ dep: d.id, what: p, date: () => commitDate(r, sha) });
		} else if (/@sha256:[0-9a-f]{64}$/.test(p) && !/^(deb|asset|tool):/.test(p)) {
			items.push({ dep: d.id, what: p, date: () => imageDate(p) });
		} else if ((m = /^pip:(.+)$/.exec(p))) {
			for (const [name, version] of pipPins(fs.readFileSync(path.join(repo, m[1]), 'utf8'))) {
				items.push({ dep: d.id, what: `${name}==${version} (${m[1]})`, date: () => pypiDate(name, version) });
			}
		} else if (/^(apt|deb):/.test(p)) {
			exempt.push(`${d.id}: ${p.slice(0, 70)} (Debian archive, apt-signed; not a CFS feed: dated when bumped)`);
		} else {
			items.push({ dep: d.id, what: p, date: () => Promise.reject(new Error('no date source for this pin form')) });
		}
	}
}

// npm packages installed by exact version in tracked Dockerfiles (e.g. build/vsce). The file
// list comes from `git ls-files -z` on stdin when given `-` (containers can't read a worktree's git).
// Transport, chosen by environment, never by fallback (AGENTS.md: never bypass CFS): CI reads the
// public registry (its only transport, EDR cfs-local-builds); local runs take dates the host
// resolved through CFS (`gh cfs -- npm view`, in ./seclab lint pin-age) via --npm-dates FILE.
const listed = process.argv.includes('-') ? fs.readFileSync(0, 'utf8') : execFileSync('git', ['-C', repo, 'ls-files', '-z'], { encoding: 'utf8' });
const files = listed.split('\0').filter(f => /(^|\/)Dockerfile[^/]*$/.test(f));
const npmPins: Array<{ file: string; name: string; version: string }> = [];
for (const f of files) {
	const text = fs.readFileSync(path.join(repo, f), 'utf8').replace(/\\\r?\n/g, ' ');
	for (const line of text.split('\n').filter(l => /\bnpm\s+(install|i)\b/.test(l))) {
		for (const t of line.split(/\s+/)) {
			const m = /^((?:@[a-z0-9._-]+\/)?[a-z0-9._-]+)@([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.+-]*)$/.exec(t);
			if (m) {
				npmPins.push({ file: f, name: m[1], version: m[2] });
			}
		}
	}
}
if (process.argv.includes('--list-npm')) {
	for (const p of npmPins) {
		console.log(`${p.name} ${p.version}`);
	}
	process.exit(0);
}
const datesArg = process.argv.indexOf('--npm-dates');
const cfsDates = datesArg > 0 ? JSON.parse(fs.readFileSync(process.argv[datesArg + 1], 'utf8')) as Record<string, string> : {};
for (const p of npmPins) {
	const key = `${p.name}@${p.version}`;
	items.push({ dep: p.file, what: key, date: async () => {
		if (process.env.CI) {
			return npmDatePublic(p.name, p.version);
		}
		const d = cfsDates[key];
		if (typeof d !== 'string' || !/^\d{4}-\d\d-\d\dT/.test(d)) {
			throw new Error('not available through CFS (run ./seclab lint pin-age; if CFS auth fails: gh cfs doctor --auth)');
		}
		return d;
	} });
}

const seen = new Set<string>();
const unique = items.filter(i => !seen.has(i.what) && seen.add(i.what));
const now = Date.now();
const results: Array<{ item: Item; date?: string; error?: string }> = [];
for (let i = 0; i < unique.length; i += 8) {
	results.push(...await Promise.all(unique.slice(i, i + 8).map(async item => {
		try {
			return { item, date: await item.date() };
		} catch (e) {
			return { item, error: (e as Error).message.slice(0, 160) };
		}
	})));
}
const bad: string[] = [];
for (const r of results) {
	const age = r.date ? ageDays(r.date, now) : NaN;
	const line = `${r.item.dep}: ${r.item.what.slice(0, 100)}  ${r.date ? `${r.date.slice(0, 10)} (${age.toFixed(1)} d)` : `unknown: ${r.error}`}`;
	if (!r.date || !(age >= minDays)) {
		bad.push(line);
	} else if (process.argv.includes('--verbose')) {
		console.log(`ok    ${line}`);
	}
}
for (const e of exempt) {
	console.log(`exempt ${e}`);
}
for (const b of bad) {
	console.log(`FAIL  ${b}`);
}
console.log(bad.length
	? `pin-age: ${bad.length} of ${results.length} pin(s) younger than ${minDays} days or undated (re-pin to a version at least ${minDays} days old; never wait out the CFS hold)`
	: `pin-age: ok (${results.length} pins at least ${minDays} days old, ${exempt.length} exempt)`);
process.exit(bad.length ? 1 : 0);
