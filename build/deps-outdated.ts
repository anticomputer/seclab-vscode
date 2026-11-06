// Dependency update report (ADR supply-chain provenance): what Dependabot can't see. Reads
// deps/registry.json and reports, as Markdown on stdout:
//   - image pins whose tag now points at a different digest (a rebuild, e.g. a base-image
//     security refresh);
//   - entries with `track.github` whose newest release at least 7 days old differs from
//     `track.version`.
// Both respect the 7-day rule (EDR pin-age-cooldown): nothing CFS would still hold is suggested.
// It never changes a pin: an update is a normal change (register entry, verification, review).
// Anonymous reads only; registry/API text is data, quoted, never interpreted.
//   node build/deps-outdated.ts > report.md     (exit 0; per-entry errors are listed)

import * as fs from 'node:fs';
import * as path from 'node:path';
import { parseRef, Registry } from './registry.ts';
import { ageDays, COOLDOWN_DAYS, imageDate } from './release-dates.ts';

interface Dep { id: string; name: string; kind: string; pins: string[]; track?: { github?: string; version?: string } }
const repo = path.resolve(import.meta.dirname, '..');
const deps = (JSON.parse(fs.readFileSync(path.join(repo, 'deps/registry.json'), 'utf8')) as { deps: Dep[] }).deps;
const safe = (s: string) => s.replace(/[^A-Za-z0-9._:/+-]/g, '?').slice(0, 120); // no `@` (mentions), always in code spans (EE-3)

const rows: string[] = [];
const errors: string[] = [];
for (const d of deps) {
	if (d.kind === 'oci-image') {
		for (const p of d.pins) {
			const ref = parseRef(p);
			if (!ref?.tag || !ref.digest) {
				continue;
			}
			try {
				const now = await new Registry(ref).tagDigest(ref.tag);
				// The 7-day rule (EDR pin-age-cooldown): suggest a moved tag only once its image is old enough.
				if (now !== ref.digest && ageDays(await imageDate(`${ref.host}/${ref.repo}@${now}`)) >= COOLDOWN_DAYS) {
					rows.push(`| ${d.id} | tag \`${safe(ref.tag)}\` moved | \`${ref.digest.slice(0, 19)}…\` | \`${safe(now).slice(0, 19)}…\` |`);
				}
			} catch (e) {
				errors.push(`- ${d.id}: \`${safe((e as Error).message)}\``);
			}
		}
	}
	if (d.track?.github && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(d.track.github)) {
		try {
			// The newest release at least COOLDOWN_DAYS old (never one CFS still holds).
			const r = await fetch(`https://api.github.com/repos/${d.track.github}/releases?per_page=30`, { headers: { accept: 'application/vnd.github+json' } });
			if (!r.ok) {
				throw new Error(`releases: HTTP ${r.status}`);
			}
			const releases = (await r.json()) as Array<{ tag_name?: string; published_at?: string; draft?: boolean; prerelease?: boolean }>;
			const ok = releases.filter(x => !x.draft && !x.prerelease && x.published_at && ageDays(x.published_at) >= COOLDOWN_DAYS)
				.sort((a, b) => Date.parse(b.published_at!) - Date.parse(a.published_at!));
			if (!ok.length) {
				throw new Error(`no release at least ${COOLDOWN_DAYS} days old among the latest 30`);
			}
			const tag = String(ok[0].tag_name ?? '');
			if (tag.replace(/^v|^lychee-v/, '') !== (d.track.version ?? '').replace(/^v/, '')) {
				rows.push(`| ${d.id} | new release | \`${safe(d.track.version ?? '?')}\` | \`${safe(tag)}\` |`);
			}
		} catch (e) {
			errors.push(`- ${d.id}: \`${safe((e as Error).message)}\``);
		}
	}
}
console.log([
	'Dependency updates the register tracks and Dependabot can\'t see (`node build/deps-outdated.ts`).',
	'Each update is a normal change: new pin, register entry, publisher verification, review.',
	'',
	// "Nothing outdated." only when every lookup succeeded: a failing registry must not
	// silence the report (EE-1).
	rows.length ? ['| Entry | Change | Pinned | Available |', '|---|---|---|---|', ...rows].join('\n') : errors.length ? 'No updates found among the lookups that succeeded.' : 'Nothing outdated.',
	...(errors.length ? ['', 'Could not check:', ...errors] : []),
].join('\n'));
