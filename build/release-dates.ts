// Publish dates for pinned dependencies (the 7-day rule: no pin newer than the feed's hold, EDR
// pin-age-cooldown). Shared by the pin-age lint (build/pin-age.ts) and the update report
// (build/deps-outdated.ts). Anonymous reads (a GitHub token only from the environment, for
// rate limits); every answer is data, never interpreted.

import { parseRef } from './registry.ts';

export const COOLDOWN_DAYS = 7;
const DAY = 86_400_000;

/** Days since `iso`, at `now` (fractional). */
export function ageDays(iso: string, now = Date.now()): number {
	return (now - Date.parse(iso)) / DAY;
}

async function json(url: string, headers: Record<string, string> = {}): Promise<unknown> {
	for (let attempt = 0; ; attempt++) {
		const r = await fetch(url, { headers: { 'user-agent': 'seclab-vscode-pin-age', ...headers } });
		if (r.ok) {
			return r.json();
		}
		if (attempt >= 2 || (r.status < 500 && r.status !== 429)) {
			throw new Error(`${new URL(url).host}${new URL(url).pathname}: HTTP ${r.status}`);
		}
		await new Promise(res => setTimeout(res, 2000 * (attempt + 1)));
	}
}

function gh(path: string): Promise<unknown> {
	const token = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;
	return json(`https://api.github.com/${path}`, { accept: 'application/vnd.github+json', ...(token ? { authorization: `Bearer ${token}` } : {}) });
}

const REPO = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

/** A commit's committer date (when it reached the repository). */
export async function commitDate(repo: string, sha: string): Promise<string> {
	if (!REPO.test(repo) || !/^[0-9a-f]{40}$/.test(sha)) {
		throw new Error(`bad commit reference ${repo}@${sha}`);
	}
	const c = await gh(`repos/${repo}/commits/${sha}`) as { commit?: { committer?: { date?: string } } };
	const d = c.commit?.committer?.date;
	if (!d) {
		throw new Error(`${repo}@${sha.slice(0, 12)}: no commit date`);
	}
	return d;
}

/** A GitHub release's publish date, by tag. */
export async function releaseDate(repo: string, tag: string): Promise<string> {
	if (!REPO.test(repo) || !/^[A-Za-z0-9._-]+$/.test(tag)) {
		throw new Error(`bad release reference ${repo}@${tag}`);
	}
	const r = await gh(`repos/${repo}/releases/tags/${tag}`) as { published_at?: string };
	if (!r.published_at) {
		throw new Error(`${repo} ${tag}: no publish date`);
	}
	return r.published_at;
}

/** The first upload time of a PyPI release (the version's publish date). */
export async function pypiDate(name: string, version: string): Promise<string> {
	if (!/^[A-Za-z0-9._-]+$/.test(name) || !/^[A-Za-z0-9.!+_-]+$/.test(version)) {
		throw new Error(`bad PyPI reference ${name}==${version}`);
	}
	const r = await json(`https://pypi.org/pypi/${name}/${version}/json`) as { urls?: Array<{ upload_time_iso_8601?: string }> };
	const times = (r.urls ?? []).map(u => u.upload_time_iso_8601).filter((t): t is string => !!t).sort();
	if (!times.length) {
		throw new Error(`${name}==${version}: no uploaded files`);
	}
	return times[0];
}

/**
 * An npm version's publish date from the PUBLIC registry. CI only: local runs must date npm pins
 * through CFS (AGENTS.md: never bypass CFS; build/pin-age.ts takes them from `gh cfs -- npm view`).
 */
export async function npmDatePublic(name: string, version: string): Promise<string> {
	if (!process.env.CI) {
		throw new Error('the public npm registry is CI-only; local runs date npm pins through CFS');
	}
	if (!/^(@[a-z0-9._-]+\/)?[a-z0-9._-]+$/.test(name) || !/^[0-9A-Za-z.+-]+$/.test(version)) {
		throw new Error(`bad npm reference ${name}@${version}`);
	}
	const r = await json(`https://registry.npmjs.org/${name.replace('/', '%2f')}`) as { time?: Record<string, string> }; // public-registry: CI only (guarded above)
	const t = r.time?.[version];
	if (!t) {
		throw new Error(`${name}@${version}: not published`);
	}
	return t;
}

/** Docker Hub's record of a tag: its current digest and when that was pushed. */
export interface HubTag { digest?: string; tag_last_pushed?: string }
type Hub = (repo: string, tag: string) => Promise<HubTag>;

async function hubTag(repo: string, tag: string): Promise<HubTag> {
	if (!/^[a-z0-9._-]+\/[a-z0-9._-]+$/.test(repo) || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(tag)) {
		throw new Error(`bad Docker Hub reference ${repo}:${tag}`);
	}
	return await json(`https://hub.docker.com/v2/repositories/${repo}/tags/${tag}`) as HubTag;
}

const realDate = (x: unknown): x is string => typeof x === 'string' && Number.isFinite(Date.parse(x));

/**
 * When a pinned image digest was published, the date the 7-day hold counts from. Only a
 * publication record counts (EDR pin-age-cooldown, addendum of 2026-11-20): Docker Hub's
 * `tag_last_pushed` for a tagged Docker Hub pin that is the tag's current digest. Nothing about
 * the image itself dates its publication: Docker Official Images keep `created` across rebuilds,
 * an index is re-pushed under a new digest when a platform is added, and a new index of old
 * images carries old build times (review of PR 74). So a digest its tag has moved on from, a
 * failed Hub lookup, an untagged pin and any other registry are undated, and an undated pin fails
 * unless its register entry records an owner-approved `ageExempt`. pin-age judges only pins a
 * change adds or alters (`imagePinsToJudge`), so a tag moving on later doesn't fail a pin judged
 * when it landed. `hub` is injectable for the tests (build/release-dates.test.ts).
 */
export async function imageDate(pin: string, opts: { hub?: Hub } = {}): Promise<string> {
	const ref = parseRef(pin);
	if (!ref?.digest) {
		throw new Error(`not a digest pin: ${pin.slice(0, 80)}`);
	}
	if (ref.host !== 'registry-1.docker.io' || !ref.tag) {
		throw new Error(`${ref.host} ${ref.tag ? '' : '(untagged) '}has no publication date for a digest: needs an owner-approved ageExempt`);
	}
	let rec: HubTag;
	try {
		rec = await (opts.hub ?? hubTag)(ref.repo, ref.tag);
	} catch (e) {
		throw new Error(`Docker Hub lookup failed, so the digest is undated: ${(e as Error).message.slice(0, 80)}`);
	}
	if (rec.digest !== ref.digest) {
		throw new Error(`not the current digest of ${ref.repo}:${ref.tag}, so Docker Hub has no publication date for it: pin the tag's current digest`);
	}
	if (!realDate(rec.tag_last_pushed)) {
		throw new Error(`Docker Hub has no push date for ${ref.repo}:${ref.tag}`);
	}
	return rec.tag_last_pushed;
}

/** An image pin: a digest reference that isn't a deb, asset or tool pin. */
export const isImagePin = (p: string) => /@sha256:[0-9a-f]{64}$/.test(p) && !/^(deb|asset|tool):/.test(p);

/**
 * The image pins pin-age dates: those the base register (main's, at the merge base) doesn't
 * already hold as judged. An unchanged pin was judged by publication date when it landed;
 * re-judging it would fail every pin whose tag has since moved on, on every unrelated change. A
 * pin the base exempted was never judged, so it doesn't count as held: dropping its exemption
 * has it judged (review of PR 74). A base exemption without a pin list covered all its pins.
 */
export function imagePinsToJudge(pins: string[], base: { deps: Array<{ pins?: unknown; ageExempt?: unknown }> }): { judge: string[]; unchanged: string[] } {
	if (!Array.isArray(base?.deps)) {
		throw new Error('the base register has no deps array');
	}
	const strings = (x: unknown) => Array.isArray(x) ? x.filter((p): p is string => typeof p === 'string') : [];
	const held = new Set(base.deps.flatMap(d => {
		if (!d.ageExempt) {
			return strings(d.pins);
		}
		const scoped = (d.ageExempt as { pins?: unknown }).pins;
		const exempt = new Set(Array.isArray(scoped) ? strings(scoped) : strings(d.pins));
		return strings(d.pins).filter(p => !exempt.has(p));
	}));
	const images = pins.filter(isImagePin);
	return { judge: images.filter(p => !held.has(p)), unchanged: images.filter(p => held.has(p)) };
}

/** The reason an `ageExempt` records, or an error: an exemption is an owner-approved exception and must say why. */
export function ageExemptReason(x: unknown): string {
	const r = (x as { reason?: unknown } | null)?.reason;
	if (typeof r !== 'string' || r.trim().length < 20) {
		throw new Error('an ageExempt must record its reason (at least 20 characters)');
	}
	return r.trim();
}

/**
 * The pins an entry's `ageExempt` covers: exactly the pins it lists, each still one of the entry's
 * pins (review IMB-9). An exemption is approved for the pins it names, so a bump falls outside it
 * and is judged (and fails, for a pin with no publication date) until a new approval names it.
 */
export function ageExemptPins(d: { pins: string[]; ageExempt?: unknown }): Set<string> {
	if (!d.ageExempt) {
		return new Set();
	}
	ageExemptReason(d.ageExempt);
	const listed = (d.ageExempt as { pins?: unknown }).pins;
	if (!Array.isArray(listed) || !listed.length || !listed.every((p): p is string => typeof p === 'string')) {
		throw new Error('an ageExempt must list the exact pins it covers (ageExempt.pins)');
	}
	const stale = listed.filter(p => !d.pins.includes(p));
	if (stale.length) {
		throw new Error(`ageExempt.pins names ${stale.length} pin(s) the entry no longer holds: the exemption doesn't carry over to a bump`);
	}
	return new Set(listed);
}
