// Publish dates for pinned dependencies (the 7-day rule: no pin newer than the feed's hold, EDR
// pin-age-cooldown). Shared by the pin-age lint (build/pin-age.ts) and the update report
// (build/deps-outdated.ts). Anonymous reads (a GitHub token only from the environment, for
// rate limits); every answer is data, never interpreted.

import { parseRef, Registry } from './registry.ts';

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

// The platforms we pull: hosted runners (amd64) and Docker Desktop on Apple silicon (arm64).
const RUN_ARCHES = new Set(['amd64', 'arm64']);

type Get = (kind: 'manifests' | 'blobs', digest: string) => Promise<Buffer | string>;

/**
 * An image's build date: the config's `created`. For an index, the newest `created` over the
 * images we run from it (linux/amd64 and linux/arm64), so neither platform we pull is younger
 * than the date the hold is measured from (review BMP-1); an index with neither is dated over
 * every image it holds. Attestation manifests aside. `get` is injectable for the self-test.
 */
export async function imageDate(pin: string, get?: Get): Promise<string> {
	const ref = parseRef(pin);
	if (!ref?.digest) {
		throw new Error(`not a digest pin: ${pin.slice(0, 80)}`);
	}
	if (!get) {
		const reg = new Registry(ref);
		get = (kind, digest) => reg.byDigest(kind, digest);
	}
	const fetchJson = async (kind: 'manifests' | 'blobs', digest: string) => JSON.parse((await get!(kind, digest)).toString());
	const top = await fetchJson('manifests', ref.digest) as {
		manifests?: Array<{ digest: string; platform?: { os?: string; architecture?: string }; annotations?: Record<string, string> }>;
	};
	let digests = [ref.digest];
	if (top.manifests) {
		const images = top.manifests.filter(x => !x.annotations?.['vnd.docker.reference.type'] && x.platform?.os !== 'unknown');
		const run = images.filter(x => x.platform?.os === 'linux' && RUN_ARCHES.has(x.platform.architecture ?? ''));
		digests = (run.length ? run : images).map(x => x.digest);
	}
	if (!digests.length) {
		throw new Error(`${pin.slice(0, 60)}: index has no image`);
	}
	let newest = '';
	for (const d of digests) {
		const m = (d === ref.digest ? top : await fetchJson('manifests', d)) as { config?: { digest: string } };
		if (!m.config?.digest) {
			throw new Error(`${pin.slice(0, 60)}: manifest has no config`);
		}
		const cfg = await fetchJson('blobs', m.config.digest) as { created?: string };
		if (!cfg.created || Number.isNaN(Date.parse(cfg.created))) {
			throw new Error(`${pin.slice(0, 60)}: config has no created date`);
		}
		if (!newest || Date.parse(cfg.created) > Date.parse(newest)) {
			newest = cfg.created;
		}
	}
	return newest;
}
