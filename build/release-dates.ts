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

/** An npm version's publish date. */
export async function npmDate(name: string, version: string): Promise<string> {
	if (!/^(@[a-z0-9._-]+\/)?[a-z0-9._-]+$/.test(name) || !/^[0-9A-Za-z.+-]+$/.test(version)) {
		throw new Error(`bad npm reference ${name}@${version}`);
	}
	const r = await json(`https://registry.npmjs.org/${name.replace('/', '%2f')}`) as { time?: Record<string, string> };
	const t = r.time?.[version];
	if (!t) {
		throw new Error(`${name}@${version}: not published`);
	}
	return t;
}

/** An image's build date (the config's `created`; for an index, its linux/amd64 image). */
export async function imageDate(pin: string): Promise<string> {
	const ref = parseRef(pin);
	if (!ref?.digest) {
		throw new Error(`not a digest pin: ${pin.slice(0, 80)}`);
	}
	const reg = new Registry(ref);
	let m = JSON.parse((await reg.byDigest('manifests', ref.digest)).toString()) as {
		manifests?: Array<{ digest: string; platform?: { os?: string; architecture?: string }; annotations?: Record<string, string> }>;
		config?: { digest: string };
	};
	if (m.manifests) {
		const images = m.manifests.filter(x => !x.annotations?.['vnd.docker.reference.type'] && x.platform?.os !== 'unknown');
		const pick = images.find(x => x.platform?.os === 'linux' && x.platform.architecture === 'amd64') ?? images[0];
		if (!pick) {
			throw new Error(`${pin.slice(0, 60)}: index has no image`);
		}
		m = JSON.parse((await reg.byDigest('manifests', pick.digest)).toString());
	}
	if (!m.config?.digest) {
		throw new Error(`${pin.slice(0, 60)}: manifest has no config`);
	}
	const cfg = JSON.parse((await reg.byDigest('blobs', m.config.digest)).toString()) as { created?: string };
	if (!cfg.created) {
		throw new Error(`${pin.slice(0, 60)}: config has no created date`);
	}
	return cfg.created;
}
