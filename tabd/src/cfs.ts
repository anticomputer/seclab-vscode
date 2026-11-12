// CFS package feeds in tabs (ADR cfs-package-feeds-in-tabs; plan increment B4, tabd side).
// The trusted provider table entry: the tab never chooses the feed URLs, the tenant or the
// scope. Off by default; the user turns it on per tab (`tab.packages.set`). The tab gets only
// the broker's sentinel; the real Azure DevOps token is minted here, on the host, with `az`,
// and given to the broker just in time (`credential.provide`). It is never written to disk.

import { spawn } from 'node:child_process';
import { CFS_HOST, loadCfsConfig, type CfsConfig } from './cfs-config.ts';

export { CFS_HOST };
export const CFS_CREDENTIAL_ID = 'cfs';
export const CFS_RESOURCE = '499b84ac-1321-427f-aa17-267ca6975798';
/** Re-mint when the cached token has less than this left. */
const REFRESH_MARGIN_S = 300;
/** Exactly what newCfsSentinel mints (base64url of 32 bytes), which seclab-tab-env also requires. */
const SENTINEL_RE = /^seclab_cfs_[A-Za-z0-9_-]{43}$/;

/**
 * The feed paths and tenant, from the host-side config (tabd/src/cfs-config.ts, EDR
 * cfs-config-outside-repo): never from the tree, never from a tab. The PyPI simple index links
 * its files under the feed's GUID path (measured 2026-11-06, tabd/test/e2e-cfs.ts), so
 * downloads have their own path.
 */
export interface CfsFeeds { readonly npmPath: string; readonly pypiPath: string; readonly pypiDownloadPath: string; readonly tenant: string }

export function cfsFeeds(c: CfsConfig): CfsFeeds {
	const p = (u: string) => new URL(u).pathname;
	const index = p(c.pypiIndex);
	return { npmPath: p(c.npmRegistry), pypiPath: index.slice(0, index.length - 'simple/'.length), pypiDownloadPath: p(c.pypiDownload), tenant: c.tenant };
}

/** The host's feeds, or why CFS is off (a missing or malformed config). Messages carry no value. */
export function loadCfsFeeds(file?: string): { feeds: CfsFeeds } | { problem: string } {
	try {
		return { feeds: cfsFeeds(loadCfsConfig(file)) };
	} catch (e) {
		return { problem: (e as Error).message };
	}
}

/** The feed rules, GET only, on the exact feed paths (`policy.update addAllow`). */
export function cfsAllowRules(f: CfsFeeds): Record<string, unknown>[] {
	return [
		{ id: 'cfs-npm', host: CFS_HOST, methods: ['GET'], path: `${f.npmPath}**` },
		{ id: 'cfs-pypi', host: CFS_HOST, methods: ['GET'], path: `${f.pypiPath}**` },
		{ id: 'cfs-pypi-files', host: CFS_HOST, methods: ['GET'], path: `${f.pypiDownloadPath}**` },
	];
}

/** The rule ids above (removed on disable). */
export const CFS_RULE_IDS = ['cfs-npm', 'cfs-pypi', 'cfs-pypi-files'];

/**
 * `credential.import` params (broker revision 7): the same credential as
 * broker/examples/cfs-feeds.policy.json, with the host-chosen sentinel persisted for the tab (so
 * the tab's npm/pip config stays valid across restarts), injected as Basic cfs:<token> on the
 * feed reads only, the azure-devops provider backstop, and a per-broker-start budget that bounds
 * ingestion under the user's identity. Confirmed bindings: never a first-use prompt.
 */
export function cfsImportParams(f: CfsFeeds, sentinel: string, token: AzToken): Record<string, unknown> {
	if (!SENTINEL_RE.test(sentinel)) {
		throw new Error('cfs sentinel has an unexpected format');
	}
	return {
		id: CFS_CREDENTIAL_ID,
		value: token.value,
		sentinel,
		provider: 'azure-devops',
		inject: { header: 'Authorization', fmt: 'Basic {base64:cfs:{value}}' },
		bind: [
			{ host: CFS_HOST, path: `${f.npmPath}**`, methods: ['GET'] },
			{ host: CFS_HOST, path: `${f.pypiPath}**`, methods: ['GET'] },
			{ host: CFS_HOST, path: `${f.pypiDownloadPath}**`, methods: ['GET'] },
		],
		budget: { requests: 5000, bytes: 2 * 1024 ** 3 },
		source: { kind: 'host', label: 'CFS package feeds (az)' },
	};
}

/** A fresh host-chosen sentinel for a tab (persisted with the tab; not a secret). */
export function newCfsSentinel(bytes: (n: number) => Buffer): string {
	return `seclab_cfs_${bytes(32).toString('base64url')}`;
}

export function isCfsSentinel(s: unknown): s is string {
	return typeof s === 'string' && SENTINEL_RE.test(s);
}

export interface AzToken { value: string; expiresAt: number }

/**
 * Parse `az account get-access-token -o json`: the tenant must be CFS's (as the CFS helper
 * checks), the token non-empty, and the expiry (epoch seconds) in the future.
 */
export function parseAzToken(stdout: string, tenant: string, nowS = Date.now() / 1000): AzToken {
	let j: Record<string, unknown>;
	try {
		j = JSON.parse(stdout) as Record<string, unknown>;
	} catch {
		throw new Error('az: output is not JSON');
	}
	if (j.tenant !== tenant) {
		throw new Error('az: token is for another tenant');
	}
	const value = j.accessToken;
	if (typeof value !== 'string' || !/^[A-Za-z0-9._~+/=-]{16,8192}$/.test(value)) {
		throw new Error('az: no usable access token');
	}
	const exp = Number(j.expires_on ?? (typeof j.expiresOn === 'string' ? Date.parse(j.expiresOn) / 1000 : NaN));
	if (!Number.isFinite(exp) || exp <= nowS) {
		throw new Error('az: token already expired');
	}
	return { value, expiresAt: Math.floor(exp) };
}

/** Mints and caches the host's CFS token, in memory only; concurrent callers share one `az` run. */
export class CfsTokenSource {
	private cached: AzToken | undefined;
	private inflight: Promise<AzToken> | undefined;
	private readonly az: string;
	readonly feeds: CfsFeeds;
	constructor(feeds: CfsFeeds, az = '/opt/homebrew/bin/az') {
		this.feeds = feeds;
		this.az = az;
	}

	async token(): Promise<AzToken> {
		const now = Date.now() / 1000;
		if (this.cached && this.cached.expiresAt - REFRESH_MARGIN_S > now) {
			return this.cached;
		}
		this.cached = undefined;
		this.inflight ??= this.mint().finally(() => {
			this.inflight = undefined;
		});
		const t = await this.inflight;
		this.cached = t;
		return t;
	}

	private mint(): Promise<AzToken> {
		return new Promise((resolve, reject) => {
			// Fixed argv; the token arrives on stdout only and is never logged.
			const p = spawn(this.az, ['account', 'get-access-token', '--tenant', this.feeds.tenant, '--resource', CFS_RESOURCE, '--output', 'json'], { stdio: ['ignore', 'pipe', 'pipe'] });
			let out = '';
			let err = '';
			p.stdout.on('data', (d: Buffer) => out += d.toString('utf8'));
			p.stderr.on('data', (d: Buffer) => err += d.toString('utf8'));
			const timer = setTimeout(() => p.kill('SIGKILL'), 60_000);
			p.on('error', e => {
				clearTimeout(timer);
				reject(new Error(`az: ${e.message} (install azure-cli and run 'az login')`));
			});
			p.on('close', code => {
				clearTimeout(timer);
				if (code !== 0) {
					// az's own message, which names the problem (not logged in, MFA); never the token.
					reject(new Error(`az exited ${code}: ${err.trim().split('\n').slice(-2).join(' ').slice(0, 300)}`));
					return;
				}
				try {
					resolve(parseAzToken(out, this.feeds.tenant));
				} catch (e) {
					reject(e as Error);
				}
			});
		});
	}
}

/**
 * The tab's package configuration line (install script input): `feed -`, or the sentinel, its
 * base64 (npm's _password), and the npm and PyPI feed paths, which the root script checks again.
 */
export function feedInstallLine(sentinel: string | undefined, f?: CfsFeeds): string {
	if (!sentinel) {
		return 'feed -';
	}
	if (!SENTINEL_RE.test(sentinel)) {
		throw new Error('cfs sentinel has an unexpected format');
	}
	if (!f) {
		throw new Error('cfs feeds are not configured');
	}
	return `feed ${sentinel} ${Buffer.from(sentinel).toString('base64')} ${f.npmPath} ${f.pypiPath}`;
}
