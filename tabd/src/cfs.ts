// CFS package feeds in tabs (ADR cfs-package-feeds-in-tabs; plan increment B4, tabd side).
// The trusted provider table entry: the tab never chooses the feed URLs, the tenant or the
// scope. Off by default; the user turns it on per tab (`tab.packages.set`). The tab gets only
// the broker's sentinel; the real Azure DevOps token is minted here, on the host, with `az`,
// and given to the broker just in time (`credential.provide`). It is never written to disk.

import { spawn } from 'node:child_process';

export const CFS_CREDENTIAL_ID = 'cfs';
export const CFS_HOST = 'pkgs.dev.azure.com';
export const CFS_NPM_PATH = '/github-cfs/GitHubCFS/_packaging/github-cfs-oss/npm/registry/';
export const CFS_PYPI_PATH = '/github-cfs/GitHubCFS/_packaging/github-cfs-pypi/pypi/';
export const CFS_TENANT = '398a6654-997b-47e9-b12b-9515b896b4de';
export const CFS_RESOURCE = '499b84ac-1321-427f-aa17-267ca6975798';
/** Re-mint when the cached token has less than this left. */
const REFRESH_MARGIN_S = 300;
/** Exactly what newCfsSentinel mints (base64url of 32 bytes), which seclab-tab-env also requires. */
const SENTINEL_RE = /^seclab_cfs_[A-Za-z0-9_-]{43}$/;

/** The two feed rules, GET only, on the exact feed paths (`policy.update addAllow`). */
export function cfsAllowRules(): Record<string, unknown>[] {
	return [
		{ id: 'cfs-npm', host: CFS_HOST, methods: ['GET'], path: `${CFS_NPM_PATH}**` },
		{ id: 'cfs-pypi', host: CFS_HOST, methods: ['GET'], path: `${CFS_PYPI_PATH}**` },
	];
}

/**
 * `credential.import` params (broker revision 7): the same credential as
 * broker/examples/cfs-feeds.policy.json, with the host-chosen sentinel persisted for the tab (so
 * the tab's npm/pip config stays valid across restarts), injected as Basic cfs:<token> on the
 * feed reads only, the azure-devops provider backstop, and a lifetime budget that bounds
 * ingestion under the user's identity. Confirmed bindings: never a first-use prompt.
 */
export function cfsImportParams(sentinel: string, token: AzToken): Record<string, unknown> {
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
			{ host: CFS_HOST, path: `${CFS_NPM_PATH}**`, methods: ['GET'] },
			{ host: CFS_HOST, path: `${CFS_PYPI_PATH}**`, methods: ['GET'] },
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
export function parseAzToken(stdout: string, nowS = Date.now() / 1000): AzToken {
	let j: Record<string, unknown>;
	try {
		j = JSON.parse(stdout) as Record<string, unknown>;
	} catch {
		throw new Error('az: output is not JSON');
	}
	if (j.tenant !== CFS_TENANT) {
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
	constructor(az = '/opt/homebrew/bin/az') {
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
			const p = spawn(this.az, ['account', 'get-access-token', '--tenant', CFS_TENANT, '--resource', CFS_RESOURCE, '--output', 'json'], { stdio: ['ignore', 'pipe', 'pipe'] });
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
					resolve(parseAzToken(out));
				} catch (e) {
					reject(e as Error);
				}
			});
		});
	}
}

/** The tab's package configuration lines (install script input): npm user config and pip's index URL. */
export function feedInstallLine(sentinel: string | undefined): string {
	if (!sentinel) {
		return 'feed -';
	}
	if (!SENTINEL_RE.test(sentinel)) {
		throw new Error('cfs sentinel has an unexpected format');
	}
	return `feed ${sentinel} ${Buffer.from(sentinel).toString('base64')}`;
}
