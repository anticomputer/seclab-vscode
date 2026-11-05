// Minimal anonymous OCI registry client for the dependency tools (no credentials ever).
// Every by-digest read is re-hashed, so a registry can't substitute content.

import { createHash } from 'node:crypto';

export interface ImageRef { host: string; repo: string; tag?: string; digest?: string }

/** `[registry/]repo[:tag][@sha256:…]`; Docker Hub names get registry-1.docker.io and library/. */
export function parseRef(ref: string): ImageRef | undefined {
	const m = /^(?:([a-z0-9.-]+\.[a-z]{2,}(?::\d+)?)\/)?([a-z0-9._/-]+?)(?::([A-Za-z0-9][A-Za-z0-9._-]*))?(?:@(sha256:[0-9a-f]{64}))?$/.exec(ref);
	if (!m) {
		return undefined;
	}
	const hub = !m[1] || m[1] === 'docker.io';
	return { host: hub ? 'registry-1.docker.io' : m[1], repo: hub && !m[2].includes('/') ? `library/${m[2]}` : m[2], tag: m[3], digest: m[4] };
}

const ACCEPT = 'application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json';
/** Token realms we accept (a hostile registry must not point us anywhere else). */
const REALMS = /^https:\/\/(auth\.docker\.io|ghcr\.io|quay\.io|gcr\.io|[a-z0-9-]+\.pkg\.dev|public\.ecr\.aws|mcr\.microsoft\.com)\//;

export class Registry {
	private token = '';
	readonly ref: ImageRef;
	constructor(ref: ImageRef) {
		this.ref = ref;
	}

	async get(path: string, accept = ACCEPT, method = 'GET'): Promise<Response> {
		const url = `https://${this.ref.host}/v2/${this.ref.repo}/${path}`;
		const h = () => ({ accept, ...(this.token ? { authorization: `Bearer ${this.token}` } : {}) });
		let r = await fetch(url, { method, headers: h(), redirect: 'follow' });
		if (r.status === 401 && !this.token) {
			const ch = r.headers.get('www-authenticate') ?? '';
			const realm = /realm="([^"]+)"/.exec(ch)?.[1] ?? '';
			const service = /service="([^"]+)"/.exec(ch)?.[1];
			if (!REALMS.test(realm)) {
				throw new Error(`refusing auth realm ${realm.slice(0, 80)} for ${this.ref.host}`);
			}
			const t = await fetch(`${realm}?${new URLSearchParams({ ...(service ? { service } : {}), scope: `repository:${this.ref.repo}:pull` })}`);
			this.token = ((await t.json()) as { token?: string; access_token?: string }).token ?? '';
			r = await fetch(url, { method, headers: h(), redirect: 'follow' });
		}
		if (!r.ok) {
			throw new Error(`${this.ref.host}/${this.ref.repo} ${path}: HTTP ${r.status}`);
		}
		return r;
	}

	/** Fetch by digest and re-hash. */
	async byDigest(kind: 'manifests' | 'blobs', digest: string): Promise<Buffer> {
		const b = Buffer.from(await (await this.get(`${kind}/${digest}`)).arrayBuffer());
		const h = `sha256:${createHash('sha256').update(b).digest('hex')}`;
		if (h !== digest) {
			throw new Error(`${kind}/${digest}: content hashes to ${h}`);
		}
		return b;
	}

	/** The digest a tag points at now (HEAD; the registry's word, used only to report drift). */
	async tagDigest(tag: string): Promise<string> {
		const r = await this.get(`manifests/${tag}`, ACCEPT, 'HEAD');
		const d = r.headers.get('docker-content-digest') ?? '';
		if (!/^sha256:[0-9a-f]{64}$/.test(d)) {
			throw new Error(`${tag}: no content digest`);
		}
		return d;
	}
}
