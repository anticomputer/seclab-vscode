// Resolve what to signature-check for a pinned multi-platform image (ADR supply-chain
// provenance). Some publishers (docker/github-builder: zizmor) sign the BuildKit attestation
// manifest of each platform, not the image itself. The index annotation linking the two is
// unsigned, so this walks the pinned index by digest (every blob is re-hashed) and requires,
// for every platform image, an attestation manifest whose signed in-toto statement names that
// image's digest as a subject. It prints the attestation digests; the caller cosign-verifies
// each with the pinned identity. Any gap exits non-zero (fail closed).
//   node build/verify-image.ts <registry>/<repo>@sha256:<index-digest>
// Runs in the pinned node container (network on: registry reads only, no credentials).

import { createHash } from 'node:crypto';

const ref = process.argv[2] ?? '';
const m = /^([a-z0-9.-]+\.[a-z]{2,}|docker\.io)\/([a-z0-9._/-]+)@(sha256:[0-9a-f]{64})$/.exec(ref);
if (!m) {
	console.error('usage: verify-image.ts <registry>/<repo>@sha256:<digest>');
	process.exit(2);
}
const host = m[1] === 'docker.io' ? 'registry-1.docker.io' : m[1];
const repo = m[1] === 'docker.io' && !m[2].includes('/') ? `library/${m[2]}` : m[2];
const ACCEPT = 'application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json';

let token = '';
async function get(path: string, accept = ACCEPT): Promise<Buffer> {
	const url = `https://${host}/v2/${repo}/${path}`;
	let r = await fetch(url, { headers: { accept, ...(token ? { authorization: `Bearer ${token}` } : {}) }, redirect: 'follow' });
	if (r.status === 401 && !token) {
		const ch = r.headers.get('www-authenticate') ?? '';
		const realm = /realm="([^"]+)"/.exec(ch)?.[1];
		const service = /service="([^"]+)"/.exec(ch)?.[1];
		if (!realm || !/^https:\/\//.test(realm)) {
			throw new Error(`no usable auth challenge from ${host}`);
		}
		const t = await fetch(`${realm}?${new URLSearchParams({ ...(service ? { service } : {}), scope: `repository:${repo}:pull` })}`);
		token = ((await t.json()) as { token?: string; access_token?: string }).token ?? '';
		r = await fetch(url, { headers: { accept, authorization: `Bearer ${token}` }, redirect: 'follow' });
	}
	if (!r.ok) {
		throw new Error(`${path}: HTTP ${r.status}`);
	}
	return Buffer.from(await r.arrayBuffer());
}
/** Fetch by digest and re-hash: the registry can't substitute content. */
async function byDigest(kind: 'manifests' | 'blobs', digest: string): Promise<Buffer> {
	const b = await get(`${kind}/${digest}`);
	const h = `sha256:${createHash('sha256').update(b).digest('hex')}`;
	if (h !== digest) {
		throw new Error(`${kind}/${digest}: content hashes to ${h}`);
	}
	return b;
}

interface Desc { mediaType: string; digest: string; platform?: { os: string; architecture: string }; annotations?: Record<string, string> }
const index = JSON.parse((await byDigest('manifests', m[3])).toString('utf8')) as { manifests?: Desc[] };
if (!Array.isArray(index.manifests)) {
	throw new Error('pinned digest is not an index');
}
const images = index.manifests.filter(d => d.platform && d.platform.os !== 'unknown');
const atts = index.manifests.filter(d => d.annotations?.['vnd.docker.reference.type'] === 'attestation-manifest');
const out: string[] = [];
for (const img of images) {
	let bound = '';
	for (const a of atts) {
		const man = JSON.parse((await byDigest('manifests', a.digest)).toString('utf8')) as { layers?: Desc[] };
		for (const l of man.layers ?? []) {
			if (!/in-toto/.test(l.mediaType)) {
				continue;
			}
			const st = JSON.parse((await byDigest('blobs', l.digest)).toString('utf8')) as { subject?: Array<{ digest?: { sha256?: string } }> };
			if ((st.subject ?? []).some(s => `sha256:${s.digest?.sha256}` === img.digest)) {
				bound = a.digest;
			}
		}
		if (bound) {
			break;
		}
	}
	if (!bound) {
		console.error(`verify-image: ${img.platform?.os}/${img.platform?.architecture} ${img.digest} has no attestation naming it`);
		process.exit(1);
	}
	out.push(`${img.platform?.os}/${img.platform?.architecture} ${img.digest} ${bound}`);
}
if (!out.length) {
	console.error('verify-image: no platform images in the index');
	process.exit(1);
}
console.log(out.join('\n'));
