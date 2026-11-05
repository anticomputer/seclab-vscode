// Resolve what to signature-check for a pinned multi-platform image (ADR supply-chain
// provenance). Some publishers (docker/github-builder: zizmor) sign the BuildKit attestation
// manifest of each platform, not the image itself. The index annotation linking the two is
// unsigned, so this walks the pinned index by digest (every blob is re-hashed) and requires,
// for every platform image, an attestation manifest whose signed in-toto statement names that
// image's digest as a subject. It prints "<platform> <image> <attestation>" lines; the caller
// cosign-verifies each attestation with the pinned identity. Any gap exits non-zero.
//   node build/verify-image.ts <registry>/<repo>@sha256:<index-digest>
// Runs in the pinned node container (network on: anonymous registry reads only).

import { parseRef, Registry } from './registry.ts';

const ref = parseRef(process.argv[2] ?? '');
if (!ref?.digest) {
	console.error('usage: verify-image.ts <registry>/<repo>@sha256:<digest>');
	process.exit(2);
}
const reg = new Registry(ref);

interface Desc { mediaType: string; digest: string; platform?: { os: string; architecture: string; variant?: string }; annotations?: Record<string, string> }
const index = JSON.parse((await reg.byDigest('manifests', ref.digest)).toString('utf8')) as { manifests?: Desc[] };
if (!Array.isArray(index.manifests)) {
	console.error('verify-image: the pinned digest is not an index');
	process.exit(1);
}
const images = index.manifests.filter(d => d.platform && d.platform.os !== 'unknown');
const atts = index.manifests.filter(d => d.annotations?.['vnd.docker.reference.type'] === 'attestation-manifest');
// Subjects named by each attestation's in-toto statements (content-addressed through the index).
const subjects = new Map<string, Set<string>>();
for (const a of atts) {
	const man = JSON.parse((await reg.byDigest('manifests', a.digest)).toString('utf8')) as { layers?: Desc[] };
	const s = new Set<string>();
	for (const l of man.layers ?? []) {
		if (!/^application\/vnd\.in-toto\+json$/.test(l.mediaType)) {
			continue;
		}
		const st = JSON.parse((await reg.byDigest('blobs', l.digest)).toString('utf8')) as { subject?: Array<{ digest?: { sha256?: string } }> };
		for (const x of st.subject ?? []) {
			if (/^[0-9a-f]{64}$/.test(x.digest?.sha256 ?? '')) {
				s.add(`sha256:${x.digest?.sha256}`);
			}
		}
	}
	subjects.set(a.digest, s);
}
const out: string[] = [];
for (const img of images) {
	const plat = `${img.platform?.os}/${img.platform?.architecture}${img.platform?.variant ? `/${img.platform.variant}` : ''}`;
	// The attestation the index points at for this image must itself name it (both must hold).
	const bound = atts.find(a => a.annotations?.['vnd.docker.reference.digest'] === img.digest && subjects.get(a.digest)?.has(img.digest));
	if (!bound) {
		console.error(`verify-image: ${plat} ${img.digest} has no attestation naming it`);
		process.exit(1);
	}
	out.push(`${plat} ${img.digest} ${bound.digest}`);
}
if (!out.length) {
	console.error('verify-image: no platform images in the index');
	process.exit(1);
}
console.log(out.join('\n'));
