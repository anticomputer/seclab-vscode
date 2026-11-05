// Fill missing lockfile integrity for an offline install (EDR cfs-local-builds). Runs in the CFS
// fetch stage, after `npm ci --ignore-scripts` in DIR, with the token-bearing npm config.
//   node lock-fill.mjs DIR OUTDIR
// Upstream leaves `integrity` (and `resolved`) out of some entries (build/rspack), so npm
// resolves them from registry metadata, and an offline install can't find them by hash. For
// exactly those entries, ask npm for that exact name@version (through CFS, from the cache just
// filled) and record its sha512, plus the canonical registry.npmjs.org URL if `resolved` is
// missing too. Nothing else in the lockfile changes: the same package set, versions, existing
// hashes and URLs. A non-sha512 answer fails. If anything was added, the filled lockfile goes
// to OUTDIR/DIR.
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

const NAME_RE = /^(@[a-z0-9_][a-z0-9._-]*\/)?[a-z0-9_][a-z0-9._-]*$/i; // never starts with '-' or '.' (YY-3)
const VERSION_RE = /^[0-9][0-9A-Za-z.+-]*$/;
const SHA512_RE = /^sha512-[A-Za-z0-9+/]{86}==$/;
const registryUrl = (name, version) => `https://registry.npmjs.org/${name}/-/${name.replace(/^@[^/]+\//, '')}-${version}.tgz`;
const nameOf = (k, v) => v.name ?? k.slice(k.lastIndexOf('node_modules/') + 'node_modules/'.length);
/** A registry package entry npm fetches, lacking `integrity`: the only kind filled. */
const fillable = (k, v) => k.includes('node_modules/') && !v.link && !v.inBundle && !v.extraneous && !v.integrity;

// --verify UPSTREAM FILLED (build.sh, before the overlay; review YY-5): FILLED must equal
// UPSTREAM except for `integrity` (sha512) and the canonical `resolved` added to fillable
// entries that lacked them.
if (process.argv[2] === '--verify') {
	const [up, filled] = process.argv.slice(3).map(f => JSON.parse(fs.readFileSync(f, 'utf8')));
	const bad = m => {
		console.error(`lock-fill --verify: ${process.argv[4]}: ${m}`);
		process.exit(1);
	};
	const strip = JSON.parse(JSON.stringify(filled));
	for (const [k, v] of Object.entries(up.packages ?? {})) {
		const f = strip.packages?.[k];
		if (!f) {
			bad(`${k} missing`);
		}
		if (fillable(k, v) && f.integrity !== undefined) {
			if (!SHA512_RE.test(f.integrity)) {
				bad(`${k}: filled integrity is not sha512`);
			}
			delete f.integrity;
			if (v.resolved === undefined && f.resolved !== undefined) {
				if (f.resolved !== registryUrl(nameOf(k, v), v.version)) {
					bad(`${k}: filled resolved is not the canonical registry URL`);
				}
				delete f.resolved;
			}
		}
	}
	if (JSON.stringify(strip) !== JSON.stringify(up)) {
		bad('differs from upstream beyond filled integrity and resolved');
	}
	process.exit(0);
}

const [dir, outDir] = process.argv.slice(2);
const file = path.join(dir, 'package-lock.json');
const lock = JSON.parse(fs.readFileSync(file, 'utf8'));
const fail = m => {
	console.error(`lock-fill: ${dir}: ${m}`);
	process.exit(1);
};
let added = 0;
for (const [k, v] of Object.entries(lock.packages ?? {})) {
	// Only registry packages: skip local path entries (no node_modules/ in the key, e.g. a
	// package's own `packageMocks/keytar`) and extraneous ones, which npm ci never fetches.
	if (!fillable(k, v)) {
		continue;
	}
	// A non-registry source (git, tarball URL) gets no registry hash (review YY-3).
	if (v.resolved !== undefined && !v.resolved.startsWith('https://registry.npmjs.org/')) {
		fail(`${k}: resolved from ${v.resolved.slice(0, 60)}, not the registry; refusing to fill`);
	}
	const name = nameOf(k, v);
	if (!NAME_RE.test(name) || !VERSION_RE.test(v.version ?? '')) {
		fail(`${k}: unexpected name or version`);
	}
	const r = spawnSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts', '--loglevel=error', '--', `${name}@${v.version}`], { cwd: '/tmp', encoding: 'utf8' });
	let integrity;
	try {
		integrity = JSON.parse(r.stdout)[0]?.integrity;
	} catch { /* below */ }
	if (r.status !== 0 || typeof integrity !== 'string' || !SHA512_RE.test(integrity)) {
		fail(`${k}: no sha512 integrity for ${name}@${v.version} (${String(integrity).slice(0, 12)})`);
	}
	v.integrity = integrity;
	// The canonical registry URL, as upstream records for every other entry (scoped packages
	// keep their scope in the path; the file name is the bare name). replace-registry-host maps
	// it to CFS at install time; with it, npm looks the tarball up by this integrity.
	if (!v.resolved) {
		v.resolved = registryUrl(name, v.version);
	}
	added++;
}
if (added) {
	fs.mkdirSync(path.join(outDir, dir), { recursive: true });
	fs.writeFileSync(path.join(outDir, dir, 'package-lock.json'), JSON.stringify(lock, null, '\t') + '\n');
	console.log(`lock-fill: ${dir}: added integrity to ${added} entr${added === 1 ? 'y' : 'ies'}`);
}
