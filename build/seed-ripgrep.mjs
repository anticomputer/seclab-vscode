// Seed @vscode/ripgrep's download cache with the pinned prebuilt binary (build/ripgrep.lock),
// so its postinstall never calls the GitHub API and never installs an unverified binary.
//   node build/seed-ripgrep.mjs SRC                      before `npm ci` in SRC
//   node build/seed-ripgrep.mjs --verify-installed SRC   after it: the installed rg must be the
//                                                         pinned binary, whatever path the
//                                                         postinstall took (review VV-5)
// Fails closed: an @vscode/ripgrep version other than the pinned one, an unknown platform, or a
// hash mismatch stops the build.
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

const verifyInstalled = process.argv[2] === '--verify-installed';
const src = process.argv[verifyInstalled ? 3 : 2];
if (!src) {
	console.error('usage: seed-ripgrep.mjs [--verify-installed] SRC');
	process.exit(2);
}
const lock = fs.readFileSync(new URL('./ripgrep.lock', import.meta.url), 'utf8').split('\n').map(l => l.replace(/#.*/, '').trim()).filter(Boolean).map(l => l.split(/\s+/));
const get = k => lock.find(l => l[0] === k)?.[1];
const pkg = get('package');
const release = get('release');
const assets = new Map(lock.filter(l => l[0] === 'asset').map(l => [l[1], l[2]]));

const upstream = JSON.parse(fs.readFileSync(path.join(src, 'package-lock.json'), 'utf8')).packages?.['node_modules/@vscode/ripgrep']?.version;
if (upstream !== pkg) {
	console.error(`seed-ripgrep: upstream pins @vscode/ripgrep ${upstream}, build/ripgrep.lock has ${pkg}; bump the lock`);
	process.exit(1);
}
const target = { 'darwin-arm64': 'aarch64-apple-darwin', 'darwin-x64': 'x86_64-apple-darwin', 'linux-arm64': 'aarch64-unknown-linux-musl', 'linux-x64': 'x86_64-unknown-linux-musl' }[`${process.platform}-${process.arch}`];
const asset = target && `ripgrep-${release}-${target}.tar.gz`;
const want = asset && assets.get(asset);
if (!want || !/^[0-9a-f]{64}$/.test(want)) {
	console.error(`seed-ripgrep: no pinned asset for ${process.platform}-${process.arch}`);
	process.exit(1);
}
const sha = b => createHash('sha256').update(b).digest('hex');
if (verifyInstalled) {
	const binWant = lock.find(l => l[0] === 'bin' && l[1] === target)?.[2];
	const rg = path.join(src, 'node_modules', '@vscode', 'ripgrep', 'bin', 'rg');
	const got = fs.existsSync(rg) ? sha(fs.readFileSync(rg)) : 'missing';
	if (!binWant || got !== binWant) {
		console.error(`seed-ripgrep: installed ${rg} sha256 ${got} != pinned ${binWant ?? '(none)'}`);
		process.exit(1);
	}
	console.log(`seed-ripgrep: installed rg is the pinned binary (${target})`);
	process.exit(0);
}
// The postinstall's cache path: os.tmpdir()/vscode-ripgrep-cache-<package version>/<asset>.
const dir = path.join(os.tmpdir(), `vscode-ripgrep-cache-${pkg}`);
const dest = path.join(dir, asset);
if (fs.existsSync(dest) && sha(fs.readFileSync(dest)) === want) {
	console.log(`seed-ripgrep: ${asset} already cached and verified`);
	process.exit(0);
}
const res = await fetch(`https://github.com/microsoft/ripgrep-prebuilt/releases/download/${release}/${asset}`, { redirect: 'follow' });
if (!res.ok) {
	console.error(`seed-ripgrep: download failed: HTTP ${res.status}`);
	process.exit(1);
}
const body = Buffer.from(await res.arrayBuffer());
if (sha(body) !== want) {
	console.error(`seed-ripgrep: ${asset} sha256 ${sha(body)} != pinned ${want}`);
	process.exit(1);
}
fs.mkdirSync(dir, { recursive: true });
fs.rmSync(dest, { force: true });
fs.writeFileSync(dest, body);
console.log(`seed-ripgrep: ${asset} verified (sha256 pinned) and cached`);
