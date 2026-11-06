// CFS package feeds in a real tab (ADR cfs-package-feeds-in-tabs, open items): local only,
// needs docker, the broker image (./seclab image oci) and `az` logged in to the CFS tenant on
// this host. Never in CI (the harness can't reach CFS).
//   node tabd/test/e2e-cfs.ts
// Turns feeds on for an OCI tab, then from inside the tab, with only the sentinel:
//   - the npm packument and a tarball, recording any redirect and whether it needs credentials;
//   - a real npm (itself fetched from CFS) running `npm view` and `npm pack`;
//   - the PyPI simple index and one file (curl; pip's requests, like curl, drops Authorization
//     across hosts);
//   - negatives: a POST to a feed path, and the sentinel sent to `_apis` (both refused).
// Then reads the broker's audit (credential.used: host, path, status, bytes) and checks that
// the token appears nowhere in the tab. Prints a measurement summary; fails on any check.

import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../src/client.ts';
import { CfsTokenSource } from '../src/cfs.ts';
import { teardownGate, writeManifest, writeSnapshot } from '../../test/containment/teardown.ts';

const repo = path.resolve(import.meta.dirname, '../..');
const work = path.join(repo, '.work', 'e2e-cfs');
const state = path.join(work, 'state');
const ws = path.join(work, 'tabs', 'ws1');
fs.rmSync(work, { recursive: true, force: true });
fs.mkdirSync(ws, { recursive: true });
fs.mkdirSync(state, { recursive: true, mode: 0o700 });
writeSnapshot(work);
writeManifest(work, { driver: 'oci', stateDirs: [state] });
process.on('exit', code => {
	if (!teardownGate(work) && code === 0) {
		process.exitCode = 1;
	}
});

const client = new TabdClient({
	command: process.execPath,
	args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', state, '--driver', 'oci', '--broker', 'required', '--allowed-root', path.join(work, 'tabs')],
	env: { HOME: process.env.HOME, USER: process.env.USER, PATH: '/usr/bin:/bin' },
});
client.on('stderr', (s: string) => process.stderr.write(`[tabd] ${s}`));
const problems: string[] = [];
client.on('notification', (method: string, p: Record<string, unknown>) => {
	if (method === 'tab.packages.problem') {
		problems.push(String(p.message));
	}
});
await client.initialize('e2e-cfs', '0', { approvals: true });
const { tab } = await client.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
const tabId = tab.metadata.name;
writeManifest(work, { tabs: [tabId] });
const ctr = `seclab-${tabId}`;
let failed = false;
const check = (name: string, fn: () => void) => {
	try {
		fn();
		console.log(`ok   ${name}`);
	} catch (e) {
		failed = true;
		console.log(`FAIL ${name}: ${(e as Error).message}`);
	}
};
/** A shell snippet in the tab, as the tab user, with the tab's own environment. */
const inTab = (script: string, timeout = 120_000) => spawnSync('docker', ['exec', '-u', '1000:1000', '--', ctr, '/opt/seclab/bin/seclab-tab-env', 'sh', '-c', script], { encoding: 'utf8', timeout });
const FEED = 'https://pkgs.dev.azure.com/github-cfs/GitHubCFS/_packaging';
try {
	await client.request('tab.ensureRunning', { tabId });
	await client.request('tab.packages.set', { tabId, cfs: true });
	// The import is synchronous on a running tab; give the config a moment to land.
	const auth = 'S="$(sed -n "s|^https://cfs:\\([^@]*\\)@.*|\\1|p" /run/seclab-broker/pip-index-url)"';
	check('the tab has the sentinel config, not a token', () => {
		const r = inTab(`${auth}; echo "$S"; echo "$NPM_CONFIG_REGISTRY"; test -n "$PIP_INDEX_URL" && echo pip-set`);
		const [s, reg, pip] = r.stdout.trim().split('\n');
		assert.match(s, /^seclab_cfs_[A-Za-z0-9_-]{43}$/, r.stderr);
		assert.equal(reg, `${FEED}/github-cfs-oss/npm/registry/`);
		assert.equal(pip, 'pip-set');
	});

	// npm: packument, then the tarball, recording a redirect.
	const pk = inTab(`${auth}; curl -sS --max-time 60 -u "cfs:$S" -o /tmp/pk.json -w '%{http_code}' ${FEED}/github-cfs-oss/npm/registry/is-number && node -e 'const p=require("/tmp/pk.json");console.log(" "+p.versions["7.0.0"].dist.tarball)' 2>/dev/null || true`.replace('node -e', '/opt/seclab-reh/node -e'));
	const [pkCode, tarball] = pk.stdout.trim().split(' ');
	check('npm packument through the broker (200)', () => assert.equal(pkCode, '200', pk.stderr));
	const tb = inTab(`${auth}; curl -sS --max-time 60 -u "cfs:$S" -o /tmp/t.tgz -D /tmp/h -w '%{http_code} %{redirect_url}' '${tarball ?? ''}'; echo; grep -i '^location:' /tmp/h | head -1 | sed 's/[?].*/?…/'`);
	console.log(`     tarball: ${tarball}\n     first response: ${tb.stdout.trim().replace(/[?].*$/m, '?…')}`);
	const tbFinal = inTab(`${auth}; curl -sSL --max-time 120 -u "cfs:$S" -o /tmp/t.tgz -w '%{http_code} %{url_effective} %{num_redirects}' '${tarball ?? ''}'`);
	// Measured 2026-11-06: tarballs answer 303 to <prefix>vsblobprodcus<NNN>.blob.core.windows.net
	// with a signed query, and that host is not allowed (open decision, EDR cfs-feeds-tabd). Until
	// it is, the download must end refused at a CFS storage host, never anywhere else.
	const BLOB = /^https:\/\/[a-z0-9]+vsblobprodcus[0-9]+\.blob\.core\.windows\.net\//;
	check('npm tarball: 303 to a CFS storage host, refused there (no credential sent)', () => {
		const [code, effective, redirects] = tbFinal.stdout.trim().split(' ');
		assert.equal(redirects, '1', tbFinal.stdout);
		assert.match(effective, BLOB, tbFinal.stdout);
		assert.match(code, /^(403|000)$/, tbFinal.stdout);
	});
	console.log(`     final: ${tbFinal.stdout.trim().split('\n')[0].replace(/[?]\S*/, '?…')}`);

	// A real npm client, itself from CFS: its packument is readable, but its tarball redirects to
	// a storage host as above, so `npm view` runs only once that is decided. Measured here: the
	// npm packument read (credential.used, ~24 MB).
	const npm = inTab(`cd /tmp && ${auth} && curl -sS --max-time 120 -u "cfs:$S" -o npm.json -w '%{http_code}' ${FEED}/github-cfs-oss/npm/registry/npm`, 300_000);
	check('the npm packument (a large read) through the broker (200)', () => assert.equal(npm.stdout.trim(), '200', npm.stderr));

	// PyPI: simple index and one file.
	const idx = inTab(`${auth}; curl -sS --max-time 60 -u "cfs:$S" -o /tmp/six.html -w '%{http_code}' ${FEED}/github-cfs-pypi/pypi/simple/six/; echo; grep -o 'href="[^"]*six-1\\.16\\.0-py2\\.py3-none-any\\.whl[^"]*"' /tmp/six.html | head -1`);
	const [idxCode, hrefLine] = idx.stdout.trim().split('\n');
	check('PyPI simple index (200)', () => assert.equal(idxCode, '200', idx.stderr));
	const href = /href="([^"]+)"/.exec(hrefLine ?? '')?.[1];
	const fileUrl = href ? new URL(href.replace(/&amp;/g, '&'), `${FEED}/github-cfs-pypi/pypi/simple/six/`).toString() : '';
	console.log(`     PyPI file link: ${fileUrl.replace(/[?#].*$/, '…')}`);
	const pf = inTab(`${auth}; curl -sSL --max-time 120 -u "cfs:$S" -o /tmp/six.whl -w '%{http_code} %{url_effective} %{num_redirects}' '${fileUrl}'`);
	check('PyPI file: linked under the feed GUID download path, credentialed there, then 303 to a CFS storage host, refused there', () => {
		assert.ok(fileUrl.startsWith('https://pkgs.dev.azure.com/github-cfs/9abd351f-45b0-4bcb-a45d-5c080edea161/_packaging/58e9c775-3dd3-4039-9d28-acc0988184b3/pypi/download/'), fileUrl);
		const [code, effective] = pf.stdout.trim().split(' ');
		assert.match(effective, BLOB, pf.stdout + pf.stderr);
		assert.match(code, /^(403|000)$/, pf.stdout);
	});
	console.log(`     final: ${pf.stdout.trim().replace(/[?]\S*/, '?…')}`);

	// Negatives: a write, and the sentinel sent to the REST API.
	const post = inTab(`${auth}; curl -sS --max-time 30 -o /dev/null -w '%{http_code}' -u "cfs:$S" -X POST ${FEED}/github-cfs-oss/npm/registry/is-number`);
	check('a POST to a feed path is refused (403, or the connection closed)', () => assert.match(post.stdout.trim(), /^(403|000)$/, post.stdout));
	const api = inTab(`${auth}; curl -sS --max-time 30 -o /dev/null -w '%{http_code}' -u "cfs:$S" https://pkgs.dev.azure.com/github-cfs/_apis/connectionData`);
	check('the sentinel sent to _apis is refused', () => assert.match(api.stdout.trim(), /^403$/, api.stdout));

	// The token appears nowhere in the tab (its config, its environment).
	const token = (await new CfsTokenSource().token()).value;
	check('the token is not in the tab', () => {
		const r = inTab('cat /run/seclab-broker/* 2>/dev/null; env');
		assert.ok(r.stdout.length > 0);
		assert.ok(!r.stdout.includes(token), 'token found in the tab');
	});
	check('no tab.packages.problem', () => assert.deepEqual(problems, []));

	// The broker's audit: every credentialed response, and what was refused.
	const logs = execFileSync('docker', ['logs', '--', `${ctr}-broker`], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }) + spawnSync('docker', ['logs', '--', `${ctr}-broker`], { encoding: 'utf8' }).stderr;
	const audits = logs.split('\n').map(l => {
		try {
			return (JSON.parse(l) as { audit?: Record<string, unknown> }).audit;
		} catch {
			return undefined;
		}
	}).filter((a): a is Record<string, unknown> => !!a);
	const used = audits.filter(a => a.type === 'credential.used');
	const hosts = new Map<string, number>();
	for (const a of audits.filter(x => typeof x.host === 'string')) {
		hosts.set(`${a.type} ${a.host}`, (hosts.get(`${a.type} ${a.host}`) ?? 0) + 1);
	}
	console.log('\n     broker audit (type host: count):');
	for (const [k, n] of [...hosts].sort()) {
		console.log(`       ${k}: ${n}`);
	}
	console.log('     credential.used (status, path prefix, bytes):');
	for (const a of used.slice(0, 30)) {
		console.log(`       ${a.status} ${String(a.path).split('/').slice(0, 8).join('/')} ${a.respBytes}`);
	}
	check('credentialed responses are audited (credential.used)', () => assert.ok(used.length > 0));
	check('no credential.used outside pkgs.dev.azure.com', () => assert.ok(used.every(a => a.host === 'pkgs.dev.azure.com'), JSON.stringify(used.map(a => a.host))));
	check('no audit line carries the token', () => assert.ok(!logs.includes(token)));
	fs.writeFileSync(path.join(work, 'audit-summary.json'), JSON.stringify({ hosts: Object.fromEntries(hosts), used: used.map(a => ({ status: a.status, host: a.host, path: a.path, respBytes: a.respBytes })) }, null, '\t'));
} finally {
	await client.request('tab.remove', { tabId }).catch(e => {
		failed = true;
		console.log(`remove: ${(e as Error).message}`);
	});
	client.dispose();
}
console.log(failed ? 'e2e-cfs: FAILED' : 'e2e-cfs: all checks passed');
process.exitCode = failed ? 1 : 0;
