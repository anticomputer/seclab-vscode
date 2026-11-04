// Pre-mount secret scanning, end to end with the real gitleaks image and a real tab.
//   node test/secrets/run.ts [sbx|oci]
// Fixture: canary secrets in a working-tree file, .git/config (remote URL) and git history.
// Plus regressions for review round 5 (S2/S3), each of which hid a secret before:
//   .gitleaksignore + inline gitleaks:allow, history blinders (-diff attributes,
//   core.bigFileThreshold, diff.noprefix, color.diff), a reflog-only commit, a staged-only
//   blob, and a nested repository's .git/config;
// and round 6 (N1): a repo with a symlinked HEAD, a commondir layout, a symlink that
// steers a write into an unscanned path, and a file padded past the size limit.
// Expect: the open is blocked with all of them; moving the two current ones rewrites them
// to sentinels; the rest need an explicit exception; after that the tab starts and the
// moved canaries are nowhere in the mounted workspace.

import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import { mintCanary } from '../canary/canary.ts';

const driver = process.argv[2] ?? 'sbx';
const repo = path.resolve(import.meta.dirname, '../..');
const work = path.join(repo, '.work', 'secrets', driver);
fs.rmSync(work, { recursive: true, force: true });
const ws = path.join(work, 'tabs', 'ws');
fs.mkdirSync(ws, { recursive: true });
const C = Object.fromEntries(['tree', 'config', 'history', 'allow', 'ignored', 'reflog', 'staged', 'nested', 'symhead', 'common', 'link']
	.map(k => [k, mintCanary(k).value])) as Record<'tree' | 'config' | 'history' | 'allow' | 'ignored' | 'reflog' | 'staged' | 'nested' | 'symhead' | 'common' | 'link', string>;

// Build the fixture repo. Hooks disabled; nothing here reads hostile config.
const gitIn = (dir: string, ...a: string[]) => execFileSync('git', ['-C', dir, '-c', 'core.hooksPath=/dev/null', ...a], { stdio: 'ignore' });
const git = (...a: string[]) => gitIn(ws, ...a);
const write = (f: string, s: string) => fs.writeFileSync(path.join(ws, f), s);
git('init', '-q');
git('config', 'user.email', 'test@example.invalid');
git('config', 'user.name', 'test');
write('old.env', `TOKEN=${C.history}\n`);
git('add', 'old.env');
git('commit', '-qm', 'add');
git('rm', '-q', 'old.env');
git('commit', '-qm', 'remove');
write('reflog.env', `TOKEN=${C.reflog}\n`);
git('add', 'reflog.env');
git('commit', '-qm', 'oops');
git('reset', '-q', '--hard', 'HEAD~1'); // now reachable only from the reflog
write('staged.env', `TOKEN=${C.staged}\n`);
git('add', 'staged.env');
write('staged.env', 'TOKEN=placeholder\n'); // only the index blob holds the canary
write('app.env', `NAME=demo\nAPI_TOKEN=${C.tree}\n`);
write('allow.env', `KEY=${C.allow} # gitleaks:allow\n`);
write('ignored.env', `KEY=${C.ignored}\n`);
write('.gitleaksignore', ['app.env', 'allow.env', 'ignored.env', '/scan/ws/app.env', '/scan/ws/allow.env', '/scan/ws/ignored.env', 'ws/ignored.env']
	.flatMap(f => [1, 2].map(l => `${f}:seclab-canary:${l}`)).join('\n') + '\n');
fs.writeFileSync(path.join(ws, '.git', 'info', 'attributes'), '* -diff\n* binary\n');
git('config', 'remote.origin.url', `https://x-access-token:${C.config}@github.com/example/repo.git`);
for (const [k, v] of [['core.bigFileThreshold', '1'], ['diff.noprefix', 'true'], ['color.diff', 'always'], ['log.showRoot', 'false']]) {
	git('config', k, v);
}
fs.mkdirSync(path.join(ws, 'sub'));
gitIn(path.join(ws, 'sub'), 'init', '-q');
gitIn(path.join(ws, 'sub'), 'config', 'remote.origin.url', `https://x-access-token:${C.nested}@github.com/example/sub.git`);
// N1: symlinked HEAD (valid to git).
fs.mkdirSync(path.join(ws, 'symhead'));
gitIn(path.join(ws, 'symhead'), 'init', '-q');
gitIn(path.join(ws, 'symhead'), 'config', 'remote.origin.url', `https://x-access-token:${C.symhead}@github.com/example/s.git`);
fs.rmSync(path.join(ws, 'symhead', '.git', 'HEAD'));
fs.symlinkSync('refs/heads/main', path.join(ws, 'symhead', '.git', 'HEAD'));
// N1: commondir layout: .git holds only HEAD + commondir; objects/refs/config live in .git/c.
const cdir = path.join(ws, 'cdir', '.git');
fs.mkdirSync(cdir, { recursive: true });
execFileSync('git', ['init', '-q', '--bare', path.join(cdir, 'c')], { stdio: 'ignore' });
execFileSync('git', ['--git-dir', path.join(cdir, 'c'), 'config', 'remote.origin.url', `https://x-access-token:${C.common}@github.com/example/c.git`], { stdio: 'ignore' });
fs.rmSync(path.join(cdir, 'c', 'HEAD'));
fs.writeFileSync(path.join(cdir, 'HEAD'), 'ref: refs/heads/main\n');
fs.writeFileSync(path.join(cdir, 'commondir'), 'c\n');
execFileSync('git', ['--git-dir', cdir, 'rev-parse', '--git-common-dir'], { stdio: 'ignore' }); // valid to git
// N1: write-through symlink into an allowlisted path (as if a host tool wrote .env.local).
fs.mkdirSync(path.join(ws, 'node_modules', '.cache'), { recursive: true });
fs.writeFileSync(path.join(ws, 'node_modules', '.cache', 'x'), `TOKEN=${C.link}\n`);
fs.symlinkSync('node_modules/.cache/x', path.join(ws, '.env.local'));
// N1: padded past the size limit (sparse).
fs.writeFileSync(path.join(ws, 'big.env'), '');
fs.truncateSync(path.join(ws, 'big.env'), 65_000_000);

const client = new TabdClient({
	command: process.execPath,
	args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', path.join(work, 'state'), '--driver', driver, '--allowed-root', path.join(work, 'tabs')],
	env: { HOME: process.env.HOME, USER: process.env.USER },
});
client.on('stderr', (s: string) => process.stderr.write(`[tabd] ${s}`));
interface F { id: string; source: string; file: string; line: number; rule: string; movable: boolean }
let tabId = '';
let ok = false;
try {
	await client.initialize('secrets', '0');
	tabId = (await client.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } })).tab.metadata.name;

	// 1. Blocked, with every canary attributed, and no secret value anywhere in the response.
	const err = await client.request('tab.ensureRunning', { tabId }).then(() => undefined, e => e as Error & { code?: number });
	assert.equal(err?.code, -32020, `expected a block, got ${err?.message}`);
	const scan = await client.request<{ complete: boolean; error?: string; findings: F[] }>('tab.scan', { tabId });
	const canary = scan.findings.filter(f => f.rule === 'seclab-canary');
	const has = (source: string | RegExp, file: string) => canary.filter(f => (typeof source === 'string' ? f.source === source : source.test(f.source)) && f.file === file);
	const show = JSON.stringify(scan);
	assert.ok(scan.complete, `scan incomplete: ${scan.error}`);
	assert.equal(has('worktree', 'app.env').length, 1, show);
	assert.equal(has('git-dir', '.git/config').length, 1, show);
	assert.ok(has('history', 'old.env').length >= 1, `history blinders not defeated: ${show}`);
	assert.equal(has('worktree', 'allow.env').length, 1, `gitleaks:allow honoured: ${show}`);
	assert.equal(has('worktree', 'ignored.env').length, 1, `.gitleaksignore honoured: ${show}`);
	assert.ok(has(/^(history|objects)$/, 'reflog.env').length + has('objects', '.git (object store)').length >= 2, `reflog-only or staged-only commit missed: ${show}`);
	assert.equal(has('git-dir', 'sub/.git/config').length, 1, `nested repository missed: ${show}`);
	assert.equal(has('git-dir', 'symhead/.git/config').length, 1, `symlinked-HEAD repository missed: ${show}`);
	assert.equal(has('git-dir', 'cdir/.git/c/config').length, 1, `commondir repository missed: ${show}`);
	assert.equal(canary.filter(f => f.source === 'worktree' && (f.file === 'node_modules/.cache/x' || f.file === '.env.local')).length, 1, `symlink write-through missed: ${show}`);
	assert.equal(scan.findings.filter(f => f.rule === 'unscanned-large-file' && f.file === 'big.env').length, 1, `padded file dropped silently: ${show}`);
	assert.ok(!Object.values(C).some(v => show.includes(v)), 'findings must be redacted');
	console.log(`PASS  blocked; findings: ${canary.map(f => `${f.source}:${f.file}:${f.line}`).join(', ')}`);

	// 2. Move the current ones to the vault (sentinels in the files).
	const moves = [...has('worktree', 'app.env'), ...has('git-dir', '.git/config')].map(f => ({ id: f.id, bind: { host: 'api.github.com', path: '/**' } }));
	await client.request('tab.moveSecrets', { tabId, moves });
	assert.ok(!fs.readFileSync(path.join(ws, 'app.env'), 'utf8').includes(C.tree));
	assert.ok(!fs.readFileSync(path.join(ws, '.git', 'config'), 'utf8').includes(C.config));
	console.log('PASS  moved worktree + .git/config secrets; files now hold sentinels');

	// 3. The rest still block until explicitly accepted (recorded exception).
	const err2 = await client.request('tab.ensureRunning', { tabId }).then(() => undefined, e => e as Error & { code?: number });
	assert.equal(err2?.code, -32020);
	const rescan = await client.request<{ findings: F[] }>('tab.scan', { tabId });
	assert.ok(!rescan.findings.some(f => (f.source === 'worktree' && f.file === 'app.env') || (f.source === 'git-dir' && f.file === '.git/config')), JSON.stringify(rescan.findings));
	await client.request('tab.ensureRunning', { tabId, acceptFindings: rescan.findings.map(f => f.id) });
	const audit = fs.readFileSync(path.join(work, 'state', 'audit.log'), 'utf8');
	assert.match(audit, /secret\.exception/);
	assert.ok(!Object.values(C).some(v => audit.includes(v)), 'audit log must not contain secrets');
	console.log('PASS  remaining findings opened only with a recorded exception; audit log has no secret values');

	// 4. Inside the tab, the moved canaries are gone from the working copy and git config.
	const runtime = driver === 'sbx' ? '/opt/homebrew/bin/sbx' : 'docker';
	const user = driver === 'sbx' ? ['-u', 'agent'] : [];
	const r = spawnSync(runtime, ['exec', ...user, `seclab-${tabId}`, 'sh', '-c', `cat '${ws}/app.env' '${ws}/.git/config'`], { encoding: 'utf8' });
	assert.equal(r.status, 0, r.stderr);
	assert.ok(!r.stdout.includes(C.tree) && !r.stdout.includes(C.config), 'moved secrets visible in the tab');
	console.log('PASS  moved secrets are not visible inside the tab');

	// 5. Restore (tab stopped first).
	await client.request('tab.stop', { tabId });
	const res = await client.request<{ restored: string[] }>('tab.restoreSecrets', { tabId });
	assert.equal(res.restored.length, 2);
	assert.ok(fs.readFileSync(path.join(ws, 'app.env'), 'utf8').includes(C.tree));
	assert.ok(fs.readFileSync(path.join(ws, '.git', 'config'), 'utf8').includes(C.config));
	console.log('PASS  restore puts the original values back');
	ok = true;
} catch (e) {
	console.log(`FAIL  ${(e as Error).message}`);
} finally {
	if (tabId && process.env.KEEP !== '1') {
		await client.request('tab.remove', { tabId }).catch(() => undefined);
	}
	client.dispose();
	fs.rmSync(ws, { recursive: true, force: true }); // the fixture holds canary secrets
}
process.exit(ok ? 0 : 1);
