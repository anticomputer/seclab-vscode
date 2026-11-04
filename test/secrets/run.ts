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
try {
	fs.chmodSync(path.join(work, 'tabs', 'ws', 'lockdir'), 0o700); // left by an aborted run
} catch { /* absent */ }
fs.rmSync(work, { recursive: true, force: true });
const ws = path.join(work, 'tabs', 'ws');
fs.mkdirSync(ws, { recursive: true });
const C = Object.fromEntries(['tree', 'config', 'history', 'allow', 'ignored', 'reflog', 'staged', 'nested', 'symhead', 'common', 'link', 'dirlink', 'objplant', 'abscommon', 'magic', 'envlib', 'archive', 'quoted', 'jar', 'nested2']
	.map(k => [k, mintCanary(k).value])) as Record<'tree' | 'config' | 'history' | 'allow' | 'ignored' | 'reflog' | 'staged' | 'nested' | 'symhead' | 'common' | 'link' | 'dirlink' | 'objplant' | 'abscommon' | 'magic' | 'envlib' | 'archive' | 'quoted' | 'jar' | 'nested2', string>;

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
git('config', 'remote.origin.url', `https://x-access-token:${C.config}@git.example.test/example/repo.git`);
for (const [k, v] of [['core.bigFileThreshold', '1'], ['diff.noprefix', 'true'], ['color.diff', 'always'], ['log.showRoot', 'false']]) {
	git('config', k, v);
}
fs.mkdirSync(path.join(ws, 'sub'));
gitIn(path.join(ws, 'sub'), 'init', '-q');
gitIn(path.join(ws, 'sub'), 'config', 'remote.origin.url', `https://x-access-token:${C.nested}@git.example.test/example/sub.git`);
// N1: symlinked HEAD (valid to git).
fs.mkdirSync(path.join(ws, 'symhead'));
gitIn(path.join(ws, 'symhead'), 'init', '-q');
gitIn(path.join(ws, 'symhead'), 'config', 'remote.origin.url', `https://x-access-token:${C.symhead}@git.example.test/example/s.git`);
fs.rmSync(path.join(ws, 'symhead', '.git', 'HEAD'));
fs.symlinkSync('refs/heads/main', path.join(ws, 'symhead', '.git', 'HEAD'));
// N1: commondir layout: .git holds only HEAD + commondir; objects/refs/config live in .git/c.
const cdir = path.join(ws, 'cdir', '.git');
fs.mkdirSync(cdir, { recursive: true });
execFileSync('git', ['init', '-q', '--bare', path.join(cdir, 'c')], { stdio: 'ignore' });
execFileSync('git', ['--git-dir', path.join(cdir, 'c'), 'config', 'remote.origin.url', `https://x-access-token:${C.common}@git.example.test/example/c.git`], { stdio: 'ignore' });
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
// R1: a directory link into a git dir subtree the copy used to exclude, and a file planted
// under objects/ with a non-object name.
fs.mkdirSync(path.join(ws, '.git', 'modules', 'stash'), { recursive: true });
fs.writeFileSync(path.join(ws, '.git', 'modules', 'stash', 'prod.env'), `TOKEN=${C.dirlink}\n`);
fs.symlinkSync('.git/modules/stash', path.join(ws, 'secrets'));
fs.mkdirSync(path.join(ws, '.git', 'objects', 'ab'), { recursive: true });
fs.writeFileSync(path.join(ws, '.git', 'objects', 'ab', 'abc.env'), `TOKEN=${C.objplant}\n`);
// R1 (macOS only): a link that resolves inside the workspace only on case-insensitive APFS.
if (process.platform === 'darwin') {
	fs.symlinkSync('NODE_MODULES/.cache/x', path.join(ws, '.env.alias'));
}
// R2: an absolute commondir (the workspace's real path, valid in the tab).
const acd = path.join(ws, 'acd', '.git');
fs.mkdirSync(acd, { recursive: true });
execFileSync('git', ['init', '-q', '--bare', path.join(acd, 'c')], { stdio: 'ignore' });
execFileSync('git', ['--git-dir', path.join(acd, 'c'), 'config', 'remote.origin.url', `https://x-access-token:${C.abscommon}@git.example.test/example/a.git`], { stdio: 'ignore' });
fs.rmSync(path.join(acd, 'c', 'HEAD'));
fs.writeFileSync(path.join(acd, 'HEAD'), 'ref: refs/heads/main\n');
fs.writeFileSync(path.join(acd, 'commondir'), `${path.join(acd, 'c')}\n`);
// R3: a file the scanner can't read and a directory it can't list.
fs.writeFileSync(path.join(ws, 'locked.env'), 'TOKEN=placeholder\n', { mode: 0o200 });
fs.mkdirSync(path.join(ws, 'lockdir'), { mode: 0o300 });
// Round 8: a zip magic header in front of a secret (gitleaks skips "binary" files), and a
// directory link into a tree gitleaks allowlists case-insensitively (Env/lib).
fs.writeFileSync(path.join(ws, 'zip.env'), Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x0a]), Buffer.from(`TOKEN=${C.magic}\n`)]));
fs.mkdirSync(path.join(ws, 'Env', 'lib', 'stash'), { recursive: true });
fs.writeFileSync(path.join(ws, 'Env', 'lib', 'stash', 'prod.env'), `TOKEN=${C.envlib}\n`);
fs.symlinkSync('Env/lib/stash', path.join(ws, 'secrets2'));
// Round 9: a secret inside an archive (gitleaks skips archives by default), and a
// magic-header file whose name zerolog quotes (spaces, non-ASCII).
const arcSrc = path.join(work, 'arc');
fs.mkdirSync(arcSrc, { recursive: true });
fs.writeFileSync(path.join(arcSrc, 'creds.env'), `TOKEN=${C.archive}\n`);
execFileSync('tar', ['-czf', path.join(ws, 'backup.tar.gz'), '-C', arcSrc, 'creds.env']);
fs.rmSync(arcSrc, { recursive: true, force: true });
fs.writeFileSync(path.join(ws, 'Résumé data.dat'), Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x0a]), Buffer.from(`TOKEN=${C.quoted}\n`)]));
// Round 10 (F1): an archive gitleaks doesn't recognise by name (a .jar is a zip), and a
// zip nested in a tar.gz (needs TMPDIR on the read-only scanner).
const jarSrc = path.join(work, 'jar');
fs.mkdirSync(jarSrc, { recursive: true });
fs.writeFileSync(path.join(jarSrc, 'application.properties'), `db.password=${C.jar}\n`);
execFileSync('zip', ['-q', '-j', path.join(ws, 'app.jar'), path.join(jarSrc, 'application.properties')]);
fs.writeFileSync(path.join(jarSrc, 'inner.env'), `TOKEN=${C.nested2}\n`);
execFileSync('zip', ['-q', '-j', path.join(jarSrc, 'inner.zip'), path.join(jarSrc, 'inner.env')]);
execFileSync('tar', ['-czf', path.join(ws, 'nested.tar.gz'), '-C', jarSrc, 'inner.zip']);
fs.rmSync(jarSrc, { recursive: true, force: true });

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
	// The unlistable lockdir makes the scan incomplete (on purpose: never silent), and that is the only reason.
	assert.equal(scan.complete, false, show);
	assert.equal(scan.error, 'secret scan incomplete: some paths could not be listed or read', show);
	assert.equal(has('worktree', 'app.env').length, 1, show);
	assert.equal(has('git-dir', '.git/config').length, 1, show);
	assert.ok(has('history', 'old.env').length >= 1, `history blinders not defeated: ${show}`);
	assert.equal(has('worktree', 'allow.env').length, 1, `gitleaks:allow honoured: ${show}`);
	assert.equal(has('worktree', 'ignored.env').length, 1, `.gitleaksignore honoured: ${show}`);
	assert.ok(has(/^(history|objects)$/, 'reflog.env').length + has('objects', '.git (object store)').length >= 2, `reflog-only or staged-only commit missed: ${show}`);
	assert.equal(has('git-dir', 'sub/.git/config').length, 1, `nested repository missed: ${show}`);
	assert.equal(has('git-dir', 'symhead/.git/config').length, 1, `symlinked-HEAD repository missed: ${show}`);
	assert.equal(has('git-dir', 'cdir/.git/c/config').length, 1, `commondir repository missed: ${show}`);
	assert.equal(canary.filter(f => f.source === 'worktree' && ['node_modules/.cache/x', '.env.local', '.env.alias'].includes(f.file)).length, 1, `symlink write-through missed: ${show}`);
	assert.equal(scan.findings.filter(f => f.rule === 'unscanned-large-file' && f.file === 'big.env').length, 1, `padded file dropped silently: ${show}`);
	assert.equal(has('worktree', 'secrets/prod.env').length, 1, `directory link into a git dir missed: ${show}`);
	assert.equal(has('git-dir', '.git/objects/ab/abc.env').length, 1, `file planted under objects/ missed: ${show}`);
	assert.equal(has('git-dir', 'acd/.git/c/config').length, 1, `absolute commondir missed: ${show}`);
	assert.equal(has('worktree', 'zip.env').length, 1, `secret behind a zip magic header missed: ${show}`);
	assert.equal(canary.filter(f => f.file.startsWith('backup.tar.gz')).length, 1, `secret inside an archive missed: ${show}`);
	assert.equal(has('worktree', 'Résumé data.dat').length, 1, `magic-header file with a quoted name missed: ${show}`);
	assert.equal(canary.filter(f => f.file.startsWith('app.jar!')).length, 1, `secret in a .jar (zip not recognised by name) missed: ${show}`);
	assert.equal(scan.findings.filter(f => f.file === 'nested.tar.gz' && f.rule === 'unscanned-archive').length
		+ canary.filter(f => f.file.startsWith('nested.tar.gz!')).length >= 1, true, `zip nested in a tar.gz neither scanned nor blocked: ${show}`);
	assert.equal(canary.filter(f => f.source === 'worktree' && ['Env/lib/stash/prod.env', 'secrets2/prod.env'].includes(f.file)).length, 1, `link into an allowlisted tree missed: ${show}`);
	for (const p of ['locked.env', 'lockdir']) {
		assert.equal(scan.findings.filter(f => f.rule === 'unscanned-unreadable' && f.file === p).length, 1, `unreadable ${p} skipped silently: ${show}`);
	}
	if (process.platform === 'darwin') {
		// Docker Desktop file sharing is case-insensitive like APFS, so the alias resolves in
		// the scanner (scanned under the link; value-deduped with .env.local) or, where it
		// doesn't, tabd's host-side check blocks it.
		assert.ok(scan.findings.some(f => f.file === '.env.alias') || canary.some(f => f.file === '.env.local'), `case-alias link missed: ${show}`);
	}
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
	await client.request('tab.ensureRunning', { tabId, acceptFindings: [...rescan.findings.map(f => f.id), 'scan-incomplete'] });
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
	console.log(`FAIL  ${(e as Error).message}${(e as { data?: unknown }).data ? ` ${JSON.stringify((e as { data?: unknown }).data)}` : ''}`);
} finally {
	if (tabId && process.env.KEEP !== '1') {
		await client.request('tab.remove', { tabId }).catch(() => undefined);
	}
	client.dispose();
	fs.chmodSync(path.join(ws, 'lockdir'), 0o700);
	fs.rmSync(ws, { recursive: true, force: true }); // the fixture holds canary secrets
}
process.exit(ok ? 0 : 1);
