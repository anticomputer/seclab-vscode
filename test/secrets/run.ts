// Pre-mount secret scanning, end to end with the real gitleaks image and a real tab.
//   node test/secrets/run.ts [sbx|oci]
// Fixture: a canary secret in a working-tree file, one in .git/config (remote URL), and one
// only in git history. Expect: the open is blocked with all three; moving the two current
// ones rewrites them to sentinels; history needs an explicit exception; after that the tab
// starts and the moved canaries are nowhere in the mounted workspace.

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
const [inTree, inConfig, inHistory] = [mintCanary('worktree'), mintCanary('git-config'), mintCanary('history')].map(c => c.value);

// Build the fixture repo. Hooks disabled; nothing here reads hostile config.
const git = (...a: string[]) => execFileSync('git', ['-C', ws, '-c', 'core.hooksPath=/dev/null', ...a], { stdio: 'ignore' });
git('init', '-q');
git('config', 'user.email', 'test@example.invalid');
git('config', 'user.name', 'test');
fs.writeFileSync(path.join(ws, 'old.env'), `TOKEN=${inHistory}\n`);
git('add', 'old.env');
git('commit', '-qm', 'add');
git('rm', '-q', 'old.env');
git('commit', '-qm', 'remove');
fs.writeFileSync(path.join(ws, 'app.env'), `NAME=demo\nAPI_TOKEN=${inTree}\n`);
git('config', 'remote.origin.url', `https://x-access-token:${inConfig}@github.com/example/repo.git`);

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

	// 1. Blocked, with all three findings, and no secret value anywhere in the response.
	const err = await client.request('tab.ensureRunning', { tabId }).then(() => undefined, e => e as Error & { code?: number });
	assert.equal(err?.code, -32020, `expected a block, got ${err?.message}`);
	const scan = await client.request<{ findings: F[] }>('tab.scan', { tabId });
	const bySource = (s: string) => scan.findings.filter(f => f.source === s && f.rule === 'seclab-canary');
	assert.equal(bySource('worktree').length, 1, JSON.stringify(scan.findings));
	assert.equal(bySource('git-config').length, 1, JSON.stringify(scan.findings));
	assert.ok(bySource('history').length >= 1, JSON.stringify(scan.findings));
	assert.ok(![inTree, inConfig, inHistory].some(v => JSON.stringify(scan).includes(v)), 'findings must be redacted');
	console.log(`PASS  blocked; findings: ${scan.findings.map(f => `${f.source}:${f.file}:${f.line}:${f.rule}`).join(', ')}`);

	// 2. Move the current ones to the vault (sentinels in the files).
	const moves = [...bySource('worktree'), ...bySource('git-config')].map(f => ({ id: f.id, bind: { host: 'api.github.com', path: '/**' } }));
	await client.request('tab.moveSecrets', { tabId, moves });
	assert.ok(!fs.readFileSync(path.join(ws, 'app.env'), 'utf8').includes(inTree));
	assert.ok(!fs.readFileSync(path.join(ws, '.git', 'config'), 'utf8').includes(inConfig));
	console.log('PASS  moved worktree + .git/config secrets; files now hold sentinels');

	// 3. History still blocks until explicitly accepted (recorded exception).
	const err2 = await client.request('tab.ensureRunning', { tabId }).then(() => undefined, e => e as Error & { code?: number });
	assert.equal(err2?.code, -32020);
	const rescan = await client.request<{ findings: F[] }>('tab.scan', { tabId });
	assert.ok(rescan.findings.every(f => f.source === 'history' || f.rule !== 'seclab-canary'), JSON.stringify(rescan.findings));
	await client.request('tab.ensureRunning', { tabId, acceptFindings: rescan.findings.map(f => f.id) });
	const audit = fs.readFileSync(path.join(work, 'state', 'audit.log'), 'utf8');
	assert.match(audit, /secret\.exception/);
	assert.ok(![inTree, inConfig, inHistory].some(v => audit.includes(v)), 'audit log must not contain secrets');
	console.log('PASS  history finding opened only with a recorded exception; audit log has no secret values');

	// 4. Inside the tab, the moved canaries are gone from the working copy and git config.
	const runtime = driver === 'sbx' ? '/opt/homebrew/bin/sbx' : 'docker';
	const user = driver === 'sbx' ? 'agent' : '1000:1000';
	const r = spawnSync(runtime, ['exec', '-u', user, `seclab-${tabId}`, 'sh', '-c', `cat '${ws}/app.env' '${ws}/.git/config'`], { encoding: 'utf8' });
	assert.equal(r.status, 0, r.stderr);
	assert.ok(!r.stdout.includes(inTree) && !r.stdout.includes(inConfig), 'moved secrets visible in the tab');
	console.log('PASS  moved secrets are not visible inside the tab');

	// 5. Restore (tab stopped first).
	await client.request('tab.stop', { tabId });
	const res = await client.request<{ restored: string[] }>('tab.restoreSecrets', { tabId });
	assert.equal(res.restored.length, 2);
	assert.ok(fs.readFileSync(path.join(ws, 'app.env'), 'utf8').includes(inTree));
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
