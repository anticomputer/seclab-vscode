// Containment suite, level B: the real editor triggers the vectors.
//   prepare <user-data-dir> [sbx|oci]  create the fixture workspace, claim its tab in the
//                                      editor's tabd state, preinstall the rogue extension
//                                      into the tab, write test user settings
//   check   <user-data-dir>            assert the evidence the editor-run vectors left behind,
//                                      then tear the run down (teardown.ts): stops the editor,
//                                      removes the tab and the profile; fails on leftovers
// In between, open the tab with the fork in the background (never activated; AGENTS.md):
//   node test/window.ts launch --env ... <dir> <printed folder uri>   (prepare prints the exact line)

import { execFileSync, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import { deserialize, mintCanary, scan, serialize } from '../canary/canary.ts';
import { beaconPort, checkUserDataDir, editorLaunchCommand, lockRun } from '../harness.ts';
import { brokerProxy, checkEvidence, readEvidence, report, type Check } from './assert.ts';
import { materialiseFixture, teardownGate, writeManifest, writeSnapshot } from './teardown.ts';

const [mode, userDataArg, driverArg] = process.argv.slice(2);
if ((mode !== 'prepare' && mode !== 'check') || !userDataArg) {
	console.error('usage: check-evidence.ts prepare|check <user-data-dir> [sbx|oci]');
	process.exit(2);
}
const driver = driverArg ?? 'sbx';
const repo = path.resolve(import.meta.dirname, '../..');
const userData = path.resolve(userDataArg);
checkUserDataDir(userData);
const base = path.resolve(process.env.SECLAB_EVIDENCE_DIR ?? path.join(repo, '.work', 'containment-editor'));
lockRun(path.join(base, '..', `${path.basename(base)}.lock.d`));
const ws = path.join(base, 'ws-editor');
const canary = path.join(base, 'canary', 'secret.txt');
const marker = path.join(base, 'PWNED');
const stateDir = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');

if (mode === 'prepare') {
	// A previous run's claim points at the old fixture (a new folder has a new inode, which
	// tabd rightly refuses): remove its tabs and sandboxes, then start from clean state.
	if (fs.existsSync(stateDir)) {
		const old = new TabdClient({
			command: process.execPath,
			args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', driver, '--allowed-root', base],
			env: { HOME: process.env.HOME, USER: process.env.USER },
		});
		await old.initialize('containment-editor-cleanup', '0');
		for (const t of (await old.request<{ tabs: Array<{ metadata: { name: string } }> }>('tab.list')).tabs) {
			await old.request('tab.remove', { tabId: t.metadata.name }).catch(() => undefined);
		}
		old.dispose();
		fs.rmSync(stateDir, { recursive: true, force: true });
	}
	fs.rmSync(base, { recursive: true, force: true });
	fs.mkdirSync(path.dirname(canary), { recursive: true });
	fs.writeFileSync(canary, 'HOST-SECRET-CANARY\n');
	materialiseFixture(base, path.join(import.meta.dirname, 'fixtures', 'malicious-workspace'), ws);
	const port = await beaconPort();
	// Per-run arming nonce: the fixture is inert anywhere but inside this run dir.
	const arm = randomBytes(16).toString('hex');
	// Armed for a bounded window only (FS-3): a prepared hostile repo shouldn't stay live.
	const until = Math.floor(Date.now() / 1000) + Number(process.env.SECLAB_ARM_SECONDS ?? 4 * 3600);
	// Anchor the arming nonce on the host side too: probe-safety's env route and
	// teardown's keychain check both read it, and a missing anchor must fail
	// loudly rather than silently skip those checks.
	fs.mkdirSync(base, { recursive: true });
	fs.writeFileSync(path.join(base, '.seclab-probe-nonce'), arm);
	fs.writeFileSync(path.join(ws, '.seclab', 'targets'), `canary=${canary}\nmarker=${marker}\nloopback=${port}\narm=${arm}\nrun=${base}\nuntil=${until}\n`
		+ (process.env.SECLAB_CANARY_CLIPBOARD === '1' ? 'clipboard=1\n' : ''));
	writeSnapshot(base);
	// What this run owns, for teardown.ts: the editor and its tabd are found by the unique
	// user-data-dir (never by program name), the tab by id.
	writeManifest(base, {
		driver: driver as 'sbx' | 'oci', userDataDir: userData, stateDirs: [stateDir],
		// The RPC-lockdown probe runs start an egress beacon at this path. It is
		// not a tab, so teardown only reaps it if the run claims it: a mark must
		// name a program plus arguments containing the run dir.
		commandMarks: [`beacon.ts start ${path.join(base, 'beacon.log')}`],
	});
	// Git repo with a hostile core.fsmonitor. Only `init` and `config` run on the host;
	// neither reads core.fsmonitor. Nothing here may run `git status` on the host.
	execFileSync('git', ['-C', ws, 'init', '-q']);
	execFileSync('git', ['-C', ws, 'config', 'core.fsmonitor', 'sh .seclab/probe.sh fsmonitor']);
	// Disarm on EVERY exit, not just a clean `check`. An aborted or crashed
	// prepare used to leave a host git repo whose core.fsmonitor runs probe.sh
	// on the next `git status` -- from the user's own editor, a watcher or a
	// grep. Probe safety review 2026-11-04, finding 5.
	const disarm = (): void => {
		try { fs.rmSync(path.join(ws, '.git'), { recursive: true, force: true }); } catch { /* best effort */ }
	};
	process.on('exit', disarm);
	process.on('SIGINT', () => { disarm(); process.exit(130); });
	process.on('SIGTERM', () => { disarm(); process.exit(143); });
	process.on('uncaughtException', err => { disarm(); console.error(err); process.exit(2); });
	// Test profile: Workspace Trust off and automatic tasks on, i.e. the worst case for us
	// (trust is UX, not a boundary). Plus editor-side canaries (shared canary harness):
	// user settings (incl. a secret-bearing setting) and, only if opted in, the clipboard
	// (seeding it overwrites the user's real clipboard: SECLAB_CANARY_CLIPBOARD=1).
	// The RPC escape probes are armed by the same arm=/run=/until= fields this
	// harness already writes into .seclab/targets. One arming mechanism, not two.
	const canaries = [mintCanary('user-settings'), mintCanary('user-settings-proxy-auth'), mintCanary('clipboard'), mintCanary('editor-env')];
	fs.writeFileSync(path.join(base, 'canaries.json'), serialize(canaries));
	fs.mkdirSync(path.join(userData, 'User'), { recursive: true });
	fs.writeFileSync(path.join(userData, 'User', 'settings.json'), JSON.stringify({
		'security.workspace.trust.enabled': false,
		'task.allowAutomaticTasks': 'on',
		'seclab.tabs.driver': driver,
		'seclab.tabs.allowedRoots': [base],
		'seclab.test.canary': canaries[0].value,
		'http.proxyAuthorization': `Basic ${canaries[1].value}`,
	}, null, '\t'));
	if (process.env.SECLAB_CANARY_CLIPBOARD === '1') {
		// Opt-in only, and put the user's clipboard back afterwards: it is
		// commonly a password or token, which is exactly why clipboard-read is
		// a probe at all (probe safety review, finding 7).
		const savedClipboard = spawnSync('pbpaste', [], { encoding: 'utf8' }).stdout ?? '';
		process.on('exit', () => {
			try { spawnSync('pbcopy', [], { input: savedClipboard }); } catch { /* best effort */ }
		});
		spawnSync('pbcopy', [], { input: canaries[2].value });
	}
	// Package the rogue extension (vsce in a container) and preinstall it into the tab.
	// The guards live in one place (test/containment/probe-safety.js) but must
	// ship inside the .vsix: a require() reaching outside the extension root
	// throws at activation, which silently produced no probe evidence at all.
	// Copied at package time so there is still a single source of truth; the
	// lint asserts the copies match.
	for (const dir of ['rogue-extension', 'rogue-reh']) {
		fs.copyFileSync(path.join(import.meta.dirname, 'probe-safety.js'),
			path.join(import.meta.dirname, dir, 'probe-safety.js'));
	}
	const vsixDir = path.join(ws, '.seclab');
	// vsce comes from a local image whose npm fetch went through GitHub CFS (EDR cfs-local-builds);
	// it packages with no token and no network.
	const VSCE_IMAGE = 'seclab-vsce:3.9.2';
	if (spawnSync('docker', ['image', 'inspect', VSCE_IMAGE], { stdio: 'ignore' }).status !== 0) {
		execFileSync('gh', ['cfs', '--', 'docker', 'build', '-q', '-t', VSCE_IMAGE, path.join(repo, 'build', 'vsce')], { stdio: 'inherit' });
	}
	execFileSync('docker', ['run', '--rm', '--network', 'none', '--user', `${process.getuid!()}:${process.getgid!()}`, '-v', `${path.join(import.meta.dirname, 'rogue-extension')}:/ext:ro`, '-v', `${vsixDir}:/out`,
		VSCE_IMAGE, 'sh', '-c', 'cp -r /ext /tmp/e && cd /tmp/e && vsce package --allow-missing-repository --skip-license -o /out/rogue.vsix'], { stdio: 'inherit' });
	const client = new TabdClient({
		command: process.execPath,
		args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', driver, '--allowed-root', base],
		env: { HOME: process.env.HOME, USER: process.env.USER },
	});
	await client.initialize('containment-editor', '0');
	const { tab } = await client.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
	writeManifest(base, { tabs: [tab.metadata.name] });
	await client.request('tab.ensureRunning', { tabId: tab.metadata.name });
	const name = `seclab-${tab.metadata.name}`;
	const runtime = driver === 'sbx' ? '/opt/homebrew/bin/sbx' : 'docker';
	const user = driver === 'sbx' ? ['-u', 'agent'] : [];
	const r = spawnSync(runtime, ['exec', ...user, name, '/opt/seclab/bin/seclab-tab-env',
		'/opt/seclab-reh/bin/seclab-code-server', '--install-extension', path.join(vsixDir, 'rogue.vsix')], { encoding: 'utf8' });
	console.log(r.stdout.trim(), r.stderr.trim());
	client.dispose(); // stops the tab; the editor restarts it (extensions persist in the tab)
	await new Promise(res => client.once('exit', res));
	console.log(`\nprepared tab ${tab.metadata.name} for ${ws}`);
	console.log(`\nnow open the TAB directly (never the local path: a local window must not open this hostile workspace).`);
	console.log(`Keep --user-data-dir SHORT: macOS caps unix socket paths at 104 bytes and a deep path silently fails to open a window.\n`);
	console.log(`  ${editorLaunchCommand(userData, `vscode-remote://seclab+${tab.metadata.name}${ws}`, {
		SECLAB_EDITOR_CANARY: canaries[3].value, SECLAB_PROBE_NONCE: arm, SECLAB_PROBE_RUNDIR: base, SECLAB_PROBE_BEACON_PORT: String(port),
	})}`);
} else {
	const checks: Check[] = [];
	for (const vector of ['task', 'fsmonitor', 'rogue-extension']) {
		checks.push(...checkEvidence(readEvidence(ws, vector), vector, { marker, proxy: brokerProxy(driver) }));
	}
	const hostFile = path.join(ws, '.seclab-evidence', 'rogue-extension-host.json');
	const host = fs.existsSync(hostFile) ? JSON.parse(fs.readFileSync(hostFile, 'utf8')) : undefined;
	checks.push({ vector: 'rogue-extension', name: 'ui-kind rogue extension was forced into the tab (remoteName=seclab)', ok: host?.remoteName === 'seclab' && host?.seclabTab === '1', detail: JSON.stringify(host) });
	// No trusted-side extension agents in tab windows: the same ui-declared extension
	// registered a chat participant and called vscode.lm, and that code ran in the tab.
	const agentFile = path.join(ws, '.seclab-evidence', 'rogue-agent.json');
	const agent = fs.existsSync(agentFile) ? JSON.parse(fs.readFileSync(agentFile, 'utf8')) as Record<string, unknown> : undefined;
	checks.push({ vector: 'rogue-extension', name: 'ui-declared chat participant / vscode.lm caller ran in the tab, not trusted-side', ok: agent?.ranIn === 'tab' && agent?.remoteName === 'seclab',
		detail: JSON.stringify(agent ?? 'no rogue-agent.json') });
	checks.push({ vector: 'host', name: 'canary intact', ok: fs.readFileSync(canary, 'utf8') === 'HOST-SECRET-CANARY\n', detail: '' });
	// Shared canary harness, editor side: nothing the rogue extension observed through the
	// API (env, configuration, clipboard, auth sessions, secrets) nor any evidence may
	// contain an editor-side canary in any encoding.
	const canaries = deserialize(fs.readFileSync(path.join(base, 'canaries.json'), 'utf8'));
	const evDir = path.join(ws, '.seclab-evidence');
	const observedOk = fs.existsSync(path.join(evDir, 'rogue-observed.json'));
	checks.push({ vector: 'canary', name: 'rogue extension recorded its API observations', ok: observedOk, detail: '' });
	// Stores the rogue extension can still read through the extension API until the RPC
	// capability filter (M4) lands: configuration (user settings) and the clipboard.
	const M4 = 'M4 RPC capability filter (docs/adr/20261104-rpc-capability-filter.md)';
	const knownUntilM4 = new Set(['user-settings', 'clipboard']);
	for (const f of fs.existsSync(evDir) ? fs.readdirSync(evDir) : []) {
		for (const h of scan(canaries, f, fs.readFileSync(path.join(evDir, f)))) {
			checks.push({ vector: 'canary', name: `no ${h.store} canary in tab-observable data`, ok: false, detail: `${h.encoding} in ${h.source}`,
				knownGap: knownUntilM4.has(h.store) ? M4 : undefined });
		}
	}
	checks.push({ vector: 'canary', name: 'no editor-side canary observed by the tab (outside known gaps)', ok: !checks.some(c => c.vector === 'canary' && !c.ok && !c.knownGap), detail: '' });
	const ok = report(checks);
	// Disarm the hostile git config left in the host work dir.
	fs.rmSync(path.join(ws, '.git'), { recursive: true, force: true });
	// End of run: stop the editor (by its user-data-dir) and everything it started, remove
	// the tab, delete the profile holding the armed rogue extension, diff the host.
	const clean = teardownGate(base);
	process.exit(ok && clean ? 0 : 1);
}
