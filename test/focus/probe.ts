// Focus probe: does a background editor window ever take focus, and on which path? (2026-11-06:
// an agentic run on the release build took focus mid-run.) macOS, sbx, local only.
//   node test/focus/probe.ts prepare [--app PATH] [--skip step,step]   # a benign tab with the probe extension; prints the launch line
//   node test/window.ts launch [--app PATH] ...     # (the printed line) background launch; the watcher kills on a steal
//   node test/focus/probe.ts check                  # marks vs steals, then the teardown gate
// The probe extension (test/focus/probe-extension) steps through the paths one at a time and
// timestamps each; the watcher (test/harness.ts) records the first frontmost sample and kills the
// editor, so a steal is matched to the last mark before it. Nothing here is hostile: the
// workspace is a README and the extension only drives editor commands.

import { execFileSync, spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import { checkUserDataDir, editorLaunchCommand, focusStealLog } from '../harness.ts';
import { readManifest, verifyTeardown, writeManifest, writeSnapshot } from '../containment/teardown.ts';

const repo = path.resolve(import.meta.dirname, '../..');
const base = path.join(repo, '.work', 'focus-probe');
const ws = path.join(base, 'ws');
const userData = path.join(os.homedir(), '.seclab-test', 'fp');
const stateDir = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');
const SBX = '/opt/homebrew/bin/sbx';
const VSCE_IMAGE = 'seclab-vsce:3.9.2';
const [mode, ...rest] = process.argv.slice(2);
const opt = (name: string) => {
	const i = rest.indexOf(name);
	return i >= 0 ? rest[i + 1] : undefined;
};
const appArg = opt('--app') ? path.resolve(opt('--app')!) : undefined;
const skipArg = opt('--skip');

if (mode === 'prepare') {
	checkUserDataDir(userData);
	if (fs.existsSync(path.join(base, 'run.json'))) {
		console.error('a previous focus-probe run is still recorded: run `node test/focus/probe.ts check` first');
		process.exit(1);
	}
	fs.rmSync(base, { recursive: true, force: true });
	fs.rmSync(userData, { recursive: true, force: true });
	fs.mkdirSync(ws, { recursive: true });
	fs.writeFileSync(path.join(ws, 'README.md'), '# focus probe workspace\n');
	if (skipArg) {
		// Map later paths on a build that already failed an earlier one.
		fs.writeFileSync(path.join(ws, '.seclab-focus-skip'), skipArg.replace(/[^a-z,-]/g, '') + '\n');
	}
	writeSnapshot(base);
	writeManifest(base, { driver: 'sbx', userDataDir: userData, stateDirs: [stateDir] });
	fs.mkdirSync(path.join(userData, 'User'), { recursive: true });
	fs.writeFileSync(path.join(userData, 'User', 'settings.json'), JSON.stringify({
		'security.workspace.trust.enabled': false,
		'seclab.tabs.driver': 'sbx',
		'seclab.tabs.allowedRoots': [base],
		'window.restoreWindows': 'none',
	}, null, '\t'));
	// Package the probe (vsce in its local CFS-built image, no network) and preinstall it in the tab.
	const vsixDir = path.join(base, 'vsix');
	fs.mkdirSync(vsixDir, { recursive: true });
	execFileSync('docker', ['run', '--rm', '--network', 'none', '--user', `${process.getuid!()}:${process.getgid!()}`,
		'-v', `${path.join(import.meta.dirname, 'probe-extension')}:/ext:ro`, '-v', `${vsixDir}:/out`,
		VSCE_IMAGE, 'sh', '-c', 'cp -r /ext /tmp/e && cd /tmp/e && vsce package --allow-missing-repository --skip-license -o /out/focus-probe.vsix'], { stdio: 'inherit' });
	const client = new TabdClient({
		command: process.execPath,
		args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', 'sbx', '--allowed-root', base],
		env: { HOME: process.env.HOME, USER: process.env.USER },
	});
	await client.initialize('focus-probe', '0');
	const { tab } = await client.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
	writeManifest(base, { tabs: [tab.metadata.name] });
	await client.request('tab.ensureRunning', { tabId: tab.metadata.name });
	// The vsix is copied into the workspace for the install (the tab sees only the workspace).
	fs.copyFileSync(path.join(vsixDir, 'focus-probe.vsix'), path.join(ws, '.focus-probe.vsix'));
	const r = spawnSync(SBX, ['exec', '-u', 'agent', `seclab-${tab.metadata.name}`, '/opt/seclab/bin/seclab-tab-env',
		'/opt/seclab-reh/bin/seclab-code-server', '--install-extension', path.join(ws, '.focus-probe.vsix')], { encoding: 'utf8' });
	console.log(r.stdout.trim(), r.stderr.trim());
	if (r.status !== 0) {
		console.error('could not install the probe extension in the tab');
		process.exit(1);
	}
	client.dispose();
	await new Promise(res => client.once('exit', res));
	console.log(`\nprepared tab ${tab.metadata.name}. Launch in the BACKGROUND (the watcher kills the editor on any focus steal):\n`);
	console.log(`  ${editorLaunchCommand(userData, `vscode-remote://seclab+${tab.metadata.name}${ws}`, {}, appArg)}\n`);
	console.log('then, after about 2 minutes (or as soon as it was killed):  node test/focus/probe.ts check\n');
} else if (mode === 'check') {
	const m = readManifest(base);
	const tabId = (m.tabs ?? [])[0];
	const marks = tabId ? spawnSync(SBX, ['exec', '-u', 'agent', `seclab-${tabId}`, 'cat', path.join(ws, '.seclab-focus', 'marks.log')], { encoding: 'utf8' }).stdout ?? '' : '';
	const steals = fs.existsSync(focusStealLog(userData)) ? fs.readFileSync(focusStealLog(userData), 'utf8').trim() : '';
	console.log(`marks (in the tab):\n${marks.trim() || '(none)'}\n`);
	if (steals) {
		const at = Date.parse(steals.split(' ')[0]);
		const before = marks.trim().split('\n').filter(l => Date.parse(l.split(' ')[0]) <= at).pop() ?? '(before the first mark)';
		console.log(`FOCUS STOLEN:\n${steals}\nlast step before it: ${before}\n`);
	} else {
		console.log(`no focus steal recorded; ${/ done$/m.test(marks) ? 'every step ran' : 'NOT every step ran (see marks)'}\n`);
	}
	const gate = verifyTeardown(base);
	for (const c of gate) {
		console.log(`${c.ok ? 'OK  ' : 'FAIL'}  ${c.name}${c.ok || !c.detail ? '' : `  ${c.detail}`}`);
	}
	// Torn down (whatever the focus verdict): retire the manifest so the next prepare can run.
	if (gate.filter(c => !/took focus/.test(c.name)).every(c => c.ok)) {
		fs.renameSync(path.join(base, 'run.json'), path.join(base, `run-checked-${Date.now()}.json`));
	}
	process.exit(!steals && / done$/m.test(marks) && gate.every(c => c.ok) ? 0 : 1);
} else {
	console.error('usage: probe.ts prepare [--app PATH] | check');
	process.exit(2);
}
