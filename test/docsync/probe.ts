// Document-sync probe: which host-side documents does the window push into a tab's extension host?
// (patch 0035, EDR document-sync-provenance). macOS, sbx, local only.
//   node test/docsync/probe.ts prepare [--app PATH]   # benign tab + probe extension; fake canaries; prints the launch line
//   node test/window.ts launch …                      # (the printed line) background launch, focus watcher
//   node test/docsync/probe.ts seed                   # when the probe asks: one canary line into the window's host log
//   node test/docsync/probe.ts check [--measure]      # report + assertions (or only scheme counts), then the teardown gate
// Canaries are generated fake `seclabcanary_ds_` values, seeded on the host only: a JSONC comment in
// the isolated profile's settings.json and keybindings.json, a host file outside the tab's mount,
// and a host log line. A comment, because setting values reach a tab anyway through the
// configuration snapshot (a separate sibling; the value canary is reported, not asserted). The tab
// never learns a canary: the probe reports hashes of what it saw.
// The probe's report is tab-controlled data: it's read through a fixed schema, and nothing in it is
// followed.

import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import { checkUserDataDir, editorLaunchCommand, focusStealLog } from '../harness.ts';
import { readManifest, treeTexts, verifyTeardown, writeManifest, writeSnapshot } from '../containment/teardown.ts';

const repo = path.resolve(import.meta.dirname, '../..');
const base = path.join(repo, '.work', 'docsync');
const ws = path.join(base, 'ws');
const hostFile = path.join(base, 'host', 'note.txt');
const canaryFile = path.join(base, 'canaries.json');
const userData = path.join(os.homedir(), '.seclab-test', 'ds');
const stateDir = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');
const SBX = '/opt/homebrew/bin/sbx';
const VSCE_IMAGE = 'seclab-vsce:3.9.2';
const [mode, ...rest] = process.argv.slice(2);
const opt = (name: string) => {
	const i = rest.indexOf(name);
	return i >= 0 ? rest[i + 1] : undefined;
};
const appArg = opt('--app') ? path.resolve(opt('--app')!) : undefined;
const CANARY_KINDS = ['settingsComment', 'keybindingsComment', 'hostFile', 'windowLog', 'settingsValue'] as const;
type Canaries = Record<typeof CANARY_KINDS[number], string>;
const asserted: Array<keyof Canaries> = ['settingsComment', 'keybindingsComment', 'hostFile', 'windowLog'];
const sha = (s: string) => createHash('sha256').update(s).digest('hex');
const tabId = () => (readManifest(base).tabs ?? [])[0];
const inTab = (args: string[]) => spawnSync(SBX, ['exec', '-u', 'agent', `seclab-${tabId()}`, ...args], { encoding: 'utf8', maxBuffer: 64 << 20 });

if (mode === 'prepare') {
	checkUserDataDir(userData);
	if (fs.existsSync(path.join(base, 'run.json'))) {
		console.error('a previous docsync run is still recorded: run `node test/docsync/probe.ts check` first');
		process.exit(1);
	}
	fs.rmSync(base, { recursive: true, force: true });
	fs.rmSync(userData, { recursive: true, force: true });
	fs.mkdirSync(path.join(ws, '.seclab'), { recursive: true });
	fs.mkdirSync(path.dirname(hostFile), { recursive: true });
	const canaries = Object.fromEntries(CANARY_KINDS.map(k => [k, `seclabcanary_ds_${randomBytes(16).toString('hex')}`])) as Canaries;
	fs.writeFileSync(canaryFile, JSON.stringify(canaries));
	writeSnapshot(base);
	writeManifest(base, { driver: 'sbx', userDataDir: userData, stateDirs: [stateDir] });

	// The tab's workspace: benign files, a git repo with one uncommitted change, a notebook.
	fs.writeFileSync(path.join(ws, 'README.md'), '# docsync probe workspace\n');
	fs.writeFileSync(path.join(ws, 'tracked.txt'), 'committed line\n');
	fs.writeFileSync(path.join(ws, 'nb.ipynb'), JSON.stringify({
		cells: [{ cell_type: 'markdown', metadata: {}, source: ['# docsync cell'] }],
		metadata: {}, nbformat: 4, nbformat_minor: 5,
	}));
	const git = (...a: string[]) => execFileSync('git', ['-C', ws, '-c', 'user.name=docsync', '-c', 'user.email=docsync@example.invalid', '-c', 'commit.gpgsign=false', ...a], { stdio: 'ignore' });
	git('init', '-q');
	git('add', 'README.md', 'tracked.txt', 'nb.ipynb');
	git('commit', '-q', '-m', 'docsync fixture');
	fs.appendFileSync(path.join(ws, 'tracked.txt'), 'uncommitted line\n');
	fs.writeFileSync(path.join(ws, '.git', 'info', 'exclude'), '.seclab/\n.seclab-docsync/\n.docsync-probe.vsix\n');

	// Host-side content the user may open in the tab window.
	fs.writeFileSync(hostFile, `host note\n${canaries.hostFile}\n`);
	fs.mkdirSync(path.join(userData, 'User'), { recursive: true });
	fs.writeFileSync(path.join(userData, 'User', 'settings.json'), `{
\t// ${canaries.settingsComment}
\t"security.workspace.trust.enabled": false,
\t"seclab.tabs.driver": "sbx",
\t"seclab.tabs.allowedRoots": [${JSON.stringify(base)}],
\t"window.restoreWindows": "none",
\t"git.openRepositoryInParentFolders": "never",
\t"docsync.sibling": ${JSON.stringify(canaries.settingsValue)}
}
`);
	fs.writeFileSync(path.join(userData, 'User', 'keybindings.json'), `// ${canaries.keybindingsComment}\n[]\n`);

	// Arm the probe for this run only.
	const until = Math.floor(Date.now() / 1000) + 2 * 3600;
	fs.writeFileSync(path.join(ws, '.seclab', 'targets'), `arm=${randomBytes(16).toString('hex')}\nrun=${base}\nuntil=${until}\nhostfile=${hostFile}\n`);

	// Package the probe (vsce in its local CFS-built image, no network) and preinstall it in the tab.
	const vsixDir = path.join(base, 'vsix');
	fs.mkdirSync(vsixDir, { recursive: true });
	execFileSync('docker', ['run', '--rm', '--network', 'none', '--user', `${process.getuid!()}:${process.getgid!()}`,
		'-v', `${path.join(import.meta.dirname, 'probe-extension')}:/ext:ro`, '-v', `${vsixDir}:/out`,
		VSCE_IMAGE, 'sh', '-c', 'cp -r /ext /tmp/e && cd /tmp/e && vsce package --allow-missing-repository --skip-license -o /out/docsync-probe.vsix'], { stdio: 'inherit' });
	const client = new TabdClient({
		command: process.execPath,
		args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', 'sbx', '--allowed-root', base],
		env: { HOME: process.env.HOME, USER: process.env.USER },
	});
	await client.initialize('docsync-probe', '0');
	const { tab } = await client.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
	writeManifest(base, { tabs: [tab.metadata.name] });
	await client.request('tab.ensureRunning', { tabId: tab.metadata.name });
	fs.copyFileSync(path.join(vsixDir, 'docsync-probe.vsix'), path.join(ws, '.docsync-probe.vsix'));
	const r = inTab(['/opt/seclab/bin/seclab-tab-env', '/opt/seclab-reh/bin/seclab-code-server', '--install-extension', path.join(ws, '.docsync-probe.vsix')]);
	console.log(r.stdout.trim(), r.stderr.trim());
	client.dispose();
	await new Promise(res => client.once('exit', res));
	if (r.status !== 0) {
		console.error('could not install the probe extension in the tab; run `node test/docsync/probe.ts check` to tear down');
		process.exit(1);
	}
	console.log(`\nprepared tab ${tab.metadata.name}. Launch in the BACKGROUND:\n`);
	console.log(`  ${editorLaunchCommand(userData, `vscode-remote://seclab+${tab.metadata.name}${ws}`, {}, appArg)}\n`);
	console.log('then:  node test/docsync/probe.ts seed   (waits for the probe), then about 2 minutes later:  node test/docsync/probe.ts check\n');
} else if (mode === 'seed') {
	// The window's own host log only exists once the window runs: wait for the probe to reach the
	// output step, append one canary line to the newest window log, and tell the probe.
	const canaries = JSON.parse(fs.readFileSync(canaryFile, 'utf8')) as Canaries;
	const ready = path.join(ws, '.seclab-docsync', 'ready-output');
	for (let i = 0; i < 300 && inTab(['test', '-e', ready]).status !== 0; i++) {
		spawnSync('sleep', ['1']);
	}
	const logs = path.join(userData, 'logs');
	const candidates = fs.existsSync(logs) ? fs.readdirSync(logs).flatMap(d => {
		const dir = path.join(logs, d);
		return fs.statSync(dir).isDirectory() ? fs.readdirSync(dir).filter(w => /^window\d+$/.test(w)).map(w => path.join(dir, w, 'renderer.log')) : [];
	}).filter(f => fs.existsSync(f)).sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs) : [];
	if (!candidates.length) {
		console.error('no window renderer.log in the isolated profile');
		process.exit(1);
	}
	fs.appendFileSync(candidates[0], `\n[docsync] ${canaries.windowLog}\n`);
	inTab(['touch', path.join(ws, '.seclab-docsync', 'seeded')]);
	console.log(`seeded ${path.relative(userData, candidates[0])}`);
} else if (mode === 'check') {
	const measure = rest.includes('--measure');
	const canaries = JSON.parse(fs.readFileSync(canaryFile, 'utf8')) as Canaries;
	const raw = tabId() ? inTab(['cat', path.join(ws, '.seclab-docsync', 'report.json')]).stdout ?? '' : '';
	// Tab-side text outputs: the REH and extension-host logs and the workspace tree.
	const tabLogs = tabId() ? inTab(['sh', '-c', 'cat /run/user/$(id -u)/seclab/reh.log; find "$HOME" -maxdepth 7 -name "*.log" -size -8M -exec cat {} + 2>/dev/null']).stdout ?? '' : '';
	const wsText = [...treeTexts(ws).values()].join('\n');
	const steals = fs.existsSync(focusStealLog(userData)) ? fs.readFileSync(focusStealLog(userData), 'utf8').trim() : '';

	const results: Array<{ name: string; ok: boolean; detail?: string }> = [];
	const expect = (name: string, ok: boolean, detail?: string) => results.push({ name, ok, detail });
	let rep: any;
	try {
		rep = JSON.parse(raw);
	} catch {
		rep = undefined;
	}
	const isCount = (v: unknown) => Number.isInteger(v) && (v as number) >= 0;
	const schemeOk = (s: string) => /^[a-z][a-z0-9+.-]{0,63}$/i.test(s);
	const valid = !!rep && rep.schema === 'seclab-docsync-report/1' && typeof rep.done === 'boolean'
		&& Array.isArray(rep.steps) && rep.steps.every((s: any) => typeof s?.name === 'string' && typeof s?.ok === 'boolean')
		&& rep.schemes && typeof rep.schemes === 'object' && Object.entries(rep.schemes).every(([k, c]: [string, any]) => schemeOk(k) && ['open', 'change', 'close', 'snapshot'].every(f => isCount(c?.[f])))
		&& Array.isArray(rep.hits) && rep.hits.every((h: any) => schemeOk(h?.scheme) && /^[0-9a-f]{64}$/.test(h?.sha256))
		&& ['precreated', 'foreignSeen'].every(f => typeof rep.perf?.[f] === 'boolean')
		&& ['editSaved', 'untitledTyped', 'tabUntitled', 'gitDoc', 'cellDoc'].every(f => typeof rep.controls?.[f] === 'boolean');
	expect('report present and matches the schema', valid);
	const byHash = new Map(CANARY_KINDS.map(k => [sha(canaries[k]), k]));
	const hitKinds = valid ? (rep.hits as Array<{ scheme: string; sha256: string }>).map(h => ({ scheme: h.scheme, kind: byHash.get(h.sha256) ?? 'unknown' })) : [];
	if (valid) {
		const names = (rep.steps as Array<{ name: string; ok: boolean }>).map(s => `${s.ok ? '' : '!'}${s.name}`.replace(/[^a-z!-]/g, '?'));
		console.log(`steps: ${names.join(' ')}${rep.done ? '' : ' (NOT done)'}`);
		console.log('documents the tab saw, by scheme (open/change/close/snapshot):');
		for (const [s, c] of Object.entries(rep.schemes as Record<string, Record<string, number>>).sort()) {
			console.log(`  ${s.padEnd(28)} ${c.open}/${c.change}/${c.close}/${c.snapshot}`);
		}
		console.log(`canary hits: ${hitKinds.map(h => `${h.kind} via ${h.scheme}`).join(', ') || 'none'}`);
		console.log(`perf pre-create: precreated=${rep.perf.precreated} foreignSeen=${rep.perf.foreignSeen}`);
		console.log(`controls: ${JSON.stringify(rep.controls)}`);
		console.log(`hijack: providers=${Number(rep.hijack?.providers) || 0} fsUserdata=${String(rep.hijack?.fsUserdata ?? '').replace(/[^\x20-\x7e]/g, '?').slice(0, 120)}\n`);
		expect('every probe step ran', rep.done === true);
		for (const k of CANARY_KINDS) {
			const via = hitKinds.filter(h => h.kind === k).map(h => h.scheme);
			expect(`no ${k} canary in any tab document`, via.length === 0, via.join(','));
		}
		expect('hijack 2: the tab pre-created perf:Startup Performance', rep.perf.precreated === true);
		expect('hijack 2: no host content reached the tab through the pre-created model', rep.perf.foreignSeen === false);
		for (const c of ['editSaved', 'untitledTyped', 'tabUntitled', 'gitDoc', 'cellDoc']) {
			expect(`control: ${c}`, rep.controls[c] === true);
		}
	}
	for (const k of asserted) {
		const where = [['tab logs', tabLogs], ['workspace tree', wsText], ['report', raw]].filter(([, t]) => t.includes(canaries[k])).map(([n]) => n);
		expect(`no ${k} canary in tab-side output`, where.length === 0, where.join(','));
	}
	const configHashes: unknown[] = valid && Array.isArray(rep.configHashes) ? rep.configHashes : [];
	console.log(`sibling (not asserted): a user setting's value reaches the tab through configuration: ${configHashes.includes(sha(canaries.settingsValue))}`);
	expect('no focus steal', !steals);
	const gate = verifyTeardown(base);
	if (gate.every(c => c.ok)) {
		fs.renameSync(path.join(base, 'run.json'), path.join(base, `run-checked-${Date.now()}.json`));
	}
	for (const c of [...(measure ? results.filter(r => /schema|focus/.test(r.name)) : results), ...gate]) {
		console.log(`${c.ok ? 'OK  ' : 'FAIL'}  ${c.name}${c.ok || !c.detail ? '' : `  ${c.detail}`}`);
	}
	const relevant = measure ? results.filter(r => /schema|focus/.test(r.name)) : results;
	process.exit(relevant.every(r => r.ok) && gate.every(c => c.ok) ? 0 : 1);
} else {
	console.error('usage: probe.ts prepare [--app PATH] | seed | check [--measure]');
	process.exit(2);
}
