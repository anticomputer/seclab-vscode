// Notebook-sync probe: do host notebooks opened in a tab window reach the tab's extension host?
// (sibling DOCSYNC-R2 of patch 0035). macOS, sbx, local only. One run:
//   node test/nbsync/probe.ts prepare [--app PATH]   # benign tab + probe extension; fake canaries on the host
//   node test/window.ts launch …                     # (the printed line) background launch, focus watcher
//   node test/nbsync/probe.ts check [--measure]      # report + assertions (or only the measurement), then the teardown gate
//   node test/nbsync/probe.ts drive --app PATH [--measure]   # all of it in one go through the headless driver (builds with patch 0012's bootstrap)
// Canaries are generated fake `seclabcanary_nb_` values, seeded on the host only: a markdown cell of
// a host .ipynb, and a line of a host .seclabnb (a type only the probe's serializer reads). The
// tab's own notebook carries a detection value, to prove the probe sees cells on this build. The
// probe opens the host notebooks in the window as a user would, and asks for one itself. Its
// report holds schemes and line hashes; it is tab-controlled data, read through a fixed schema.

import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { pathToFileURL } from 'node:url';
import { TabdClient } from '../../tabd/src/client.ts';
import { DrivenEditor } from '../driver/editor.ts';
import { checkUserDataDir, editorLaunchCommand, focusStealLog } from '../harness.ts';
import { readManifest, verifyTeardown, writeManifest, writeSnapshot } from '../containment/teardown.ts';

const repo = path.resolve(import.meta.dirname, '../..');
const base = path.join(repo, '.work', 'nbsync');
const ws = path.join(base, 'ws');
const hostIpynb = path.join(base, 'host', 'host.ipynb');
const hostNb = path.join(base, 'host', 'host.seclabnb');
const canaryFile = path.join(base, 'canaries.json');
// Written by drive from the window's RPC-filter log (host-written, fixed refs only).
const evidenceFile = path.join(base, 'drive-evidence.json');
const resultsFile = path.join(repo, '.work', 'nbsync-results.jsonl');
const userData = path.join(os.homedir(), '.seclab-test', 'nb');
const stateDir = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');
const SBX = '/opt/homebrew/bin/sbx';
const VSCE_IMAGE = 'seclab-vsce:3.9.2';
const [mode, ...rest] = process.argv.slice(2);
const appArg = rest.includes('--app') ? path.resolve(rest[rest.indexOf('--app') + 1]) : undefined;
const sha = (s: string) => createHash('sha256').update(s).digest('hex');
const tabId = () => (readManifest(base).tabs ?? [])[0];
const inTab = (args: string[]) => spawnSync(SBX, ['exec', '-u', 'agent', `seclab-${tabId()}`, ...args], { encoding: 'utf8', maxBuffer: 16 << 20 });
const KINDS = ['hostIpynb', 'hostNb', 'detect'] as const;
type Canaries = Record<typeof KINDS[number], string>;
const SYNC = ['notebooks', 'notebooks-cell', 'onopen', 'onopen-cell', 'onchange', 'onchange-cell', 'celldocs'];
const ipynb = (text: string) => JSON.stringify({
	cells: [{ cell_type: 'markdown', metadata: {}, source: [text] }],
	metadata: {}, nbformat: 4, nbformat_minor: 5,
}, null, 1);

async function prepare(): Promise<string> {
	checkUserDataDir(userData);
	if (fs.existsSync(path.join(base, 'run.json'))) {
		console.error('a previous nbsync run is still recorded: run `node test/nbsync/probe.ts check` first');
		process.exit(1);
	}
	fs.rmSync(base, { recursive: true, force: true });
	fs.rmSync(userData, { recursive: true, force: true });
	fs.mkdirSync(path.join(ws, '.seclab'), { recursive: true });
	fs.mkdirSync(path.dirname(hostIpynb), { recursive: true });
	const c = Object.fromEntries(KINDS.map(k => [k, `seclabcanary_nb_${k}_${randomBytes(12).toString('hex')}`])) as Canaries;
	fs.writeFileSync(canaryFile, JSON.stringify(c));
	writeSnapshot(base);
	writeManifest(base, { driver: 'sbx', userDataDir: userData, stateDirs: [stateDir] });
	fs.writeFileSync(path.join(ws, 'README.md'), '# nbsync probe workspace\n');
	fs.writeFileSync(path.join(ws, 'nb.ipynb'), ipynb(c.detect));
	fs.writeFileSync(hostIpynb, ipynb(c.hostIpynb));
	fs.writeFileSync(hostNb, `seclab probe notebook\n${c.hostNb}\n`);
	fs.mkdirSync(path.join(userData, 'User'), { recursive: true });
	fs.writeFileSync(path.join(userData, 'User', 'settings.json'), JSON.stringify({
		'security.workspace.trust.enabled': false, 'seclab.tabs.driver': 'sbx', 'seclab.tabs.allowedRoots': [base], 'window.restoreWindows': 'none',
		'workbench.welcomePage.experimentalOnboarding': false, 'workbench.startupEditor': 'none', 'workbench.tips.enabled': false, 'chat.disableAIFeatures': true,
	}, null, '\t'));
	const until = Math.floor(Date.now() / 1000) + 2 * 3600;
	fs.writeFileSync(path.join(ws, '.seclab', 'targets'), `arm=${randomBytes(16).toString('hex')}\nrun=${base}\nuntil=${until}\nhostipynb=${hostIpynb}\nhostnb=${hostNb}\n`);

	const vsixDir = path.join(base, 'vsix');
	fs.mkdirSync(vsixDir, { recursive: true });
	execFileSync('docker', ['run', '--rm', '--network', 'none', '--user', `${process.getuid!()}:${process.getgid!()}`,
		'-v', `${path.join(import.meta.dirname, 'probe-extension')}:/ext:ro`, '-v', `${vsixDir}:/out`,
		VSCE_IMAGE, 'sh', '-c', 'cp -r /ext /tmp/e && cd /tmp/e && vsce package --allow-missing-repository --skip-license -o /out/nbsync-probe.vsix'], { stdio: 'ignore' });
	const client = new TabdClient({
		command: process.execPath,
		args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', 'sbx', '--allowed-root', base],
		env: { HOME: process.env.HOME, USER: process.env.USER },
	});
	await client.initialize('nbsync-probe', '0');
	const { tab } = await client.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
	writeManifest(base, { tabs: [tab.metadata.name] });
	await client.request('tab.ensureRunning', { tabId: tab.metadata.name });
	fs.copyFileSync(path.join(vsixDir, 'nbsync-probe.vsix'), path.join(ws, '.nbsync-probe.vsix'));
	const r = inTab(['/opt/seclab/bin/seclab-tab-env', '/opt/seclab-reh/bin/seclab-code-server', '--install-extension', path.join(ws, '.nbsync-probe.vsix')]);
	client.dispose();
	await new Promise(res => client.once('exit', res));
	if (r.status !== 0) {
		console.error('could not install the probe extension in the tab; run `node test/nbsync/probe.ts check` to tear down');
		process.exit(1);
	}
	return tab.metadata.name;
}

async function check(measure: boolean): Promise<boolean> {
	const c = JSON.parse(fs.readFileSync(canaryFile, 'utf8')) as Canaries;
	const reportPath = path.join(ws, '.seclab-nbsync', 'report.json');
	const read = () => {
		try {
			return JSON.parse(tabId() ? inTab(['cat', reportPath]).stdout ?? '' : '');
		} catch {
			return undefined;
		}
	};
	let rep: any = read();
	for (let i = 0; i < 120 && tabId() && rep?.done !== true; i++) {
		spawnSync('sleep', ['1']);
		rep = read();
	}
	const armed = (fs.readFileSync(path.join(ws, '.seclab', 'targets'), 'utf8').match(/^arm=([0-9a-f]{32})$/m) ?? [])[1];
	const hitOk = (h: any) => !!h && typeof h.channel === 'string' && /^[a-z-]{1,20}$/.test(h.channel) && typeof h.phase === 'string' && /^[a-z-]{1,30}$/.test(h.phase) && /^[0-9a-f]{64}$/.test(h.sha256);
	const valid = !!rep && rep.schema === 'seclab-nbsync-report/1' && rep.arm === armed && typeof rep.done === 'boolean'
		&& Array.isArray(rep.hits) && rep.hits.length <= 5000 && rep.hits.every(hitOk)
		&& !!rep.schemes && typeof rep.schemes === 'object' && Object.entries(rep.schemes).every(([k, v]) => /^[a-z-]{1,20}:[a-z0-9.+-]{1,40}$/.test(k) && Number.isInteger(v))
		&& !!rep.steps && typeof rep.steps === 'object' && Object.entries(rep.steps).every(([k, v]) => /^[a-z-]{1,30}$/.test(k) && typeof v === 'string' && /^[\x20-\x7e]{0,60}$/.test(v))
		&& !!rep.controls && ['ownNotebook', 'tabUntitled', 'tabUntitledEdited'].every(k => typeof rep.controls[k] === 'boolean');
	const launched = (() => {
		try {
			return String(JSON.parse(fs.readFileSync(path.join(userData, 'seclab-launch.json'), 'utf8')).app ?? '');
		} catch {
			return '';
		}
	})();
	const steals = fs.existsSync(focusStealLog(userData)) ? fs.readFileSync(focusStealLog(userData), 'utf8').trim() : '';
	const results: Array<{ name: string; ok: boolean }> = [];
	const expect = (name: string, ok: boolean) => results.push({ name, ok });
	expect('report present, from this run, and matches the schema', valid);
	const byHash = new Map(KINDS.map(k => [sha(c[k]), k]));
	const hits: Array<{ kind: string; channel: string; phase: string }> = valid
		? (rep.hits as Array<{ channel: string; phase: string; sha256: string }>).filter(h => byHash.has(h.sha256)).map(h => ({ kind: byHash.get(h.sha256)!, channel: h.channel, phase: h.phase }))
		: [];
	if (valid) {
		console.log(`steps: ${JSON.stringify(rep.steps)}`);
		console.log(`schemes (channel:scheme -> count): ${JSON.stringify(rep.schemes)}`);
		console.log(`canary hits: ${hits.map(h => `${h.kind}@${h.channel}/${h.phase}`).join(', ') || 'none'}`);
		console.log(`controls: ${JSON.stringify(rep.controls)}`);
		if (!measure) {
			// Notebooks in a tab need the tab's serializer. Where the RPC filter refuses it (patch 0005's
			// default deny), no notebook opens in the window, so the leak checks below can't be vacuous
			// unless that refusal is shown; otherwise detection must work on this build.
			let ev: { serializerRefused?: unknown } = {};
			try {
				ev = JSON.parse(fs.readFileSync(evidenceFile, 'utf8'));
			} catch {
				ev = {};
			}
			const off = ev.serializerRefused === true;
			console.log(`notebooks in this tab: ${off ? 'off (the RPC filter refused the tab\'s serializer)' : 'on'}`);
			expect('the probe finished', rep.done === true);
			if (off) {
				expect('control: no notebook opened in the tab at all (its own included), consistent with the refused serializer', rep.controls.ownNotebook === false && rep.controls.tabUntitled === false && Object.keys(rep.schemes).length === 0);
			} else {
				expect('control: detection works: the tab\'s own notebook cell was seen', hits.some(h => h.kind === 'detect' && SYNC.includes(h.channel)));
				expect('control: the tab\'s own notebook is synced', rep.controls.ownNotebook === true);
				expect('control: a notebook the tab created is synced and takes an edit', rep.controls.tabUntitled === true && rep.controls.tabUntitledEdited === true);
			}
			expect('DOCSYNC-R2 NB-1 no host notebook cell reaches the tab through the notebook sync', !hits.some(h => h.kind !== 'detect' && SYNC.includes(h.channel)));
			expect('DOCSYNC-R2 NB-2 no host notebook bytes reach a serializer in the tab', !hits.some(h => h.kind !== 'detect' && h.channel === 'serializer'));
		}
	}
	expect('no focus steal', !steals);
	const gate = verifyTeardown(base);
	if (gate.every(g => g.ok)) {
		fs.renameSync(path.join(base, 'run.json'), path.join(base, `run-checked-${Date.now()}.json`));
	}
	for (const r of [...results, ...gate]) {
		console.log(`${r.ok ? 'OK  ' : 'FAIL'}  ${r.name}`);
	}
	const pass = results.every(r => r.ok) && gate.every(g => g.ok);
	fs.appendFileSync(resultsFile, JSON.stringify({ at: new Date().toISOString(), app: launched, measure, pass, hits, schemes: valid ? rep.schemes : null, steps: valid ? rep.steps : null }) + '\n');
	return pass;
}

if (mode === 'prepare') {
	const tab = await prepare();
	console.log(`prepared tab ${tab}. Launch in the BACKGROUND:\n`);
	console.log(`  ${editorLaunchCommand(userData, `vscode-remote://seclab+${tab}${ws}`, {}, appArg)}\n`);
	console.log('then, after about a minute:  node test/nbsync/probe.ts check\n');
} else if (mode === 'drive') {
	// The window opens the host notebooks itself, as a user would (File > Open, drag and drop):
	// a build with the RPC filter refuses the tab's own vscode.open, so the tab can't stand in.
	if (!appArg) {
		console.error('drive needs --app');
		process.exit(2);
	}
	const tab = await prepare();
	let ed: DrivenEditor | undefined;
	try {
		ed = await DrivenEditor.launch({
			app: appArg, userData, folderUri: `vscode-remote://seclab+${tab}${ws}`,
			args: ['--file-uri', pathToFileURL(hostIpynb).href, '--file-uri', pathToFileURL(hostNb).href],
		});
		for (let i = 0; i < 120 && inTab(['grep', '-q', '"done":true', path.join(ws, '.seclab-nbsync', 'report.json')]).status !== 0; i++) {
			spawnSync('sleep', ['1']);
		}
		spawnSync('sleep', ['5']);
		// Evidence from the window, before teardown removes the profile: which editors it opened (the
		// host notebooks' tab labels), and what the RPC filter refused (fixed-shape refs only).
		const labels = await ed.evaluate<string[]>(`[...document.querySelectorAll('.tabs-container .tab .label-name')].map(e => e.textContent ?? '')`).catch(() => [] as string[]);
		console.log(`window editors: ${JSON.stringify(labels.filter(l => /^[\w. -]{1,60}$/.test(l)))}`);
		await ed.screenshot(path.join(base, 'drive.png')).catch(() => 0);
		const denies = new Map<string, number>();
		const walk = (d: string): string[] => fs.existsSync(d) ? fs.readdirSync(d, { withFileTypes: true }).flatMap(e => e.isDirectory() ? walk(path.join(d, e.name)) : e.name === 'seclabRpcFilter.log' ? [path.join(d, e.name)] : []) : [];
		for (const f of walk(path.join(userData, 'logs'))) {
			for (const m of fs.readFileSync(f, 'utf8').matchAll(/"ref":"((?:rpc|cmd):[A-Za-z0-9_.$-]{1,120})","verdict":"deny"/g)) {
				if (/otebook|executeCommand|vscode\.open/i.test(m[1])) {
					denies.set(m[1], (denies.get(m[1]) ?? 0) + 1);
				}
			}
		}
		console.log(`filter denials (notebook-related ref -> lines): ${JSON.stringify(Object.fromEntries(denies))}`);
		fs.writeFileSync(evidenceFile, JSON.stringify({ serializerRefused: denies.has('rpc:MainThreadNotebook.$registerNotebookSerializer'), editors: labels.length }));
	} catch (e) {
		console.error(`drive: ${String(e)}`);
	} finally {
		await ed?.close().catch(() => undefined);
	}
	process.exit(await check(rest.includes('--measure')) ? 0 : 1);
} else if (mode === 'check') {
	process.exit(await check(rest.includes('--measure')) ? 0 : 1);
} else {
	console.error('usage: probe.ts prepare [--app PATH] | drive --app PATH [--measure] | check [--measure]');
	process.exit(2);
}
