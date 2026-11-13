// Configuration-snapshot probe: which host setting values reach a tab's extension host? (patch
// 0036, EDR configuration-snapshot). macOS, sbx, local only. One run:
//   node test/configsync/probe.ts prepare [--app PATH]   # benign tab + probe extension; canaries in the isolated profile
//   node test/window.ts launch …                         # (the printed line) background launch, focus watcher
//   node test/configsync/probe.ts seed                   # when the probe asks: change host settings (the change path)
//   node test/configsync/probe.ts check [--measure]      # report + assertions (or only counts), then the teardown gate
// Repeat the cycle (at least 10 times) to cover start-up races: upstream registers some settings at
// run time (http.proxyAuthorization's scope follows http.useLocalProxyConfiguration).
// Canaries are generated fake `seclabcanary_cf_` values, only in the isolated profile's host
// settings.json, one per withholding rule:
//   undeclared     an undeclared key: dropped by the declaration rule;
//   proxyAuth      http.proxyAuthorization (Basic, base64): withheld by its name, however registered;
//   password       a low-entropy value under a tab-declared credential name: the name rule (the
//                  scanner misses it, checked in build/secret-rules/secret-rules.test.ts);
//   secretValue    a secret-shaped value under a neutral tab-declared name: the gitleaks rules;
//   changed        a second proxy credential written by `seed` while the tab runs: the change path;
//   toolsEnv       a credential URL in an env-style map under a tab-declared key (review 0036 A1);
//   nested         nested-form settings under a tab-declared prefix of core keys (`remote`, A3);
//   label          a plain value under a tab-declared key: no extension-declared key receives a
//                  host value (A1, option 1). toolsEnv and label both evade the classifier.
// A detection canary in the tab's own workspace settings passes unchanged and must be seen.
// Positive controls: editor.tabSize (core, host value) arrives and changes; a tab extension's own
// setting arrives from the tab's workspace settings (its host value, `host-value`, must not win).
// The probe reports hashes and setting names only, never values; its report is tab-controlled data,
// read through a fixed schema.

import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import { checkUserDataDir, editorLaunchCommand, focusStealLog } from '../harness.ts';
import { readManifest, verifyTeardown, writeManifest, writeSnapshot } from '../containment/teardown.ts';

const repo = path.resolve(import.meta.dirname, '../..');
const base = path.join(repo, '.work', 'configsync');
const ws = path.join(base, 'ws');
const canaryFile = path.join(base, 'canaries.json');
const resultsFile = path.join(repo, '.work', 'configsync-results.jsonl');
const userData = path.join(os.homedir(), '.seclab-test', 'cs');
const settingsFile = path.join(userData, 'User', 'settings.json');
const stateDir = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');
const SBX = '/opt/homebrew/bin/sbx';
const VSCE_IMAGE = 'seclab-vsce:3.9.2';
const [mode, ...rest] = process.argv.slice(2);
const appArg = rest.includes('--app') ? path.resolve(rest[rest.indexOf('--app') + 1]) : undefined;
const KINDS = ['undeclared', 'proxyAuth', 'password', 'secretValue', 'changed', 'toolsEnv', 'nested', 'label'] as const;
// Seeded in the tab's own workspace settings, which pass unchanged: proves detection works on the build.
const DETECT = 'detect';
type Canaries = Record<typeof KINDS[number] | typeof DETECT, string>;
const sha = (s: string) => createHash('sha256').update(s).digest('hex');
const tabId = () => (readManifest(base).tabs ?? [])[0];
const inTab = (args: string[]) => spawnSync(SBX, ['exec', '-u', 'agent', `seclab-${tabId()}`, ...args], { encoding: 'utf8', maxBuffer: 64 << 20 });
const basic = (canary: string) => `Basic ${Buffer.from(`probe:${canary}`).toString('base64')}`;
const settings = (c: Canaries, tabSize: number, proxyCanary: string) => JSON.stringify({
	'security.workspace.trust.enabled': false,
	'seclab.tabs.driver': 'sbx',
	'seclab.tabs.allowedRoots': [base],
	'window.restoreWindows': 'none',
	'editor.tabSize': tabSize,
	'seclabProbe.undeclared': c.undeclared,
	'http.proxyAuthorization': basic(proxyCanary),
	'seclabProbe.password': c.password,
	'seclabProbe.endpointValue': `apikey=${c.secretValue}`,
	'seclabProbe.color': 'host-value',
	'seclabProbe.label': c.label,
	// An env-style map under a tab-declared key (review 0036 A1), and nested-form settings under a
	// tab-declared prefix of core keys (A3).
	'seclabProbe.toolsEnv': { DATABASE_URL: `postgres://app:${c.toolsEnv}@db.invalid/prod` },
	remote: { seclabProbeNested: c.nested },
}, null, '\t');

if (mode === 'prepare') {
	checkUserDataDir(userData);
	if (fs.existsSync(path.join(base, 'run.json'))) {
		console.error('a previous configsync run is still recorded: run `node test/configsync/probe.ts check` first');
		process.exit(1);
	}
	fs.rmSync(base, { recursive: true, force: true });
	fs.rmSync(userData, { recursive: true, force: true });
	fs.mkdirSync(path.join(ws, '.seclab'), { recursive: true });
	const hex = () => randomBytes(16).toString('hex');
	const c: Canaries = {
		undeclared: `seclabcanary_cf_${hex()}`,
		proxyAuth: `seclabcanary_cf_${hex()}`,
		password: `seclabcanary_cf_${'a'.repeat(16)}${randomBytes(2).toString('hex')}`,
		secretValue: `seclabcanary_cf_${hex()}`,
		changed: `seclabcanary_cf_${hex()}`,
		toolsEnv: `seclabcanary_cf_${hex()}`,
		nested: `seclabcanary_cf_${hex()}`,
		label: `seclabcanary_cf_${hex()}`,
		detect: `seclabcanary_cf_${hex()}`,
	};
	fs.writeFileSync(canaryFile, JSON.stringify(c));
	writeSnapshot(base);
	writeManifest(base, { driver: 'sbx', userDataDir: userData, stateDirs: [stateDir] });
	fs.writeFileSync(path.join(ws, 'README.md'), '# configsync probe workspace\n');
	fs.mkdirSync(path.join(ws, '.vscode'), { recursive: true });
	fs.writeFileSync(path.join(ws, '.vscode', 'settings.json'), JSON.stringify({ 'seclabProbe.detect': c.detect, 'seclabProbe.color': 'teal' }));
	fs.mkdirSync(path.dirname(settingsFile), { recursive: true });
	fs.writeFileSync(settingsFile, settings(c, 7, c.proxyAuth));
	const until = Math.floor(Date.now() / 1000) + 2 * 3600;
	fs.writeFileSync(path.join(ws, '.seclab', 'targets'), `arm=${randomBytes(16).toString('hex')}\nrun=${base}\nuntil=${until}\n`);

	const vsixDir = path.join(base, 'vsix');
	fs.mkdirSync(vsixDir, { recursive: true });
	execFileSync('docker', ['run', '--rm', '--network', 'none', '--user', `${process.getuid!()}:${process.getgid!()}`,
		'-v', `${path.join(import.meta.dirname, 'probe-extension')}:/ext:ro`, '-v', `${vsixDir}:/out`,
		VSCE_IMAGE, 'sh', '-c', 'cp -r /ext /tmp/e && cd /tmp/e && vsce package --allow-missing-repository --skip-license -o /out/configsync-probe.vsix'], { stdio: 'ignore' });
	const client = new TabdClient({
		command: process.execPath,
		args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', 'sbx', '--allowed-root', base],
		env: { HOME: process.env.HOME, USER: process.env.USER },
	});
	await client.initialize('configsync-probe', '0');
	const { tab } = await client.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
	writeManifest(base, { tabs: [tab.metadata.name] });
	await client.request('tab.ensureRunning', { tabId: tab.metadata.name });
	fs.copyFileSync(path.join(vsixDir, 'configsync-probe.vsix'), path.join(ws, '.configsync-probe.vsix'));
	const r = inTab(['/opt/seclab/bin/seclab-tab-env', '/opt/seclab-reh/bin/seclab-code-server', '--install-extension', path.join(ws, '.configsync-probe.vsix')]);
	client.dispose();
	await new Promise(res => client.once('exit', res));
	if (r.status !== 0) {
		console.error('could not install the probe extension in the tab; run `node test/configsync/probe.ts check` to tear down');
		process.exit(1);
	}
	console.log(`prepared tab ${tab.metadata.name}. Launch in the BACKGROUND:\n`);
	console.log(`  ${editorLaunchCommand(userData, `vscode-remote://seclab+${tab.metadata.name}${ws}`, {}, appArg)}\n`);
	console.log('then:  node test/configsync/probe.ts seed   then:  node test/configsync/probe.ts check\n');
} else if (mode === 'seed') {
	const c = JSON.parse(fs.readFileSync(canaryFile, 'utf8')) as Canaries;
	const ready = path.join(ws, '.seclab-configsync', 'ready-change');
	for (let i = 0; i < 300 && inTab(['test', '-e', ready]).status !== 0; i++) {
		spawnSync('sleep', ['1']);
	}
	fs.writeFileSync(settingsFile, settings(c, 9, c.changed));
	console.log('changed host settings');
	for (let i = 0; i < 200 && inTab(['sh', '-c', `grep -q '"done":true' ${path.join(ws, '.seclab-configsync', 'report.json')}`]).status !== 0; i++) {
		spawnSync('sleep', ['1']);
	}
} else if (mode === 'check') {
	const measure = rest.includes('--measure');
	const c = JSON.parse(fs.readFileSync(canaryFile, 'utf8')) as Canaries;
	const raw = tabId() ? inTab(['cat', path.join(ws, '.seclab-configsync', 'report.json')]).stdout ?? '' : '';
	let rep: any;
	try {
		rep = JSON.parse(raw);
	} catch {
		rep = undefined;
	}
	const armed = (fs.readFileSync(path.join(ws, '.seclab', 'targets'), 'utf8').match(/^arm=([0-9a-f]{32})$/m) ?? [])[1];
	const valid = !!rep && rep.schema === 'seclab-configsync-report/1' && rep.arm === armed && typeof rep.done === 'boolean'
		&& Array.isArray(rep.hits) && rep.hits.every((h: any) => ['initial', 'after-change'].includes(h?.phase) && /^[0-9a-f]{64}$/.test(h?.sha256))
		&& Array.isArray(rep.keys) && rep.keys.every((k: unknown) => typeof k === 'string' && /^[\x20-\x7e]{1,300}$/.test(k))
		&& ['tabSizeInitial', 'colorInitial', 'changeSeen'].every(f => typeof rep.controls?.[f] === 'boolean');
	const launched = (() => {
		try {
			return String(JSON.parse(fs.readFileSync(path.join(userData, 'seclab-launch.json'), 'utf8')).app ?? '');
		} catch {
			return '';
		}
	})();
	const steals = fs.existsSync(focusStealLog(userData)) ? fs.readFileSync(focusStealLog(userData), 'utf8').trim() : '';
	const results: Array<{ name: string; ok: boolean; detail?: string }> = [];
	const expect = (name: string, ok: boolean, detail = '') => results.push({ name, ok, detail });
	expect('report present, from this run, and matches the schema', valid);
	const byHash = new Map([...KINDS, DETECT].map(k => [sha(c[k]), k]));
	const hits = valid ? (rep.hits as Array<{ phase: string; sha256: string }>).map(h => `${byHash.get(h.sha256) ?? 'unknown'}@${h.phase}`) : [];
	if (valid) {
		console.log(`canary hits: ${hits.join(', ') || 'none'}`);
		console.log(`controls: ${JSON.stringify(rep.controls)}; ${rep.keys.length} setting names reached the tab`);
		expect('the probe finished', rep.done === true);
		expect('CFG-6 detection works on this build: the tab-owned canary was seen', hits.some(h => h.startsWith(`${DETECT}@`)));
		const seen = (k: string) => hits.some(h => h.startsWith(`${k}@`));
		expect('CFG-1 an extension-declared key receives no host value (env-map URL, plain value)', !seen('toolsEnv') && !seen('label'));
		expect('CFG-3 nested-form settings under a tab-declared prefix stay on the host', !seen('nested'));
		for (const k of KINDS) {
			const at = hits.filter(h => h.startsWith(`${k}@`));
			expect(`no ${k} canary reached the tab`, at.length === 0, at.join(','));
		}
		for (const f of ['tabSizeInitial', 'colorInitial', 'changeSeen']) {
			expect(`control: ${f}`, rep.controls[f] === true);
		}
		fs.writeFileSync(path.join(repo, '.work', `configsync-keys-${launched ? path.basename(path.dirname(launched)) : 'unknown'}.txt`), rep.keys.join('\n') + '\n');
	}
	expect('no focus steal', !steals);
	const gate = verifyTeardown(base);
	if (gate.every(g => g.ok)) {
		fs.renameSync(path.join(base, 'run.json'), path.join(base, `run-checked-${Date.now()}.json`));
	}
	const relevant = measure ? results.filter(r => /schema|focus/.test(r.name)) : results;
	for (const r of [...relevant, ...gate]) {
		console.log(`${r.ok ? 'OK  ' : 'FAIL'}  ${r.name}${r.ok || !r.detail ? '' : `  ${r.detail}`}`);
	}
	const pass = relevant.every(r => r.ok) && gate.every(g => g.ok);
	fs.appendFileSync(resultsFile, JSON.stringify({ at: new Date().toISOString(), app: launched, pass, hits }) + '\n');
	process.exit(pass ? 0 : 1);
} else {
	console.error('usage: probe.ts prepare [--app PATH] | seed | check [--measure]');
	process.exit(2);
}
