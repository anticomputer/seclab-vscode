// Window decision logs end to end (EDR window-decision-logs): the trusted renderer's RPC-filter and
// AHP-gate logs reach tabd as trusted events only when the build carries both the RPC policy
// stamp (product.json seclabRpcPolicy) and the filter's enforcing marker in the workbench bundle.
//   node test/observability/window-log-probe.ts --app PATH.app [--variants full,no-stamp,no-marker] [--keep]
// For each variant, a sandboxed tab with an armed test extension (rpc-prober) makes the RPC filter
// refuse one inert command. Then:
//   full       the denial and the gate's lines arrive in tabd's log as trusted events;
//   no-stamp   a copy of the app without the product.json stamp: the window logs have the same
//              lines, tabd gets none, and the Tab Manager says why;
//   no-marker  a copy whose bundle carries an altered marker: likewise.
// The copies are made under the run directory from the given app, then unregistered from
// LaunchServices and deleted at the end of each variant. The editor is
// driven headlessly (test/driver: CDP pipe, background-only, never focused). sbx only. Each variant
// ends with the shared teardown gate.

import { execFileSync, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import type { ObsEvent } from '../../tabd/src/obs/schema.ts';
import { printChecks, removeRunResources, stopRunProcesses, verifyTeardown, writeManifest, writeSnapshot } from '../containment/teardown.ts';
import { DrivenEditor } from '../driver/editor.ts';
import { checkUserDataDir } from '../harness.ts';
import { appBuildProblem } from '../app-build.ts';

const args = process.argv.slice(2);
const opt = (k: string) => (args.indexOf(k) >= 0 ? args[args.indexOf(k) + 1] : undefined);
const appArg = opt('--app');
const keep = args.includes('--keep');
const VARIANTS = ['full', 'no-stamp', 'no-marker'] as const;
type Variant = typeof VARIANTS[number];
const wanted = (opt('--variants') ?? VARIANTS.join(',')).split(',') as Variant[];
if (!appArg || !wanted.every(v => (VARIANTS as readonly string[]).includes(v))) {
	console.error('usage: window-log-probe.ts --app PATH.app [--variants full,no-stamp,no-marker] [--keep]');
	process.exit(2);
}
const sourceApp = path.resolve(appArg);
const repo = path.resolve(import.meta.dirname, '../..');
// The source app is judged once, by its own location's rule; its altered copies then run as that
// build's commit rather than being judged by where the copies sit (review FAB2-4).
{
	const problem = appBuildProblem(sourceApp, { repoRoot: repo, expect: process.env.SECLAB_APP_SHA || undefined });
	if (problem) {
		console.error(`refusing: ${problem}`);
		process.exit(2);
	}
	const info = ['build-info-app.json', 'build-info.json'].map(f => path.join(path.dirname(sourceApp), f)).find(f => fs.existsSync(f));
	const sha = info ? (JSON.parse(fs.readFileSync(info, 'utf8')) as { repoSha?: string }).repoSha : undefined;
	if (sha) {
		process.env.SECLAB_APP_SHA = sha;
	}
}
const SBX = '/opt/homebrew/bin/sbx';
const VSCE_IMAGE = 'seclab-vsce:3.9.2';
const MARKER_PREFIX = ['seclabRpcFilter', 'Enforcing:'].join('');
const PROBED = 'cmd:seclab.windowLogProbe.doesNotExist';
const LSREGISTER = '/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister';

let failures = 0;
const check = (name: string, ok: boolean, detail = '') => {
	console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : `: ${detail}`}`);
	failures += ok ? 0 : 1;
};
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
const resources = (app: string) => path.join(app, 'Contents', 'Resources', 'app');

/** JSON objects from a window log (logger prefix, then the object). */
function logObjects(file: string): Array<Record<string, any>> {
	if (!fs.existsSync(file)) {
		return [];
	}
	return fs.readFileSync(file, 'utf8').split('\n').flatMap(l => {
		const at = l.indexOf('{');
		try {
			return at < 0 ? [] : [JSON.parse(l.slice(at))];
		} catch {
			return [];
		}
	});
}

function findFiles(dir: string, name: RegExp): string[] {
	const out: string[] = [];
	for (const e of fs.existsSync(dir) ? fs.readdirSync(dir, { withFileTypes: true }) : []) {
		const p = path.join(dir, e.name);
		if (e.isDirectory()) {
			out.push(...findFiles(p, name));
		} else if (name.test(e.name)) {
			out.push(p);
		}
	}
	return out;
}

/** The app this variant runs: the source app, or a copy with the stamp or the marker taken away. */
function variantApp(v: Variant, base: string): string {
	if (v === 'full') {
		return sourceApp;
	}
	const app = path.join(base, 'app', path.basename(sourceApp));
	fs.mkdirSync(path.dirname(app), { recursive: true });
	execFileSync('ditto', [sourceApp, app]);
	// The copy is the source build minus one thing: it keeps that build's info, so a launch still
	// checks which commit it is (review FAB-3).
	for (const f of ['build-info.json', 'build-info-app.json']) {
		const src = path.join(path.dirname(sourceApp), f);
		if (fs.existsSync(src)) {
			fs.copyFileSync(src, path.join(path.dirname(app), f));
		}
	}
	if (v === 'no-stamp') {
		const pj = path.join(resources(app), 'product.json');
		const product = JSON.parse(fs.readFileSync(pj, 'utf8'));
		delete product.seclabRpcPolicy;
		fs.writeFileSync(pj, JSON.stringify(product, null, '\t'));
	} else {
		const bundle = path.join(resources(app), 'out', 'vs', 'workbench', 'workbench.desktop.main.js');
		const js = fs.readFileSync(bundle, 'latin1');
		const n = js.split(MARKER_PREFIX).length - 1;
		if (n < 1) {
			throw new Error('the source app has no enforcing marker to alter');
		}
		// Same length, so nothing else in the bundle moves; the filter still runs and still logs.
		fs.writeFileSync(bundle, js.split(MARKER_PREFIX).join(MARKER_PREFIX.replace('Enforcing', 'Enforcin_')), 'latin1');
	}
	return app;
}

async function runVariant(v: Variant): Promise<void> {
	console.log(`\n== ${v}`);
	// Under .work/test-builds, so a test build's altered copies run from where test builds may
	// (Copilot review on PR 42).
	const base = path.join(repo, '.work', 'test-builds', 'window-log-probe', v);
	const userData = path.join(os.homedir(), '.seclab-test', `wl-${v}`);
	checkUserDataDir(userData);
	const stateDir = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');
	fs.rmSync(base, { recursive: true, force: true });
	fs.rmSync(userData, { recursive: true, force: true });
	fs.mkdirSync(base, { recursive: true });
	writeSnapshot(base);
	writeManifest(base, { driver: 'sbx', userDataDir: userData, stateDirs: [stateDir] });
	const ws = path.join(base, 'tabs', 'acme-app');
	fs.mkdirSync(path.join(ws, '.seclab'), { recursive: true });
	fs.writeFileSync(path.join(ws, 'README.md'), '# acme-app\n');
	fs.writeFileSync(path.join(ws, '.seclab', 'rpc-prober-arm'), `arm=${randomBytes(16).toString('hex')}\nuntil=${Math.floor(Date.now() / 1000) + 3600}\n`);
	writeManifest(base, { workspaces: [ws] });
	fs.mkdirSync(path.join(userData, 'User'), { recursive: true });
	fs.writeFileSync(path.join(userData, 'User', 'settings.json'), JSON.stringify({
		'security.workspace.trust.enabled': false,
		'seclab.tabs.driver': 'sbx',
		'seclab.tabs.allowedRoots': [path.join(base, 'tabs')], // not base: the altered app copies live there
		'seclab.activity.revealOnAlert': false,
		'workbench.startupEditor': 'none',
		'workbench.welcomePage.experimentalOnboarding': false,
		'workbench.tips.enabled': false,
		'chat.disableAIFeatures': true,
	}, null, '\t'));
	let ed: DrivenEditor | undefined;
	try {
		const app = variantApp(v, base);
		const vsixDir = path.join(base, 'vsix');
		fs.mkdirSync(vsixDir, { recursive: true });
		execFileSync('docker', ['run', '--rm', '--network', 'none', '--user', `${process.getuid!()}:${process.getgid!()}`,
			'-v', `${path.join(import.meta.dirname, 'rpc-prober')}:/ext:ro`, '-v', `${vsixDir}:/out`,
			VSCE_IMAGE, 'sh', '-c', 'cp -r /ext /tmp/e && cd /tmp/e && vsce package --allow-missing-repository --skip-license -o /out/prober.vsix'], { stdio: 'ignore' });
		const client = new TabdClient({
			command: process.execPath,
			args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', 'sbx', '--allowed-root', path.join(base, 'tabs')],
			env: { HOME: process.env.HOME, USER: process.env.USER },
		});
		await client.initialize('window-log-probe', '0');
		const tabId = (await client.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } })).tab.metadata.name;
		writeManifest(base, { tabs: [tabId] });
		await client.request('tab.ensureRunning', { tabId });
		fs.copyFileSync(path.join(vsixDir, 'prober.vsix'), path.join(ws, '.seclab', 'prober.vsix'));
		const inst = spawnSync(SBX, ['exec', '-u', 'agent', `seclab-${tabId}`, '/opt/seclab/bin/seclab-tab-env', '/opt/seclab-reh/bin/seclab-code-server', '--install-extension', path.join(ws, '.seclab', 'prober.vsix')], { encoding: 'utf8' });
		check(`${v}: prober extension installed in the tab`, inst.status === 0, inst.stderr.slice(-300));
		await client.request('shutdown', {}).catch(() => undefined);
		client.dispose();

		ed = await DrivenEditor.launch({ app, userData, folderUri: `vscode-remote://seclab+${tabId}${ws}` });
		await ed.waitFor(`document.querySelector('.monaco-workbench')`, 90_000);
		let prober: { remoteName?: string; refused?: boolean } | undefined;
		for (const end = Date.now() + 120_000; !prober && Date.now() < end; await sleep(2000)) {
			const r = spawnSync(SBX, ['exec', '-u', 'agent', `seclab-${tabId}`, 'cat', '/tmp/seclab-rpc-prober.json'], { encoding: 'utf8' });
			prober = r.status === 0 ? JSON.parse(r.stdout) : undefined;
		}
		check(`${v}: the prober ran in the tab and its call was refused`, prober?.remoteName === 'seclab' && prober.refused === true, JSON.stringify(prober));

		const logs = path.join(userData, 'logs');
		const gateLines = findFiles(logs, /^seclabAhpGate\.log$/).flatMap(logObjects);
		const events = () => {
			const dir = path.join(stateDir, 'events', tabId);
			return fs.existsSync(dir) ? fs.readdirSync(dir).filter(f => f.endsWith('.jsonl')).flatMap(f => fs.readFileSync(path.join(dir, f), 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l) as ObsEvent)) : [];
		};
		const forwarded = () => events().filter(e => e.class === 'rpc.decision' || e.class === 'ahp.decision');
		if (v === 'full') {
			for (const end = Date.now() + 60_000; Date.now() < end && !(forwarded().some(e => e.detail?.ref === PROBED) && (!gateLines.length || forwarded().some(e => e.source === 'ahp-gate'))); await sleep(1000)) { /* wait */ }
		} else {
			await sleep(20_000); // forwarding would have happened well within this
		}
		const got = forwarded();
		const tmLog = findFiles(logs, /seclab Tab Manager\.log$/).map(f => fs.readFileSync(f, 'utf8')).join('\n');
		const reason = /gate and filter decisions are not forwarded: ([^\n]*)/.exec(tmLog)?.[1] ?? '';
		const rpcLinesBefore = findFiles(logs, /^seclabRpcFilter\.log$/).flatMap(logObjects);
		check(`${v}: the window's RPC-filter log has the filter's install line and the prober's denial`, rpcLinesBefore.some(o => o.detail?.ref === 'rpc:seclab.installed') && rpcLinesBefore.some(o => o.detail?.ref === PROBED && o.detail?.verdict === 'deny'), `${rpcLinesBefore.length} lines`);
		console.log(`${v}: window logs: ${rpcLinesBefore.length} RPC-filter line(s), ${gateLines.length} AHP-gate line(s); tabd: ${got.length} forwarded event(s)${reason ? `; Tab Manager: ${reason}` : ''}`);
		if (v === 'full') {
			const denial = got.find(e => e.detail?.ref === PROBED);
			check('full: the denial arrived in tabd as a trusted rpc.decision from rpc-filter, its tab-chosen ref tagged untrusted', denial?.source === 'rpc-filter' && denial.integrity === 'trusted' && denial.detail?.verdict === 'deny' && denial.untrusted.includes('detail.ref'), JSON.stringify(denial));
			check('full: the filter\'s install line (naming its marker) arrived too', got.some(e => e.detail?.ref === 'rpc:seclab.installed' && e.integrity === 'trusted'));
			check('full: the window wrote AHP-gate decisions, and each arrived in tabd as a trusted ahp.decision', gateLines.length > 0 && got.filter(e => e.source === 'ahp-gate' && e.class === 'ahp.decision' && e.integrity === 'trusted').length >= gateLines.length, `${gateLines.length} gate line(s), ${got.filter(e => e.source === 'ahp-gate').length} forwarded`);
			check('full: nothing forwarded claims another integrity', got.every(e => e.integrity === 'trusted'));
			check('full: the Tab Manager did not decline', !reason, reason);
		} else {
			check(`${v}: nothing from either window log reached tabd`, got.length === 0, got.map(e => `${e.source}:${e.detail?.ref ?? e.detail?.gateRule}`).join(' '));
			const expect = v === 'no-stamp' ? /no RPC policy table applied/ : /RPC policy table applied \([0-9a-f]{12}\), enforcement marker missing/;
			check(`${v}: the Tab Manager declined and says why`, expect.test(reason), reason || 'no reason logged');
		}
	} catch (e) {
		check(`${v}: run`, false, (e as Error).message);
	} finally {
		await ed?.close().catch(() => undefined);
		// The altered copy is unregistered and deleted on every path (review round 14): it carries
		// the product's bundle id and URL scheme, so LaunchServices could pick it.
		const copy = path.join(base, 'app');
		for (const a of fs.existsSync(copy) ? fs.readdirSync(copy).filter(n => n.endsWith('.app')) : []) {
			spawnSync(LSREGISTER, ['-u', path.join(copy, a)], { stdio: 'ignore' });
		}
		fs.rmSync(copy, { recursive: true, force: true });
		check(`${v}: no app copy left in the run directory`, findFiles(base, /^Info\.plist$/).length === 0);
		if (keep) {
			console.log(`KEEP: ${v} not torn down. Later: node test/containment/teardown.ts verify ${base}`);
			failures++;
		} else {
			stopRunProcesses(base);
			removeRunResources(base);
			if (!printChecks(verifyTeardown(base))) {
				failures++;
			}
		}
	}
}

for (const v of wanted) {
	await runVariant(v);
}
console.log(failures ? `\n${failures} check(s) failed` : '\nWINDOW LOG PROBE OK');
process.exit(failures ? 1 : 0);
