// Settings-withheld notice end to end (EDR settings-withheld-notice): a canary credential in the
// host's user settings is withheld from a tab by patch 0036, and the Tab Manager tells the user
// once, naming the key, never the value. A test extension inside the tab forges the same command
// five ways; none of its claims may produce an event or a notification.
//   node test/observability/withheld-probe.ts ~/.seclab-test/withheld --app PATH.app [--forged-only] [--keep]
// Needs a build with 0036 (and the shared classifier bundled into the Tab Manager); against any
// other build the Tab Manager refuses every call. --forged-only runs just the forged half there:
// each call must reach the Tab Manager's handler (its log says so) and produce nothing.
// sbx only. The editor launches in the background and never takes focus; the shared teardown
// gate runs at the end. The canary is an obviously fake seclabcanary_ value.

import { execFileSync, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import type { ObsEvent } from '../../tabd/src/obs/schema.ts';
import { printChecks, removeRunResources, stopRunProcesses, verifyTeardown, writeManifest, writeSnapshot } from '../containment/teardown.ts';
import { checkUserDataDir, launchEditorInBackground } from '../harness.ts';

const args = process.argv.slice(2);
const userDataArg = args.find((a, i) => !a.startsWith('--') && args[i - 1] !== '--app');
const keep = args.includes('--keep');
/** A build without 0036: only the forged half (every call reaches the handler and is refused). */
const forgedOnly = args.includes('--forged-only');
const app = args.includes('--app') ? path.resolve(args[args.indexOf('--app') + 1]) : undefined;
if (!userDataArg || !app) {
	console.error('usage: withheld-probe.ts USER_DATA_DIR --app PATH.app [--forged-only] [--keep]');
	process.exit(2);
}
const repo = path.resolve(import.meta.dirname, '../..');
const userData = path.resolve(userDataArg);
checkUserDataDir(userData);
const base = path.join(repo, '.work', 'withheld-probe');
const stateDir = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');
const notifications = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'notifications.jsonl');
const SBX = '/opt/homebrew/bin/sbx';
const VSCE_IMAGE = 'seclab-vsce:3.9.2';
const KEY = 'seclabProbe.apiToken';
const CANARY = `seclabcanary_withheld_${randomBytes(8).toString('hex')}`;
const FORGED_KEYS = /seclabProbe\.(forgedToken|flood\d+\.token)|workbench\.startupEditor|Probe‹|Probe\[/;

let failures = 0;
const check = (name: string, ok: boolean, detail = '') => {
	console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : `: ${detail}`}`);
	failures += ok ? 0 : 1;
};
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

fs.rmSync(base, { recursive: true, force: true });
fs.rmSync(userData, { recursive: true, force: true });
fs.mkdirSync(base, { recursive: true });
writeSnapshot(base);
writeManifest(base, { driver: 'sbx', userDataDir: userData, stateDirs: [stateDir] });
const ws = path.join(base, 'tabs', 'acme-app');
fs.mkdirSync(path.join(ws, '.seclab'), { recursive: true });
fs.writeFileSync(path.join(ws, 'README.md'), '# acme-app\n');
fs.writeFileSync(path.join(ws, '.seclab', 'withheld-arm'), `arm=${randomBytes(16).toString('hex')}\nuntil=${Math.floor(Date.now() / 1000) + 3600}\n`);
writeManifest(base, { workspaces: [ws] });
fs.mkdirSync(path.join(userData, 'User'), { recursive: true });
fs.writeFileSync(path.join(userData, 'User', 'settings.json'), JSON.stringify({
	'security.workspace.trust.enabled': false,
	'seclab.tabs.driver': 'sbx',
	'seclab.tabs.allowedRoots': [base],
	'seclab.activity.revealOnAlert': false,
	'workbench.startupEditor': 'none',
	'chat.disableAIFeatures': true,
	[KEY]: CANARY,
}, null, '\t'));

let tabId = '';
let windowPid: number | undefined;
try {
	const vsixDir = path.join(base, 'vsix');
	fs.mkdirSync(vsixDir, { recursive: true });
	execFileSync('docker', ['run', '--rm', '--network', 'none', '--user', `${process.getuid!()}:${process.getgid!()}`,
		'-v', `${path.join(import.meta.dirname, 'withheld-forger')}:/ext:ro`, '-v', `${vsixDir}:/out`,
		VSCE_IMAGE, 'sh', '-c', 'cp -r /ext /tmp/e && cd /tmp/e && vsce package --allow-missing-repository --skip-license -o /out/forger.vsix'], { stdio: 'inherit' });
	const client = new TabdClient({
		command: process.execPath,
		args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', 'sbx', '--allowed-root', base],
		env: { HOME: process.env.HOME, USER: process.env.USER },
	});
	await client.initialize('withheld-probe', '0');
	tabId = (await client.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } })).tab.metadata.name;
	writeManifest(base, { tabs: [tabId] });
	await client.request('tab.ensureRunning', { tabId });
	fs.copyFileSync(path.join(vsixDir, 'forger.vsix'), path.join(ws, '.seclab', 'forger.vsix'));
	const inst = spawnSync(SBX, ['exec', '-u', 'agent', `seclab-${tabId}`, '/opt/seclab/bin/seclab-tab-env', '/opt/seclab-reh/bin/seclab-code-server', '--install-extension', path.join(ws, '.seclab', 'forger.vsix')], { encoding: 'utf8' });
	check('forger extension installed in the tab', inst.status === 0, inst.stderr.slice(-300));
	await client.request('shutdown', {}).catch(() => undefined);
	client.dispose();

	const launch = await launchEditorInBackground(userData, `vscode-remote://seclab+${tabId}${ws}`, {}, 90_000, app);
	windowPid = launch.pid;
	check('editor launched in the background (no focus taken)', !launch.stoleFocus, `pid ${launch.pid}`);
	if (launch.stoleFocus) {
		throw new Error('focus stolen: stop (AGENTS rule)');
	}
	type Shown = { kind: string; message: string; actions: string[]; tabId: string };
	let shown: Shown[] = [];
	let forger: { remoteName?: string; canaryVisible?: boolean; results?: Record<string, { sent: boolean }> } | undefined;
	for (const end = Date.now() + 180_000; Date.now() < end; await sleep(2000)) {
		try {
			shown = fs.readFileSync(notifications, 'utf8').trim().split('\n').filter(Boolean).map(l => JSON.parse(l) as Shown);
		} catch { /* not yet */ }
		if (!forger) {
			const r = spawnSync(SBX, ['exec', '-u', 'agent', `seclab-${tabId}`, 'cat', '/tmp/seclab-withheld-forger.json'], { encoding: 'utf8' });
			forger = r.status === 0 ? JSON.parse(r.stdout) : undefined;
		}
		if (forger && (forgedOnly || shown.some(s => s.kind === 'config.withheld'))) {
			break;
		}
	}
	await sleep(5000); // let any notification a forged call might have caused arrive too
	try {
		shown = fs.readFileSync(notifications, 'utf8').trim().split('\n').filter(Boolean).map(l => JSON.parse(l) as Shown);
	} catch { /* none */ }
	check('the forger ran in the tab and made its five calls (sent, or refused by the RPC filter)', forger?.remoteName === 'seclab' && Object.keys(forger.results ?? {}).length === 5, JSON.stringify(forger));
	// The Tab Manager's own log (trusted side) shows each call reached its handler and was refused.
	const tmLogs: string[] = [];
	const walk = (d: string) => {
		for (const e of fs.existsSync(d) ? fs.readdirSync(d, { withFileTypes: true }) : []) {
			const p = path.join(d, e.name);
			if (e.isDirectory()) {
				walk(p);
			} else if (/seclab Tab Manager\.log$|seclab\.tab-manager.*\.log$/i.test(p)) {
				tmLogs.push(fs.readFileSync(p, 'utf8'));
			}
		}
	};
	walk(path.join(userData, 'logs'));
	const handled = tmLogs.join('\n').split('\n').filter(l => /seclab\.tabs\.settingsWithheld.*(ignored|refused)/.test(l));
	if (forgedOnly) {
		const sent = Object.values(forger?.results ?? {}).filter(r => r.sent).length;
		console.log(`forger: ${JSON.stringify(forger?.results)}; Tab Manager handler lines: ${handled.length}, e.g. ${JSON.stringify(handled[0]?.replace(/^.*?\[warning\]\s*/, '') ?? '')}`);
		check('every forged call that reached the editor reached the Tab Manager\'s handler and was refused there', sent > 0 && handled.length >= sent, `sent ${sent}, handler lines ${handled.length}: ${handled.slice(0, 3).join(' | ')}`);
	} else {
		check('0036 kept the canary setting out of the tab', forger?.canaryVisible === false, JSON.stringify(forger?.canaryVisible));
	}

	const withheld = shown.filter(s => s.kind === 'config.withheld');
	if (forgedOnly) {
		check('no "setting withheld" notification from a forged call', withheld.length === 0, JSON.stringify(withheld));
	} else {
		check('one "setting withheld" notification, for this tab, naming the canary key as code', withheld.length === 1 && withheld[0].tabId === tabId && withheld[0].message.includes(`\`${KEY}\``) && withheld[0].message.startsWith('Tab “acme-app”:'), JSON.stringify(withheld));
		check('it offers Open Settings', withheld[0]?.actions.includes('open-settings') ?? false, JSON.stringify(withheld[0]?.actions));
	}
	check('no notification names a forged key', !shown.some(s => FORGED_KEYS.test(s.message)), JSON.stringify(shown.map(s => s.message)));

	const logDir = path.join(stateDir, 'events', tabId);
	const events = fs.existsSync(logDir) ? fs.readdirSync(logDir).filter(f => f.endsWith('.jsonl')).flatMap(f => fs.readFileSync(path.join(logDir, f), 'utf8').trim().split('\n').filter(Boolean).map(l => JSON.parse(l) as ObsEvent)) : [];
	const cw = events.filter(e => e.class === 'config.withheld');
	if (forgedOnly) {
		check('tabd: no config.withheld event from a forged call', cw.length === 0, JSON.stringify(cw.map(e => e.detail)));
	} else {
		check('tabd: exactly one config.withheld event, trusted, for the canary key; no forged key', cw.length === 1 && cw[0].integrity === 'trusted' && cw[0].detail?.key === KEY && cw[0].untrusted.includes('detail.key'), JSON.stringify(cw.map(e => e.detail)));
	}
	const everything = `${fs.existsSync(notifications) ? fs.readFileSync(notifications, 'utf8') : ''}\n${events.map(e => JSON.stringify(e)).join('\n')}`;
	check('the canary value appears in no notification and no event', !everything.includes(CANARY));
} catch (e) {
	check('run', false, (e as Error).message);
} finally {
	if (keep) {
		console.log(`KEEP: not torn down (editor pid ${windowPid ?? '?'}). Later: node test/containment/teardown.ts verify ${base}`);
		failures++;
	} else {
		stopRunProcesses(base);
		removeRunResources(base);
		if (!printChecks(verifyTeardown(base))) {
			failures++;
		}
	}
}
console.log(failures ? `\n${failures} check(s) failed` : '\nWITHHELD PROBE OK');
process.exit(failures ? 1 : 0);
