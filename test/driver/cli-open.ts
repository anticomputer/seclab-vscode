// A local folder opened through the CLI never loads in a window: the main process routes it to the
// Tab Manager (patch 0041, ADR route-folder-opens-in-main; findings m0#2b-1 and m0#3-2). Headless:
// the editor is launched with the folder as its CLI argument and driven over its CDP pipe.
// - Every page is auto-attached paused, before its first script, and gets a reporter that sends
//   back its window configuration (workspace or none) over a CDP binding, for every document it
//   loads (a reload included). No document may have a workspace; the run needs reports.
// - The Tab Manager must receive the open: its confirmation names the folder, and the main log
//   shows that main routed it (not the Tab Manager's fallback, which reopens a local folder).
// - The run then declines, so nothing is claimed and no tab is created.
//   node test/driver/cli-open.ts --app APP --profile DIR [-- EXTRA_EDITOR_ARGS]

import * as fs from 'node:fs';
import * as path from 'node:path';
import { DrivenEditor } from './editor.ts';
import { checkUserDataDir } from '../harness.ts';

const argv = process.argv.slice(2);
const dash = argv.indexOf('--');
const extra = dash >= 0 ? argv.splice(dash).slice(1) : [];
const opt = (k: string) => (argv.indexOf(k) >= 0 ? argv[argv.indexOf(k) + 1] : undefined);
const app = opt('--app');
const profile = opt('--profile') && path.resolve(opt('--profile')!);
if (!app || !profile) {
	console.error('usage: cli-open.ts --app APP --profile DIR [-- EXTRA_EDITOR_ARGS]');
	process.exit(2);
}
checkUserDataDir(profile);
const results: Array<{ ok: boolean; name: string; detail: string }> = [];
const check = (name: string, ok: boolean, detail = '') => {
	results.push({ ok, name, detail });
	console.log(`${ok ? 'OK  ' : 'FAIL'}  ${name}${ok || !detail ? '' : `  ${detail}`}`);
};

// The folder: a sibling of the profile, with a name no other window can have.
const folder = `${profile}-folder-${process.pid}`;
fs.rmSync(folder, { recursive: true, force: true });
fs.mkdirSync(folder, { recursive: true });
fs.writeFileSync(path.join(folder, 'README.md'), 'Headless driver fixture: a folder opened through the CLI.\n');
// Custom dialogs: the confirmation is in the DOM (and never a native sheet).
fs.mkdirSync(path.join(profile, 'User'), { recursive: true });
fs.writeFileSync(path.join(profile, 'User', 'settings.json'), JSON.stringify({
	'workbench.welcomePage.experimentalOnboarding': false,
	'workbench.startupEditor': 'none',
	'workbench.tips.enabled': false,
	'chat.disableAIFeatures': true,
	'window.dialogStyle': 'custom',
}, null, '\t'));

// Runs in each document before its own scripts: reports the window configuration once it is
// resolved (the preload exposes it), or that it never was.
const BINDING = 'seclabCliOpenReport';
const REPORTER = `(() => {
	const t0 = Date.now();
	const tick = () => {
		const c = globalThis.vscode?.context?.configuration?.();
		if (c) { globalThis.${BINDING}(JSON.stringify({ workspace: c.workspace ?? null })); return; }
		if (Date.now() - t0 > 60000) { globalThis.${BINDING}(JSON.stringify({ unresolved: true })); return; }
		setTimeout(tick, 10);
	};
	tick();
})();`;
const reports: Array<{ workspace?: unknown; unresolved?: boolean }> = [];
const setupErrors: string[] = [];
const onPipe = async (cdp: DrivenEditor['cdp']) => {
	cdp.on((method, params: { sessionId?: string; targetInfo?: { type?: string }; waitingForDebugger?: boolean; name?: string; payload?: string }) => {
		if (method === 'Target.attachedToTarget' && params.sessionId) {
			const s = params.sessionId;
			// A paused target answers only after it resumes: send everything, then resume, then wait.
			const sent = params.targetInfo?.type === 'page' ? [
				cdp.send('Runtime.enable', {}, s),
				cdp.send('Runtime.addBinding', { name: BINDING }, s),
				cdp.send('Page.enable', {}, s),
				cdp.send('Page.addScriptToEvaluateOnNewDocument', { source: REPORTER }, s),
			] : [];
			if (params.waitingForDebugger) {
				sent.push(cdp.send('Runtime.runIfWaitingForDebugger', {}, s));
			}
			Promise.all(sent).catch((e: Error) => setupErrors.push(e.message));
		} else if (method === 'Runtime.bindingCalled' && params.name === BINDING && params.payload) {
			reports.push(JSON.parse(params.payload));
		}
	});
	await cdp.send('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true });
};

let ed: DrivenEditor | undefined;
try {
	ed = await DrivenEditor.launch({ app, userData: profile, args: [...extra, folder], onPipe });
	await ed.waitFor(`document.querySelector('.monaco-workbench .part.statusbar')`, 60_000);
	const asks = `[...document.querySelectorAll('.monaco-dialog-box, .notifications-toasts')].some(n => n.innerText.includes(${JSON.stringify(folder)}))`;
	const asked = await ed.waitFor(asks, 60_000).then(() => true, () => false);
	// A moment more: the open must not be followed by a local load.
	await new Promise(r => setTimeout(r, 3_000));
	const withWorkspace = reports.filter(r => r.workspace || r.unresolved);
	check('every window document reported its configuration from its first script', reports.length > 0 && setupErrors.length === 0, `${reports.length} report(s); ${setupErrors.join('; ').slice(0, 200)}`);
	check('no window ever had a workspace: the folder never loaded locally, not even before a dialog (m0#2b-1, m0#3-2)', withWorkspace.length === 0, JSON.stringify(withWorkspace).slice(0, 300));
	check('the Tab Manager received the open and asked about the folder', asked);
	const logs = path.join(profile, 'logs');
	const mainLog = fs.existsSync(logs) ? fs.readdirSync(logs).map(d => path.join(logs, d, 'main.log')).filter(f => fs.existsSync(f)).map(f => fs.readFileSync(f, 'utf8')).join('\n') : '';
	check('the main process routed it (patch 0041), not the Tab Manager\'s fallback', /\[seclab\] routed 1 local folder\(s\) or workspace\(s\) to the Tab Manager/.test(mainLog));
	// Decline: nothing is claimed, and nothing loads.
	const before = reports.length;
	await ed.key('Escape');
	await new Promise(r => setTimeout(r, 2_000));
	check('no window loads the folder after declining', reports.slice(before).every(r => !r.workspace && !r.unresolved));
	await ed.close();
} catch (e) {
	check('driven run', false, (e as Error).message.slice(0, 300));
	await ed?.close().catch(() => undefined);
} finally {
	fs.rmSync(folder, { recursive: true, force: true });
}
const failed = results.filter(r => !r.ok).length;
console.log(`\ncli-open: ${results.length - failed}/${results.length} passed`);
process.exit(failed ? 1 : 0);
