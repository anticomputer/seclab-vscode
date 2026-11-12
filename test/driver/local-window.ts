// Local windows run no extension that isn't a ui built-in, and a VSIX can't make itself one
// (findings m0#3-1 and m0#4-1; patches 0002, 0003, 0004). Headless: the editor is driven over its
// CDP pipe and each fixture shows its activation as its own status bar item, which the driver
// reads. The control is the Tab Manager's own item (a ui built-in): it proves activation shows.
//   node test/driver/local-window.ts --app APP --profile DIR --vsix-dir DIR [-- EXTRA_EDITOR_ARGS]
// The VSIXs are zipped from test/driver/local-window/* in the runner container (VS Code reads only
// extension/package.json from a VSIX: extensionManagementUtil.getManifest), so no vsce and no
// registry; they're installed with the build's own CLI (cli.js under ELECTRON_RUN_AS_NODE).

import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { DrivenEditor, editorEnv, executable } from './editor.ts';
import { checkUserDataDir, preparePortable } from '../harness.ts';
import { liveMark } from '../liveness.ts';

const argv = process.argv.slice(2);
const dash = argv.indexOf('--');
const extra = dash >= 0 ? argv.splice(dash).slice(1) : [];
const opt = (k: string) => (argv.indexOf(k) >= 0 ? argv[argv.indexOf(k) + 1] : undefined);
const app = opt('--app');
const profile = opt('--profile');
const vsixDir = opt('--vsix-dir');
if (!app || !profile || !vsixDir) {
	console.error('usage: local-window.ts --app APP --profile DIR --vsix-dir DIR [-- EXTRA_EDITOR_ARGS]');
	process.exit(2);
}
// installRefused: the install itself must fail with this reason (the attack stops there).
const FIXTURES: Array<{ name: string; why: string; installRefused?: RegExp }> = [
	{ name: 'workspace-ext', why: 'a workspace extension does not run in a local window (m0#3-1, patch 0003)' },
	{ name: 'third-party-ui', why: 'a third-party extension that declares ui does not run in a local window either (product.json forces it into the tab)' },
	{ name: 'spoofed-isbuiltin', why: 'a VSIX claiming isBuiltin and ui under its own id does not run in a local window (m0#4-1, patches 0002/0004)' },
	{ name: 'spoofed-builtin', why: 'a VSIX claiming a ui-allowlisted built-in id is refused at install (m0#4-1)', installRefused: /built-in extension and not allowed to be updated/ },
];
// Literal marks, one per fixture (the liveness gate reads them from the code).
const LIVE: Record<string, () => void> = {
	'workspace-ext': () => liveMark('driver:local-window/workspace-ext'),
	'third-party-ui': () => liveMark('driver:local-window/third-party-ui'),
	'spoofed-isbuiltin': () => liveMark('driver:local-window/spoofed-isbuiltin'),
	'spoofed-builtin': () => liveMark('driver:local-window/spoofed-builtin'),
};
const results: Array<{ ok: boolean; name: string; detail: string }> = [];
const check = (name: string, ok: boolean, detail = '') => {
	results.push({ ok, name, detail });
	console.log(`${ok ? 'OK  ' : 'FAIL'}  ${name}${ok || !detail ? '' : `  ${detail}`}`);
};

const resources = process.platform === 'darwin' ? path.join(app, 'Contents', 'Resources', 'app') : path.join(app, 'resources', 'app');
const env = { ...editorEnv({ userData: profile }), ELECTRON_RUN_AS_NODE: '1' };
checkUserDataDir(path.resolve(profile));
fs.mkdirSync(profile, { recursive: true });
preparePortable(path.resolve(profile)); // the CLI installs into the same portable dir the editor uses
const installed = new Map<string, boolean>();
for (const f of FIXTURES) {
	// A fixture that could never activate would pass vacuously (review TTT-1): its entry point
	// must exist and parse.
	const dir = path.join(import.meta.dirname, 'local-window', f.name);
	const main = path.join(dir, JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')).main ?? '');
	const syntax = spawnSync(process.execPath, ['--check', main], { encoding: 'utf8' });
	check(`${f.name}'s entry point exists and parses`, fs.existsSync(main) && syntax.status === 0, syntax.stderr.slice(0, 200));
	// The run looks for this exact status text, so the fixture must show it on activation
	// (review UUU-2): a renamed marker would make every "not active" check vacuous.
	const src = fs.existsSync(main) ? fs.readFileSync(main, 'utf8') : '';
	check(`${f.name} shows the marker the run looks for when it activates`, src.includes(`item.text = 'seclab-local-window: ${f.name} active';`) && src.includes('item.show();'));
	const r = spawnSync(executable(app), [path.join(resources, 'out', 'cli.js'), '--user-data-dir', profile, '--install-extension', path.resolve(vsixDir, `${f.name}.vsix`), '--force'], { env, encoding: 'utf8', timeout: 120_000 });
	const out = `${r.stdout}${r.stderr}`;
	installed.set(f.name, r.status === 0);
	if (f.installRefused) {
		check(f.why, r.status !== 0 && f.installRefused.test(out), `${r.status}: ${out.trim().slice(0, 300)}`);
	} else {
		check(`installed ${f.name}`, r.status === 0, `${r.status}: ${out.trim().slice(0, 300)}`);
	}
}

let ed: DrivenEditor | undefined;
try {
	ed = await DrivenEditor.launch({ app, userData: profile, args: extra });
	await ed.waitFor(`document.querySelector('.monaco-workbench .part.statusbar')`, 60_000);
	const items = `[...document.querySelectorAll('.part.statusbar .statusbar-item')].map(e => e.id + ' ' + (e.innerText || '')).join('\\n')`;
	// The control: the Tab Manager (a ui built-in) shows its item, so activation is visible. It
	// must be seen through the same text the fixtures are matched on, so an empty innerText (a
	// renderer change) fails here instead of making the fixture checks vacuous (review UUU-2).
	// The fixtures then get the same time after it.
	const controlSeen = `(${items}).split('\\n').some(l => l.split(' ')[0].includes('seclab.tab-manager') && l.slice(l.indexOf(' ') + 1).trim() !== '')`;
	const control = await ed.waitFor(controlSeen, 60_000).then(() => true, () => false);
	check('control: a ui built-in (the Tab Manager) activates and its status text is visible', control);
	await new Promise(r => setTimeout(r, 10_000));
	const seen = await ed.evaluate<string>(items);
	for (const f of FIXTURES) {
		const active = seen.includes(`seclab-local-window: ${f.name} active`);
		if (!f.installRefused) {
			check(f.why, control && installed.get(f.name) === true && !active, active ? 'it activated' : '');
		} else {
			check(`${f.name} is not active either`, !active);
		}
		// Liveness (EDR liveness-gate): this fixture was installed (or refused) and observed.
		LIVE[f.name]();
	}
	await ed.close();
} catch (e) {
	check('driven run', false, (e as Error).message.slice(0, 300));
	await ed?.close().catch(() => undefined);
}
const failed = results.filter(r => !r.ok).length;
console.log(`\nlocal-window: ${results.length - failed}/${results.length} passed`);
process.exit(failed ? 1 : 0);
