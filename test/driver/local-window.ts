// Local windows run no workspace extension, and a VSIX can't make itself a ui built-in
// (findings m0#3-1 and m0#4-1; patches 0002, 0003, 0004). Headless: the editor is driven over its
// CDP pipe and each fixture reports activation through a status bar message the driver reads.
//   node test/driver/local-window.ts --app APP --profile DIR --vsix-dir DIR
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
const FIXTURES = [
	{ vsix: 'ui-control.vsix', mark: 'ui-control active', mustActivate: true, why: 'a ui extension runs in a local window (the harness sees activation)' },
	{ vsix: 'workspace-ext.vsix', mark: 'workspace-ext active', mustActivate: false, why: 'no workspace extension activates in a local window (m0#3-1, patch 0003)' },
	{ vsix: 'spoofed-builtin.vsix', mark: 'spoofed-builtin active', mustActivate: false, why: 'a VSIX claiming isBuiltin and a ui-allowlisted id stays a workspace extension (m0#4-1, patches 0002/0004)' },
];
// Literal marks, one per fixture (the liveness gate reads them from the code).
const LIVE: Record<string, () => void> = {
	'ui-control.vsix': () => liveMark('driver:local-window/ui-control'),
	'workspace-ext.vsix': () => liveMark('driver:local-window/workspace-ext'),
	'spoofed-builtin.vsix': () => liveMark('driver:local-window/spoofed-builtin'),
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
for (const f of FIXTURES) {
	const r = spawnSync(executable(app), [path.join(resources, 'out', 'cli.js'), '--user-data-dir', profile, '--install-extension', path.resolve(vsixDir, f.vsix), '--force'], { env, encoding: 'utf8', timeout: 120_000 });
	check(`installed ${f.vsix}`, r.status === 0, `${r.status}: ${(r.stderr || r.stdout).trim().slice(0, 300)}`);
}

let ed: DrivenEditor | undefined;
try {
	ed = await DrivenEditor.launch({ app, userData: profile, args: extra });
	await ed.waitFor(`document.querySelector('.monaco-workbench .part.statusbar')`, 60_000);
	const text = `document.querySelector('.part.statusbar')?.textContent ?? ''`;
	// The control proves activation is visible; the others get the same time after it.
	await ed.waitFor(`(${text}).includes('seclab-local-window: ui-control active')`, 60_000).catch(() => undefined);
	await new Promise(r => setTimeout(r, 10_000));
	const seen = await ed.evaluate<string>(text);
	for (const f of FIXTURES) {
		const active = seen.includes(`seclab-local-window: ${f.mark}`);
		check(f.why, active === f.mustActivate, `status bar: ${JSON.stringify(seen.slice(0, 200))}`);
		// Liveness (EDR liveness-gate): this fixture was installed and observed in a driven window.
		LIVE[f.vsix]();
	}
	await ed.close();
} catch (e) {
	check('driven run', false, (e as Error).message.slice(0, 300));
	await ed?.close().catch(() => undefined);
}
const failed = results.filter(r => !r.ok).length;
console.log(`\nlocal-window: ${results.length - failed}/${results.length} passed`);
process.exit(failed ? 1 : 0);
