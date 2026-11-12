// Headless driver self-test: launch the editor over its CDP pipe, drive it from inside, take a
// screenshot from its own renderer, quit. Proves the driver on a build before probes use it.
//   node test/driver/selftest.ts --app APP --profile DIR [--shot OUT.png] [-- EXTRA_EDITOR_ARGS]
// Linux: under Xvfb (./seclab test driver). macOS: needs a build with patch 0012's bootstrap policy.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { DrivenEditor } from './editor.ts';

const argv = process.argv.slice(2);
const dash = argv.indexOf('--');
const extra = dash >= 0 ? argv.splice(dash).slice(1) : [];
const opt = (k: string) => (argv.indexOf(k) >= 0 ? argv[argv.indexOf(k) + 1] : undefined);
const app = opt('--app');
const profile = opt('--profile');
const shot = opt('--shot') ?? path.join(profile ?? '.', '..', 'driver-selftest.png');
if (!app || !profile) {
	console.error('usage: selftest.ts --app APP --profile DIR [--shot OUT.png] [-- EXTRA_EDITOR_ARGS]');
	process.exit(2);
}

const results: Array<{ ok: boolean; name: string; detail: string }> = [];
const check = (name: string, ok: boolean, detail = '') => {
	results.push({ ok, name, detail });
	console.log(`${ok ? 'OK  ' : 'FAIL'}  ${name}${ok || !detail ? '' : `  ${detail}`}`);
};

const statusBarShown = `(() => { const s = document.querySelector('.part.statusbar'); return !!s && s.offsetParent !== null && s.getBoundingClientRect().height > 0; })()`;

let ed: DrivenEditor | undefined;
try {
	ed = await DrivenEditor.launch({ app, userData: profile, smokeDriver: true, args: extra });
	check('launched over --remote-debugging-pipe and attached to the workbench page', true);
	await ed.driver('whenWorkbenchRestored');
	check('workbench restored (window.driver)', true);
	const title = await ed.evaluate<string>('document.title');
	check('reads UI state (document title)', typeof title === 'string' && title.length > 0, JSON.stringify(title));
	check('reads the DOM (.monaco-workbench)', await ed.evaluate<boolean>(`!!document.querySelector('.monaco-workbench')`));
	const before = await ed.evaluate<boolean>(statusBarShown);
	await ed.command('View: Toggle Status Bar Visibility');
	await ed.waitFor(before ? `!${statusBarShown}` : statusBarShown, 10_000).then(() => true, () => false).then(ok =>
		check('runs a command through the palette (status bar toggled)', ok, `status bar shown before: ${before}`));
	await ed.command('View: Toggle Status Bar Visibility');
	await ed.waitFor(statusBarShown, 10_000).catch(() => undefined);
	const bytes = await ed.screenshot(shot);
	const png = fs.readFileSync(shot);
	const isPng = png.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
	const w = isPng ? png.readUInt32BE(16) : 0;
	const h = isPng ? png.readUInt32BE(20) : 0;
	const inner = await ed.evaluate<{ w: number; h: number }>('({ w: innerWidth, h: innerHeight })');
	check('screenshot from the renderer (PNG, window-sized)', isPng && bytes > 10_000 && Math.abs(w / (inner.w || 1) - Math.round(w / (inner.w || 1))) < 0.01 && h > 0,
		`${bytes} bytes, ${w}x${h}, viewport ${inner.w}x${inner.h}`);
	const holders = ed.cdpFdHolders();
	check('no other process holds the CDP pipe (no login shell, no inheriting child)', holders.length === 0, holders.join(' | '));
	const pid = ed.child.pid;
	await ed.close();
	check('quits through CDP (Browser.close)', ed.child.exitCode !== null || ed.child.signalCode !== null, `pid ${pid}`);
} catch (e) {
	check('driver run', false, (e as Error).message.slice(0, 300));
	await ed?.close().catch(() => undefined);
}
const failed = results.filter(r => !r.ok).length;
console.log(`\ndriver self-test: ${results.length - failed}/${results.length} passed; screenshot ${shot}`);
process.exit(failed ? 1 : 0);
