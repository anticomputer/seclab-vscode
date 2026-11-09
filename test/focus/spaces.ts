// Focus probe, Space changes (path c, 2026-11-09): when a Space becomes current, macOS activates
// the owner of its topmost window, and a background editor that was alone on a Space was made the
// front process. This drives that case on purpose, then the ordinary one:
//   1. switch to the empty Space to the right and launch the prepared run's editor there (its
//      window is the only one on that Space);
//   2. switch away and back three times (back = the Space where the editor's window is alone);
//   3. end on the starting Space.
// Every switch is a host mark in .work/focus-probe/host-marks.log, so `node test/focus/probe.ts
// check` matches any steal to the switch before it. The launch's watcher kills the editor on the
// first steal (fail closed). Each switch must change the on-screen window set (read-only
// CGWindowList), or the run stops: an unbound shortcut would type into the user's app instead
// (review LLL-5).
// Needs: an empty Space immediately to the right of the current one, the default "Move right/left
// a space" shortcuts (Ctrl+Arrow), and permission for the calling process to send keystrokes
// through System Events. It moves the user's screen between Spaces for about a minute: run it only
// when the user has agreed to that.
//   node test/focus/probe.ts prepare [--app PATH] --skip <all steps>
//   node test/focus/spaces.ts [--app PATH]
//   node test/focus/probe.ts check --no-host-steps

import { execFileSync, spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { readManifest } from '../containment/teardown.ts';

const repo = path.resolve(import.meta.dirname, '../..');
const base = path.join(repo, '.work', 'focus-probe');
const marks = path.join(base, 'host-marks.log');
const args = process.argv.slice(2);
const app = args[0] === '--app' && args[1] ? path.resolve(args[1]) : undefined;
if (args.length !== (app ? 2 : 0) || (app && !/\.app$/.test(app))) {
	console.error('usage: spaces.ts [--app PATH.app]');
	process.exit(2);
}
if (!fs.existsSync(path.join(base, 'run.json'))) {
	console.error('no prepared focus-probe run: run `node test/focus/probe.ts prepare` first');
	process.exit(2);
}
// The launch is built from the prepared run, never from a command line (review LLL-2): no shell.
const m = readManifest(base);
const tab = (m.tabs ?? [])[0];
if (!tab || !/^t-[a-z0-9]{26}$/.test(tab) || !m.userDataDir) {
	console.error('the prepared run has no tab or profile');
	process.exit(2);
}
const launchArgv = ['test/window.ts', 'launch', ...(app ? ['--app', app] : []), m.userDataDir, `vscode-remote://seclab+${tab}${path.join(base, 'ws')}`];

const mark = (text: string) => fs.appendFileSync(marks, `${new Date().toISOString()} host ${text}\n`);
const pause = (s: number) => spawnSync('sleep', [String(s)]);
const ONSCREEN_JXA = `ObjC.import('CoreGraphics');
function run() {
	const all = ObjC.deepUnwrap(ObjC.castRefToObject($.CGWindowListCopyWindowInfo($.kCGWindowListOptionOnScreenOnly, 0)));
	return JSON.stringify(all.filter(w => w.kCGWindowLayer === 0).map(w => w.kCGWindowNumber).sort((a, b) => a - b));
}`;
const onScreen = () => execFileSync('osascript', ['-l', 'JavaScript', '-e', ONSCREEN_JXA], { encoding: 'utf8' }).trim(); // fixture-lint: allow persistence -- read-only CGWindowList query (did the Space change?)
// Ctrl+Right / Ctrl+Left: the system's own Space shortcuts, handled by the Dock. No app is
// addressed except System Events, a faceless helper.
const KEY = { right: 124, left: 123 } as const;
function space(dir: keyof typeof KEY, why: string): void {
	const before = onScreen();
	mark(`space ${dir} (${why})`);
	const r = spawnSync('osascript', ['-e', `tell application "System Events" to key code ${KEY[dir]} using control down`], { encoding: 'utf8' }); // fixture-lint: allow persistence -- a Space-switch keystroke only; changes no setting
	pause(4);
	if (r.status !== 0 || onScreen() === before) {
		mark(`space ${dir} did not happen`);
		console.error(r.status !== 0 ? `could not switch Spaces: ${r.stderr.trim()}` : 'the Space did not change (shortcut unbound, or no empty Space to the right): run invalid');
		process.exit(1);
	}
}

space('right', 'to the empty Space');
mark('launch on the empty Space');
const l = spawnSync(process.execPath, launchArgv, { cwd: repo, encoding: 'utf8' });
process.stdout.write(l.stdout);
process.stderr.write(l.stderr);
pause(20);
for (let i = 1; i <= 3; i++) {
	space('left', `away from the editor's Space, ${i}`);
	space('right', `back to the Space where the editor's window is alone, ${i}`);
}
space('left', 'home');
mark('spaces finished');
console.log(`spaces: done (launch exit ${l.status}); now run: node test/focus/probe.ts check --no-host-steps`);
process.exit(l.status === 0 ? 0 : 1);
