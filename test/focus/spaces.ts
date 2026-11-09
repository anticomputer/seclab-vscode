// Focus probe, Space changes (path c, 2026-11-09): when a Space becomes current, macOS activates
// the owner of its topmost window, and a background editor that was alone on a Space was made the
// front process. This drives that case on purpose, then the ordinary one:
//   1. switch to the empty Space to the right and launch the editor there (its window is the only
//      one on that Space), with the printed `node test/window.ts launch ...` line;
//   2. switch away and back three times (back = the Space where the editor's window is topmost);
//   3. end on the starting Space.
// Every switch is a host mark in .work/focus-probe/host-marks.log, so `node test/focus/probe.ts
// check` matches any steal to the switch before it. The launch's watcher kills the editor on the
// first steal (fail closed).
// Needs: an empty Space immediately to the right of the current one, the default "Move right/left
// a space" shortcuts (Ctrl+Arrow), and permission for the calling process to send keystrokes
// through System Events. It moves the user's screen between Spaces for about a minute: run it only
// when the user has agreed to that.
//   node test/focus/probe.ts prepare [--app PATH] --skip <all steps>   # prints the launch line
//   node test/focus/spaces.ts '<the printed launch line>'
//   node test/focus/probe.ts check --no-host-steps

import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

const repo = path.resolve(import.meta.dirname, '../..');
const marks = path.join(repo, '.work', 'focus-probe', 'host-marks.log');
const launch = process.argv[2] ?? '';
// Only the line probe.ts prints: our launcher, nothing else.
if (!/^node test\/window\.ts launch (?:--app \S+ )?(?:--env \S+ )*\S+ vscode-remote:\/\/seclab\+t-[a-z0-9]+\/\S+$/.test(launch)) {
	console.error('usage: spaces.ts \'node test/window.ts launch ...\' (the line `probe.ts prepare` printed)');
	process.exit(2);
}
if (!fs.existsSync(path.join(repo, '.work', 'focus-probe', 'run.json'))) {
	console.error('no prepared focus-probe run: run `node test/focus/probe.ts prepare` first');
	process.exit(2);
}

const mark = (text: string) => fs.appendFileSync(marks, `${new Date().toISOString()} host ${text}\n`);
const pause = (s: number) => spawnSync('sleep', [String(s)]);
// Ctrl+Right / Ctrl+Left: the system's own Space shortcuts, handled by the Dock. No app is
// addressed except System Events, a faceless helper.
const KEY = { right: 124, left: 123 } as const;
function space(dir: keyof typeof KEY, why: string): void {
	mark(`space ${dir} (${why})`);
	const r = spawnSync('osascript', ['-e', `tell application "System Events" to key code ${KEY[dir]} using control down`], { encoding: 'utf8' }); // fixture-lint: allow persistence -- a Space-switch keystroke only; changes no setting
	if (r.status !== 0) {
		mark(`space ${dir} failed`);
		console.error(`could not switch Spaces: ${r.stderr.trim()}`);
		process.exit(1);
	}
	pause(4);
}

space('right', 'to the empty Space');
mark('launch on the empty Space');
const l = spawnSync('sh', ['-c', launch], { cwd: repo, encoding: 'utf8' });
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
