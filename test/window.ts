// Editor windows for demos, screenshots and containment-editor runs, without ever taking focus
// from the user (AGENTS.md hard rule). macOS only.
//   node test/window.ts launch [--env K=V]... USER_DATA_DIR FOLDER_URI   # background launch; exit 1 if it took focus
//   node test/window.ts shot USER_DATA_DIR OUT.png                       # capture the (covered) window by id
//   (launch also starts `window.ts watch USER_DATA_DIR -`: it records any later focus steal, and
//    teardown fails the run if one happened; review UU-2)
// Teardown stays with each suite (demo.ts teardown, check-evidence's manifest).

import * as fs from 'node:fs';
import * as path from 'node:path';
import { captureWindow, checkUserDataDir, editorPid, editorWindowId, focusStealLog, launchEditorInBackground, startFocusWatch, watchFocus } from './harness.ts';

const argv = process.argv.slice(2);
const mode = argv.shift();
const env: Record<string, string> = {};
while (argv[0] === '--env' && /^[A-Z_][A-Z0-9_]*=/.test(argv[1] ?? '')) {
	const kv = argv.splice(0, 2)[1];
	env[kv.slice(0, kv.indexOf('='))] = kv.slice(kv.indexOf('=') + 1);
}
const [userDataArg, arg] = argv;
if (process.platform !== 'darwin' || !['launch', 'shot', 'watch'].includes(mode ?? '') || !userDataArg || !arg || argv.length !== 2) {
	console.error('usage (macOS): window.ts launch [--env K=V]... USER_DATA_DIR FOLDER_URI | window.ts shot USER_DATA_DIR OUT.png');
	process.exit(2);
}
const userData = path.resolve(userDataArg);
checkUserDataDir(userData);

if (mode === 'watch') {
	await watchFocus(userData);
} else if (mode === 'launch') {
	const r = await launchEditorInBackground(userData, arg, env);
	console.log(`editor pid ${r.pid}, window ${r.windowId}, launched in the background`);
	if (r.stoleFocus) {
		fs.appendFileSync(focusStealLog(userData), `${new Date().toISOString()} editor pid ${r.pid} took focus at launch\n`);
		console.error('FAIL: the editor became the frontmost app (focus stolen). Report it; do not work around it with activate.');
		process.exit(1);
	}
	startFocusWatch(userData);
} else {
	const steals = fs.existsSync(focusStealLog(userData)) ? fs.readFileSync(focusStealLog(userData), 'utf8').trim() : '';
	if (steals) {
		console.error(`FAIL: the editor took focus during this run; not capturing:\n${steals}`);
		process.exit(1);
	}
	const pid = editorPid(userData);
	const id = pid ? editorWindowId(pid) : 0;
	if (!id) {
		console.error(`no editor window for ${userData}`);
		process.exit(1);
	}
	captureWindow(id, path.resolve(arg));
	console.log(`captured window ${id} -> ${arg}`);
}
