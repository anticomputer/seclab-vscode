// Editor windows for demos and containment-editor runs, without ever taking focus from the
// user (AGENTS.md hard rule). macOS only. No screen capture, UI automation or synthetic
// input: a run's evidence is read from files and logs, never from the screen.
//   node test/window.ts launch [--app PATH.app] [--rpc-trace .work/LOG] [--env K=V]... USER_DATA_DIR FOLDER_URI   # background launch; exit 1 if it took focus
//   (every background launch starts `window.ts watch USER_DATA_DIR -` first: it samples the
//    frontmost app every 200 ms for the editor's whole life, and on the first sample in which the
//    editor is frontmost it records the steal and kills the editor's process tree; teardown fails
//    the run if one happened. Review UU-2, 2026-11-06 focus steal.)
// Teardown stays with each suite (demo.ts teardown, check-evidence's manifest).

import * as fs from 'node:fs';
import * as path from 'node:path';
import { appHasCanaryClipboard, checkUserDataDir, focusStealLog, launchEditorInBackground, watchFocus } from './harness.ts';

const argv = process.argv.slice(2);
const mode = argv.shift();
let app: string | undefined;
if (argv[0] === '--app' && argv[1]) {
	app = path.resolve(argv.splice(0, 2)[1]);
	if (!/\.app$/.test(app) || !fs.existsSync(path.join(app, 'Contents', 'MacOS'))) {
		console.error(`--app must be an existing .app bundle: ${app}`);
		process.exit(2);
	}
}
let rpcTrace: string | undefined;
if (argv[0] === '--rpc-trace' && argv[1]) {
	// Measurement only: validated by rpcTraceArgs (a plain path under this checkout's .work/).
	rpcTrace = path.resolve(argv.splice(0, 2)[1]);
}
const env: Record<string, string> = {};
while (argv[0] === '--env' && /^[A-Z_][A-Z0-9_]*=/.test(argv[1] ?? '')) {
	const kv = argv.splice(0, 2)[1];
	env[kv.slice(0, kv.indexOf('='))] = kv.slice(kv.indexOf('=') + 1);
}
const [userDataArg, arg] = argv;
if (process.platform !== 'darwin' || !['launch', 'watch'].includes(mode ?? '') || !userDataArg || !arg || argv.length !== 2) {
	console.error('usage (macOS): window.ts launch [--app PATH.app] [--env K=V]... USER_DATA_DIR FOLDER_URI');
	process.exit(2);
}
const userData = path.resolve(userDataArg);
checkUserDataDir(userData);

if (mode === 'watch') {
	await watchFocus(userData);
} else {
	// No run ever reads the system clipboard. A workspace whose targets claim the canary
	// clipboard (the probes will then read the clipboard) launches only an app that carries
	// it, and the canary seed only goes to such an app: a swapped --app or a forged targets
	// line must not turn a probe into a read of the user's clipboard. The workspace is found
	// from any folder form (vscode-remote:, file:, a plain path); an unrecognised form fails.
	let folder: string | undefined;
	if (/^vscode-remote:\/\//.test(arg)) {
		folder = /^vscode-remote:\/\/[^/]+(\/.*)$/.exec(arg)?.[1];
	} else if (/^file:\/\//.test(arg)) {
		try { folder = new URL(arg).pathname; } catch { folder = undefined; }
	} else if (path.isAbsolute(arg)) {
		folder = arg;
	}
	if (folder === undefined) {
		console.error('refusing: the folder argument is not a vscode-remote:, file: URI or absolute path');
		process.exit(2);
	}
	const targetsFile = path.join(decodeURIComponent(folder), '.seclab', 'targets');
	const claimsCanaryClipboard = fs.existsSync(targetsFile) && /^clipboard=/m.test(fs.readFileSync(targetsFile, 'utf8'));
	if ((claimsCanaryClipboard || env.SECLAB_TEST_CLIPBOARD_CANARY !== undefined) && !(app && appHasCanaryClipboard(app))) {
		console.error('refusing: this run reads the clipboard, and the app has no canary clipboard (test/builds/variants.json hook canary-clipboard); pass the test build with --app');
		process.exit(2);
	}
	const r = await launchEditorInBackground(userData, arg, env, undefined, app, rpcTrace);
	console.log(`editor pid ${r.pid}, window ${r.windowId}, launched in the background`);
	if (r.stoleFocus) {
		if (!fs.existsSync(focusStealLog(userData)) || !fs.readFileSync(focusStealLog(userData), 'utf8').trim()) {
			fs.appendFileSync(focusStealLog(userData), `${new Date().toISOString()} editor pid ${r.pid} took focus at launch\n`);
		}
		console.error('FAIL: the editor became the frontmost app (focus stolen); it was killed. Report it; do not work around it with activate.');
		process.exit(1);
	}
}
