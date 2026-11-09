// Shared harness helpers: lets several worktrees (and sessions) run the suites at once.
//   SECLAB_BEACON_PORT  host-loopback beacon port (default: a free port picked per run)
//   SECLAB_EVIDENCE_DIR level B fixture dir (default: <repo>/.work/containment-editor)

import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { createHash, createHmac } from 'node:crypto';
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';

export const repoRoot = path.resolve(import.meta.dirname, '..');

/** Third-party images the harness runs, pinned by digest (build/check-pins.ts enforces it). */
export const NODE_IMAGE = 'node:24.22.1-trixie@sha256:f1e034976f948cf212ef1f659c12e5dd58ac7eab947831813e81a62401ca38be';
export const NGINX_IMAGE = 'nginx:alpine@sha256:785835ea65db4bba6f021acc0f3be91b0fef76a53fe41f8588c6698d2aed0606';

/** Short, stable id for this worktree: keeps global names (docker containers) apart. */
export const worktreeId = createHash('sha256').update(repoRoot).digest('hex').slice(0, 8);

/** SECLAB_BEACON_PORT, or a free loopback port. */
export async function beaconPort(): Promise<number> {
	const fixed = Number(process.env.SECLAB_BEACON_PORT ?? 0);
	if (Number.isInteger(fixed) && fixed > 0 && fixed < 65536) {
		return fixed;
	}
	return new Promise((resolve, reject) => {
		const s = net.createServer();
		s.once('error', reject);
		s.listen(0, '127.0.0.1', () => {
			const port = (s.address() as net.AddressInfo).port;
			s.close(() => resolve(port));
		});
	});
}

/**
 * One run per directory at a time: an exclusive lockfile with our pid. A lock left by a
 * dead process is taken over. Released on exit.
 */
export function lockRun(dir: string): void {
	fs.mkdirSync(dir, { recursive: true });
	const lock = path.join(dir, 'run.lock');
	for (let attempt = 0; attempt < 2; attempt++) {
		try {
			fs.writeFileSync(lock, String(process.pid), { flag: 'wx' });
			process.on('exit', () => fs.rmSync(lock, { force: true }));
			return;
		} catch {
			const pid = Number(fs.readFileSync(lock, 'utf8'));
			let alive = false;
			try {
				process.kill(pid, 0);
				alive = pid > 0;
			} catch { /* not running */ }
			if (alive) {
				throw new Error(`another run (pid ${pid}) holds ${lock}`);
			}
			fs.rmSync(lock, { force: true });
		}
	}
	throw new Error(`could not take ${lock}`);
}

/**
 * Electron's main IPC socket lives in the user-data dir; macOS caps unix socket paths at
 * 104 bytes, so a deep path (e.g. inside a worktree's .work/) makes the editor exit at
 * start. Fail early with a hint instead. Test profiles must also be isolated: never a real
 * editor profile (they hold auth sessions and settings with secrets).
 */
export function checkUserDataDir(userData: string): void {
	checkIsolatedProfile(userData);
	if (process.platform === 'darwin' && path.join(userData, '1.14-main.sock').length >= 104) {
		throw new Error(`user-data-dir too long for macOS unix sockets (${userData}); use a short one such as ~/.seclab-test/<name>`);
	}
}

/** Test profiles live only under ~/.seclab-test/ or this worktree's .work/ (never a real profile), also after resolving links (R-3). */
export function checkIsolatedProfile(userData: string): void {
	const home = os.homedir();
	const roots = [path.join(home, '.seclab-test'), path.join(repoRoot, '.work')];
	const under = (p: string, rs: string[]) => rs.some(r => p.startsWith(r + path.sep));
	if (!under(userData, roots)) {
		throw new Error(`test user-data-dir must be under ~/.seclab-test/ or this worktree's .work/ (isolated profile), got ${userData}`);
	}
	// The deepest existing ancestor, resolved, must still be inside a resolved root.
	let p = userData;
	while (!fs.existsSync(p) && path.dirname(p) !== p) {
		p = path.dirname(p);
	}
	const real = fs.realpathSync.native(p);
	const realRoots = roots.filter(r => fs.existsSync(r)).map(r => fs.realpathSync.native(r));
	if (!realRoots.some(r => real === r || real.startsWith(r + path.sep))) {
		throw new Error(`test user-data-dir resolves outside the test roots (symlink?): ${userData} -> ${real}`);
	}
}

/** Host paths a payload that escaped containment might touch. Stat only: never read. */
const WATCHED = ['.ssh', '.gitconfig', '.zshrc', '.zprofile', '.zshenv', '.bashrc', '.bash_profile', '.profile', 'Library/LaunchAgents', '.config/git',
	'.aws', '.npmrc', '.netrc', '.git-credentials', '.vimrc', '.tmux.conf', '.config/fish', '.config/autostart', '.config/starship.toml',
	'.config/nvim/init.lua', '.config/nvim/init.vim'];

const PRESENCE = ['', '.config'];
// Entries tools create under normal use during a long (level B) run: not a tripwire.
const PRESENCE_NOISE = new Set(['.DS_Store', '.lesshst', '.viminfo', '.zsh_history', '.zsh_sessions', '.bash_history', '.python_history',
	'.node_repl_history', '.cache', '.Trash', '.CFUserTextEncoding']);

export type Snapshot = Record<string, string>;

/**
 * Stat-only snapshot of the watched paths, recursing into directories (FS-6). Entry names
 * inside them (e.g. key file names in the SSH directory) are never stored: they're HMAC'd
 * with a per-run key (T-7: no precomputed dictionary), and a change is reported against the
 * watched top-level path. Only snapshots taken with the same key are comparable.
 */
export function hostSnapshot(key: string): Snapshot {
	const out: Snapshot = {};
	const h = (s: string) => createHmac('sha256', key).update(s).digest('hex').slice(0, 16);
	const visit = (top: string, rel: string, depth: number) => {
		const p = path.join(os.homedir(), rel);
		const k = rel === top ? top : `${top}#${h(rel)}`;
		let st: fs.Stats;
		try {
			st = fs.lstatSync(p);
		} catch {
			out[k] = 'absent';
			return;
		}
		out[k] = `${st.ino}:${st.size}:${st.mtimeMs}`;
		if (st.isDirectory()) {
			let entries: string[] = [];
			try {
				entries = fs.readdirSync(p);
			} catch { /* unreadable: the dir's own stat still counts */ }
			if (depth >= 4 || entries.length > 500) {
				out[`${top}#capped`] = 'snapshot depth/size cap reached: not fully watched';
				process.stderr.write(`harness: host snapshot cap reached under ~/${top}; entries beyond it are not watched\n`);
			}
			if (depth < 4) {
				for (const e of entries.slice(0, 500)) {
					visit(top, path.join(rel, e), depth + 1);
				}
			}
		}
	};
	for (const rel of WATCHED) {
		visit(rel, rel, 0);
	}
	// New entries directly in $HOME or ~/.config (dropped dotfiles, persistence): presence
	// only, names hashed. Their mtimes change under normal use, so they aren't recorded.
	for (const rel of PRESENCE) {
		let entries: string[] = [];
		try {
			entries = fs.readdirSync(path.join(os.homedir(), rel));
		} catch { /* absent */ }
		for (const e of entries) {
			if (!PRESENCE_NOISE.has(e)) {
				out[`${rel || '.'}#${h(path.join(rel, e))}`] = 'present';
			}
		}
	}
	return out;
}

export function snapshotDiff(before: Snapshot, after: Snapshot): string[] {
	const changed = new Set(Object.keys({ ...before, ...after }).filter(k => before[k] !== after[k]).map(k => `~/${k.split('#')[0]}`));
	return [...changed];
}


// ---- Editor windows never take focus (AGENTS.md hard rule; user: "you keep popping up on top
// of my ongoing work"). Launch in the background with LaunchServices (`open -g -n`), never
// activate, and capture the window by id while it stays covered on the current Space
// (`screencapture -o -l`, which reads the window's own backing store). `open -g` alone is not
// enough: Electron's macOS show() activates the app itself (a real launch stole
// focus). So the launch sets SECLAB_BACKGROUND_WINDOWS=1, and patch 0012 makes the app show
// windows inactive and never focus or activate. launchEditorInBackground still checks the
// frontmost app: if the editor took focus anyway, the run fails loudly.

/** The locally fetched/built macOS app (./seclab fetch macos). */
export const EDITOR_APP = path.join(repoRoot, '.work', 'app', 'seclab-vscode.app');

/** argv that opens an isolated-profile editor window without activating it. SECLAB_BACKGROUND_WINDOWS
 *  (patch 0012) makes the app itself show windows inactive and never focus or activate. */
export function editorLaunchArgv(userData: string, folderUri: string, env: Record<string, string> = {}, app = EDITOR_APP): string[] {
	const envArgs = Object.entries({ ...env, SECLAB_BACKGROUND_WINDOWS: '1' }).flatMap(([k, v]) => ['--env', `${k}=${v}`]);
	// The main process's stderr carries the background-windows guard's record (click-through
	// windows, dialogs not shown), which the focus probe checks.
	return ['open', '-g', '-n', ...envArgs, '--stderr', editorStderrLog(userData), '-a', app, '--args', '--user-data-dir', userData, '--folder-uri', folderUri];
}

/** Where the editor's main-process stderr goes (inside the run's profile, removed at teardown). */
export function editorStderrLog(userData: string): string {
	return path.join(userData, 'editor-stderr.log');
}

/** The same, as one copy-pasteable shell line (for "prepare" steps that print the command). */
export function editorLaunchCommand(userData: string, folderUri: string, env: Record<string, string> = {}, app?: string): string {
	const envArgs = Object.entries(env).map(([k, v]) => ` --env ${shq(`${k}=${v}`)}`).join('');
	return `node test/window.ts launch${app ? ` --app ${shq(app)}` : ''}${envArgs} ${shq(userData)} ${shq(folderUri)}`;
}

function shq(s: string): string {
	return /^[\w@%+=:,./-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`;
}

/** pid of the frontmost app, read-only (lsappinfo never changes focus). */
export function frontmostPid(): number {
	const asn = execFileSync('lsappinfo', ['front'], { encoding: 'utf8' }).trim();
	const m = /"pid"=(\d+)/.exec(execFileSync('lsappinfo', ['info', '-only', 'pid', asn], { encoding: 'utf8' }));
	return m ? Number(m[1]) : 0;
}

/** Main process of the editor using this profile (not a helper: those carry --type=). */
export function editorPid(userData: string): number {
	const ps = execFileSync('ps', ['-axww', '-o', 'pid=,args='], { encoding: 'utf8' });
	// The path must end the option value (SS-6: /x/run1 must not match /x/run10).
	const re = new RegExp(`\\s--user-data-dir(=|\\s+)${userData.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(\\s|$)`);
	for (const line of ps.split('\n')) {
		const m = /^\s*(\d+)\s+(.*)$/.exec(line);
		if (m && m[2].includes('/Contents/MacOS/') && !m[2].includes('--type=') && re.test(m[2])) {
			return Number(m[1]);
		}
	}
	return 0;
}

// Read-only window list (CGWindowListCopyWindowInfo): ids, owners, bounds. No activate, no focus.
const WINDOW_LIST_JXA = `ObjC.import('CoreGraphics');
function run(argv) {
	const all = ObjC.deepUnwrap(ObjC.castRefToObject($.CGWindowListCopyWindowInfo($.kCGWindowListOptionAll, 0)));
	return JSON.stringify(all.filter(w => w.kCGWindowOwnerPID === Number(argv[0]) && w.kCGWindowLayer === 0)
		.map(w => ({ id: w.kCGWindowNumber, w: w.kCGWindowBounds.Width, h: w.kCGWindowBounds.Height })));
}`;

/** The editor's largest normal-layer window, or 0. */
export function editorWindowId(pid: number): number {
	const wins = editorWindows(pid);
	wins.sort((a, b) => b.w * b.h - a.w * a.h);
	return wins.length && wins[0].w > 200 ? wins[0].id : 0;
}

/** The editor's normal-layer windows (read-only CGWindowList query). */
export function editorWindows(pid: number): Array<{ id: number; w: number; h: number }> {
	const out = execFileSync('osascript', ['-l', 'JavaScript', '-e', WINDOW_LIST_JXA, String(pid)], { encoding: 'utf8' }); // fixture-lint: allow persistence -- read-only CGWindowList query (window ids for screencapture -l); no activation
	return JSON.parse(out) as Array<{ id: number; w: number; h: number }>;
}

export interface BackgroundLaunch { pid: number; windowId: number; stoleFocus: boolean }

/** Launch without activating; wait for the window; report whether the editor took focus. The focus
 *  watcher starts before the editor does and runs for its whole life: the first sample in which the
 *  editor is the frontmost app is recorded and the editor's process tree is killed (fail closed). */
export async function launchEditorInBackground(userData: string, folderUri: string, env: Record<string, string> = {}, timeoutMs = 90_000, app = EDITOR_APP): Promise<BackgroundLaunch> {
	if (editorPid(userData)) {
		throw new Error(`an editor already runs with ${userData}; tear it down first`);
	}
	startFocusWatch(userData);
	fs.mkdirSync(userData, { recursive: true });
	const argv = editorLaunchArgv(userData, folderUri, env, app);
	execFileSync(argv[0], argv.slice(1), { stdio: 'ignore' });
	const deadline = Date.now() + timeoutMs;
	let pid = 0;
	let windowId = 0;
	while (Date.now() < deadline && !windowId && !focusStolen(userData)) {
		await new Promise(r => setTimeout(r, 1000));
		pid ||= editorPid(userData);
		windowId = pid ? editorWindowId(pid) : 0;
	}
	if (focusStolen(userData)) {
		return { pid, windowId, stoleFocus: true };
	}
	if (!windowId) {
		throw new Error(`no editor window for ${userData} within ${timeoutMs / 1000}s`);
	}
	// Activation happens as the window is shown; give it a moment to settle, then check.
	await new Promise(r => setTimeout(r, 1500));
	if (!focusStolen(userData) && frontmostPid() === pid) {
		killTree(pid);
		fs.appendFileSync(focusStealLog(userData), `${new Date().toISOString()} editor pid ${pid} was the frontmost app at launch; killed it and its processes\n`);
	}
	// A background editor must be a background-only app (activation policy "prohibited"), which
	// LaunchServices never makes the front process: not on a click, not when another app's
	// window closes, not on a Space change (patch 0012). Any other build can take focus, so it
	// isn't run at all (accessory builds included: a Space change made one front, 2026-11-09).
	if (!focusStolen(userData) && appType(pid) !== 'BackgroundOnly') {
		killTree(pid);
		fs.appendFileSync(focusStealLog(userData), `${new Date().toISOString()} editor pid ${pid} is a ${appType(pid) || 'unknown'} app, not a background-only one: its build lacks the background-windows guard; killed it\n`);
	}
	return { pid, windowId, stoleFocus: focusStolen(userData) };
}

/** macOS application type of a process (Foreground, UIElement, BackgroundOnly), read-only. */
export function appType(pid: number): string {
	const asn = spawnSync('lsappinfo', ['find', `pid=${pid}`], { encoding: 'utf8' }).stdout.trim();
	if (!asn) {
		return '';
	}
	return /"ApplicationType"="([^"]+)"/.exec(spawnSync('lsappinfo', ['info', '-only', 'ApplicationType', asn], { encoding: 'utf8' }).stdout)?.[1] ?? '';
}

function focusStolen(userData: string): boolean {
	return fs.existsSync(focusStealLog(userData)) && fs.readFileSync(focusStealLog(userData), 'utf8').trim() !== '';
}

/** Capture one window by id, covered or not, without touching focus or z-order. */
export function captureWindow(windowId: number, out: string): void {
	fs.mkdirSync(path.dirname(out), { recursive: true });
	execFileSync('screencapture', ['-o', '-x', '-l', String(windowId), out], { stdio: 'inherit' });
}

/** Where the focus watcher records steals; teardown fails the run if it isn't empty (UU-2). */
export function focusStealLog(userData: string): string {
	return path.join(userData, 'seclab-focus-steals.log');
}

/** Watch the frontmost app for the editor's whole life, from before it starts (review UU-2). */
export function startFocusWatch(userData: string): void {
	spawn(process.execPath, [path.join(repoRoot, 'test', 'window.ts'), 'watch', userData, '-'], { detached: true, stdio: 'ignore' }).unref();
}

const WATCH_SAMPLE_MS = 200;

/**
 * Wait for the editor to start (up to 2 minutes), then sample the frontmost app every 200 ms while
 * it runs. The first sample in which it is frontmost is recorded and the editor's whole process
 * tree is killed at once: a run that steals focus must not keep the user's desktop (fail closed).
 */
export async function watchFocus(userData: string): Promise<void> {
	const failed = (why: string) => fs.appendFileSync(focusStealLog(userData), `${new Date().toISOString()} focus watcher failed: ${why} (the run can't show it kept focus)\n`);
	try {
		let pid = 0;
		for (const until = Date.now() + 120_000; !pid && Date.now() < until;) {
			await new Promise(r => setTimeout(r, WATCH_SAMPLE_MS));
			pid = editorPid(userData);
		}
		// Follow the profile's editor, even across a relaunch, until none has run for 5 s. A
		// sampling error must fail the run, never silently stop the watch (review AAA-4).
		let errors = 0;
		let lastSeen = Date.now();
		while (pid || Date.now() - lastSeen < 5000) {
			try {
				if (pid && frontmostPid() === pid) {
					killTree(pid);
					fs.appendFileSync(focusStealLog(userData), `${new Date().toISOString()} editor pid ${pid} became the frontmost app; killed it and its processes\n`);
					return;
				}
				errors = 0;
			} catch (e) {
				if (++errors >= 5) {
					failed((e as Error).message.slice(0, 200));
					if (pid) {
						killTree(pid);
					}
					return;
				}
			}
			await new Promise(r => setTimeout(r, WATCH_SAMPLE_MS));
			pid = editorPid(userData);
			if (pid) {
				lastSeen = Date.now();
			}
		}
	} catch (e) {
		failed((e as Error).message.slice(0, 200));
	}
}

/**
 * SIGKILL a process and all its descendants, except tabd and its children (review AAA-3): with
 * the editor gone tabd sees EOF on stdin and stops its tabs itself, instead of leaving them
 * running unsupervised or a policy write half done.
 */
export function killTree(root: number): void {
	const rows = execFileSync('ps', ['-axww', '-o', 'pid=,ppid=,args='], { encoding: 'utf8' }).trim().split('\n')
		.map(l => /^\s*(\d+)\s+(\d+)\s+(.*)$/.exec(l)).filter((m): m is RegExpExecArray => !!m)
		.map(m => ({ pid: Number(m[1]), ppid: Number(m[2]), args: m[3] }));
	const isTabd = (args: string) => /(\/tabd\/src\/main\.ts|\/seclab-tab-manager\/dist\/tabd\.js)\s.*--state-dir\s/.test(args);
	const tree = new Set([root]);
	for (let grew = true; grew;) {
		grew = false;
		for (const r of rows) {
			if (tree.has(r.ppid) && !tree.has(r.pid) && !isTabd(r.args)) {
				tree.add(r.pid);
				grew = true;
			}
		}
	}
	for (const p of tree) {
		try {
			process.kill(p, 'SIGKILL');
		} catch { /* already gone */ }
	}
}
