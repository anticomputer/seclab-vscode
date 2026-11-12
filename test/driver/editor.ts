// Headless editor driver (EDR headless-driver): launch the editor with its CDP pipe and drive it
// from inside, never through the OS. Opens, commands, DOM and UI state go through the renderer
// (CDP Runtime/Input, and upstream's smoke-test `window.driver` when asked for); screenshots come
// from the renderer itself (CDP Page.captureScreenshot), so nothing here needs an OS privacy
// permission: no Accessibility, no Screen Recording, no keystrokes to the window server.
//   macOS: the app's binary is exec'd directly (open -g can't pass fds 3/4). That is only safe
//   for a build whose bootstrap makes the app background-only before AppKit finishes launching
//   (patch 0012, "bootstrap" policy); others are refused. The focus watcher still runs.
//   Linux: under Xvfb (DISPLAY must be set), e.g. in the CI container (test/driver/xvfb/).

import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Readable, Writable } from 'node:stream';
import { CdpPipe } from './cdp.ts';
import {
	appType, checkUserDataDir, editorLaunchRecord, editorPortableDir, editorStderrLog, editorWindowId, focusStealLog,
	frontmostPid, killTree, preparePortable, startFocusWatch,
} from '../harness.ts';

/** What patch 0012's bootstrap (out/mainImpl.js) logs when it sets the policy there; a runtime
 *  string, so it survives minification. */
export const BOOTSTRAP_POLICY_MARK = '[background windows] activation policy: prohibited (bootstrap)';

export interface DriveOptions {
	app: string;                     // .app (macOS) or the unpacked VSCode-linux-<arch> dir
	userData: string;                // isolated profile (checkUserDataDir)
	folderUri?: string;              // omitted: an empty window
	env?: Record<string, string>;
	smokeDriver?: boolean;           // --enable-smoke-test-driver (window.driver); changes some behaviour
	args?: string[];
	timeoutMs?: number;
}

function appResources(app: string): string {
	return process.platform === 'darwin' ? path.join(app, 'Contents', 'Resources', 'app') : path.join(app, 'resources', 'app');
}

export function executable(app: string): string {
	if (process.platform === 'darwin') {
		const plist = path.join(app, 'Contents', 'Info.plist');
		const name = spawnSync('plutil', ['-extract', 'CFBundleExecutable', 'raw', '-o', '-', plist], { encoding: 'utf8' }).stdout.trim();
		if (!/^\w[\w .-]*$/.test(name)) {
			throw new Error(`no CFBundleExecutable in ${plist}`);
		}
		return path.join(app, 'Contents', 'MacOS', name);
	}
	const product = JSON.parse(fs.readFileSync(path.join(appResources(app), 'product.json'), 'utf8'));
	if (!/^\w[\w.-]*$/.test(product.applicationName ?? '')) {
		throw new Error('product.json has no applicationName');
	}
	return path.join(app, product.applicationName);
}

/** A build whose bootstrap sets the background-only policy (safe to exec directly on macOS). */
export function hasBootstrapPolicy(app: string): boolean {
	try {
		return fs.readFileSync(path.join(appResources(app), 'out', 'mainImpl.js'), 'utf8').includes(BOOTSTRAP_POLICY_MARK);
	} catch {
		return false;
	}
}

// The editor gets a clean environment, never the launcher's (which may hold tokens): what
// LaunchServices would give it, plus the run's own variables.
export function editorEnv(opts: Pick<DriveOptions, 'env' | 'userData'>): NodeJS.ProcessEnv {
	const keep = ['HOME', 'USER', 'LOGNAME', 'SHELL', 'PATH', 'TMPDIR', 'LANG', 'LC_ALL', 'DISPLAY', 'XAUTHORITY', 'XDG_RUNTIME_DIR'];
	const env: NodeJS.ProcessEnv = {};
	for (const k of keep) {
		if (process.env[k] !== undefined) {
			env[k] = process.env[k];
		}
	}
	return { ...env, ...opts.env, SECLAB_BACKGROUND_WINDOWS: '1', VSCODE_PORTABLE: editorPortableDir(opts.userData),
		// As the real `code` launcher sets it: every shell-environment resolution in the main
		// process is skipped, including the pty service's, which ignores --force-disable-user-env
		// (review RRR-1). No login shell runs, so none can inherit the CDP fds.
		VSCODE_CLI: '1' };
}

export class DrivenEditor {
	readonly child: ChildProcess;
	readonly cdp: CdpPipe;
	readonly session: string;
	readonly userData: string;

	private constructor(child: ChildProcess, cdp: CdpPipe, session: string, userData: string) {
		this.child = child;
		this.cdp = cdp;
		this.session = session;
		this.userData = userData;
	}

	static async launch(opts: DriveOptions): Promise<DrivenEditor> {
		const userData = path.resolve(opts.userData);
		checkUserDataDir(userData);
		const app = path.resolve(opts.app);
		if (process.platform === 'darwin' && !hasBootstrapPolicy(app)) {
			throw new Error(`${app}: its bootstrap doesn't make the app background-only, so a direct launch could take focus; use a build with patch 0012's bootstrap policy`);
		}
		if (process.platform === 'linux' && !process.env.DISPLAY) {
			throw new Error('DISPLAY is not set: run under Xvfb (test/driver/xvfb/)');
		}
		fs.mkdirSync(userData, { recursive: true });
		preparePortable(userData);
		// A quiet first run, unless the run brought its own settings: the onboarding modal takes
		// focus and keys, and the welcome page covers the view.
		const settings = path.join(userData, 'User', 'settings.json');
		if (!fs.existsSync(settings)) {
			fs.mkdirSync(path.dirname(settings), { recursive: true });
			fs.writeFileSync(settings, JSON.stringify({
				'workbench.welcomePage.experimentalOnboarding': false,
				'workbench.startupEditor': 'none',
				'workbench.tips.enabled': false,
				'chat.disableAIFeatures': true,
			}, null, '\t'));
		}
		if (process.platform === 'darwin') {
			startFocusWatch(userData);
		}
		const args = [
			'--user-data-dir', userData,
			...(opts.folderUri ? ['--folder-uri', opts.folderUri] : ['--new-window']),
			'--remote-debugging-pipe',
			// The CDP fds are inheritable. Belt and braces with VSCODE_CLI=1 (editorEnv), which also
			// covers the pty service's shell resolution that ignores this flag (RRR-1).
			'--force-disable-user-env',
			...(opts.smokeDriver ? ['--enable-smoke-test-driver'] : []),
			...(opts.args ?? []),
		];
		const stderr = fs.openSync(editorStderrLog(userData), 'a');
		const child = spawn(executable(app), args, { env: editorEnv(opts), stdio: ['ignore', stderr, stderr, 'pipe', 'pipe'], detached: true });
		fs.closeSync(stderr);
		const cdp = new CdpPipe(child.stdio[3] as Writable, child.stdio[4] as Readable);
		fs.writeFileSync(editorLaunchRecord(userData), JSON.stringify({ app, pid: child.pid, driven: true }));
		const deadline = Date.now() + (opts.timeoutMs ?? 120_000);
		let target: { targetId: string } | undefined;
		while (!target && Date.now() < deadline) {
			if (child.exitCode !== null) {
				throw new Error(`the editor exited (${child.exitCode}); see ${editorStderrLog(userData)}`);
			}
			const { targetInfos } = await cdp.send<{ targetInfos: Array<{ targetId: string; type: string; url: string }> }>('Target.getTargets');
			target = targetInfos.find(t => t.type === 'page' && /\/workbench\/workbench\.html/.test(t.url));
			if (!target) {
				await new Promise(r => setTimeout(r, 500));
			}
		}
		if (!target) {
			killTree(child.pid!);
			throw new Error('no workbench window appeared');
		}
		const { sessionId } = await cdp.send<{ sessionId: string }>('Target.attachToTarget', { targetId: target.targetId, flatten: true });
		// The page behaves as focused (as Playwright does), so key events reach the workbench.
		// Renderer-only: the OS window is never focused or raised.
		await cdp.send('Emulation.setFocusEmulationEnabled', { enabled: true }, sessionId);
		const ed = new DrivenEditor(child, cdp, sessionId, userData);
		if (process.platform === 'darwin') {
			await ed.checkBackground();
		}
		return ed;
	}

	// Same gate as a LaunchServices background launch (harness launchEditorInBackground).
	private async checkBackground(): Promise<void> {
		const pid = this.child.pid!;
		for (const until = Date.now() + 30_000; !editorWindowId(pid) && Date.now() < until;) {
			await new Promise(r => setTimeout(r, 500));
		}
		await new Promise(r => setTimeout(r, 1500));
		const steal = fs.existsSync(focusStealLog(this.userData)) && fs.readFileSync(focusStealLog(this.userData), 'utf8').trim();
		const why = steal ? 'took focus' : frontmostPid() === pid ? 'is the frontmost app' : appType(pid) !== 'BackgroundOnly' ? `is a ${appType(pid) || 'unknown'} app, not background-only` : '';
		if (why) {
			killTree(pid);
			if (!steal) {
				fs.appendFileSync(focusStealLog(this.userData), `${new Date().toISOString()} driven editor pid ${pid} ${why}; killed it\n`);
			}
			throw new Error(`driven launch: the editor ${why}`);
		}
	}

	/** Evaluate in the workbench renderer; returns the value (JSON) or throws the page's error. */
	async evaluate<T = unknown>(expression: string, timeoutMs = 60_000): Promise<T> {
		const r = await this.cdp.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }, this.session, timeoutMs);
		if (r.exceptionDetails) {
			throw new Error(`evaluate: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
		}
		return r.result?.value as T;
	}

	/** Upstream's smoke-test window driver (needs smokeDriver: true); waits for it to register. */
	async driver<T = unknown>(method: string, ...args: unknown[]): Promise<T> {
		if (!/^[a-zA-Z]+$/.test(method)) {
			throw new Error(`bad driver method ${method}`);
		}
		await this.waitFor('window.driver', 60_000);
		return this.evaluate<T>(`window.driver.${method}(...${JSON.stringify(args)})`);
	}

	async waitFor(expression: string, timeoutMs = 30_000): Promise<void> {
		for (const until = Date.now() + timeoutMs; ;) {
			if (await this.evaluate<boolean>(`!!(${expression})`).catch(() => false)) {
				return;
			}
			if (Date.now() > until) {
				throw new Error(`waitFor timed out: ${expression}`);
			}
			await new Promise(r => setTimeout(r, 250));
		}
	}

	/** A key event delivered to the renderer (CDP Input), not to the window server. */
	async key(key: 'Enter' | 'Escape' | 'F1'): Promise<void> {
		const codes = { Enter: 13, Escape: 27, F1: 112 } as const;
		for (const type of ['rawKeyDown', 'keyUp']) {
			await this.cdp.send('Input.dispatchKeyEvent', { type, key, code: key, windowsVirtualKeyCode: codes[key], nativeVirtualKeyCode: codes[key] }, this.session);
		}
	}

	async type(text: string): Promise<void> {
		await this.cdp.send('Input.insertText', { text }, this.session);
	}

	/** Run a command by its palette label (F1, type, Enter), as a user would. */
	async command(label: string): Promise<void> {
		await this.key('F1');
		await this.waitFor(`document.querySelector('.quick-input-widget') && getComputedStyle(document.querySelector('.quick-input-widget')).display !== 'none'`);
		await this.type(label);
		await new Promise(r => setTimeout(r, 750));
		await this.key('Enter');
	}

	/** PNG of the window's own renderer output (no OS capture). */
	async screenshot(out: string): Promise<number> {
		const { data } = await this.cdp.send<{ data: string }>('Page.captureScreenshot', { format: 'png' }, this.session);
		const png = Buffer.from(data, 'base64');
		fs.mkdirSync(path.dirname(path.resolve(out)), { recursive: true });
		fs.writeFileSync(out, png);
		return png.length;
	}

	/**
	 * Processes other than the editor's main process that hold its CDP fds (3 and 4). Must be
	 * empty: a holder could read the driver's commands and forge answers (reviews QQQ-1, RRR-1).
	 * Linux: /proc fd links; macOS: lsof device addresses of the editor's descendants.
	 */
	cdpFdHolders(): string[] {
		const pid = this.child.pid!;
		if (process.platform === 'linux') {
			const link = (p: string, fd: number) => { try { return fs.readlinkSync(`/proc/${p}/fd/${fd}`); } catch { return ''; } };
			const mine = new Set([link(String(pid), 3), link(String(pid), 4)].filter(Boolean));
			const holders: string[] = [];
			for (const p of fs.readdirSync('/proc').filter(d => /^\d+$/.test(d) && d !== String(pid))) {
				let fds: string[] = [];
				try { fds = fs.readdirSync(`/proc/${p}/fd`); } catch { continue; }
				if (fds.some(fd => mine.has(link(p, Number(fd))))) {
					holders.push(`${p}: ${fs.readFileSync(`/proc/${p}/cmdline`, 'utf8').replace(/\0/g, ' ').slice(0, 120)}`);
				}
			}
			return holders;
		}
		const ps = spawnSync('ps', ['-axo', 'pid=,ppid='], { encoding: 'utf8' }).stdout.trim().split('\n').map(l => l.trim().split(/\s+/).map(Number));
		const tree = new Set([pid]);
		for (let grew = true; grew;) {
			grew = false;
			for (const [p, pp] of ps) {
				if (!tree.has(p) && tree.has(pp)) { tree.add(p); grew = true; }
			}
		}
		const out = spawnSync('lsof', ['-nP', '-a', '-p', [...tree].join(','), '-d', '3,4', '-F', 'pd'], { encoding: 'utf8' }).stdout;
		const byPid = new Map<number, Set<string>>();
		let cur = 0;
		for (const l of out.split('\n')) {
			if (l.startsWith('p')) { cur = Number(l.slice(1)); byPid.set(cur, new Set()); }
			if (l.startsWith('d')) { byPid.get(cur)?.add(l.slice(1)); }
		}
		const mine = byPid.get(pid) ?? new Set<string>();
		return [...byPid].filter(([p, d]) => p !== pid && [...d].some(x => mine.has(x))).map(([p]) => String(p));
	}

	/** Quit through CDP (Browser.close), then make sure the process tree is gone. */
	async close(): Promise<void> {
		await this.cdp.send('Browser.close', {}, undefined, 10_000).catch(() => undefined);
		for (const until = Date.now() + 15_000; this.child.exitCode === null && this.child.signalCode === null && Date.now() < until;) {
			await new Promise(r => setTimeout(r, 250));
		}
		if (this.child.exitCode === null && this.child.signalCode === null) {
			killTree(this.child.pid!);
		}
	}
}
