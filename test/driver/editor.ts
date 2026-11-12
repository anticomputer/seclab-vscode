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
	return { ...env, ...opts.env, SECLAB_BACKGROUND_WINDOWS: '1', VSCODE_PORTABLE: editorPortableDir(opts.userData) };
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
		if (process.platform === 'darwin') {
			startFocusWatch(userData);
		}
		const args = [
			'--user-data-dir', userData,
			...(opts.folderUri ? ['--folder-uri', opts.folderUri] : ['--new-window']),
			'--remote-debugging-pipe',
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

	/** Upstream's smoke-test window driver (needs smokeDriver: true). */
	driver<T = unknown>(method: string, ...args: unknown[]): Promise<T> {
		if (!/^[a-zA-Z]+$/.test(method)) {
			throw new Error(`bad driver method ${method}`);
		}
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
