/*---------------------------------------------------------------------------------------------
 *  seclab Tab Manager: the editor-side client of seclab-tabd.
 *  - registers the `seclab` remote authority resolver (ManagedResolvedAuthority over
 *    supervisor channels; no listener, no port)
 *  - routes local folder windows into `vscode-remote://seclab+<tabId>/<path>`
 *  - surfaces tab status and fence failures in the UI
 *  It runs in the local, first-party-only extension host (extensionKind: ui).
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as vscode from 'vscode';
import { TabdClient, type TabdChannel } from '../tabd-src/client.ts';

const AUTHORITY_PREFIX = 'seclab';
const TAB_ID_RE = /^t-[a-z2-7]{26}$/;

interface TabView {
	metadata: { name: string };
	spec: { workspace: { hostPath: string } };
	status: { phase: string };
}

let log: vscode.LogOutputChannel;
let client: TabdClient | undefined;
let clientReady: Promise<TabdClient> | undefined;
let extensionContext: vscode.ExtensionContext;

export function activate(context: vscode.ExtensionContext): void {
	extensionContext = context;
	log = vscode.window.createOutputChannel('seclab Tab Manager', { log: true });
	context.subscriptions.push(log);

	context.subscriptions.push(vscode.workspace.registerRemoteAuthorityResolver(AUTHORITY_PREFIX, {
		resolve: (authority, ctx) => resolve(authority, ctx),
	}));

	context.subscriptions.push(
		vscode.commands.registerCommand('seclab.openFolder', openFolderWithDialog),
		vscode.commands.registerCommand('seclab.showLog', () => log.show()),
	);

	showStatus();

	// Route local folder windows into tabs (no core patch; see docs/edr/20261104-tab-manager-routing.md).
	if (vscode.env.remoteName === undefined) {
		void routeLocalWindow();
	}
}

export function deactivate(): void {
	// Closing stdin makes the supervisor stop the tabs it connected (fail closed).
	client?.dispose();
}

// ---- supervisor ---------------------------------------------------------------------------

function stateDir(): string {
	return path.join(extensionContext.globalStorageUri.fsPath, 'tabd');
}

function sensitivePaths(): string[] {
	// The editor's own data and code must never be mountable into a tab.
	const globalStorage = extensionContext.globalStorageUri.fsPath; // <userData>/User/globalStorage/<ext>
	const userData = path.resolve(globalStorage, '..', '..', '..');
	const appRoot = vscode.env.appRoot; // <App>.app/Contents/Resources/app on macOS
	const appBundle = process.platform === 'darwin' ? path.resolve(appRoot, '..', '..', '..') : path.resolve(appRoot, '..');
	return [globalStorage, userData, appBundle, extensionContext.extensionPath];
}

function getClient(): Promise<TabdClient> {
	if (clientReady) {
		return clientReady;
	}
	clientReady = (async () => {
		const cfg = vscode.workspace.getConfiguration('seclab.tabs');
		const args = [
			extensionContext.asAbsolutePath(path.join('dist', 'tabd.js')),
			'--state-dir', stateDir(),
			'--driver', cfg.get<string>('driver', 'sbx'),
		];
		const image = cfg.get<string>('image', '');
		if (image) {
			args.push('--image', image);
		}
		for (const root of cfg.get<string[]>('allowedRoots', [])) {
			args.push('--allowed-root', root);
		}
		for (const s of sensitivePaths()) {
			args.push('--sensitive', s);
		}
		fs.mkdirSync(stateDir(), { recursive: true, mode: 0o700 });
		// Allowlisted environment only (the supervisor wipes its env anyway).
		const env: NodeJS.ProcessEnv = { ELECTRON_RUN_AS_NODE: '1' };
		for (const k of ['HOME', 'USER', 'LOGNAME', 'LANG', 'TMPDIR', 'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG', 'SECLAB_SBX', 'SECLAB_DOCKER']) {
			if (process.env[k]) {
				env[k] = process.env[k];
			}
		}
		const c = new TabdClient({ command: process.execPath, args, env });
		c.on('stderr', (s: string) => log.debug(`[tabd] ${s.trimEnd()}`));
		c.on('notification', (method: string, params: Record<string, unknown>) => onNotification(method, params));
		c.on('exit', (code: unknown) => {
			log.warn(`seclab-tabd exited (${String(code)})`);
			client = undefined;
			clientReady = undefined;
		});
		const init = await c.initialize('seclab-tab-manager', '0.1.0');
		log.info(`seclab-tabd ${init.protocolVersion}; drivers ${JSON.stringify(init.drivers)}`);
		client = c;
		return c;
	})();
	clientReady.catch(() => { clientReady = undefined; });
	return clientReady;
}

function onNotification(method: string, params: Record<string, unknown>): void {
	if (method === 'tab.status') {
		log.info(`tab ${String(params.tabId)}: ${String(params.phase)}`);
		const conditions = (params.conditions as Array<{ type: string; status: string; message?: string }> | undefined) ?? [];
		const fence = conditions.find(c => c.type === 'FenceVerified' && c.status === 'False');
		if (fence) {
			// Tab-derived text is shown as plain text only.
			void vscode.window.showErrorMessage(`Tab network fence failed; the tab was stopped. ${fence.message ?? ''}`, { modal: false });
		}
	} else if (method === 'audit') {
		log.trace(`audit ${JSON.stringify(params)}`);
	} else if (method === 'log') {
		log.info(`tabd: ${String(params.message)}`);
	}
}

// ---- resolver -------------------------------------------------------------------------------

function within(child: string, parent: string): boolean {
	const c = child.normalize('NFC').toLowerCase(), p = parent.normalize('NFC').toLowerCase();
	return c === p || c.startsWith(p.endsWith('/') ? p : p + '/');
}

async function resolve(authority: string, ctx: vscode.RemoteAuthorityResolverContext): Promise<vscode.ResolverResult> {
	const tabId = authority.slice(AUTHORITY_PREFIX.length + 1);
	if (!authority.startsWith(`${AUTHORITY_PREFIX}+`) || !TAB_ID_RE.test(tabId)) {
		throw vscode.RemoteAuthorityResolverError.NotAvailable('Invalid tab authority', false);
	}
	log.info(`resolve ${authority} (attempt ${ctx.resolveAttempt})`);
	let c: TabdClient;
	let tab: TabView;
	try {
		c = await getClient();
		tab = (await c.request<{ tab: TabView }>('tab.get', { tabId })).tab;
	} catch (e) {
		throw vscode.RemoteAuthorityResolverError.NotAvailable(`Unknown tab: ${(e as Error).message}`, false);
	}

	// Tab IDs are public. Bind the authority to what this window actually opens: every
	// folder (and the workspace file) must be inside the tab's own workspace, so a crafted
	// URI or .code-workspace cannot apply one tab's content to another tab.
	const hostPath = tab.spec.workspace.hostPath;
	const opened = [...(vscode.workspace.workspaceFolders ?? []).map(f => f.uri), ...(vscode.workspace.workspaceFile ? [vscode.workspace.workspaceFile] : [])];
	for (const uri of opened) {
		if (uri.scheme !== 'vscode-remote' || uri.authority !== authority || !within(uri.path, hostPath)) {
			throw vscode.RemoteAuthorityResolverError.NotAvailable(`Refusing: ${uri.toString()} is not inside tab ${tabId} (${hostPath})`, false);
		}
	}

	const { connectionToken } = await vscode.window.withProgress(
		{ location: vscode.ProgressLocation.Notification, title: `Starting sandboxed tab for ${path.basename(hostPath)}` },
		async () => {
			try {
				return await c.request<{ connectionToken: string }>('tab.ensureRunning', { tabId });
			} catch (e) {
				throw vscode.RemoteAuthorityResolverError.TemporarilyNotAvailable(`Tab failed to start: ${(e as Error).message}`);
			}
		});

	const authorityResult = new vscode.ManagedResolvedAuthority(async () => {
		const cl = await getClient();
		const { channel } = await cl.connect(tabId); // the supervisor re-verifies the fence first
		log.debug(`channel ${channel.id} open for ${tabId}`);
		return toMessagePassing(channel);
	}, connectionToken);
	// Inside a tab, Workspace Trust is UX only: containment comes from the sandbox. Marking
	// the remote trusted lets tasks etc. run in the tab without the trust prompt, which in
	// turn lets local (unsandboxed) windows keep Restricted Mode as their default.
	return Object.assign(authorityResult, { isTrusted: true });
}

function toMessagePassing(ch: TabdChannel): vscode.ManagedMessagePassing {
	const onMessage = new vscode.EventEmitter<Uint8Array>();
	const onClose = new vscode.EventEmitter<Error | undefined>();
	const onEnd = new vscode.EventEmitter<void>();
	ch.onData(d => onMessage.fire(d));
	ch.onEnd(() => onEnd.fire());
	ch.onClose(err => {
		if (err) {
			log.warn(`channel ${ch.id} closed: ${err}`);
		}
		onClose.fire(err ? new Error(err) : undefined);
	});
	return {
		onDidReceiveMessage: onMessage.event,
		onDidClose: onClose.event,
		onDidEnd: onEnd.event,
		send: d => ch.write(d),
		end: () => ch.end(),
	};
}

// ---- routing --------------------------------------------------------------------------------

function tabUri(tabId: string, hostPath: string): vscode.Uri {
	return vscode.Uri.from({ scheme: 'vscode-remote', authority: `${AUTHORITY_PREFIX}+${tabId}`, path: hostPath });
}

async function claim(hostPath: string): Promise<TabView> {
	if (vscode.workspace.getConfiguration('seclab.tabs').get<string[]>('allowedRoots', []).length === 0) {
		await chooseAllowedRoot(hostPath);
	}
	const c = await getClient();
	return (await c.request<{ tab: TabView }>('tab.claim', { workspace: { hostPath } })).tab;
}

/**
 * Tabs may only be opened under explicitly chosen project roots (tabd fails closed
 * without one). Ask once, store it application-wide, restart the supervisor with it.
 */
async function chooseAllowedRoot(near: string): Promise<void> {
	const pick = await vscode.window.showInformationMessage(
		'Choose the folder that contains your projects. Only folders inside it can be opened as sandboxed tabs.',
		{ modal: true, detail: `Opening: ${near}` }, 'Choose Projects Folder…');
	if (!pick) {
		throw new Error('no projects folder chosen');
	}
	const root = await vscode.window.showOpenDialog({
		canSelectFolders: true, canSelectFiles: false, canSelectMany: false,
		defaultUri: vscode.Uri.file(path.dirname(near)), openLabel: 'Use as Projects Folder',
	});
	if (!root?.[0] || root[0].scheme !== 'file') {
		throw new Error('no projects folder chosen');
	}
	await vscode.workspace.getConfiguration('seclab.tabs').update('allowedRoots', [root[0].fsPath], vscode.ConfigurationTarget.Global);
	restartClient();
}

function restartClient(): void {
	client?.dispose();
	client = undefined;
	clientReady = undefined;
}

/** Native host folder dialog (a user gesture), then open the folder as a tab. */
async function openFolderWithDialog(): Promise<void> {
	const picked = await vscode.window.showOpenDialog({
		canSelectFolders: true, canSelectFiles: false, canSelectMany: false,
		defaultUri: vscode.Uri.file(process.env.HOME ?? '/'),
		openLabel: 'Open in Sandboxed Tab',
	});
	const folder = picked?.[0];
	if (!folder || folder.scheme !== 'file') {
		return;
	}
	try {
		const tab = await claim(folder.fsPath);
		await vscode.commands.executeCommand('vscode.openFolder', tabUri(tab.metadata.name, tab.spec.workspace.hostPath), { forceNewWindow: true });
	} catch (e) {
		void vscode.window.showErrorMessage(`Cannot open as a tab: ${(e as Error).message}`);
	}
}

/**
 * A local (unsandboxed) window was opened with a folder: CLI, recents, File > Open,
 * Finder, a link. Re-open it as a tab in the same window, or close the folder: a local
 * folder window is never left running (fail closed). New paths need explicit
 * confirmation because the source of a local open can't be distinguished from here.
 * Until main-process routing lands (ADR 20261104-route-folder-opens-in-main, proposed), the
 * local window exists briefly before the reroute. Residual: if the user previously trusted
 * the folder, built-ins (git, tasks) can run on the host in that moment.
 */
async function routeLocalWindow(): Promise<void> {
	const folders = vscode.workspace.workspaceFolders ?? [];
	if (folders.length === 0 && !vscode.workspace.workspaceFile) {
		return; // empty window: stays local (built-in extensions only); see the routing EDR
	}
	if (folders.length !== 1 || vscode.workspace.workspaceFile || folders[0].uri.scheme !== 'file') {
		await vscode.window.showWarningMessage('Multi-root and non-file workspaces cannot be opened as sandboxed tabs yet, so this workspace was closed.',
			{ modal: true, detail: 'Open each folder with "seclab: Open Folder in New Tab…".' });
		await vscode.commands.executeCommand('workbench.action.closeFolder');
		return;
	}
	const hostPath = folders[0].uri.fsPath;
	try {
		const c = await getClient();
		const known = (await c.request<{ tabs: TabView[] }>('tab.list')).tabs
			.some(t => t.spec.workspace.hostPath.normalize('NFC').toLowerCase() === hostPath.normalize('NFC').toLowerCase());
		if (!known) {
			const ok = await vscode.window.showWarningMessage(
				`Open "${hostPath}" in a sandboxed tab?`,
				{ modal: true, detail: 'Extensions, terminals and tasks for this folder will run in an isolated sandbox with only this folder mounted. Choosing Cancel closes the folder.' },
				'Open in Sandboxed Tab');
			if (ok !== 'Open in Sandboxed Tab') {
				await vscode.commands.executeCommand('workbench.action.closeFolder');
				return;
			}
		}
		const tab = await claim(hostPath);
		await vscode.commands.executeCommand('vscode.openFolder', tabUri(tab.metadata.name, tab.spec.workspace.hostPath), { forceReuseWindow: true });
	} catch (e) {
		await vscode.window.showErrorMessage(`Cannot open as a tab, closing the folder: ${(e as Error).message}`, { modal: true });
		await vscode.commands.executeCommand('workbench.action.closeFolder');
	}
}

function showStatus(): void {
	const item = vscode.window.createStatusBarItem('seclab.tab', vscode.StatusBarAlignment.Left, 1000);
	if (vscode.env.remoteName === AUTHORITY_PREFIX) {
		item.text = '$(shield) Tab';
		item.tooltip = 'Sandboxed tab: extensions, terminals and tasks run in this tab\'s sandbox';
	} else {
		item.text = '$(warning) Not sandboxed';
		item.tooltip = 'This window is not a sandboxed tab. Use "seclab: Open Folder in New Tab…"';
		item.command = 'seclab.openFolder';
	}
	item.command ??= 'seclab.showLog';
	item.show();
	extensionContext.subscriptions.push(item);
}
