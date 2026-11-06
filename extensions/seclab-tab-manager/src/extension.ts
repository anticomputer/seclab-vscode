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
import type { ObsEvent } from '../tabd-src/obs/schema.ts';
import { TabActivity } from './activity.ts';
import { DetectionsSummary } from './detections.ts';
import { DetectionNotifier } from './notifications.ts';
import { EgressPrompts } from './prompts.ts';
import { PackageFeeds } from './packages.ts';
import { WriteBackReview } from './writeback.ts';

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
let activity: TabActivity | undefined;
let writeBack: WriteBackReview | undefined;
let notifier: DetectionNotifier | undefined;
let summary: DetectionsSummary | undefined;
let prompts: EgressPrompts | undefined;
let packages: PackageFeeds | undefined;
/** Tabs whose broker reported `capabilities.denyRules` (tab.get → broker). */
const blockable = new Set<string>();

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
		vscode.commands.registerCommand('seclab.removeTab', removeTab),
		vscode.commands.registerCommand('seclab.resetTab', resetThisTab),
	);

	showStatus();
	// Tab activity (observability) for this window's tab; filled in by resolve().
	activity = new TabActivity(context);
	// Write-back review (ADR write-back-gate): held changes, decisions, "not gated" notice.
	writeBack = new WriteBackReview(context, getClient, currentTabId(), log);
	// Broker prompts (EDR egress-prompts): this window's tab asks; user activity opens its gate.
	prompts = new EgressPrompts(getClient, log);
	context.subscriptions.push(prompts);
	const here = currentTabId();
	if (here) {
		prompts.watchUserActivity(here);
	}
	// CFS package feeds, per tab, off by default (ADR cfs-package-feeds-in-tabs).
	packages = new PackageFeeds(getClient, currentTabId, log);
	context.subscriptions.push(packages);
	// Detection notifications for this window's tab, and the cross-tab summary (ADR detection notifications).
	notifier = new DetectionNotifier(context, {
		getClient, currentTabId, log,
		heldChanges: () => writeBack?.heldCount() ?? 0,
		canBlock: tabId => blockable.has(tabId),
	});
	summary = new DetectionsSummary(context, getClient, async (tabId, hostPath) => {
		if (tabId === currentTabId()) {
			await vscode.commands.executeCommand('seclab.tabActivity.focus');
		} else {
			await vscode.commands.executeCommand('vscode.openFolder', tabUri(tabId, hostPath), { forceNewWindow: true });
		}
	});

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
		const gcDays = cfg.get<number>('gcDays', 30);
		args.push('--gc-days', String(Number.isInteger(gcDays) && gcDays >= 0 && gcDays <= 3650 ? gcDays : 30));
		fs.mkdirSync(stateDir(), { recursive: true, mode: 0o700 });
		// Allowlisted environment only (the supervisor wipes its env anyway).
		const env: NodeJS.ProcessEnv = { ELECTRON_RUN_AS_NODE: '1' };
		for (const k of ['HOME', 'USER', 'LOGNAME', 'LANG', 'TMPDIR', 'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG']) {
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
			activity?.detach();
		});
		const init = await c.initialize('seclab-tab-manager', '0.1.0', { approvals: true });
		log.info(`seclab-tabd ${init.protocolVersion}; drivers ${JSON.stringify(init.drivers)}`);
		client = c;
		return c;
	})();
	clientReady.catch(() => { clientReady = undefined; });
	return clientReady;
}

function onNotification(method: string, params: Record<string, unknown>): void {
	if (method === 'tab.event' || method === 'tab.observation') {
		activity?.onNotification(method, params);
		if (method === 'tab.event' && activity?.owns(params.subscription)) {
			const e = params.event as ObsEvent;
			notifier?.onEvent(e, params.replay === true);
			if (e.class === 'detection') {
				summary?.poke();
			}
		}
		return;
	}
	if (method === 'tab.writeback.pending') {
		writeBack?.onPending(params);
		return;
	}
	if (method === 'tab.approval') {
		prompts?.onApproval(params);
		return;
	}
	if (method === 'tab.approval.resolved') {
		prompts?.onResolved(params);
		return;
	}
	if (method === 'tab.packages.problem') {
		packages?.onProblem(params);
		return;
	}
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
			let accept: string[] | undefined;
			for (let attempt = 0; attempt < 5; attempt++) {
				try {
					return await c.request<{ connectionToken: string }>('tab.ensureRunning', { tabId, acceptFindings: accept });
				} catch (e) {
					const err = e as Error & { code?: number; data?: unknown };
					if (err.code === -32020 || err.code === -32021) {
						// Secrets found in the folder (or the scan could not complete): decide in trusted UI.
						accept = await resolveSecretFindings(c, tabId, hostPath, err.data as ScanStatus | undefined);
						continue;
					}
					throw vscode.RemoteAuthorityResolverError.TemporarilyNotAvailable(`Tab failed to start: ${err.message}`);
				}
			}
			throw vscode.RemoteAuthorityResolverError.NotAvailable('Tab not opened: secrets unresolved', false);
		});
	void activity?.attach(c, tabId).catch(e => log.warn(`tab activity unavailable: ${(e as Error).message}`));
	notifier?.setTabName(tabId, hostPath);
	prompts?.setTabName(tabId, hostPath);
	packages?.setTabName(tabId, hostPath);
	void c.request<{ tab: TabView & { status: { brokerCapabilities?: Record<string, unknown> } } }>('tab.get', { tabId }).then(r => {
		if (r.tab.status.brokerCapabilities?.denyRules === true) {
			blockable.add(tabId);
		}
	}).catch(() => undefined);
	void showWorkspaceSummary(c, tabId, hostPath);

	// B3c: every connection after the first (the window opens several, and reopens them on a
	// reconnect) first makes sure the tab and its REH run. tab.ensureRunning leaves a running tab
	// with a live REH alone, and the connection token is the tab's own, stable across restarts,
	// so a server that died (or a tab stopped with its supervisor) comes back without a window
	// reload. Secret-scan findings on a restart still need the resolver's trusted UI: the
	// reconnect then fails and the window offers its reload.
	let connects = 0;
	const authorityResult = new vscode.ManagedResolvedAuthority(async () => {
		const cl = await getClient();
		if (connects++ > 0) {
			await cl.request('tab.ensureRunning', { tabId });
			log.info(`tab ${tabId}: reconnect (attempt ${connects - 1}), tab and server running`);
		}
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

// ---- pre-open workspace summary (informational) ---------------------------------------------

/**
 * What this folder would run automatically or feed to AI agents (tabd `tab.inspect`). Shown
 * once per open, informational only: in a tab these run inside the sandbox. All text is the
 * folder's own content, shown as plain text in a read-only document.
 */
async function showWorkspaceSummary(c: TabdClient, tabId: string, hostPath: string): Promise<void> {
	try {
		const r = await c.request<{ items: Array<{ kind: string; path: string; detail: string }>; truncated: boolean }>('tab.inspect', { tabId });
		if (!r.items.length) {
			return;
		}
		const kinds = [...new Set(r.items.map(i => i.kind))];
		const pick = await vscode.window.showInformationMessage(
			`"${safeText(path.basename(hostPath), 60)}" configures ${r.items.length} thing(s) that run automatically or steer AI agents (${safeText(kinds.slice(0, 3).join(', '), 120)}${kinds.length > 3 ? ', …' : ''}). They run inside this tab's sandbox.`,
			'Show Details');
		if (pick === 'Show Details') {
			const text = r.items.map(i => `${safeText(i.kind, 80)}\n  ${safeText(i.path, 200)}\n  ${safeText(i.detail, 600)}\n`).join('\n')
				+ (r.truncated ? '\n… more not listed\n' : '');
			const doc = await vscode.workspace.openTextDocument({ content: `What this folder runs automatically or feeds to AI agents (informational)\n\n${text}`, language: 'plaintext' });
			await vscode.window.showTextDocument(doc, { preview: true });
		}
	} catch (e) {
		log.warn(`workspace summary unavailable: ${safeText((e as Error).message)}`);
		void vscode.window.showWarningMessage('Could not summarise what this folder runs automatically (it runs inside the tab regardless).');
	}
}

// ---- pre-mount secret findings (ADR 20261104-pre-mount-secret-scan) -------------------------

interface SecretFinding { id: string; source: string; file: string; line: number; rule: string; movable: boolean }
interface ScanStatus { findings?: SecretFinding[]; incomplete?: boolean; overflow?: boolean; error?: string | null }

/** Text from the user's folder (file names) is data: escape anything that could fake layout. */
function safeText(s: unknown, max = 200): string {
	// Controls/format escaped; markdown link and codicon syntax neutralised, so folder-derived
	// text can't render as a link (incl. command: links) or an icon in a notification (RR-2).
	const esc = String(s).replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}]/gu, c => `\\u{${c.codePointAt(0)!.toString(16)}}`)
		.replace(/\[/g, '［').replace(/\]/g, '］').replace(/\$\(/g, '$\u200a(');
	return esc.length > max ? `${esc.slice(0, max - 1)}…` : esc;
}

const SOURCE_LABEL: Record<string, string> = { history: '  (git history)', objects: '  (git object store)', 'git-dir': '  (git directory)' };

// Suggested credential bindings for "move to broker", by gitleaks rule prefix.
const BIND_SUGGESTIONS: Array<[RegExp, string]> = [
	[/^github/, 'api.github.com'], [/^gitlab/, 'gitlab.com'], [/^aws/, '*.amazonaws.com'], [/^npm/, 'registry.npmjs.org'],
	[/^slack/, 'slack.com'], [/^openai/, 'api.openai.com'], [/^anthropic/, 'api.anthropic.com'], [/^stripe/, 'api.stripe.com'],
];

/**
 * Secrets were found in the folder (or the scan failed). Returns the ids to accept
 * (recorded as an exception) after the user decides, or throws to cancel. "Move to broker"
 * rewrites the working copy (sentinels) and returns undefined so the caller rescans.
 */
async function resolveSecretFindings(c: TabdClient, tabId: string, hostPath: string, status: ScanStatus | undefined): Promise<string[] | undefined> {
	const findings = Array.isArray(status?.findings) ? status.findings : [];
	const incomplete = status?.incomplete !== false;
	const name = safeText(path.basename(hostPath), 80);
	const incompleteNote = !incomplete ? '' : status?.overflow
		? '\n\nWARNING: the scan produced more secret-like matches than can be reviewed. This can be a deliberate attempt (for example by an extension that ran in this tab before) to hide real secrets among decoys. Opening exposes every file in the folder to the tab.'
		: `\n\nThe scan did not complete (${safeText(status?.error ?? 'unknown error', 300)}). Other secrets may be present.`;
	if (findings.length === 0) {
		const title = status?.overflow ? `Too many secret-like values in "${name}" to review.` : `The secret scan of "${name}" could not complete.`;
		const pick = await vscode.window.showWarningMessage(title,
			{ modal: true, detail: `${incompleteNote.trim()}\n\nOpening anyway is recorded as an exception in the audit log.` }, 'Open Anyway');
		if (pick !== 'Open Anyway') {
			throw vscode.RemoteAuthorityResolverError.NotAvailable('Tab not opened: secret scan incomplete', false);
		}
		return ['scan-incomplete'];
	}
	// File names come from the user's folder: escaped plain text, values are never shown.
	const shown = findings.slice(0, 50);
	const list = shown.map(f => `• ${safeText(f.file)}${f.source === 'objects' ? '' : `:${Number(f.line)}`}  ${safeText(f.rule, 64)}${SOURCE_LABEL[f.source] ?? ''}${/^(unscanned-|unrecognised-)/.test(f.rule) ? '  (could not be scanned)' : '  [redacted]'}`).join('\n')
		+ (findings.length > shown.length ? `\n… and ${findings.length - shown.length} more` : '');
	const movable = findings.filter(f => f.movable);
	const choices = movable.length ? ['Move to Broker…', 'Open Anyway'] : ['Open Anyway'];
	const pick = await vscode.window.showWarningMessage(`${findings.length} secret(s) found in "${name}". A sandboxed tab must never see a real secret.`,
		{ modal: true, detail: `${list}${incompleteNote}\n\nMove to Broker replaces each value in your working copy with a sentinel (no commit is made; restorable). Git history and object-store copies can't be moved: purge them (for example git filter-repo, then expire the reflog and gc) or open anyway. Open Anyway records an exception.` },
		...choices);
	if (pick === 'Open Anyway') {
		return [...findings.map(f => f.id), ...(incomplete ? ['scan-incomplete'] : [])];
	}
	if (pick !== 'Move to Broker…') {
		throw vscode.RemoteAuthorityResolverError.NotAvailable('Tab not opened: secrets in folder', false);
	}
	const moves: Array<{ id: string; bind: { host: string; path: string } }> = [];
	for (const f of movable) {
		const suggestion = BIND_SUGGESTIONS.find(([re]) => re.test(f.rule))?.[1] ?? '';
		const host = await vscode.window.showInputBox({
			title: `Bind ${safeText(f.file, 120)}:${Number(f.line)} (${safeText(f.rule, 64)}) to a host`,
			prompt: 'The broker will only ever send this credential to this host (wildcard *.example.com allowed).',
			value: suggestion, ignoreFocusOut: true,
			validateInput: v => /^(?:\*\.)?[a-z0-9.-]{1,253}$/i.test(v) ? undefined : 'Enter a hostname',
		});
		if (!host) {
			throw vscode.RemoteAuthorityResolverError.NotAvailable('Tab not opened: move cancelled', false);
		}
		moves.push({ id: f.id, bind: { host, path: '/**' } });
	}
	const confirm = await vscode.window.showWarningMessage(`Rewrite ${moves.length} file location(s) in "${hostPath}"?`,
		{ modal: true, detail: 'Each secret value is replaced by a sentinel in your working copy. Nothing is committed. You can restore the originals later.' }, 'Rewrite Files');
	if (confirm !== 'Rewrite Files') {
		throw vscode.RemoteAuthorityResolverError.NotAvailable('Tab not opened: move cancelled', false);
	}
	await c.request('tab.stop', { tabId }).catch(() => undefined);
	await c.request('tab.moveSecrets', { tabId, moves });
	// Remaining (history) findings, if any, are decided on the next attempt.
	return undefined;
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
		defaultUri: vscode.Uri.file(process.env.HOME ?? '/'), openLabel: 'Use as Projects Folder',
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
 * A local (unsandboxed) window was opened with a folder or workspace: CLI, recents,
 * File > Open, Finder, a link. Close it FIRST (before any dialog, so the local folder
 * window lives as briefly as possible), carrying the request to the now-empty window,
 * which then confirms, claims and re-opens it as a tab. With patch 0003 no workspace-kind
 * extension (built-in git included) runs in a local window at all; the residual is core
 * auto-tasks in a previously trusted folder during the moment before closeFolder.
 * The full fix is main-process routing (ADR 20261104-route-folder-opens-in-main, proposed).
 */
const PENDING_KEY = 'seclab.pendingRoute';
const PENDING_TTL_MS = 60_000;
interface PendingRoute { readonly hostPath?: string; readonly unsupported?: boolean; readonly at: number }

async function routeLocalWindow(): Promise<void> {
	const folders = vscode.workspace.workspaceFolders ?? [];
	if (folders.length > 0 || vscode.workspace.workspaceFile) {
		const single = folders.length === 1 && !vscode.workspace.workspaceFile && folders[0].uri.scheme === 'file';
		const pending: PendingRoute = single ? { hostPath: folders[0].uri.fsPath, at: Date.now() } : { unsupported: true, at: Date.now() };
		await extensionContext.globalState.update(PENDING_KEY, pending);
		await vscode.commands.executeCommand('workbench.action.closeFolder');
		return;
	}
	// Empty local window: continue a routing request handed over by closeFolder, if any.
	const pending = extensionContext.globalState.get<PendingRoute>(PENDING_KEY);
	if (!pending) {
		return;
	}
	await extensionContext.globalState.update(PENDING_KEY, undefined);
	if (Date.now() - pending.at > PENDING_TTL_MS) {
		return;
	}
	if (pending.unsupported || !pending.hostPath) {
		void vscode.window.showWarningMessage('Multi-root and non-file workspaces cannot be opened as sandboxed tabs yet, so it was closed. Open each folder with "seclab: Open Folder in New Tab…".');
		return;
	}
	const hostPath = pending.hostPath;
	try {
		const c = await getClient();
		const known = (await c.request<{ tabs: TabView[] }>('tab.list')).tabs
			.some(t => t.spec.workspace.hostPath.normalize('NFC').toLowerCase() === hostPath.normalize('NFC').toLowerCase());
		if (!known) {
			const ok = await vscode.window.showWarningMessage(
				`Open "${hostPath}" in a sandboxed tab?`,
				{ modal: true, detail: 'Extensions, terminals and tasks for this folder will run in an isolated sandbox with only this folder mounted.' },
				'Open in Sandboxed Tab');
			if (ok !== 'Open in Sandboxed Tab') {
				return;
			}
		}
		const tab = await claim(hostPath);
		await vscode.commands.executeCommand('vscode.openFolder', tabUri(tab.metadata.name, tab.spec.workspace.hostPath), { forceReuseWindow: true });
	} catch (e) {
		void vscode.window.showErrorMessage(`Cannot open as a tab: ${(e as Error).message}`);
	}
}

/** This window's tab id, if it is a tab. */
function currentTabId(): string | undefined {
	const id = vscode.env.remoteAuthority?.startsWith(`${AUTHORITY_PREFIX}+`) ? vscode.env.remoteAuthority.slice(AUTHORITY_PREFIX.length + 1) : undefined;
	return id && TAB_ID_RE.test(id) ? id : undefined;
}

/**
 * Remove a tab: its sandbox, installed extensions and tab home. The folder itself is never
 * touched. Not this window's tab (use Reset), and tabd refuses tabs holding moved secrets.
 */
async function removeTab(): Promise<void> {
	try {
		const c = await getClient();
		const here = currentTabId();
		const tabs = (await c.request<{ tabs: TabView[] }>('tab.list')).tabs.filter(t => t.metadata.name !== here);
		if (!tabs.length) {
			void vscode.window.showInformationMessage('No other tabs to remove.');
			return;
		}
		const pick = await vscode.window.showQuickPick(tabs.map(t => ({
			label: safeText(t.spec.workspace.hostPath), description: safeText(t.status.phase, 20), tabId: t.metadata.name,
		})), { title: 'Remove a sandboxed tab', placeHolder: 'The folder is kept; the tab\'s sandbox, extensions and home are deleted' });
		if (!pick) {
			return;
		}
		const ok = await vscode.window.showWarningMessage(`Remove the tab for "${pick.label}"?`, {
			modal: true,
			detail: 'Its sandbox, the extensions installed in it and its home directory are deleted. Your folder is not touched. A window open on this tab will disconnect.',
		}, 'Remove Tab');
		if (ok !== 'Remove Tab') {
			return;
		}
		await c.request('tab.remove', { tabId: pick.tabId });
		void vscode.window.showInformationMessage(`Removed the tab for "${pick.label}".`);
	} catch (e) {
		void vscode.window.showErrorMessage(`Cannot remove the tab: ${safeText((e as Error).message)}`);
	}
}

/**
 * Rebuild this window's tab from the template: discards everything the tab accumulated in
 * its sandbox (installed extensions, its home, anything a payload dropped there). The folder,
 * the tab id and any moved secrets are kept. The window reloads into the fresh tab.
 */
async function resetThisTab(): Promise<void> {
	const tabId = currentTabId();
	if (!tabId) {
		void vscode.window.showInformationMessage('This window is not a sandboxed tab.');
		return;
	}
	const ok = await vscode.window.showWarningMessage('Reset this tab to a clean sandbox?', {
		modal: true,
		detail: 'The tab\'s sandbox is rebuilt from the template: extensions installed in it, its home directory and anything that ran there are discarded. Your folder is not touched. The window reloads.',
	}, 'Reset Tab');
	if (ok !== 'Reset Tab') {
		return;
	}
	try {
		const c = await getClient();
		await c.request('tab.reset', { tabId });
		await vscode.commands.executeCommand('workbench.action.reloadWindow');
	} catch (e) {
		void vscode.window.showErrorMessage(`Cannot reset the tab: ${safeText((e as Error).message)}`);
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
