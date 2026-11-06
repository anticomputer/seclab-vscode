// CFS package feeds for this window's tab (ADR cfs-package-feeds-in-tabs; plan increment B4).
// Off by default; the user turns them on per tab here, with a modal that says what it means:
// installs run under the user's Azure DevOps identity, and a version the feed lacks gets added
// to the shared feed. The tab only ever holds a sentinel; tabd mints the token on the host.

import * as path from 'node:path';
import * as vscode from 'vscode';
import type { TabdClient } from '../tabd-src/client.ts';
import { quote } from '../tabd-src/obs/notify.ts';

export class PackageFeeds implements vscode.Disposable {
	private readonly disposables: vscode.Disposable[] = [];
	private readonly names = new Map<string, string>();
	private readonly getClient: () => Promise<TabdClient>;
	private readonly currentTabId: () => string | undefined;
	private readonly log: vscode.LogOutputChannel;

	constructor(getClient: () => Promise<TabdClient>, currentTabId: () => string | undefined, log: vscode.LogOutputChannel) {
		this.getClient = getClient;
		this.currentTabId = currentTabId;
		this.log = log;
		this.disposables.push(vscode.commands.registerCommand('seclab.packageFeeds', () => this.toggle()));
	}

	/** From tabd's record of the host folder (never workspace content; review BBB-4). */
	setTabName(tabId: string, hostPath: string): void {
		this.names.set(tabId, `${path.basename(hostPath) || hostPath}, ${tabId}`);
	}

	private tabName(): string {
		const id = this.currentTabId() ?? '';
		return this.names.get(id) ?? id;
	}

	private async toggle(): Promise<void> {
		const tabId = this.currentTabId();
		if (!tabId) {
			void vscode.window.showInformationMessage('Package feeds are set per sandboxed tab; open a folder first.');
			return;
		}
		const c = await this.getClient();
		const { cfs } = await c.request<{ cfs: boolean }>('tab.packages.get', { tabId });
		const name = quote(this.tabName(), 60);
		if (cfs) {
			const pick = await vscode.window.showInformationMessage(`GitHub CFS package feeds are on for tab ${name}.`, { modal: true }, 'Turn Off');
			if (pick === 'Turn Off') {
				await c.request('tab.packages.set', { tabId, cfs: false });
				void vscode.window.showInformationMessage(`Package feeds are off for tab ${name}.`);
			}
			return;
		}
		const pick = await vscode.window.showWarningMessage(
			`Use GitHub CFS package feeds in tab ${name}?`,
			{
				modal: true,
				detail: 'npm and pip installs in this tab will run under your Azure DevOps identity. Installing a version the feed does not have yet adds it to the shared feed. '
					+ 'The tab never sees your token: it gets a placeholder that works only for package downloads from the CFS feeds, through this tab\'s broker, '
					+ 'and at most 5000 requests or 2 GiB over the tab\'s lifetime. The token comes from `az` on this machine.',
			},
			'Use Package Feeds',
		);
		if (pick !== 'Use Package Feeds') {
			return;
		}
		try {
			const r = await c.request<{ applied: boolean }>('tab.packages.set', { tabId, cfs: true });
			void vscode.window.showInformationMessage(r.applied
				? `Package feeds are on for tab ${name}. New terminals and tasks use them.`
				: `Package feeds will be on for tab ${name} when it starts.`);
		} catch (e) {
			this.log.warn(`package feeds: ${(e as Error).message}`);
			void vscode.window.showWarningMessage(`Could not turn on package feeds: ${quote((e as Error).message, 200)}`);
		}
	}

	/** `tab.packages.problem` from tabd: usually `az` not logged in. The message is az's, quoted. */
	onProblem(params: Record<string, unknown>): void {
		if (params.tabId !== this.currentTabId()) {
			return;
		}
		void vscode.window.showWarningMessage(`Package feeds for this tab are unavailable: ${quote(params.message, 200)}. Run \`az login\` on this machine, then turn package feeds on again.`);
	}

	dispose(): void {
		for (const d of this.disposables) {
			d.dispose();
		}
	}
}
