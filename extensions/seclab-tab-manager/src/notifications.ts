/*---------------------------------------------------------------------------------------------
 *  Detection notifications (ADR detection notifications): non-modal, never focus-stealing
 *  notifications for this window's tab when something unexpected and possibly malicious happens.
 *  Driven only by tabd's event stream; wording from trusted templates (tabd-src/obs/notify.ts);
 *  tab text only as quoted, defanged data. Every action is an explicit button press.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as vscode from 'vscode';
import type { TabdClient } from '../tabd-src/client.ts';
import { buildItem, NotificationGate, notifyKind, type NotifyAction, type NotifyItem } from '../tabd-src/obs/notify.ts';
import type { ObsEvent } from '../tabd-src/obs/schema.ts';

const LABEL: Readonly<Record<NotifyAction, string>> = {
	'stop-tab': 'Stop Tab', 'open-activity': 'Open Activity', 'review-held': 'Review Held Changes', 'block-destination': 'Block Destination', 'dismiss': 'Dismiss',
};
const LOG_MAX_BYTES = 1 << 20;

export interface NotifierDeps {
	getClient(): Promise<TabdClient>;
	/** This window's tab, if it is one. */
	currentTabId(): string | undefined;
	/** Held write-back changes for this window's tab. */
	heldChanges(): number;
	/** Whether this tab's broker can deny destinations (broker capability denyRules). */
	canBlock(tabId: string): boolean;
	log: vscode.LogOutputChannel;
}

export class DetectionNotifier implements vscode.Disposable {
	private readonly gate = new NotificationGate();
	private readonly timer: NodeJS.Timeout;
	private readonly names = new Map<string, string>();
	private readonly logFile: string;
	private readonly d: NotifierDeps;

	constructor(context: vscode.ExtensionContext, d: NotifierDeps) {
		this.d = d;
		this.logFile = path.join(context.globalStorageUri.fsPath, 'notifications.jsonl');
		this.timer = setInterval(() => this.flush(), 5_000);
		context.subscriptions.push(this);
	}

	/** One event from this window's tab subscription. Replayed history never notifies. */
	onEvent(e: ObsEvent, replay: boolean): void {
		if (replay || e.tabId !== this.d.currentTabId()) {
			return;
		}
		const kind = notifyKind(e);
		if (!kind) {
			return;
		}
		const item = buildItem(e, kind, { tabName: this.names.get(e.tabId) ?? this.fallbackName(), heldChanges: this.d.heldChanges(), canBlock: this.d.canBlock(e.tabId) });
		for (const it of this.gate.offer(item)) {
			void this.show(it);
		}
	}

	/** The tab's trusted name (tabd's record: the workspace folder's name). */
	setTabName(tabId: string, hostPath: string): void {
		this.names.set(tabId, path.basename(hostPath) || tabId);
	}

	private fallbackName(): string {
		// The window's own folder name comes from the URI we opened, not from the tab.
		return path.basename(vscode.workspace.workspaceFolders?.[0]?.uri.path ?? '') || 'this tab';
	}

	private flush(): void {
		for (const it of this.gate.tick()) {
			void this.show(it);
		}
	}

	private async show(it: NotifyItem): Promise<void> {
		this.record(it);
		const buttons = it.actions.map(a => LABEL[a]);
		const show = it.severity === 'error' ? vscode.window.showErrorMessage : vscode.window.showWarningMessage;
		// Non-modal: never takes focus, never blocks the editor.
		const pick = await show(it.message, ...buttons);
		const action = (Object.keys(LABEL) as NotifyAction[]).find(a => LABEL[a] === pick);
		if (action) {
			await this.act(action, it).catch(e => void vscode.window.showErrorMessage(`seclab: ${(e as Error).message}`));
		}
	}

	private async act(a: NotifyAction, it: NotifyItem): Promise<void> {
		switch (a) {
			case 'stop-tab':
				await (await this.d.getClient()).request('tab.stop', { tabId: it.tabId });
				this.d.log.info(`tab ${it.tabId} stopped from a ${it.kind} notification`);
				return;
			case 'open-activity':
				await vscode.commands.executeCommand(it.kind === 'overflow' ? 'seclab.detections.focus' : 'seclab.tabActivity.focus');
				return;
			case 'review-held':
				await vscode.commands.executeCommand('seclab.reviewChanges');
				return;
			case 'block-destination':
				if (it.destination) {
					await (await this.d.getClient()).request('tab.egress.block', { tabId: it.tabId, host: it.destination.host, ...(it.destination.port !== undefined ? { port: it.destination.port } : {}) });
					void vscode.window.showInformationMessage(it.destination.port !== undefined
						? 'Blocked for this tab. The broker now refuses every request to that destination on that port.'
						: 'Blocked for this tab. The broker now refuses every request to that destination.');
				}
				return;
			case 'dismiss':
				return;
		}
	}

	/** What the user was shown (for audit and the e2e harness): trusted side, private, capped. */
	private record(it: NotifyItem): void {
		try {
			fs.mkdirSync(path.dirname(this.logFile), { recursive: true, mode: 0o700 });
			try {
				if (fs.statSync(this.logFile).size > LOG_MAX_BYTES) {
					fs.renameSync(this.logFile, `${this.logFile}.1`);
				}
			} catch { /* first write */ }
			fs.appendFileSync(this.logFile, JSON.stringify({ time: new Date().toISOString(), tabId: it.tabId, kind: it.kind, severity: it.severity, count: it.count, actions: it.actions, message: it.message }) + '\n', { mode: 0o600 });
		} catch (e) {
			this.d.log.warn(`notification log: ${(e as Error).message}`);
		}
	}

	dispose(): void {
		clearInterval(this.timer);
	}
}
