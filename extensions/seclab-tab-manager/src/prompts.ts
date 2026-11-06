// Egress and credential prompts (plan tabd-broker-wiring B3; EDR egress-prompts). The tab's
// broker holds a request; tabd forwards it as `tab.approval`, and this asks the user. Coordinator
// decision 3: every prompt names the tab that asks; each tab's decision is its own (there is no
// "apply to all"); the broker's per-tab rate limit stays. The default is deny: dismissing or
// ignoring a prompt lets it time out, which the broker denies, and "Allow for This Tab" is never
// the first or a pre-selected choice. Every string in an approval is tab-influenced: rendered
// with `quote`, never as markdown, a link or an icon.

import * as vscode from 'vscode';
import type { TabdClient } from '../tabd-src/client.ts';
import type { Integrity } from '../tabd-src/obs/schema.ts';
import { type ApprovalView, DECISION_LABELS, approvalPromptText } from '../tabd-src/approvals.ts';

interface Lineage { confidence?: string; chain?: string; integrity?: Integrity }

const MAX_RESOLVED = 256;

export class EgressPrompts implements vscode.Disposable {
	private readonly resolved = new Set<string>();
	private readonly disposables: vscode.Disposable[] = [];
	private readonly getClient: () => Promise<TabdClient>;
	private readonly tabName: (tabId: string) => string;
	private readonly log: vscode.LogOutputChannel;

	constructor(getClient: () => Promise<TabdClient>, tabName: (tabId: string) => string, log: vscode.LogOutputChannel) {
		this.getClient = getClient;
		this.tabName = tabName;
		this.log = log;
	}

	/** `tab.approval` from tabd. */
	onApproval(params: Record<string, unknown>): void {
		const tabId = typeof params.tabId === 'string' ? params.tabId : '';
		const a = params.approval as ApprovalView | undefined; // sanitised by tabd (approvals.ts)
		if (!tabId || !a || typeof a.approvalId !== 'string' || !Array.isArray(a.decisions) || !a.request || !a.risk) {
			return;
		}
		void this.ask(tabId, a, params.lineage as Lineage | undefined);
	}

	/** `tab.approval.resolved`: answered elsewhere, timed out, or a deny rule matched. */
	onResolved(params: Record<string, unknown>): void {
		if (typeof params.tabId === 'string' && typeof params.approvalId === 'string') {
			this.markResolved(`${params.tabId}\u0000${params.approvalId}`);
		}
	}

	private markResolved(key: string): void {
		this.resolved.add(key);
		if (this.resolved.size > MAX_RESOLVED) {
			this.resolved.delete(this.resolved.values().next().value as string);
		}
	}

	private async ask(tabId: string, a: ApprovalView, lineage: Lineage | undefined): Promise<void> {
		const buttons = DECISION_LABELS.filter(([d]) => a.decisions.includes(d));
		const text = approvalPromptText(this.tabName(tabId), a, lineage);
		const show = a.risk.flags.length || a.kind === 'credential-binding' ? vscode.window.showWarningMessage : vscode.window.showInformationMessage;
		const pick = await show(text, ...buttons.map(([, label]) => label));
		const decision = buttons.find(([, label]) => label === pick)?.[0];
		const key = `${tabId}\u0000${a.approvalId}`;
		if (!decision) {
			return; // dismissed: the broker denies it when it expires
		}
		if (this.resolved.has(key)) {
			void vscode.window.showInformationMessage('That request was already answered or timed out (denied).');
			return;
		}
		try {
			await (await this.getClient()).request('tab.approval.decide', { tabId, approvalId: a.approvalId, decision });
			this.markResolved(key);
		} catch (e) {
			this.log.warn(`approval ${a.approvalId}: ${(e as Error).message}`);
			void vscode.window.showWarningMessage('That request is no longer waiting (it was answered, timed out or blocked), so nothing was allowed.');
		}
	}

	/**
	 * The user did ordinary work in this window's tab: keyboard or mouse moves in an editor. That
	 * opens the broker's user-action gate. Consent dialogs never produce these events.
	 */
	watchUserActivity(tabId: string): void {
		let last = 0;
		this.disposables.push(vscode.window.onDidChangeTextEditorSelection(e => {
			const kind = e.kind;
			if (kind !== vscode.TextEditorSelectionChangeKind.Keyboard && kind !== vscode.TextEditorSelectionChangeKind.Mouse) {
				return;
			}
			const now = Date.now();
			if (now - last < 1000) {
				return;
			}
			last = now;
			void this.getClient().then(c => c.request('tab.userAction', { tabId })).catch(() => undefined);
		}));
	}

	dispose(): void {
		for (const d of this.disposables) {
			d.dispose();
		}
	}
}
