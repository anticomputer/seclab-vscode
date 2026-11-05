/*---------------------------------------------------------------------------------------------
 *  Write-back review (ADR write-back-gate, increment 3). A tab writes into its own overlay;
 *  tabd copies ordinary edits back and holds anything that runs code on this machine. This
 *  module shows what is held and takes the user's decision. Every path, content and link
 *  target here is chosen by the tab: shown as plain text only (escaped, codicons neutralised),
 *  diffs in read-only virtual documents, never a webview, HTML or markdown. Each decision is
 *  bound to the signature the user saw; tabd refuses if the tab changed the entry since.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import type { TabdClient } from '../tabd-src/client.ts';

const SCHEME = 'seclab-wb';

interface Pending { path: string; kind: string; reasons: string[]; sig: string }
interface Side { exists?: boolean; kind?: string; size?: number; b64?: string; truncated?: boolean; target?: string }
interface Content { path: string; kind: string; reasons: string[]; sig: string; host: Side; tab: Side }

/** Tab-controlled text as plain text: controls escaped, codicon syntax ($(…)) never rendered. */
export function plainText(s: unknown, max = 300): string {
	const esc = String(s).replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}]/gu, c => `\\u{${c.codePointAt(0)!.toString(16)}}`).replace(/\$\(/g, '$\u200a(');
	return esc.length > max ? `${esc.slice(0, max - 1)}…` : esc;
}

/** File content for display: text if it is valid UTF-8 without NULs, else a summary line. */
function render(side: Side, label: string): string {
	if (side.kind === 'absent' || side.exists === false) {
		return `(${label}: does not exist)\n`;
	}
	if (side.kind === 'symlink') {
		return `(${label}: symbolic link → ${plainText(side.target ?? '', 1000)})\n`;
	}
	if (side.kind === 'deleted') {
		return `(${label}: deleted)\n`;
	}
	if (side.kind && side.kind !== 'file') {
		return `(${label}: ${plainText(side.kind)})\n`;
	}
	const buf = Buffer.from(side.b64 ?? '', 'base64');
	let text: string | undefined;
	try {
		text = new TextDecoder('utf-8', { fatal: true }).decode(buf);
	} catch {
		text = undefined;
	}
	if (text === undefined || text.includes('\0')) {
		return `(${label}: binary, ${side.size ?? buf.length} bytes)\n`;
	}
	return side.truncated ? `${text}\n… (${label}: truncated for display; ${side.size} bytes in total)\n` : text;
}

export class WriteBackReview implements vscode.TextDocumentContentProvider {
	private readonly cache = new Map<string, string>();
	private readonly item: vscode.StatusBarItem;
	private readonly getClient: () => Promise<TabdClient>;
	private readonly tabId: string | undefined;
	private readonly log: vscode.LogOutputChannel;
	private count = 0;
	private gated: boolean | undefined;
	private prompted = false;

	constructor(ctx: vscode.ExtensionContext, getClient: () => Promise<TabdClient>, tabId: string | undefined, log: vscode.LogOutputChannel) {
		this.getClient = getClient;
		this.tabId = tabId;
		this.log = log;
		this.item = vscode.window.createStatusBarItem('seclab.writeback', vscode.StatusBarAlignment.Left, 999);
		this.item.command = 'seclab.reviewChanges';
		ctx.subscriptions.push(this.item,
			vscode.workspace.registerTextDocumentContentProvider(SCHEME, this),
			vscode.commands.registerCommand('seclab.reviewChanges', () => this.review()),
			vscode.commands.registerCommand('seclab.confirmDeletes', () => this.confirmDeletes()));
		if (tabId) {
			void this.refresh();
		}
	}

	provideTextDocumentContent(uri: vscode.Uri): string {
		return this.cache.get(uri.toString()) ?? '(no longer available)\n';
	}

	/** tab.writeback.pending for this window's tab. */
	onPending(params: Record<string, unknown>): void {
		if (params.tabId !== this.tabId || typeof params.count !== 'number') {
			return;
		}
		this.count = params.count;
		this.show();
		if (this.count > 0 && !this.prompted) {
			this.prompted = true;
			void vscode.window.showWarningMessage(
				`This tab changed ${this.count} file(s) that can run code on your machine (tasks, git hooks, build or agent config). They are held until you review them.`,
				'Review Changes').then(pick => {
				this.prompted = false;
				if (pick === 'Review Changes') {
					void this.review();
				}
			});
		}
	}

	private async refresh(): Promise<void> {
		try {
			const c = await this.getClient();
			const s = await c.request<{ gated: boolean; pending: Pending[] }>('tab.writeback.status', { tabId: this.tabId });
			this.gated = s.gated;
			this.count = s.pending.length;
			this.show();
		} catch (e) {
			this.log.warn(`write-back status: ${plainText((e as Error).message)}`);
		}
	}

	private show(): void {
		if (this.gated === false) {
			// ADR write-back-gate: say it plainly for tabs whose runtime can't gate writes.
			this.item.text = '$(warning) Write-back not gated';
			this.item.tooltip = 'This tab writes your folder directly (OCI on Docker Desktop): files it changes, including ones that run code, are not held for review.';
			this.item.command = undefined;
			this.item.show();
		} else if (this.count > 0) {
			this.item.text = `$(shield) ${this.count} held`;
			this.item.tooltip = 'Changes from this tab that can run code on your machine are held. Click to review.';
			this.item.command = 'seclab.reviewChanges';
			this.item.show();
		} else {
			this.item.hide();
		}
	}

	private async review(): Promise<void> {
		if (!this.tabId) {
			void vscode.window.showInformationMessage('This window is not a sandboxed tab.');
			return;
		}
		const c = await this.getClient();
		const s = await c.request<{ gated: boolean; active: boolean; pending: Pending[] }>('tab.writeback.status', { tabId: this.tabId });
		this.count = s.pending.length;
		this.show();
		if (!s.pending.length) {
			void vscode.window.showInformationMessage('No changes from this tab are held.');
			return;
		}
		const items = s.pending.map(p => ({
			label: plainText(p.path),
			description: plainText(p.kind),
			detail: plainText(p.reasons.join('; '), 400),
			p,
		}));
		const pick = await vscode.window.showQuickPick(items, { title: 'Held changes from this tab (they can run code on your machine)', matchOnDescription: true, matchOnDetail: true });
		if (!pick) {
			return;
		}
		await this.reviewOne(c, pick.p);
	}

	private async reviewOne(c: TabdClient, p: Pending): Promise<void> {
		let content: Content;
		try {
			content = await c.request<Content>('tab.writeback.content', { tabId: this.tabId, path: p.path });
		} catch (e) {
			void vscode.window.showErrorMessage(`Cannot show the change: ${plainText((e as Error).message)}`);
			return;
		}
		const left = vscode.Uri.from({ scheme: SCHEME, path: `/host/${p.sig}/${encodeURIComponent(p.path)}` });
		const right = vscode.Uri.from({ scheme: SCHEME, path: `/tab/${p.sig}/${encodeURIComponent(p.path)}` });
		this.cache.set(left.toString(), render(content.host, 'on your machine'));
		this.cache.set(right.toString(), render(content.tab, 'in the tab'));
		await vscode.commands.executeCommand('vscode.diff', left, right, `${plainText(p.path, 80)}: your machine ↔ tab (read-only)`, { preview: true });
		const massDelete = p.reasons.some(r => r.startsWith('mass deletion'));
		const buttons = ['Approve', 'Reject (keep the original)', 'Always allow for this tab and path'];
		const choice = await vscode.window.showWarningMessage(`Apply the tab's change to "${plainText(p.path, 120)}"?`, {
			modal: true,
			detail: `${plainText(p.kind)}. Held because: ${plainText(p.reasons.join('; '), 600)}.\n\nApprove copies exactly what is shown into your folder. Reject keeps your folder's version.${massDelete ? '\n\nThis tab deleted many files; use "seclab: Confirm Held Deletions" to release them as a batch.' : ''}`,
		}, ...buttons);
		const decision = choice === 'Approve' ? 'approve' : choice === buttons[1] ? 'reject' : choice === buttons[2] ? 'always' : undefined;
		if (!decision) {
			return;
		}
		try {
			const r = await c.request<{ result: string }>('tab.writeback.decide', { tabId: this.tabId, path: p.path, decision, sig: content.sig });
			void vscode.window.showInformationMessage(`${plainText(p.path, 120)}: ${plainText(r.result)}`);
		} catch (e) {
			void vscode.window.showErrorMessage(`Not applied: ${plainText((e as Error).message)}`);
		} finally {
			this.cache.delete(left.toString());
			this.cache.delete(right.toString());
			await this.refresh();
		}
	}

	private async confirmDeletes(): Promise<void> {
		if (!this.tabId) {
			return;
		}
		const ok = await vscode.window.showWarningMessage('Release the hold on this tab\'s deletions?', {
			modal: true,
			detail: 'This tab deleted many files, so further deletions were held. Releasing lets ordinary deletions sync again; deletions of files that run code stay held for review.',
		}, 'Release Deletions');
		if (ok !== 'Release Deletions') {
			return;
		}
		try {
			const c = await this.getClient();
			await c.request('tab.writeback.confirmDeletes', { tabId: this.tabId });
		} catch (e) {
			void vscode.window.showErrorMessage(`Not released: ${plainText((e as Error).message)}`);
		}
	}
}
