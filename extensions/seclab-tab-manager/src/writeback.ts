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
	const esc = String(s).replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}]/gu, c => `\\u{${c.codePointAt(0)!.toString(16)}}`).replace(/\$\(/g, '$\u200a(').replace(/\[/g, '［').replace(/\]/g, '］');
	return esc.length > max ? `${esc.slice(0, max - 1)}…` : esc;
}

/** A tab path for display: escaped, and long ones elided in the middle so the tail (the part
 *  that decides what the file is, e.g. `.claude/settings.json`) always shows (review OO-3). */
export function plainPath(p: string, max = 120): string {
	const esc = plainText(p, 10_000);
	if (esc.length <= max) {
		return esc;
	}
	const segs = esc.split('/');
	const tail = segs.slice(-2).join('/');
	const keep = Math.max(10, max - tail.length - 2);
	return tail.length + 2 >= max ? `…${tail.slice(-(max - 1))}` : `${esc.slice(0, keep)}…/${tail}`;
}

const WRAP_COLUMNS = 80;
/** East Asian wide/fullwidth ranges: two display columns each. */
const WIDE = /[\u1100-\u115F\u2E80-\uA4CF\uAC00-\uD7A3\uF900-\uFAFF\uFE30-\uFE4F\uFF00-\uFF60\uFFE0-\uFFE6\u{1F300}-\u{1FAFF}\u{20000}-\u{3FFFD}]/u;

/** Escaped in content (review QQ-1, QQ-3): format/bidi/zero-width, private-use, unassigned,
 *  surrogates, line/paragraph separators, tag characters, variation selectors, and the
 *  renderer's own marker characters (so only the renderer's markers appear literally). */
const ESCAPE = /[\p{Cf}\p{Zl}\p{Zp}\p{Co}\p{Cn}\p{Cs}\u{E0000}-\u{E007F}\u{FE00}-\u{FE0F}⟨⟩↪→·…]/gu;

/** Display width: wide ranges, and any non-ASCII that isn't a letter, mark, digit or
 *  punctuation (symbols, emoji, presentation forms), count 2 (review QQ-2: over-, not under-). */
function width(ch: string): number {
	return WIDE.test(ch) || (ch > '\x7f' && !/[\p{L}\p{M}\p{N}\p{P}]/u.test(ch)) ? 2 : 1;
}

/**
 * One line as the user must see it (review PP-1): no whitespace may push content off-screen.
 * Tabs show as →, any run of 8+ whitespace characters (incl. non-ASCII spaces) becomes a
 * visible ⟨N blanks⟩ marker, and lines wrap at a display width that fits a diff pane.
 */
function visibleLine(l: string): string {
	const s = l.replace(/[\t \p{Zs}]{8,}/gu, m => `⟨${m.length} blanks⟩`).replace(/\t/g, '→').replace(/[\p{Zs}]/gu, c => c === ' ' ? ' ' : '·');
	const out: string[] = [];
	let cur = '';
	let w = 0;
	for (const ch of s) {
		const cw = width(ch);
		if (w + cw > WRAP_COLUMNS) {
			out.push(cur);
			cur = '↪ ';
			w = 2;
		}
		cur += ch;
		w += cw;
	}
	out.push(cur);
	return out.join('\n');
}

/** Bytes as text the user can read completely: UTF-8 if valid (NULs escaped), else \xNN escapes. */
function readable(buf: Buffer): string {
	let text: string;
	try {
		text = new TextDecoder('utf-8', { fatal: true }).decode(buf);
	} catch {
		text = [...buf].map(b => (b >= 0x20 && b < 0x7f) || b === 0x0a || b === 0x09 ? String.fromCharCode(b) : `\\x${b.toString(16).padStart(2, '0')}`).join('');
	}
	return text.replace(/\0/g, '\\x00').replace(/\r/g, '\\r').replace(ESCAPE, c => `\\u{${c.codePointAt(0)!.toString(16)}}`).split('\n').map(visibleLine).join('\n');
}

/** File content for display, and whether everything that would be applied is shown. */
function render(side: Side, label: string): { text: string; complete: boolean } {
	if (side.kind === 'absent' || side.exists === false) {
		return { text: `(${label}: does not exist)\n`, complete: true };
	}
	if (side.kind === 'symlink') {
		return { text: `(${label}: symbolic link → ${plainText(side.target ?? '', 1000)})\n`, complete: true };
	}
	if (side.kind === 'deleted') {
		return { text: `(${label}: deleted)\n`, complete: true };
	}
	if (side.kind && side.kind !== 'file') {
		return { text: `(${label}: ${plainText(side.kind)})\n`, complete: true };
	}
	const text = readable(Buffer.from(side.b64 ?? '', 'base64'));
	return side.truncated
		? { text: `${text}\n\n… NOT SHOWN: the rest of this file (${label}: ${side.size} bytes in total) …\n`, complete: false }
		: { text, complete: true };
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
	private lastPrompt = 0;

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

	/** Held changes for this window's tab (for notification actions). */
	heldCount(): number {
		return this.count;
	}

	/** tab.writeback.pending for this window's tab. */
	onPending(params: Record<string, unknown>): void {
		if (params.tabId !== this.tabId || typeof params.count !== 'number') {
			return;
		}
		this.count = params.count;
		this.show();
		// At most one prompt a minute: a tab flipping its pending count can't spam the user.
		if (this.count > 0 && !this.prompted && Date.now() - this.lastPrompt > 60_000) {
			this.prompted = true;
			this.lastPrompt = Date.now();
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
			label: plainPath(p.path),
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
		const left = vscode.Uri.from({ scheme: SCHEME, path: `/host/${content.sig}/review.txt`, query: encodeURIComponent(p.path) });
		const right = vscode.Uri.from({ scheme: SCHEME, path: `/tab/${content.sig}/review.txt`, query: encodeURIComponent(p.path) });
		// A neutral .txt name: no language features (JSON schemas, TS servers) run on tab content (OO-5).
		const hostSide = render(content.host, 'on your machine');
		const tabSide = render(content.tab, 'in the tab');
		this.cache.set(left.toString(), hostSide.text);
		this.cache.set(right.toString(), tabSide.text);
		await vscode.commands.executeCommand('vscode.diff', left, right, `${plainPath(p.path, 80)}: your machine ↔ tab (read-only)`, { preview: true });
		const massDelete = p.reasons.some(r => r.startsWith('mass deletion'));
		// Reject first: Enter never approves (OO-4). If not all of the tab's version could be
		// shown, plain Approve and Always aren't offered (OO-2).
		const reject = 'Reject (keep the original)';
		const buttons = tabSide.complete
			? [reject, 'Approve', 'Always allow for this tab and path']
			: [reject, 'Approve without seeing all of it'];
		const choice = await vscode.window.showWarningMessage(`Apply the tab's change to "${plainPath(p.path)}"?`, {
			modal: true,
			detail: `${plainText(p.kind)}. Held because: ${plainText(p.reasons.join('; '), 600)}.\n\n`
				+ (tabSide.complete ? 'Approve copies exactly the version shown into your folder.' : 'Only the start of the tab\'s version could be shown: the rest is NOT shown and would also be copied.')
				+ ' Reject keeps your folder\'s version.'
				+ (massDelete ? '\n\nThis tab deleted many files; "seclab: Confirm Held Deletions…" releases them as a batch.' : ''),
		}, ...buttons);
		const decision = choice === 'Approve' || choice === 'Approve without seeing all of it' ? 'approve' : choice === reject ? 'reject' : choice === 'Always allow for this tab and path' ? 'always' : undefined;
		if (!decision) {
			return;
		}
		try {
			const r = await c.request<{ result: string }>('tab.writeback.decide', { tabId: this.tabId, path: p.path, decision, sig: content.sig });
			void vscode.window.showInformationMessage(`${plainPath(p.path)}: ${plainText(r.result)}`);
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
		const c = await this.getClient();
		const s = await c.request<{ pending: Pending[]; massDeleteDigest?: string }>('tab.writeback.status', { tabId: this.tabId });
		const held = s.pending.filter(p => p.reasons.some(r => r.startsWith('mass deletion')));
		if (!held.length) {
			void vscode.window.showInformationMessage('No deletions from this tab are held.');
			return;
		}
		const sample = held.slice(0, 8).map(p => `  ${plainPath(p.path, 100)}`).join('\n');
		const ok = await vscode.window.showWarningMessage(`Release ${held.length} held deletion(s) from this tab?`, {
			modal: true,
			detail: `This tab deleted many files, so its deletions were held. Releasing deletes these from your folder (deletions of files that run code stay held for review):\n${sample}${held.length > 8 ? `\n  … and ${held.length - 8} more` : ''}`,
		}, 'Release Deletions');
		if (ok !== 'Release Deletions') {
			return;
		}
		try {
			// Bound to exactly the set of held deletions this status listed (OO-6, PP-2).
			await c.request('tab.writeback.confirmDeletes', { tabId: this.tabId, digest: s.massDeleteDigest });
		} catch (e) {
			void vscode.window.showErrorMessage(`Not released: ${plainText((e as Error).message)}`);
		}
	}
}
