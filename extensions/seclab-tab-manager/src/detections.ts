/*---------------------------------------------------------------------------------------------
 *  Detections summary (ADR detection notifications): detections and trusted failures across
 *  every tab, running or stopped, from tabd's persisted per-tab logs. Plain-text TreeView (no
 *  webview, no markdown); tab text is shown quoted and defanged. Actions name a tab id taken
 *  from tabd's own tab list, never from event text, and stopping another window's tab asks first.
 *--------------------------------------------------------------------------------------------*/

import * as path from 'node:path';
import * as vscode from 'vscode';
import type { TabdClient } from '../tabd-src/client.ts';
import { chainOf } from '../tabd-src/obs/lineage.ts';
import { notifyKind, quote, TEMPLATES } from '../tabd-src/obs/notify.ts';
import type { ObsEvent, Priority } from '../tabd-src/obs/schema.ts';

const PRIORITIES: readonly Priority[] = ['emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'informational', 'debug'];
const TAB_ID_RE = /^t-[a-z2-7]{26}$/;

interface TabInfo { tabId: string; hostPath: string; phase: string }
type Node = { kind: 'tab'; tab: TabInfo; events: ObsEvent[] } | { kind: 'event'; tab: TabInfo; e: ObsEvent } | { kind: 'empty'; text: string };

export class DetectionsSummary implements vscode.TreeDataProvider<Node>, vscode.Disposable {
	private readonly changed = new vscode.EventEmitter<Node | undefined>();
	readonly onDidChangeTreeData = this.changed.event;
	private readonly view: vscode.TreeView<Node>;
	private tabs: TabInfo[] = [];
	private events: ObsEvent[] = [];
	private minPriority: Priority = 'warning';
	private tabFilter?: string;
	private ruleFilter?: string;
	private error?: string;
	private readonly timer: NodeJS.Timeout;
	private readonly getClient: () => Promise<TabdClient>;
	private readonly openTab: (tabId: string, hostPath: string) => Promise<void>;

	constructor(context: vscode.ExtensionContext, getClient: () => Promise<TabdClient>, openTab: (tabId: string, hostPath: string) => Promise<void>) {
		this.getClient = getClient;
		this.openTab = openTab;
		this.view = vscode.window.createTreeView('seclab.detections', { treeDataProvider: this });
		this.view.onDidChangeVisibility(v => {
			if (v.visible) {
				void this.reload();
			}
		});
		this.timer = setInterval(() => {
			if (this.view.visible) {
				void this.reload();
			}
		}, 30_000);
		context.subscriptions.push(this, this.view,
			// `seclab.detections.focus` is the view's built-in focus command.
			vscode.commands.registerCommand('seclab.detections.refresh', () => this.reload()),
			vscode.commands.registerCommand('seclab.detections.filter', () => this.pickFilter()),
			vscode.commands.registerCommand('seclab.detections.stopTab', (n?: Node) => this.stop(n)),
			vscode.commands.registerCommand('seclab.detections.openTab', (n?: Node) => this.open(n)),
		);
	}

	/** Something notable happened in this window's tab: refresh if the view is showing. */
	poke(): void {
		if (this.view.visible) {
			void this.reload();
		}
	}

	async reload(): Promise<void> {
		try {
			const c = await this.getClient();
			const r = await c.request<{ events: ObsEvent[]; tabs: TabInfo[] }>('tab.detections.query', { minPriority: this.minPriority, limit: 500, ...(this.tabFilter ? { tabIds: [this.tabFilter] } : {}) });
			this.tabs = r.tabs.filter(t => TAB_ID_RE.test(t.tabId));
			this.events = r.events.filter(e => !this.ruleFilter || (e.rule ?? notifyKind(e) ?? e.class) === this.ruleFilter);
			this.error = undefined;
			const n = this.events.filter(e => e.class === 'detection' || notifyKind(e)).length;
			this.view.badge = n ? { value: n, tooltip: 'Detections across tabs' } : undefined;
		} catch (e) {
			this.error = `Could not read detections: ${(e as Error).message}`;
		}
		this.changed.fire(undefined);
	}

	getChildren(n?: Node): Node[] {
		if (n?.kind === 'tab') {
			return n.events.map(e => ({ kind: 'event', tab: n.tab, e }));
		}
		if (n) {
			return [];
		}
		if (this.error) {
			return [{ kind: 'empty', text: this.error }];
		}
		const byTab = new Map<string, ObsEvent[]>();
		for (const e of this.events) {
			(byTab.get(e.tabId) ?? byTab.set(e.tabId, []).get(e.tabId)!).push(e);
		}
		const nodes = this.tabs.filter(t => byTab.has(t.tabId)).map(t => ({ kind: 'tab', tab: t, events: byTab.get(t.tabId)! }) as Node);
		return nodes.length ? nodes : [{ kind: 'empty', text: `No detections at ${this.minPriority} or above${this.tabFilter || this.ruleFilter ? ' (filtered)' : ''}.` }];
	}

	getTreeItem(n: Node): vscode.TreeItem {
		if (n.kind === 'empty') {
			return new vscode.TreeItem(n.text);
		}
		if (n.kind === 'tab') {
			const name = path.basename(n.tab.hostPath) || n.tab.tabId;
			const item = new vscode.TreeItem(`${plain(name, 60)} (${n.events.length})`, vscode.TreeItemCollapsibleState.Expanded);
			item.description = n.tab.phase;
			item.tooltip = `${plain(n.tab.hostPath, 300)}\n${n.tab.tabId} · ${n.tab.phase}`;
			item.contextValue = n.tab.phase === 'Running' ? 'seclabTabRunning' : 'seclabTab';
			item.iconPath = new vscode.ThemeIcon('folder');
			return item;
		}
		const e = n.e;
		const kind = notifyKind(e);
		const t = kind ? TEMPLATES[kind] : undefined;
		const item = new vscode.TreeItem(t ? t.what : plain(e.rule ? `${e.rule}: ${e.summary}` : e.summary, 160));
		item.description = `${e.priority} · ${e.integrity} · ${e.time.replace('T', ' ').slice(0, 19)}`;
		const lines = [t ? `${t.what}. ${t.why}` : '', `Event: ${quote(e.summary, 300)}`, `${e.source} / ${e.class}${e.rule ? ` / ${e.rule}` : ''} · #${e.seq} · ${e.time}`, `Integrity: ${e.integrity}`];
		if (e.file?.path) {
			lines.push(`File: ${quote(e.file.path, 200)}`);
		}
		if (e.net?.addr) {
			lines.push(`Network: ${quote(`${e.net.addr}${e.net.port !== undefined ? `:${e.net.port}` : ''}`, 120)}`);
		}
		if (e.proc) {
			lines.push(`Chain: ${quote(chainOf(e.proc), 200)}`);
		}
		item.tooltip = lines.filter(Boolean).join('\n'); // plain string, never markdown
		item.contextValue = n.tab.phase === 'Running' ? 'seclabDetectionRunning' : 'seclabDetection';
		const sev = PRIORITIES.indexOf(e.priority);
		item.iconPath = new vscode.ThemeIcon(e.class === 'detection' ? 'alert' : 'shield', new vscode.ThemeColor(sev <= 2 ? 'errorForeground' : 'editorWarning.foreground'));
		return item;
	}

	/** The tab a view node refers to, re-checked against tabd's tab list (never trusted as given). */
	private tabOf(n?: Node): TabInfo | undefined {
		const id = n && n.kind !== 'empty' ? n.tab.tabId : undefined;
		return id && TAB_ID_RE.test(id) ? this.tabs.find(t => t.tabId === id) : undefined;
	}

	private async stop(n?: Node): Promise<void> {
		const t = this.tabOf(n);
		if (!t) {
			return;
		}
		const name = path.basename(t.hostPath) || t.tabId;
		const ok = await vscode.window.showWarningMessage(`Stop tab ${quote(name, 60)}? Its window disconnects; your folder is not touched.`, { modal: true }, 'Stop Tab');
		if (ok === 'Stop Tab') {
			await (await this.getClient()).request('tab.stop', { tabId: t.tabId });
			await this.reload();
		}
	}

	private async open(n?: Node): Promise<void> {
		const t = this.tabOf(n);
		if (t) {
			await this.openTab(t.tabId, t.hostPath);
		}
	}

	private async pickFilter(): Promise<void> {
		const which = await vscode.window.showQuickPick(['Severity', 'Tab', 'Rule', 'Clear filters'], { title: 'Filter detections' });
		if (which === 'Severity') {
			const p = await vscode.window.showQuickPick(PRIORITIES.map(x => ({ label: x, picked: x === this.minPriority })), { title: 'Show at or above' });
			if (p) {
				this.minPriority = p.label as Priority;
			}
		} else if (which === 'Tab') {
			const p = await vscode.window.showQuickPick([{ label: 'All tabs', id: undefined as string | undefined }, ...this.tabs.map(t => ({ label: plain(path.basename(t.hostPath) || t.tabId, 60), description: t.tabId, id: t.tabId }))], { title: 'Tab' });
			if (p) {
				this.tabFilter = p.id;
			}
		} else if (which === 'Rule') {
			const rules = [...new Set(this.events.map(e => e.rule ?? notifyKind(e) ?? e.class))].sort();
			const p = await vscode.window.showQuickPick(['All rules', ...rules], { title: 'Rule' });
			if (p) {
				this.ruleFilter = p === 'All rules' ? undefined : p;
			}
		} else if (which === 'Clear filters') {
			this.minPriority = 'warning';
			this.tabFilter = this.ruleFilter = undefined;
		}
		await this.reload();
	}

	dispose(): void {
		clearInterval(this.timer);
		this.changed.dispose();
	}
}

/** Codicon syntax and newlines in tab-influenced labels must never render. */
function plain(s: string, max: number): string {
	const t = s.replace(/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g, ' ').replace(/\$\(/g, '$\u2060(');
	return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}
