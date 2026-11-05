/*---------------------------------------------------------------------------------------------
 *  Tab activity view (ADR tab-observability §4): the live, integrity-labelled event stream of
 *  this window's tab. Every string shown here came from a tab or describes one, so it is shown
 *  as plain text only: a TreeView (no webview, no HTML, no markdown), plain-string tooltips,
 *  and codicon syntax neutralised. Commands here only change what the view shows, except
 *  "deep mode", which asks the user first.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import type { TabdClient } from '../tabd-src/client.ts';
import type { ObsEvent, Priority } from '../tabd-src/obs/schema.ts';

const PRIORITIES: readonly Priority[] = ['emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'informational', 'debug'];
const MAX_ITEMS = 1000;
const BADGE: Record<string, string> = { 'trusted': 'trusted', 'host-observed': 'host-observed', 'tab-vm-root': 'tab VM root' };
const INTEGRITY_HELP: Record<string, string> = {
	'trusted': 'Produced outside the tab. The tab can neither forge nor suppress it.',
	'host-observed': 'Seen by Falco on the host kernel, outside the tab. The content (commands, paths) is chosen by the tab.',
	'tab-vm-root': 'Seen by the collector inside the tab\'s own VM. Root inside the tab could forge or hide it.',
};

interface Observation { state: string; since: string; reason: string; sensor?: string; mode?: string }

/** Codicon syntax ($(name)) in tab-controlled text must never render as an icon. */
function plain(s: string, max = 400): string {
	const t = s.replace(/\$\(/g, '$\u2060(').replace(/[\r\n]+/g, ' ');
	return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

type Item = { kind: 'status' } | { kind: 'lagged'; count: number } | { kind: 'event'; e: ObsEvent };

export class TabActivity implements vscode.TreeDataProvider<Item>, vscode.Disposable {
	private readonly changed = new vscode.EventEmitter<Item | undefined>();
	readonly onDidChangeTreeData = this.changed.event;
	private readonly status: vscode.StatusBarItem;
	private readonly view: vscode.TreeView<Item>;
	private events: ObsEvent[] = [];
	private observation: Observation = { state: 'unavailable', since: '', reason: 'not connected to a tab' };
	private tabId?: string;
	private client?: TabdClient;
	private subscription?: number;
	private minPriority: Priority = 'informational';
	private detectionsOnly = false;
	private lagged = 0;
	private revealed = false;
	private refreshTimer?: NodeJS.Timeout;

	constructor(context: vscode.ExtensionContext) {
		this.view = vscode.window.createTreeView('seclab.tabActivity', { treeDataProvider: this });
		this.status = vscode.window.createStatusBarItem('seclab.observation', vscode.StatusBarAlignment.Left, 99);
		this.status.name = 'seclab tab observation';
		this.status.command = 'seclab.activity.focus';
		context.subscriptions.push(this, this.view, this.status,
			vscode.commands.registerCommand('seclab.activity.focus', () => vscode.commands.executeCommand('seclab.tabActivity.focus')),
			vscode.commands.registerCommand('seclab.activity.filter', () => this.pickPriority()),
			vscode.commands.registerCommand('seclab.activity.toggleDetections', () => {
				this.detectionsOnly = !this.detectionsOnly;
				this.refresh();
			}),
			vscode.commands.registerCommand('seclab.activity.deepMode', () => this.deepMode()),
		);
	}

	/** This window is tab `tabId`: subscribe to its stream (replaying what the supervisor buffered). */
	async attach(client: TabdClient, tabId: string): Promise<void> {
		if (this.tabId === tabId && this.client === client && this.subscription !== undefined) {
			return;
		}
		this.tabId = tabId;
		this.client = client;
		this.events = [];
		const r = await client.request<{ subscription: number; observation: Observation | null }>('tab.events.subscribe', { tabId, sinceSeq: 0 });
		this.subscription = r.subscription;
		if (r.observation) {
			this.setObservation(r.observation);
		}
		this.refresh();
	}

	/** Supervisor notifications (routed from the Tab Manager's single client). */
	onNotification(method: string, p: Record<string, unknown>): void {
		if (method === 'tab.event' && p.subscription === this.subscription) {
			const e = p.event as ObsEvent;
			if (typeof p.lagged === 'number') {
				this.lagged += p.lagged;
			}
			if (this.events.length && e.seq <= this.events[this.events.length - 1].seq) {
				return; // replay overlap
			}
			this.events.push(e);
			if (this.events.length > MAX_ITEMS * 2) {
				this.events = this.events.slice(-MAX_ITEMS);
			}
			if (e.class === 'detection' && (e.priority === 'critical' || e.priority === 'alert' || e.priority === 'emergency')) {
				this.view.badge = { value: this.events.filter(x => x.class === 'detection').length, tooltip: 'Detections in this tab' };
				this.revealOnce();
			}
			this.scheduleRefresh();
		} else if (method === 'tab.observation' && p.tabId === this.tabId) {
			this.setObservation(p as unknown as Observation);
		}
	}

	detach(): void {
		this.subscription = undefined;
		this.setObservation({ state: 'unavailable', since: new Date().toISOString(), reason: 'supervisor disconnected' });
	}

	private setObservation(o: Observation): void {
		this.observation = o;
		if (o.state === 'unobserved') {
			this.revealOnce();
		}
		const label: Record<string, string> = { observed: '$(eye) Observed', degraded: '$(eye) Degraded', unobserved: '$(eye-closed) Unobserved', unavailable: '$(circle-slash) No sensor' };
		this.status.text = label[o.state] ?? '$(question) ?';
		this.status.tooltip = `Tab activity: ${o.state}. ${plain(o.reason, 200)}`;
		this.status.backgroundColor = o.state === 'unobserved' ? new vscode.ThemeColor('statusBarItem.errorBackground') : o.state === 'degraded' ? new vscode.ThemeColor('statusBarItem.warningBackground') : undefined;
		this.status.show();
		this.view.message = o.state === 'unobserved' ? `⚠ This tab is UNOBSERVED: ${plain(o.reason, 200)}. Activity inside the tab is not being recorded.` : undefined;
		this.refresh();
	}

	/** Bring the panel up once per tab for the first critical detection or a sensor gap. */
	private revealOnce(): void {
		if (this.revealed || !this.tabId || !vscode.workspace.getConfiguration('seclab.activity').get<boolean>('revealOnAlert', true)) {
			return;
		}
		this.revealed = true;
		void vscode.commands.executeCommand('seclab.tabActivity.focus');
	}

	private scheduleRefresh(): void {
		this.refreshTimer ??= setTimeout(() => {
			this.refreshTimer = undefined;
			this.refresh();
		}, 250);
	}

	private refresh(): void {
		this.changed.fire(undefined);
	}

	getChildren(el?: Item): Item[] {
		if (el) {
			return [];
		}
		const rank = PRIORITIES.indexOf(this.minPriority);
		const shown = this.events.filter(e => PRIORITIES.indexOf(e.priority) <= rank && (!this.detectionsOnly || e.class === 'detection')).slice(-MAX_ITEMS).reverse();
		return [{ kind: 'status' }, ...(this.lagged ? [{ kind: 'lagged', count: this.lagged } as Item] : []), ...shown.map(e => ({ kind: 'event', e }) as Item)];
	}

	getTreeItem(el: Item): vscode.TreeItem {
		if (el.kind === 'status') {
			const o = this.observation;
			const item = new vscode.TreeItem(`${o.state.toUpperCase()}${o.sensor ? ` · ${o.sensor}` : ''}${o.mode ? ` · ${o.mode} mode` : ''}`);
			item.description = plain(o.reason, 120);
			item.tooltip = `Observation: ${o.state} since ${o.since}\n${plain(o.reason, 300)}\nFilter: ${this.minPriority} and above${this.detectionsOnly ? ', detections only' : ''}`;
			item.iconPath = new vscode.ThemeIcon(o.state === 'unobserved' ? 'eye-closed' : o.state === 'unavailable' ? 'circle-slash' : 'eye',
				new vscode.ThemeColor(o.state === 'unobserved' ? 'errorForeground' : o.state === 'degraded' ? 'editorWarning.foreground' : 'foreground'));
			return item;
		}
		if (el.kind === 'lagged') {
			const item = new vscode.TreeItem(`${el.count} events were not delivered while the editor was busy (see seclab tab logs)`);
			item.iconPath = new vscode.ThemeIcon('warning');
			return item;
		}
		const e = el.e;
		const item = new vscode.TreeItem(plain(e.class === 'detection' ? `${e.rule}: ${e.summary}` : e.summary, 200));
		item.description = `${e.priority} · ${BADGE[e.integrity] ?? '?'} · ${e.time.slice(11, 23)}`;
		const lines = [
			plain(e.summary, 1000),
			`${e.source} / ${e.class}${e.rule ? ` / ${e.rule}` : ''} · #${e.seq} · ${e.time}`,
			`Integrity: ${BADGE[e.integrity] ?? '?'}. ${INTEGRITY_HELP[e.integrity] ?? ''}`,
		];
		if (e.proc) {
			lines.push(`Process ${e.proc.pid ?? '?'}${e.proc.exe ? ` ${plain(e.proc.exe, 200)}` : ''}`);
			for (const l of e.proc.lineage ?? []) {
				lines.push(`  ← ${l.pid} ${plain(l.exe, 200)}`);
			}
		}
		if (e.file) {
			lines.push(`File ${plain(e.file.path, 300)}`);
		}
		if (e.net) {
			lines.push(`Network ${plain(e.net.addr, 100)}${e.net.port !== undefined ? `:${e.net.port}` : ''} ${e.net.result ?? ''}`);
		}
		if (e.detail?.claimedExtensionId !== undefined) {
			lines.push(`Claims to be extension ${plain(String(e.detail.claimedExtensionId), 100)} (unverified)`);
		}
		if (e.redacted) {
			lines.push('Some values were redacted.');
		}
		item.tooltip = lines.join('\n'); // a plain string: never markdown
		const sev = PRIORITIES.indexOf(e.priority);
		const color = sev <= 2 ? 'errorForeground' : sev <= 4 ? 'editorWarning.foreground' : undefined;
		const icon = e.class === 'detection' ? 'alert' : e.integrity === 'trusted' ? 'shield' : e.integrity === 'host-observed' ? 'eye' : 'vm';
		item.iconPath = new vscode.ThemeIcon(icon, color ? new vscode.ThemeColor(color) : undefined);
		return item;
	}

	private async pickPriority(): Promise<void> {
		const pick = await vscode.window.showQuickPick(PRIORITIES.map(p => ({ label: p, picked: p === this.minPriority })), { title: 'Show events at or above' });
		if (pick) {
			this.minPriority = pick.label as Priority;
			this.refresh();
		}
	}

	private async deepMode(): Promise<void> {
		if (!this.client || !this.tabId) {
			return;
		}
		const choice = await vscode.window.showInformationMessage(
			'Deep mode also records every file the tab opens. File-heavy work in the tab gets much slower (about 45 µs per open). It applies the next time the tab starts.',
			{ modal: true }, 'Enable deep mode', 'Use default mode');
		if (!choice) {
			return;
		}
		await this.client.request('tab.observe', { tabId: this.tabId, mode: choice === 'Enable deep mode' ? 'deep' : 'default' });
	}

	dispose(): void {
		clearTimeout(this.refreshTimer);
		this.changed.dispose();
	}
}
