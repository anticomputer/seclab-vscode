// Which tab events deserve a notification, what it says, and how often (ADR detection
// notifications). Pure: no editor API, so it is unit-tested with tabd and shared with the Tab
// Manager. Explanations are trusted templates keyed by rule; anything the tab chose (paths,
// commands, hosts, process names) appears only as quoted, cleaned, length-capped data, never as
// markup, links or commands. A tab can make notifications happen only by making a real
// detection happen; it cannot word, suppress or multiply them.

import { chainOf } from './lineage.ts';
import type { Integrity, ObsEvent } from './schema.ts';

export type NotifyAction = 'stop-tab' | 'open-activity' | 'review-held' | 'block-destination' | 'dismiss';

export interface NotifyItem {
	/** Coalescing key: tab + kind. */
	key: string;
	tabId: string;
	kind: string;
	severity: 'error' | 'warning';
	/** One plain-text message: trusted template, then quoted facts. */
	message: string;
	/** Further occurrences folded into this one. */
	count: number;
	actions: NotifyAction[];
	/** For block-destination: the destination, as the broker reported it (display and action key only). */
	destination?: { host: string; port?: number };
	cause?: number;
}

interface Template { severity: 'error' | 'warning'; what: string; why: string }

/** Trusted wording, keyed by detection rule or by a notification kind for non-detection events. */
export const TEMPLATES: Readonly<Record<string, Template>> = {
	'credential.honeypot-read': { severity: 'error', what: 'A process read a decoy credential file', why: 'Real credentials never exist in a tab, but reading browser, wallet, SSH or cloud credential paths is what credential-stealing malware does.' },
	'loader.pipe-to-interpreter': { severity: 'error', what: 'A process downloaded code and ran it straight away', why: 'Piping a download into an interpreter is how loaders deliver malware.' },
	'task.network-tool': { severity: 'error', what: 'A network tool started from the extension host right after the folder opened', why: 'Workspace tasks that run on folder-open are a known way for a malicious repository to start malware.' },
	'workspace.host-executable-write': { severity: 'error', what: 'A file your machine may run was written in the workspace', why: 'Git hooks, .envrc, editor task files and build scripts run on your machine, outside the sandbox, the next time you use them.' },
	'escape.container-socket': { severity: 'error', what: 'A process tried to reach a container runtime socket', why: 'Talking to the container runtime is a way to escape the sandbox.' },
	'priv.escalation': { severity: 'error', what: 'A process gained root inside the tab', why: 'Root inside the tab can tamper with the in-tab sensor; what the tab reports is now less reliable.' },
	'sensor.tamper': { severity: 'error', what: 'Something in the tab attacked the activity sensor', why: 'Malware tries to blind monitoring before it acts.' },
	'ahp.ungated': { severity: 'error', what: 'An agent connection was opened without its security gate', why: 'The agent gate is what keeps a tab\'s agent from reaching your machine; an ungated connection must not happen.' },
	'ahp.deny-burst': { severity: 'warning', what: 'The agent gate refused many requests from this tab', why: 'Repeated refused requests mean something in the tab is probing for a way out.' },
	'broker.finding': { severity: 'error', what: 'The tab\'s network broker blocked a credential leak', why: 'A placeholder credential was sent where it doesn\'t belong, or a real token was about to reach the tab. The broker stopped it; something in the tab tried.' },
	'tab.unobserved': { severity: 'error', what: 'This tab is no longer observed', why: 'The activity sensor stopped. Anything the tab does now is not recorded; malware stops sensors before it acts.' },
	'fence.failed': { severity: 'error', what: 'The tab\'s network fence failed verification and the tab was stopped', why: 'The fence keeps the tab\'s traffic going through its broker. Without it, the tab could reach the network directly.' },
	'tab.quarantined': { severity: 'error', what: 'The tab was quarantined', why: 'tabd found it running without monitoring or with a broken fence, and stopped it.' },
	'broker.failed': { severity: 'error', what: 'The tab lost its network broker', why: 'All of the tab\'s traffic goes through its broker. Requests now fail; the tab can\'t reach the network.' },
};

const BIDI_AND_INVISIBLE = /[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2028\u2029\u2060-\u206f\ufeff\ufff9-\ufffb]/g;

/**
 * Tab-chosen text as inert, quoted data: control, bidi, zero-width and line-separator
 * characters removed; markdown link syntax, URL schemes and codicons broken; capped.
 */
export function quote(s: unknown, max = 80): string {
	let t = String(s ?? '').normalize('NFC').replace(BIDI_AND_INVISIBLE, ' ').replace(/\s+/g, ' ').trim();
	// Notification text renders `[label](target)` as a link and `$(name)` as an icon: neither may
	// come from a tab. Brackets become look-alikes; "://" and "command:" lose their meaning.
	t = t.replace(/\[/g, '\u2039').replace(/\]/g, '\u203a').replace(/\$\(/g, '$\u2009(').replace(/:\/\//g, ':\u2215\u2215').replace(/\b(command|vscode|file|https?):/gi, '$1\u02d0');
	if (t.length > max) {
		t = `${t.slice(0, max - 1)}…`;
	}
	return `“${t.replace(/[“”]/g, '"')}”`;
}

export const INTEGRITY_WORDS: Readonly<Record<Integrity, string>> = {
	'trusted': 'seen outside the tab',
	'host-observed': 'seen on the host kernel; the names are the tab\'s',
	'tab-vm-root': 'seen inside the tab\'s VM; root in the tab could fake it',
	'tab-reported': 'reported by the tab itself; may be made up',
};

/** The notification kind for an event, or undefined when it shouldn't notify (severity tuning). */
export function notifyKind(e: ObsEvent): string | undefined {
	if (e.class === 'detection' && e.rule && Object.hasOwn(TEMPLATES, e.rule)) {
		// Always: credential theft, host-executable writes, sandbox escape, sensor attacks, an
		// ungated agent connection, gate probing. A network tool counts only in its critical
		// (folder-open) form; routine egress (bypass attempts the fence stops, beacons, denials)
		// stays in the activity view.
		if (e.rule === 'task.network-tool' && e.priority !== 'critical') {
			return undefined;
		}
		return e.rule;
	}
	if (e.integrity !== 'trusted') {
		return undefined;
	}
	if (e.class === 'sensor.status' && e.detail?.status === 'unobserved') {
		return 'tab.unobserved';
	}
	if (e.class === 'fence.verify' && e.priority === 'critical') {
		return 'fence.failed';
	}
	if (e.class === 'tab.lifecycle' && e.detail?.action === 'tab.quarantine') {
		return 'tab.quarantined';
	}
	if (e.class === 'tab.lifecycle' && ((e.detail?.action === 'broker.control' && e.detail.outcome === 'closed') || (e.detail?.action === 'broker.configure' && e.detail.outcome === 'fail'))) {
		return 'broker.failed';
	}
	if (e.source === 'broker' && e.priority === 'critical' && /^(?:sentinel\.misplaced|credential\.backstop_denied|credential\.backstop_exception_blocked|response\.blocked)$/.test(String(e.detail?.auditType ?? ''))) {
		return 'broker.finding';
	}
	return undefined;
}

export interface NotifyContext {
	/** The tab's trusted name: from tabd's record (workspace folder name), never from tab text. */
	tabName: string;
	heldChanges: number;
	canBlock: boolean;
}

/** Build the notification for one event (no rate limiting here). */
export function buildItem(e: ObsEvent, kind: string, ctx: NotifyContext): NotifyItem {
	const t = TEMPLATES[kind];
	const facts: string[] = [];
	if (e.file?.path) {
		facts.push(`File: ${quote(e.file.path)}.`);
	}
	if (e.net?.addr && e.net.family !== 'unix') {
		// In full: Block Destination acts on this exact name, and a cut one could pass for a familiar host.
		facts.push(`Destination: ${quote(`${e.net.addr}${e.net.port !== undefined ? `:${e.net.port}` : ''}`, 270)}.`);
	} else if (e.net?.addr) {
		facts.push(`Socket: ${quote(e.net.addr)}.`);
	}
	if (e.proc && (e.proc.exe || e.proc.argv || e.proc.lineage)) {
		facts.push(`Chain: ${quote(chainOf(e.proc), 100)} (${INTEGRITY_WORDS[e.integrity]}).`);
	} else if (kind !== 'tab.unobserved' && e.integrity !== 'trusted') {
		facts.push(`(${INTEGRITY_WORDS[e.integrity]}.)`);
	}
	if (typeof e.detail?.originLabel === 'string') {
		facts.push(`The request claims to come from ${quote(e.detail.originLabel, 40)} (unverified).`);
	}
	const actions: NotifyAction[] = ['open-activity'];
	if (kind !== 'tab.quarantined' && kind !== 'fence.failed') {
		actions.unshift('stop-tab');
	}
	if (ctx.heldChanges > 0 || kind === 'workspace.host-executable-write') {
		actions.push('review-held');
	}
	const destination = e.net?.addr && e.net.family !== 'unix' && e.source === 'broker' ? { host: e.net.addr, ...(e.net.port !== undefined ? { port: e.net.port } : {}) } : undefined;
	if (ctx.canBlock && destination) {
		actions.push('block-destination');
	}
	actions.push('dismiss');
	return {
		key: `${e.tabId}\u0000${kind}`, tabId: e.tabId, kind, severity: t.severity, count: 1, actions, cause: e.seq,
		message: [`Tab ${quote(ctx.tabName, 40)}: ${t.what}.`, ...facts, t.why].join(' '),
		...(destination ? { destination } : {}),
	};
}

export interface GateOptions {
	/** Further events of the same kind in the same tab within this window fold into a count. */
	readonly windowMs?: number;
	/** At most this many notifications per minute, across all tabs; the rest are summarised. */
	readonly perMinute?: number;
	readonly now?: () => number;
}

interface Pending { item: NotifyItem; shownAt: number; extra: number }

/** Kinds only tabd itself can produce (trusted signals): never held back by the per-minute budget. */
const TRUSTED_ONLY = new Set(['tab.unobserved', 'fence.failed', 'tab.quarantined', 'broker.failed']);

/**
 * Coalescing and rate limiting. `offer` returns what to show now; `tick` (call every few
 * seconds) returns "N more" follow-ups once a window closes and one overflow summary when the
 * global limit held some back. A flood of one kind in one tab is one notification plus at
 * most one follow-up per window. Trusted-only kinds skip the budget (review NT-1), so a tab
 * can't spend it on cheap detections and then hide "this tab is no longer observed".
 */
export class NotificationGate {
	private readonly windowMs: number;
	private readonly perMinute: number;
	private readonly now: () => number;
	private readonly open = new Map<string, Pending>();
	private shown: number[] = [];
	private overflow = 0;
	private overflowTabs = new Set<string>();
	private overflowKinds = new Set<string>();

	constructor(o: GateOptions = {}) {
		this.windowMs = o.windowMs ?? 5 * 60_000;
		this.perMinute = o.perMinute ?? 3;
		this.now = o.now ?? Date.now;
	}

	offer(item: NotifyItem): NotifyItem[] {
		const t = this.now();
		const p = this.open.get(item.key);
		if (p && t - p.shownAt < this.windowMs) {
			p.extra++;
			return [];
		}
		if (this.open.size >= 256 && !p) {
			this.hold(item.tabId, item.kind, 1);
			return [];
		}
		if (!TRUSTED_ONLY.has(item.kind) && !this.take(t)) {
			this.hold(item.tabId, item.kind, 1);
			return [];
		}
		this.open.set(item.key, { item, shownAt: t, extra: 0 });
		return [item];
	}

	private hold(tabId: string, kind: string, n: number): void {
		this.overflow += n;
		this.overflowTabs.add(tabId);
		this.overflowKinds.add(kind);
	}

	tick(): NotifyItem[] {
		const t = this.now();
		const out: NotifyItem[] = [];
		for (const [k, p] of this.open) {
			if (t - p.shownAt < this.windowMs) {
				continue;
			}
			this.open.delete(k);
			if (p.extra > 0 && (TRUSTED_ONLY.has(p.item.kind) || this.take(t))) {
				out.push({ ...p.item, count: p.extra, message: `${p.extra} more: ${p.item.message}` });
			} else if (p.extra > 0) {
				this.hold(p.item.tabId, p.item.kind, p.extra);
			}
		}
		if (this.overflow > 0 && this.take(t)) {
			const kinds = [...this.overflowKinds].filter(k => Object.hasOwn(TEMPLATES, k)).map(k => TEMPLATES[k].what.toLowerCase());
			out.push({
				key: 'overflow', tabId: '', kind: 'overflow', severity: 'warning', count: this.overflow, actions: ['open-activity', 'dismiss'],
				message: `${this.overflow} more security event(s) in ${this.overflowTabs.size} tab(s) were not shown individually${kinds.length ? `, including: ${kinds.slice(0, 4).join('; ')}` : ''}. Open the detections summary to review them.`,
			});
			this.overflow = 0;
			this.overflowTabs = new Set();
			this.overflowKinds = new Set();
		}
		return out;
	}

	private take(t: number): boolean {
		this.shown = this.shown.filter(x => t - x < 60_000);
		if (this.shown.length >= this.perMinute) {
			return false;
		}
		this.shown.push(t);
		return true;
	}
}
