// Egress and credential-binding prompts (plan tabd-broker-wiring B3). The broker holds a
// request and emits `approval.requested`; tabd forwards a sanitised copy to the Tab Manager as
// `tab.approval`, and relays the user's answer with `approval.decide`. Each tab's approvals are
// its own: a decision names one tab and one approval, and only a decision that approval offered
// is relayed (coordinator decision 3: no "apply to all", an approval never grants another tab).
// Everything in an approval is broker-relayed, tab-influenced data: it is validated, capped and
// passed on as data, never interpreted.

import { INTEGRITY_WORDS, quote } from './obs/notify.ts';
import type { Integrity } from './obs/schema.ts';

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

export const DECISIONS = ['allow-once', 'allow-tab', 'deny', 'deny-new-destinations'] as const;
export type Decision = typeof DECISIONS[number];
const KINDS = new Set(['egress', 'credential-binding']);
const APPROVAL_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const HOST_RE = /^[A-Za-z0-9._:[\]-]{1,253}$/;
const MAX_PENDING_PER_TAB = 64;

export interface ApprovalView {
	approvalId: string;
	kind: 'egress' | 'credential-binding';
	request: { scheme: string; host: string; port: number; method: string; path: string };
	decisions: Decision[];
	expiresAt: number;
	waiting: number;
	risk: { flags: string[]; origin: string; originVerified: boolean; userActionSeen: boolean };
	credentialId?: string;
}

const str = (v: unknown, max: number): string => typeof v === 'string' ? v.slice(0, max) : '';

/** A sanitised approval, or undefined if it isn't one we can show and answer. */
export function sanitizeApproval(raw: unknown): ApprovalView | undefined {
	const a = raw as Record<string, unknown> | null;
	if (!a || typeof a !== 'object' || typeof a.approvalId !== 'string' || !APPROVAL_ID_RE.test(a.approvalId) || !KINDS.has(a.kind as string)) {
		return undefined;
	}
	const req = (a.request ?? {}) as Record<string, unknown>;
	const host = str(req.host, 253);
	const port = req.port;
	if (!HOST_RE.test(host) || typeof port !== 'number' || !Number.isInteger(port) || port < 1 || port > 65535) {
		return undefined;
	}
	const decisions = Array.isArray(a.decisions) ? a.decisions.filter((d): d is Decision => (DECISIONS as readonly string[]).includes(d as string)) : [];
	if (!decisions.length || typeof a.expiresAt !== 'number') {
		return undefined;
	}
	const risk = (a.risk ?? {}) as Record<string, unknown>;
	const origin = (risk.origin ?? {}) as Record<string, unknown>;
	return {
		approvalId: a.approvalId,
		kind: a.kind as ApprovalView['kind'],
		request: { scheme: str(req.scheme, 8), host, port, method: str(req.method, 16), path: str(req.path, 256) },
		decisions: [...new Set(decisions)],
		expiresAt: a.expiresAt,
		waiting: typeof a.waiting === 'number' ? Math.max(0, Math.min(a.waiting, 1_000_000)) : 0,
		risk: {
			flags: Array.isArray(risk.flags) ? risk.flags.filter((f): f is string => typeof f === 'string').slice(0, 16).map(f => f.slice(0, 64)) : [],
			origin: str(origin.label, 128),
			originVerified: origin.verified === true,
			userActionSeen: risk.userActionSeen === true,
		},
		...(typeof a.credentialId === 'string' ? { credentialId: a.credentialId.slice(0, 64) } : {}),
	};
}

/** Pending approvals per tab, and the userAction rate limit. */
export class Approvals {
	private readonly pending = new Map<string, Map<string, ApprovalView>>();
	private readonly lastUserAction = new Map<string, number>();

	/** Record a requested approval; false if it was refused (unknown shape, or the tab's cap). */
	add(tabId: string, a: ApprovalView): boolean {
		let m = this.pending.get(tabId);
		if (!m) {
			m = new Map();
			this.pending.set(tabId, m);
		}
		if (!m.has(a.approvalId) && m.size >= MAX_PENDING_PER_TAB) {
			return false;
		}
		m.set(a.approvalId, a);
		return true;
	}

	resolve(tabId: string, approvalId: string): boolean {
		return this.pending.get(tabId)?.delete(approvalId) ?? false;
	}

	list(tabId: string): ApprovalView[] {
		const now = Date.now() / 1000;
		return [...this.pending.get(tabId)?.values() ?? []].filter(a => a.expiresAt > now);
	}

	/** The decision is one this tab's approval offered (else a reason). */
	check(tabId: string, approvalId: unknown, decision: unknown): { approval: ApprovalView; decision: Decision } | string {
		if (typeof approvalId !== 'string' || !APPROVAL_ID_RE.test(approvalId)) {
			return 'approvalId is invalid';
		}
		const approval = this.pending.get(tabId)?.get(approvalId);
		if (!approval) {
			return 'no such pending approval for this tab';
		}
		if (typeof decision !== 'string' || !approval.decisions.includes(decision as Decision)) {
			return `decision must be one of ${approval.decisions.join(', ')}`;
		}
		return { approval, decision: decision as Decision };
	}

	/** At most one userAction per tab per second (the broker asks for about that). */
	userActionDue(tabId: string, now = Date.now()): boolean {
		if (now - (this.lastUserAction.get(tabId) ?? 0) < 1000) {
			return false;
		}
		this.lastUserAction.set(tabId, now);
		return true;
	}

	forget(tabId: string): void {
		this.pending.delete(tabId);
		this.lastUserAction.delete(tabId);
	}
}

export const asJson = (a: ApprovalView): Json => a as unknown as Json;

const FLAG_WORDS: Readonly<Record<string, string>> = {
	'early-after-open': 'right after the folder opened',
	'no-user-action-yet': 'before you did anything in this tab',
	'raw-ip': 'to a raw IP address',
	'ip-in-hostname': 'to an IP address hidden in a host name',
	'cleartext': 'unencrypted (http)',
	'nonstandard-port': 'on an unusual port',
};

/** Prompt buttons, deny first; "allow for this tab" last (and never pre-selected). */
export const DECISION_LABELS: ReadonlyArray<readonly [Decision, string]> = [
	['deny', 'Deny'],
	['deny-new-destinations', 'Deny All New Destinations'],
	['allow-once', 'Allow Once'],
	['allow-tab', 'Allow for This Tab'],
];

/**
 * The prompt's text: the tab first, the destination prominent, the risk, and the process lineage
 * as quoted data. Every tab-influenced string goes through `quote` (no links, icons, controls).
 */
export function approvalPromptText(tabName: string, a: ApprovalView, lineage: { confidence?: string; chain?: string; integrity?: Integrity } | undefined): string {
	const dest = `${quote(a.request.host, 120)}${a.request.port === 443 || a.request.port === 80 ? '' : `:${a.request.port}`}`;
	const what = a.kind === 'credential-binding'
		? `wants to send credential ${quote(a.credentialId ?? '?', 40)} to ${dest}`
		: `wants to connect to ${dest}`;
	const parts = [`Tab ${quote(tabName, 60)} ${what} (${quote(`${a.request.method} ${a.request.path}`, 80)}).`];
	const flags = a.risk.flags.map(f => FLAG_WORDS[f] ?? (f.startsWith('risky-destination:') ? `to a risky destination (${quote(f.slice(18), 30)})` : quote(f, 30)));
	if (flags.length) {
		parts.push(`Asked ${flags.join(', ')}.`);
	}
	if (a.risk.origin) {
		parts.push(`The tab labels it ${quote(a.risk.origin, 60)} (unverified).`);
	}
	// promptLineage confidence: single | ambiguous | none. Shown as data, never used to decide.
	if (lineage?.chain && lineage.integrity && INTEGRITY_WORDS[lineage.integrity] && lineage.confidence !== 'none') {
		parts.push(`Process: ${quote(lineage.chain, 120)} (${INTEGRITY_WORDS[lineage.integrity]}${lineage.confidence === 'ambiguous' ? '; ambiguous, may be another process' : ''}).`);
	}
	parts.push('Ignoring this denies it.');
	return parts.join(' ');
}
