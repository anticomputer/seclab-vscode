// Broker audit events into the tab's event stream (ADR tab-observability; docs/broker-protocol.md
// §4 `audit.event`, `audit.tail`). The broker is trusted (outside the tab, on a control channel
// tabd owns), so every event here is `trusted`. Its content is not: the host, method, path,
// origin label and reasons are chosen by the tab or by an upstream the tab chose. Only
// allowlisted fields are copied, each into a field that untrustedFields() tags, and every
// string goes through normalizeDraft (escaped, capped). Nothing here drives a host action.

import type { EventClass, Priority } from './schema.ts';

export const AGG_WINDOW_MS = 10_000;
/** Replay window on connect (the broker keeps at most 2000). */
export const TAIL_LIMIT = 2000;

type Detail = Record<string, string | number | boolean>;
export interface MappedAudit {
	class: EventClass;
	priority: Priority;
	summary: string;
	net?: { addr: string; port?: number };
	detail: Detail;
	/** Allowed traffic is aggregated per key and window; everything else is emitted one by one. */
	aggKey?: string;
	/** The broker's own timestamp (epoch seconds), when present. */
	ts?: number;
}

interface Kind { class: EventClass; priority: Priority; what: string; agg?: boolean }
const K = (cls: EventClass, priority: Priority, what: string, agg = false): Kind => ({ class: cls, priority, what, agg });

/** Every audit type the broker documents (docs/broker-protocol.md, generated list). */
export const AUDIT_KINDS: Readonly<Record<string, Kind>> = {
	'request.allowed': K('egress.request', 'informational', 'allowed', true),
	// Denials a tab can produce cheaply are aggregated too (review BA-1): the first per
	// destination and reason goes out at once, repeats are counted.
	'request.denied': K('egress.request', 'warning', 'denied', true),
	'request.denied_unprompted': K('egress.request', 'warning', 'denied without a prompt', true),
	'upstream.blocked': K('egress.request', 'warning', 'upstream address refused', true),
	'upstream.dns_failed': K('egress.request', 'notice', 'upstream name did not resolve', true),
	'tcp.blocked': K('egress.request', 'warning', 'non-HTTP TCP stream killed', true),
	'udp.blocked': K('egress.request', 'warning', 'UDP flow killed', true),
	'response.blocked': K('egress.request', 'critical', 'response blocked by the token scanner', true),
	'session.stripped': K('egress.request', 'notice', 'session header stripped from a credentialed response', true),
	'approval.requested': K('egress.approval', 'notice', 'prompt opened'),
	'approval.resolved': K('egress.approval', 'notice', 'prompt answered'),
	'approval.queue_full': K('egress.approval', 'warning', 'prompt not opened: hold limit reached; denied', true),
	'approval.rate_limited': K('egress.approval', 'warning', 'prompt not opened: rate limit; denied', true),
	'prompt.deny_new': K('egress.approval', 'notice', 'user chose deny-new-destinations'),
	'prompt.reset': K('egress.approval', 'informational', 'prompt state reset'),
	'credential.provided': K('credential.use', 'notice', 'real value provided'),
	'credential.revoked': K('credential.use', 'notice', 'real value revoked'),
	'credential.imported': K('credential.use', 'notice', 'credential imported'),
	'credential.needed': K('credential.use', 'notice', 'request waiting for a credential value', true),
	'credential.unavailable': K('credential.use', 'warning', 'no credential value before the hold timeout'),
	'credential.injected': K('credential.use', 'informational', 'credential injected', true),
	'credential.derived': K('credential.use', 'notice', 'minted token re-sentinelised'),
	'credential.backstop_denied': K('credential.use', 'critical', 'credentialed request hit the provider backstop', true),
	'credential.backstop_exempt': K('credential.use', 'notice', 'credentialed request passed the backstop on a declared derive route'),
	'credential.backstop_exception_blocked': K('credential.use', 'critical', 'backstop exception response blocked', true),
	'sentinel.misplaced': K('credential.use', 'critical', 'sentinel sent outside its binding', true),
	'token.redacted': K('credential.use', 'warning', 'minted token redacted', true),
	'model.call': K('model.call', 'informational', 'model call'),
	'model.denied': K('model.call', 'warning', 'model request denied by the body policy', true),
	'model.budget_exceeded': K('model.call', 'warning', 'model budget spent; denied', true),
	'broker.started': K('broker.status', 'notice', 'broker started'),
	'broker.shutdown': K('broker.status', 'notice', 'broker shut down'),
	'control.connected': K('broker.status', 'informational', 'control client connected'),
	'control.disconnected': K('broker.status', 'notice', 'control client disconnected'),
	'proxy.auth_set': K('broker.status', 'informational', 'proxy credential set'),
	'proxy.auth_failed': K('broker.status', 'warning', 'proxy authentication failed'),
	'policy.loaded': K('broker.status', 'notice', 'policy loaded'),
	'policy.updated': K('broker.status', 'notice', 'policy updated'),
	'tab.event': K('broker.status', 'informational', 'tab event'),
	'engine.error': K('broker.status', 'error', 'engine hook failed; flow failed closed', true),
};

const TYPE_RE = /^[a-z][a-z0-9_.]{0,63}$/;
const str = (v: unknown, max = 512): string | undefined => typeof v === 'string' ? v.slice(0, max) : undefined;
const num = (v: unknown): number | undefined => typeof v === 'number' && Number.isFinite(v) ? v : undefined;
const port = (v: unknown): number | undefined => typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= 65535 ? v : undefined;

/**
 * Map one audit event to an event draft (class, priority, summary, net, detail). Returns a
 * string reason when the event must be dropped. `tabId` is the tab this broker belongs to.
 */
export function mapAudit(input: unknown, tabId: string): MappedAudit | string {
	if (typeof input !== 'object' || input === null || Array.isArray(input)) {
		return 'not an object';
	}
	const e = input as Record<string, unknown>;
	const type = e.type;
	if (typeof type !== 'string' || !TYPE_RE.test(type)) {
		return 'invalid type';
	}
	if (e.tabId !== undefined && e.tabId !== tabId) {
		return 'tabId mismatch';
	}
	const kind = AUDIT_KINDS[type];
	if (!kind) {
		// Not in the documented list: record that it happened, copy nothing else.
		const d: Detail = { auditType: type };
		if (num(e.seq) !== undefined) {
			d.brokerSeq = num(e.seq)!;
		}
		return { class: 'broker.status', priority: 'notice', summary: `broker: unlisted audit type ${type}`, detail: d };
	}
	const detail: Detail = { auditType: type };
	const seq = num(e.seq);
	if (seq !== undefined) {
		detail.brokerSeq = seq;
	}
	// Broker-produced vocabulary and numbers.
	for (const k of ['scheme', 'decision', 'by', 'kind', 'provider', 'approvalId', 'credentialId', 'parentId', 'rule', 'limit', 'hook'] as const) {
		const v = e[k];
		if (typeof v === 'string') {
			detail[k] = v.slice(0, 96);
		} else if (typeof v === 'number' && Number.isFinite(v)) {
			detail[k] = v;
		}
	}
	for (const k of ['status', 'reqBytes', 'respBytes', 'durationMs', 'requests', 'bytes', 'count', 'revision', 'rules', 'waiting', 'controllers', 'epoch'] as const) {
		const v = num(e[k]);
		if (v !== undefined) {
			detail[k] = v;
		}
	}
	if (typeof e.confirmed === 'boolean') {
		detail.confirmed = e.confirmed;
	}
	// Tab- or upstream-controlled text: copied into fields untrustedFields() always tags.
	const method = str(e.method, 16);
	if (method !== undefined) {
		detail.method = method;
	}
	const path = str(e.path, 512);
	if (path !== undefined) {
		detail.path = path;
	}
	for (const [k, out] of [['reason', 'reason'], ['location', 'location'], ['header', 'header'], ['server', 'server'], ['detail', 'brokerDetail'], ['ip', 'ip']] as const) {
		const v = str(e[k], 256);
		if (v !== undefined) {
			detail[out] = v;
		}
	}
	if (Array.isArray(e.tools)) {
		detail.tools = e.tools.filter((t): t is string => typeof t === 'string').slice(0, 16).join(',').slice(0, 256);
	}
	const risk = e.risk as Record<string, unknown> | undefined;
	if (risk && typeof risk === 'object') {
		if (Array.isArray(risk.flags)) {
			detail.riskFlags = risk.flags.filter((f): f is string => typeof f === 'string').slice(0, 8).join(',');
		}
		const lbl = (risk.origin as Record<string, unknown> | undefined)?.label;
		if (typeof lbl === 'string') {
			detail.originLabel = lbl.slice(0, 96);
		}
	}
	const origin = e.origin as Record<string, unknown> | undefined;
	if (origin && typeof origin === 'object' && typeof origin.label === 'string' && detail.originLabel === undefined) {
		detail.originLabel = origin.label.slice(0, 96);
	}
	if (detail.originLabel !== undefined) {
		// The label is claimed by whatever process in the tab set the proxy username.
		detail.originVerified = false;
	}
	const host = str(e.host, 253);
	const net = host !== undefined ? { addr: host, ...(port(e.port) !== undefined ? { port: port(e.port) } : {}) } : undefined;
	const target = net ? `${detail.scheme ? `${String(detail.scheme)}://` : ''}${net.addr}${net.port !== undefined ? `:${net.port}` : ''}${detail.path ?? ''}` : '';
	const parts = [
		`broker: ${kind.what}`,
		detail.method !== undefined && net ? String(detail.method) : '',
		target,
		detail.status !== undefined && kind.class !== 'broker.status' ? `→ ${detail.status}` : '',
		detail.decision !== undefined ? `(${String(detail.decision)}${detail.by ? ` by ${String(detail.by)}` : ''})` : '',
		detail.reason !== undefined ? `: ${String(detail.reason)}` : '',
	];
	const m: MappedAudit = { class: kind.class, priority: kind.priority, summary: parts.filter(Boolean).join(' ').replace(' :', ':'), detail };
	if (num(e.ts) !== undefined) {
		m.ts = num(e.ts);
	}
	if (net) {
		m.net = net;
	}
	if (kind.agg) {
		// Keys use broker-determined fields only (review BA-1 re-review): the tab can't mint
		// keys by varying a method, a header name or a reason. Variants are only counted.
		m.aggKey = [type, net?.addr ?? '', net?.port ?? '', detail.rule ?? '', detail.credentialId ?? '', detail.provider ?? '', detail.hook ?? ''].join('\u0000');
	}
	return m;
}

export interface AuditControl {
	request(method: string, params?: Record<string, unknown>, timeoutMs?: number): Promise<unknown>;
	onNotification(cb: (n: { method: string; params: unknown }) => void): () => void;
}

export interface AuditSink {
	emit(m: MappedAudit, count?: number): void;
	status(priority: Priority, summary: string, detail: Detail): void;
	/** Every denied or blocked request, before aggregation, timed by the broker (beacon rule). */
	timing?(m: MappedAudit, tMs: number): void;
}

const TIMED = /^(?:request\.denied|request\.denied_unprompted|upstream\.blocked|tcp\.blocked|udp\.blocked|approval\.rate_limited)$/;

interface Agg { m: MappedAudit; extra: number; timer: NodeJS.Timeout }

/** Distinct aggregation keys held at once per audit type, and overall (memory bound). */
export const MAX_KEYS_PER_TYPE = 64;
export const MAX_AGG_KEYS = 1024;

/**
 * One tab's broker audit feed: live notifications plus a replay of `audit.tail` on connect,
 * deduplicated by the broker's `seq`. Seq restarts with a new broker process, identified by
 * the `ts` of its `broker.started` event, or by a tail whose seqs are all below the last one
 * seen. A seq jump is reported as a gap.
 */
export class BrokerAuditFeed {
	private lastSeq = 0;
	private instance: number | undefined;
	private readonly aggs = new Map<string, Agg>();
	private readonly keysByType = new Map<string, number>();
	private unsubscribe: (() => void) | undefined;
	private generation = 0;
	private readonly tabId: string;
	private readonly sink: AuditSink;
	private dropped = 0;

	constructor(tabId: string, sink: AuditSink) {
		this.tabId = tabId;
		this.sink = sink;
	}

	/** A (new) control channel is up: subscribe first, then replay what we missed. */
	async attach(c: AuditControl): Promise<void> {
		this.detach();
		const gen = ++this.generation;
		const early: unknown[] = [];
		let replaying = true;
		this.unsubscribe = c.onNotification(n => {
			if (n.method !== 'audit.event' || gen !== this.generation) {
				return;
			}
			if (replaying) {
				if (early.length < TAIL_LIMIT) {
					early.push(n.params);
				}
				return;
			}
			this.accept(n.params);
		});
		try {
			const r = await c.request('audit.tail', { limit: TAIL_LIMIT }) as { events?: unknown } | undefined;
			if (gen !== this.generation) {
				return;
			}
			const events = (Array.isArray(r?.events) ? r.events : []).slice(-TAIL_LIMIT);
			const started = events.find(e => (e as Record<string, unknown>)?.type === 'broker.started') as Record<string, unknown> | undefined;
			const ts = num(started?.ts);
			const seqs = events.map(e => num((e as Record<string, unknown> | null)?.seq)).filter((s): s is number => s !== undefined);
			const restartedBySeq = this.lastSeq > 0 && seqs.length > 0 && Math.max(...seqs) < this.lastSeq;
			if ((ts !== undefined && ts !== this.instance) || restartedBySeq) {
				// A new broker process: its seq starts again at 1.
				if (this.instance !== undefined || this.lastSeq > 0) {
					this.sink.status('notice', 'broker restarted: audit sequence restarts', { status: 'broker-restart' });
				}
				this.instance = ts;
				this.lastSeq = 0;
			}
			for (const e of events) {
				this.accept(e);
			}
		} catch (e) {
			if (gen === this.generation) {
				this.sink.status('warning', `broker audit replay failed: ${(e as Error).message}`, { status: 'broker-audit-replay' });
			}
		} finally {
			replaying = false;
			if (gen === this.generation) {
				for (const e of early) {
					this.accept(e);
				}
			}
		}
	}

	detach(): void {
		this.generation++;
		this.unsubscribe?.();
		this.unsubscribe = undefined;
		this.flush();
	}

	private accept(input: unknown): void {
		const seq = num((input as Record<string, unknown> | null)?.seq);
		if (seq === undefined || !Number.isInteger(seq) || seq < 1) {
			this.drop('no seq');
			return;
		}
		if (seq <= this.lastSeq) {
			return;
		}
		if (this.lastSeq > 0 && seq > this.lastSeq + 1) {
			this.sink.status('warning', `broker audit gap: ${seq - this.lastSeq - 1} event(s) missed`, { status: 'broker-audit-gap', missed: seq - this.lastSeq - 1 });
		}
		this.lastSeq = seq;
		const m = mapAudit(input, this.tabId);
		if (typeof m === 'string') {
			this.drop(m);
			return;
		}
		this.route(m);
		const ts = num((input as Record<string, unknown>).ts);
		if (m.net && TIMED.test(String(m.detail.auditType)) && ts !== undefined) {
			this.sink.timing?.(m, ts * 1000);
		}
	}

	private route(m: MappedAudit): void {
		if (!m.aggKey) {
			this.sink.emit(m);
			return;
		}
		const a = this.aggs.get(m.aggKey);
		if (a) {
			a.extra++;
			return;
		}
		const type = String(m.detail.auditType);
		if (this.aggs.size >= MAX_AGG_KEYS || (this.keysByType.get(type) ?? 0) >= MAX_KEYS_PER_TYPE) {
			// The key pool for this type is full: emit the event on its own, keeping nothing.
			// Aggregation never loses a record; the hub's per-type bucket bounds the volume
			// and reports what it drops (review BA-1 second re-review).
			this.sink.emit(m);
			return;
		}
		// First of its kind in the window goes out at once; repeats are counted.
		this.sink.emit(m);
		const key = m.aggKey;
		const timer = setTimeout(() => this.flushOne(key), AGG_WINDOW_MS);
		timer.unref();
		this.aggs.set(key, { m, extra: 0, timer });
		this.keysByType.set(type, (this.keysByType.get(type) ?? 0) + 1);
	}

	private flushOne(key: string): void {
		const a = this.aggs.get(key);
		if (!a) {
			return;
		}
		clearTimeout(a.timer);
		this.aggs.delete(key);
		const type = String(a.m.detail.auditType);
		const left = (this.keysByType.get(type) ?? 1) - 1;
		if (left > 0) {
			this.keysByType.set(type, left);
		} else {
			this.keysByType.delete(type);
		}
		if (a.extra > 0) {
			this.sink.emit({ ...a.m, summary: `${a.m.summary} ×${a.extra} more in ${AGG_WINDOW_MS / 1000} s` }, a.extra);
		}
	}

	flush(): void {
		for (const k of [...this.aggs.keys()]) {
			this.flushOne(k);
		}
	}

	private drop(reason: string): void {
		this.dropped++;
		if (this.dropped === 1 || this.dropped % 100 === 0) {
			this.sink.status('warning', `broker audit event dropped (${reason}); ${this.dropped} so far`, { status: 'broker-audit-drop', dropped: this.dropped });
		}
	}
}
