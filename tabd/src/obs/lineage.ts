// Process lineage for broker requests (ADR tab-observability §5 "lineage hints"; plan
// tabd-broker-wiring B6; EDR broker-audit-in-tab-events). The broker sees requests, not
// processes; the sensors see processes connecting to the broker, not requests. tabd joins
// them by time: the connects to the broker endpoint shortly before a broker event are the
// candidates. `single` means exactly one unused connect was in the window, not proof that this
// process made the request: a kept-alive connection carries later requests without a new
// connect, so such a request can be pinned on whoever connected next (review LN-2), or read as
// none. The result is never stronger than its weakest input: a sbx strace connect is
// `tab-vm-root`, an OCI Falco connect `host-observed`. Hence "probable", never "verified".

import type { TabContext } from './detect.ts';
import { weakestIntegrity, type Integrity, type ObsEvent, type ProcInfo } from './schema.ts';

/** How far before a broker event a connect may be, and how far after (clock and deferral slack). */
export const WINDOW_BEFORE_MS = 5_000;
export const WINDOW_AFTER_MS = 500;
const MAX_CONNECTS = 256;

interface Connect { t: number; seq: number; integrity: Integrity; proc: ProcInfo; used?: boolean }

export interface Attribution {
	confidence: 'single' | 'ambiguous' | 'none';
	candidates: number;
	/** The nearest candidate (closest in time); absent when there is none. */
	proc?: ProcInfo;
	/**
	 * Never `trusted`: with candidates, the weakest of them; with none, the tab's sensor level,
	 * because a tab can cause "no process observed" (a kept-alive connection, a dropped line).
	 */
	integrity: Integrity;
	/** Oldest ancestor first, then the process itself: "bash → node → curl". */
	chain?: string;
	cause: number[];
	/** Computed on request rather than recorded when the broker event arrived. */
	computed?: true;
}

const base = (s: string) => {
	const first = s.split(' ')[0] ?? s;
	return first.slice(first.lastIndexOf('/') + 1) || first;
};

/** A short, display-only chain from a process and its lineage (tab-chosen text: caller escapes). */
export function chainOf(p: ProcInfo): string {
	const parts = [...(p.lineage ?? [])].reverse().map(l => base(l.exe));
	parts.push(base(p.argv?.[0] ?? p.exe ?? String(p.pid ?? '?')));
	// Drop the long tail of supervisor ancestors; keep the last six hops.
	return parts.slice(-6).join(' → ');
}

export class LineageCorrelator {
	private readonly connects = new Map<string, Connect[]>();

	/** Feed every stamped event; only connects to the tab's broker endpoint are kept. */
	observe(e: ObsEvent, ctx: TabContext): void {
		if (e.class !== 'net.connect' || !e.net || !e.proc || e.integrity === 'trusted') {
			return;
		}
		const n = e.net;
		if (ctx.brokerPort === undefined || n.port !== ctx.brokerPort || !(ctx.brokerAddrs?.has(n.addr) ?? false)) {
			return;
		}
		if (n.result !== 'ok' && n.result !== 'pending') {
			return;
		}
		if (n.proto === 'udp') {
			// A UDP connect (e.g. glibc's address-selection probe in getaddrinfo) carries no request.
			return;
		}
		let list = this.connects.get(e.tabId);
		if (!list) {
			list = [];
			this.connects.set(e.tabId, list);
		}
		list.push({ t: Date.parse(e.time), seq: e.seq, integrity: e.integrity, proc: e.proc });
		if (list.length > MAX_CONNECTS) {
			list.splice(0, list.length - MAX_CONNECTS);
		}
	}

	/**
	 * Candidates for a broker event that tabd stamped at `atMs`. With `consume`, the chosen
	 * connect is used up: one connection is normally one request, so it isn't counted again for
	 * a later event (a second request on a kept-alive connection then reads as "none").
	 */
	attribute(tabId: string, atMs: number, consume = false, sensorIntegrity: Integrity = 'tab-vm-root'): Attribution {
		const list = this.connects.get(tabId) ?? [];
		const inWindow = list.filter(c => !c.used && c.t >= atMs - WINDOW_BEFORE_MS && c.t <= atMs + WINDOW_AFTER_MS);
		// One process may open several connections (happy eyeballs, retries): count processes.
		const byPid = new Map<number, Connect>();
		for (const c of inWindow) {
			const key = c.proc.pid ?? -c.seq;
			const prev = byPid.get(key);
			if (!prev || Math.abs(c.t - atMs) < Math.abs(prev.t - atMs)) {
				byPid.set(key, c);
			}
		}
		const cands = [...byPid.values()].sort((a, b) => Math.abs(a.t - atMs) - Math.abs(b.t - atMs));
		if (!cands.length) {
			return { confidence: 'none', candidates: 0, integrity: sensorIntegrity, cause: [] };
		}
		const best = cands[0];
		if (consume) {
			// Every connect of the chosen process in the window (it may have opened several).
			for (const c of inWindow) {
				if (c.proc.pid === best.proc.pid) {
					c.used = true;
				}
			}
		}
		return {
			confidence: cands.length === 1 ? 'single' : 'ambiguous',
			candidates: cands.length,
			proc: best.proc,
			integrity: weakestIntegrity(cands.map(c => c.integrity)),
			chain: chainOf(best.proc),
			cause: cands.slice(0, 8).map(c => c.seq),
		};
	}

	forget(tabId: string): void {
		this.connects.delete(tabId);
	}
}
