// Write-back gate increment 2b: per-tab engines and the sync loop (ADR write-back-gate).
// One engine per tab (state under <state>/writeback/<tabId>.json, 0600), ticks serialized per
// tab, every decision emitted to observability as a trusted `workspace.gate` event. A failing
// tick holds nothing back incorrectly: nothing is applied unless the engine applied it.

import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { WriteBackEngine, type PendingChange, type UpperChange } from './writeback.ts';
import { mirrorOne, readEntry, syncTick, type TickResult, type UpperReader } from './writeback-feed.ts';
import { WRITEBACK_POLICY } from './writeback-policy.ts';

export interface GateEvent { class: 'workspace.gate'; priority: 'informational' | 'warning'; summary: string; file?: { path: string }; detail: Record<string, string | number | boolean> }

export interface WriteBackManagerOptions {
	readonly dir: string;
	readonly intervalMs?: number;
	readonly emit?: (tabId: string, ev: GateEvent) => void;
	readonly audit?: (event: string, outcome: string, detail: Record<string, unknown>) => void;
	/** The number of held changes for a tab changed (drives the editor's prompt). */
	readonly onPending?: (tabId: string, count: number) => void;
}

interface TabState { engine: WriteBackEngine; reader: UpperReader; root: string; timer?: NodeJS.Timeout; busy?: Promise<TickResult>; lastSync?: number; lastError?: string; lastPending?: number }

export class WriteBackManager {
	private readonly o: WriteBackManagerOptions;
	private readonly tabs = new Map<string, TabState>();

	constructor(o: WriteBackManagerOptions) {
		this.o = o;
		fs.mkdirSync(o.dir, { recursive: true, mode: 0o700 });
	}

	private statePath(tabId: string): string {
		if (!/^t-[a-z2-7]{26}$/.test(tabId)) {
			throw new Error('bad tab id');
		}
		return path.join(this.o.dir, `${tabId}.json`);
	}

	/** Start syncing a running, gated tab. Idempotent. */
	start(tabId: string, root: string, rootIdentity: { dev: string; ino: string }, reader: UpperReader): void {
		if (this.tabs.has(tabId)) {
			return;
		}
		const engine = new WriteBackEngine({ root, rootIdentity, statePath: this.statePath(tabId) });
		const t: TabState = { engine, reader, root };
		this.tabs.set(tabId, t);
		t.timer = setInterval(() => {
			this.sync(tabId).catch(() => { /* recorded in lastError */ });
		}, this.o.intervalMs ?? 3000);
		t.timer.unref?.();
	}

	/** Stop syncing (the tab stopped). Pending state stays on disk and is listed again later. */
	stop(tabId: string): void {
		const t = this.tabs.get(tabId);
		if (t?.timer) {
			clearInterval(t.timer);
		}
		t?.engine.close(); // a tick still running can no longer save or write (NN-3)
		this.tabs.delete(tabId);
	}

	/** The tab's VM (and so its upper layer) is gone: forget everything for it. */
	discard(tabId: string): void {
		this.stop(tabId);
		fs.rmSync(this.statePath(tabId), { force: true });
	}

	async sync(tabId: string): Promise<TickResult> {
		const t = this.tabs.get(tabId);
		if (!t) {
			throw new Error('write-back is not active for this tab');
		}
		if (t.busy) {
			return t.busy;
		}
		t.busy = (async () => {
			try {
				const r = await syncTick(t.engine, t.reader, t.root, WRITEBACK_POLICY.caps.maxFileBytes);
				t.lastSync = Date.now();
				t.lastError = undefined;
				this.report(tabId, r);
				return r;
			} catch (e) {
				t.lastError = (e as Error).message.slice(0, 300);
				this.o.audit?.('writeback.sync', 'error', { tabId, error: t.lastError });
				throw e;
			} finally {
				t.busy = undefined;
			}
		})();
		return t.busy;
	}

	/** Both sides of a pending change, for the review UI (display only, capped). */
	async content(tabId: string, rel: string): Promise<Record<string, unknown>> {
		const t = this.active(tabId);
		const p = t.engine.pending().find(x => x.path === rel);
		if (!p) {
			throw new Error('no such pending change');
		}
		const cap = WRITEBACK_POLICY.caps.maxDiffBytes;
		const host = t.engine.hostContent(rel, cap);
		const c = await readEntry(t.reader, rel, WRITEBACK_POLICY.caps.maxFileBytes);
		// The displayed bytes must be the held bytes: the signature returned is that of this
		// read, and it must equal the held one, or a tab could show one version to the diff and
		// another to the decision (review OO-1). decide() binds to it and re-reads again.
		if (!c || t.engine.sigOf(c) !== p.sig) {
			throw new Error('the tab changed this entry since it was held; it will be listed again for review');
		}
		return {
			path: rel, kind: p.kind, reasons: p.reasons, sig: t.engine.sigOf(c),
			host: { exists: host.exists, kind: host.kind, size: host.size, b64: host.content?.toString('base64'), truncated: (host.size ?? 0) > cap },
			tab: { kind: c.kind, size: c.content?.length, b64: c.content?.subarray(0, cap).toString('base64'), truncated: (c.content?.length ?? 0) > cap, target: c.target, mode: c.mode },
		};
	}

	/**
	 * The user's decision on a held change (increment 3). Bound to the signature the UI showed:
	 * the tab's entry is re-read and the engine refuses if it changed (W-3).
	 */
	async decide(tabId: string, rel: string, decision: 'approve' | 'reject' | 'always', shownSig: string): Promise<{ result: string }> {
		const t = this.active(tabId);
		await t.busy?.catch(() => { /* tick errors are recorded */ });
		const p = t.engine.pending().find(x => x.path === rel);
		if (!p) {
			throw new Error('no such pending change');
		}
		if (p.sig !== shownSig) {
			throw new Error('the tab changed this entry since it was shown; review again');
		}
		const c = await readEntry(t.reader, rel, WRITEBACK_POLICY.caps.maxFileBytes);
		if (!c) {
			throw new Error('the tab no longer has this change');
		}
		let result: string;
		if (decision === 'reject') {
			const host = t.engine.reject(rel);
			let restored: string | undefined;
			if (c.kind === 'file' && host.content) {
				restored = await mirrorOne(t.reader, rel, createHash('sha256').update(c.content ?? Buffer.alloc(0)).digest('hex'), host.content);
			}
			if (restored) {
				t.engine.noteMirrored(rel, restored, c.mode ?? 0o644, c.nlink ?? 1);
				result = 'rejected; the original is restored in the tab';
			} else {
				t.engine.markDecided(rel, c as UpperChange);
				result = 'rejected; the host keeps its version, the tab keeps its own copy';
			}
		} else {
			if (decision === 'always') {
				t.engine.alwaysAllow(rel);
			}
			t.engine.approve(rel, c);
			result = 'applied';
		}
		this.o.emit?.(tabId, { class: 'workspace.gate', priority: 'informational', summary: `${decision} ${rel}`.slice(0, 300), file: { path: rel }, detail: { decision, decidedBy: 'user', kind: p.kind, tabHash: p.sig, hostHashBefore: p.hostHash } });
		this.pendingChanged(tabId);
		return { result };
	}

	/** The user confirmed held mass deletions: release the sticky brake. Bound to the count the user saw (OO-6). */
	confirmDeletes(tabId: string, shownCount: number): void {
		const t = this.active(tabId);
		if (t.engine.heldMassDeletions() !== shownCount) {
			throw new Error('the held deletions changed since they were shown; review again');
		}
		t.engine.clearDeleteHold();
		this.o.emit?.(tabId, { class: 'workspace.gate', priority: 'informational', summary: `mass-deletion hold released by the user (${shownCount} held)`, detail: { decision: 'confirm-deletes', decidedBy: 'user' } });
	}

	private active(tabId: string): TabState {
		const t = this.tabs.get(tabId);
		if (!t) {
			throw new Error('the tab is not running; start it to review its changes');
		}
		return t;
	}

	private pendingChanged(tabId: string): void {
		const t = this.tabs.get(tabId);
		const n = t?.engine.pending().length ?? 0;
		if (t && n !== t.lastPending) {
			t.lastPending = n;
			this.o.onPending?.(tabId, n);
		}
	}

	status(tabId: string): { active: boolean; pending: PendingChange[]; lastSync?: number; lastError?: string } {
		const t = this.tabs.get(tabId);
		if (t) {
			return { active: true, pending: t.engine.pending(), lastSync: t.lastSync, lastError: t.lastError };
		}
		// Not running: pending changes recorded on disk are still listed (fail closed, ADR §5).
		try {
			const s = JSON.parse(fs.readFileSync(this.statePath(tabId), 'utf8')) as { pending?: PendingChange[] };
			return { active: false, pending: Array.isArray(s.pending) ? s.pending : [] };
		} catch {
			return { active: false, pending: [] };
		}
	}

	private report(tabId: string, r: TickResult): void {
		this.pendingChanged(tabId);
		const emit = this.o.emit;
		if (!emit) {
			return;
		}
		for (const p of r.applied) {
			emit(tabId, { class: 'workspace.gate', priority: 'informational', summary: `synced ${p}`, file: { path: p }, detail: { decision: 'auto', decidedBy: 'policy' } });
		}
		for (const h of r.held) {
			emit(tabId, { class: 'workspace.gate', priority: 'warning', summary: `held ${h.path}: ${h.reasons.join('; ')}`.slice(0, 300), file: { path: h.path }, detail: { decision: 'held', decidedBy: 'policy', kind: h.kind, tabHash: h.sig, hostHashBefore: h.hostHash } });
		}
		for (const x of r.refused) {
			emit(tabId, { class: 'workspace.gate', priority: 'informational', summary: `not written back ${x.path}: ${x.reason}`.slice(0, 300), file: { path: x.path }, detail: { decision: 'refused', decidedBy: 'policy' } });
		}
		for (const p of r.mirrored) {
			emit(tabId, { class: 'workspace.gate', priority: 'informational', summary: `host edit mirrored into the tab: ${p}`, file: { path: p }, detail: { decision: 'mirrored', decidedBy: 'policy' } });
		}
	}
}
