// Write-back gate increment 2b: per-tab engines and the sync loop (ADR write-back-gate).
// One engine per tab (state under <state>/writeback/<tabId>.json, 0600), ticks serialized per
// tab, every decision emitted to observability as a trusted `workspace.gate` event. A failing
// tick holds nothing back incorrectly: nothing is applied unless the engine applied it.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { WriteBackEngine, type PendingChange } from './writeback.ts';
import { syncTick, type TickResult, type UpperReader } from './writeback-feed.ts';
import { WRITEBACK_POLICY } from './writeback-policy.ts';

export interface GateEvent { class: 'workspace.gate'; priority: 'informational' | 'warning'; summary: string; file?: { path: string }; detail: Record<string, string | number | boolean> }

export interface WriteBackManagerOptions {
	readonly dir: string;
	readonly intervalMs?: number;
	readonly emit?: (tabId: string, ev: GateEvent) => void;
	readonly audit?: (event: string, outcome: string, detail: Record<string, unknown>) => void;
}

interface TabState { engine: WriteBackEngine; reader: UpperReader; root: string; timer?: NodeJS.Timeout; busy?: Promise<TickResult>; lastSync?: number; lastError?: string }

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
