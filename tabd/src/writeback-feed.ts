// Write-back gate increment 2b: one sync tick from a tab's upper layer to the host checkout
// (ADR write-back-gate). The reader runs seclab-wb-feed inside the tab's VM as root; everything
// it returns is tab-controlled data, parsed strictly and bounded here, and every decision is the
// engine's. Directories are not synced on their own (files carry their parents); opaque
// directories are expanded against the host into per-file deletions.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { checkRel, metaSig, type SyncResult, type UpperChange, type WriteBackEngine } from './writeback.ts';

export interface UpperReader {
	/** `seclab-wb-feed <mode>` with the given stdin lines; returns stdout. */
	feed(mode: 'list' | 'get' | 'mirror', input?: string): Promise<string>;
}

interface Entry { p: string; k: 'file' | 'dir' | 'symlink' | 'special' | 'wh' | 'opq' | 'err'; m?: number; n?: number; s?: number; h?: string; t?: string }
export interface TickResult extends SyncResult { mirrored: string[]; truncated: boolean }

const MAX_LINES = 300_001;
const HEX64 = /^[0-9a-f]{64}$/;

function lines(out: string): unknown[] {
	const ls = out.split('\n').filter(Boolean);
	if (ls.length > MAX_LINES) {
		throw new Error('feed output too long');
	}
	return ls.map(l => JSON.parse(l) as unknown);
}

function parseList(out: string): { entries: Entry[]; truncated: boolean } {
	const recs = lines(out);
	const done = recs.at(-1) as { done?: boolean; truncated?: boolean } | undefined;
	if (!done?.done) {
		throw new Error('feed list did not complete');
	}
	const entries: Entry[] = [];
	for (const r of recs.slice(0, -1) as Entry[]) {
		if (!r || typeof r !== 'object' || !['file', 'dir', 'symlink', 'special', 'wh', 'opq', 'err'].includes(r.k)) {
			throw new Error('bad feed record');
		}
		if ((r.k === 'opq' || r.k === 'err') && r.p === '') {
			entries.push(r); // the workspace root itself
			continue;
		}
		checkRel(r.p);
		if ((r.m !== undefined && !Number.isInteger(r.m)) || (r.n !== undefined && !Number.isInteger(r.n)) || (r.h !== undefined && !HEX64.test(r.h))
			|| (r.t !== undefined && (typeof r.t !== 'string' || r.t.length > 4096))) {
			throw new Error('bad feed record fields');
		}
		entries.push(r);
	}
	return { entries, truncated: !!done.truncated };
}

/** Host files under `rel` (a workspace directory), lstat only, never following links. */
function hostFilesUnder(root: string, rel: string, cap: number): string[] {
	const out: string[] = [];
	const walk = (abs: string, r: string) => {
		let ents: fs.Dirent[];
		try {
			ents = fs.readdirSync(abs, { withFileTypes: true });
		} catch {
			return;
		}
		for (const e of ents) {
			if (out.length >= cap) {
				return;
			}
			const cr = r ? `${r}/${e.name}` : e.name;
			if (e.isDirectory()) {
				walk(path.join(abs, e.name), cr);
			} else {
				out.push(cr);
			}
		}
	};
	const abs = rel ? path.join(root, ...rel.split('/')) : root;
	try {
		if (!fs.lstatSync(abs).isDirectory()) {
			return out;
		}
	} catch {
		return out;
	}
	walk(abs, rel);
	return out;
}

export async function syncTick(engine: WriteBackEngine, reader: UpperReader, root: string, maxFileBytes: number): Promise<TickResult> {
	const { entries, truncated } = parseList(await reader.feed('list'));
	const present = new Set<string>();
	const changes: UpperChange[] = [];
	const refused: Array<{ path: string; reason: string }> = [];
	const need: Entry[] = [];
	const unchanged: Array<{ path: string; sha: string; mode: number; nlink: number }> = [];
	let incomplete = false;
	for (const e of entries) {
		switch (e.k) {
			case 'dir':
				break;
			case 'file': {
				present.add(e.p);
				if (e.h === undefined) {
					refused.push({ path: e.p, reason: (e.s ?? 0) > maxFileBytes ? 'larger than the per-file cap (never written back)' : 'unreadable in the upper layer' });
					break;
				}
				const s = metaSig({ kind: 'file', mode: e.m, sha: e.h, nlink: e.n });
				if (engine.isSynced(e.p, s)) {
					unchanged.push({ path: e.p, sha: e.h, mode: e.m ?? 0, nlink: e.n ?? 1 });
				} else {
					need.push(e);
				}
				break;
			}
			case 'symlink':
				present.add(e.p);
				changes.push({ path: e.p, kind: 'symlink', mode: e.m, nlink: e.n, target: e.t ?? '' });
				break;
			case 'special':
				present.add(e.p);
				changes.push({ path: e.p, kind: 'special', mode: e.m, nlink: e.n });
				break;
			case 'wh':
				present.add(e.p);
				changes.push({ path: e.p, kind: 'deleted' });
				break;
			case 'opq':
				// The tab replaced this directory: every lower child is hidden. One held "directory
				// deletion" item, like a whiteout of the directory, never per-file auto deletions
				// (review MM-1). The workspace root can't be replaced.
				if (e.p !== '' && hostFilesUnder(root, e.p, 1).length) {
					present.add(e.p);
					changes.push({ path: e.p, kind: 'deleted' });
				}
				break;
			case 'err':
				incomplete = true;
				break;
		}
	}
	// A listing that is truncated or couldn't read a directory may omit files the tab still has:
	// apply no deletions from it (review MM-2).
	if (truncated || incomplete) {
		for (let i = changes.length - 1; i >= 0; i--) {
			if (changes[i].kind === 'deleted') {
				changes.splice(i, 1);
			}
		}
	}
	if (need.length) {
		// Bounded per tick (count and bytes); the rest is read on the next tick.
		let budget = 32 << 20;
		const batch = need.filter((e, i) => i < 1000 && (budget -= e.s ?? 0) >= 0);
		need.length = 0;
		need.push(...batch);
	}
	if (need.length) {
		const got = lines(await reader.feed('get', need.map(e => JSON.stringify({ p: e.p })).join('\n') + '\n')) as Array<{ p?: string; b64?: string; m?: number; n?: number; err?: string }>;
		const wanted = new Set(need.map(e => e.p));
		for (const g of got) {
			if (typeof g?.p !== 'string' || !wanted.has(g.p)) {
				throw new Error('feed get answered for a path it was not asked');
			}
			wanted.delete(g.p);
			if (g.err !== undefined || typeof g.b64 !== 'string') {
				refused.push({ path: g.p, reason: `not read: ${String(g.err).slice(0, 80)}` });
				continue;
			}
			const content = Buffer.from(g.b64, 'base64');
			if (content.length > maxFileBytes) {
				refused.push({ path: g.p, reason: 'larger than the per-file cap (never written back)' });
				continue;
			}
			changes.push({ path: g.p, kind: 'file', mode: g.m, nlink: g.n, content });
		}
	}
	const res = engine.sync(changes);
	if (!truncated && !incomplete) {
		engine.forgetAbsent(present);
	}
	const mirrored: string[] = [];
	const ops = engine.mirrorPlan(unchanged);
	if (ops.length) {
		const outp = lines(await reader.feed('mirror', ops.map(o => JSON.stringify({ p: o.path, expect: o.expect, b64: o.content.toString('base64') })).join('\n') + '\n')) as Array<{ p?: string; ok?: boolean; h?: string }>;
		for (const r of outp) {
			const op = ops.find(o => o.path === r?.p);
			const u = unchanged.find(x => x.path === r?.p);
			if (op && u && r.ok === true && typeof r.h === 'string' && HEX64.test(r.h)) {
				engine.noteMirrored(op.path, r.h, u.mode, u.nlink);
				mirrored.push(op.path);
			}
		}
	}
	return { ...res, refused: [...refused, ...res.refused], mirrored, truncated };
}
