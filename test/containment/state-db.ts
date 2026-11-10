// The isolated test profile's state database: where globalState and SecretStorage land.
//
//   seedTabManagerState(userData, value)   before the editor first runs: the Tab Manager's
//                                          real globalState key holds a canary
//   partitionFindings(userData, tabId)     after the run: where the rogue probes' claimed-id
//                                          writes landed, as pass/fail facts
//
// Only ever an isolated profile under ~/.seclab-test (checkIsolatedProfile): never a real
// editor profile. Reads open the database read-only.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { checkIsolatedProfile } from '../harness.ts';

export const TAB_MANAGER = 'seclab.tab-manager';
/** What the rogue probes write under the claimed id (rpc-probes.js). */
export const PROBE_STATE_WRITE = 'written-by-a-tab';
export const PROBE_SECRET_KEY = 'seclab-probe-claim';

export function stateDbPath(userData: string): string {
	return path.join(userData, 'User', 'globalStorage', 'state.vscdb');
}

/** Seed the Tab Manager's globalState in a profile the editor has not opened yet. */
export function seedTabManagerState(userData: string, value: Record<string, unknown>): void {
	checkIsolatedProfile(userData);
	const file = stateDbPath(userData);
	if (fs.existsSync(file)) {
		throw new Error(`${file} exists: seed only a fresh profile, before the editor first runs`);
	}
	fs.mkdirSync(path.dirname(file), { recursive: true });
	const db = new DatabaseSync(file);
	try {
		db.exec('CREATE TABLE IF NOT EXISTS ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)');
		db.prepare('INSERT INTO ItemTable (key, value) VALUES (?, ?)').run(TAB_MANAGER, JSON.stringify(value));
	} finally {
		db.close();
	}
}

/** Keys and values of the profile's state database, read-only; undefined if it cannot be read. */
export function stateItems(userData: string): Map<string, string> | undefined {
	const file = stateDbPath(userData);
	if (!fs.existsSync(file)) {
		return undefined;
	}
	try {
		const db = new DatabaseSync(file, { readOnly: true });
		try {
			const rows = db.prepare('SELECT key, value FROM ItemTable').all() as Array<{ key: string; value: unknown }>;
			return new Map(rows.map(r => [String(r.key), typeof r.value === 'string' ? r.value : Buffer.from(r.value as Uint8Array).toString('utf8')]));
		} finally {
			db.close();
		}
	} catch {
		return undefined;
	}
}

export interface PartitionFinding { name: string; ok: boolean; detail: string }

/**
 * Where the probes' claimed-id writes landed. Contained: nothing under the Tab Manager's
 * real keys, and the write present under this tab's partition (which also shows the probe ran).
 */
export function partitionFindings(items: Map<string, string> | undefined, tabId: string): PartitionFinding[] {
	if (!items) {
		return [{ name: 'the profile state database was readable', ok: false, detail: 'missing or unreadable' }];
	}
	const real = items.get(TAB_MANAGER) ?? '';
	const part = items.get(`seclab-tab:${tabId}/${TAB_MANAGER}`) ?? '';
	const secretKeys = [...items.keys()].filter(k => k.startsWith('secret://'));
	const parse = (k: string): Record<string, unknown> => { try { return JSON.parse(k.slice('secret://'.length)); } catch { return {}; } };
	const unpartitionedSecret = secretKeys.some(k => { const p = parse(k); return p.extensionId === TAB_MANAGER && p.seclabTab === undefined; });
	const partitionedSecret = secretKeys.some(k => { const p = parse(k); return p.extensionId === TAB_MANAGER && p.seclabTab === tabId && p.key === PROBE_SECRET_KEY; });
	return [
		{ name: 'a claimed-id state write did not reach the Tab Manager\'s globalState', ok: !real.includes(PROBE_STATE_WRITE), detail: real.includes(PROBE_STATE_WRITE) ? 'the probe\'s write is under seclab.tab-manager' : '' },
		{ name: 'the claimed-id state write landed in this tab\'s partition (the probe ran)', ok: part.includes(PROBE_STATE_WRITE), detail: part ? '' : `no seclab-tab:${tabId}/${TAB_MANAGER} key` },
		{ name: 'a claimed-id secret write did not land under the Tab Manager\'s id', ok: !unpartitionedSecret, detail: unpartitionedSecret ? 'an unpartitioned secret:// key names seclab.tab-manager' : '' },
		{ name: 'the claimed-id secret write landed in this tab\'s partition (the probe ran)', ok: partitionedSecret, detail: partitionedSecret ? '' : `${secretKeys.length} secret key(s), none in this tab's partition` },
	];
}
