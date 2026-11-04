// Durable tab registry. Lock-free across concurrent supervisors (one per editor
// window): per-tab files plus an O_EXCL path claim keyed by sha256(hostPath).

import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { assertTabId, CONNECTION_TOKEN_RE, foldPath, mintConnectionToken, mintTabId, TEMPLATE_NAME_RE, ValidationError } from './validate.ts';

export interface TabRecord {
	readonly tabId: string;
	readonly hostPath: string;
	readonly templateName: string;
	readonly createdAt: string;
	readonly connectionToken: string;
	/** Filesystem identity at claim time; re-checked before every start. */
	readonly dev: string;
	readonly ino: string;
	/** Runtime driver the tab was created for (absent in records from before it was kept). */
	readonly driver?: string;
}

export function fileIdentity(p: string): { dev: string; ino: string } {
	const st = fs.statSync(p, { bigint: true });
	return { dev: st.dev.toString(), ino: st.ino.toString() };
}

function overlaps(a: string, b: string): boolean {
	const x = foldPath(a), y = foldPath(b);
	return x === y || x.startsWith(y + path.sep) || y.startsWith(x + path.sep);
}

export class TabStore {
	private readonly tabsDir: string;
	private readonly byPathDir: string;

	constructor(stateDir: string) {
		if (!path.isAbsolute(stateDir)) {
			throw new Error('state dir must be absolute');
		}
		this.tabsDir = path.join(stateDir, 'tabs');
		this.byPathDir = path.join(stateDir, 'by-path');
		for (const d of [stateDir, this.tabsDir, this.byPathDir]) {
			fs.mkdirSync(d, { recursive: true, mode: 0o700 });
		}
	}

	/** Returns the tab for hostPath (already canonical), creating it if needed. */
	claim(hostPath: string, templateName: string, driver?: string): { record: TabRecord; created: boolean } {
		if (!TEMPLATE_NAME_RE.test(templateName)) {
			throw new Error('invalid template name');
		}
		const key = createHash('sha256').update(foldPath(hostPath)).digest('hex');
		const claimFile = path.join(this.byPathDir, `${key}.json`);
		if (!fs.existsSync(claimFile)) {
			// No nested or overlapping tabs: a parent tab could write a child's .vscode/.git config.
			for (const other of this.list()) {
				if (overlaps(other.hostPath, hostPath)) {
					throw new ValidationError(`workspace overlaps existing tab ${other.tabId} (${other.hostPath})`);
				}
			}
		}
		const candidate: TabRecord = {
			tabId: mintTabId(), hostPath, templateName, createdAt: new Date().toISOString(), connectionToken: mintConnectionToken(),
			...fileIdentity(hostPath), ...(driver ? { driver } : {}),
		};
		// Write the tab record first, then race for the path claim.
		this.writeRecord(candidate);
		try {
			fs.writeFileSync(claimFile, JSON.stringify({ tabId: candidate.tabId, hostPath }), { flag: 'wx', mode: 0o600 });
			return { record: candidate, created: true };
		} catch (e) {
			if ((e as NodeJS.ErrnoException).code !== 'EEXIST') {
				throw e;
			}
			fs.rmSync(this.recordFile(candidate.tabId), { force: true });
			const claimed = JSON.parse(fs.readFileSync(claimFile, 'utf8')) as { tabId: unknown; hostPath: unknown };
			if (typeof claimed.hostPath !== 'string' || foldPath(claimed.hostPath) !== foldPath(hostPath)) {
				throw new Error('path claim collision');
			}
			const existing = this.get(assertTabId(claimed.tabId));
			if (!existing) {
				throw new Error('dangling path claim');
			}
			return { record: existing, created: false };
		}
	}

	get(tabId: string): TabRecord | undefined {
		assertTabId(tabId);
		let raw: string;
		try {
			raw = fs.readFileSync(this.recordFile(tabId), 'utf8');
		} catch {
			return undefined;
		}
		const r = JSON.parse(raw) as TabRecord;
		if (r.tabId !== tabId || typeof r.hostPath !== 'string' || !path.isAbsolute(r.hostPath) ||
			!TEMPLATE_NAME_RE.test(r.templateName) || !CONNECTION_TOKEN_RE.test(r.connectionToken) ||
			!/^[0-9]+$/.test(String(r.dev)) || !/^[0-9]+$/.test(String(r.ino)) || (r.driver !== undefined && !/^[a-z]{1,16}$/.test(String(r.driver)))) {
			throw new Error(`corrupt tab record ${tabId}`);
		}
		return r;
	}

	list(): TabRecord[] {
		const out: TabRecord[] = [];
		for (const f of fs.readdirSync(this.tabsDir)) {
			const m = /^(t-[a-z2-7]{26})\.json$/.exec(f);
			if (m) {
				const r = this.get(m[1]);
				if (r) {
					out.push(r);
				}
			}
		}
		return out;
	}

	forget(tabId: string): void {
		const r = this.get(tabId);
		if (!r) {
			return;
		}
		const key = createHash('sha256').update(foldPath(r.hostPath)).digest('hex');
		fs.rmSync(path.join(this.byPathDir, `${key}.json`), { force: true });
		fs.rmSync(this.recordFile(tabId), { force: true });
		fs.rmSync(path.join(this.tabsDir, `${tabId}.used`), { force: true });
		this.clearLease(tabId);
	}

	// Leases: which live supervisor (pid) is monitoring a running tab's fence.
	private leaseFile(tabId: string): string {
		return path.join(this.tabsDir, `${assertTabId(tabId)}.lease`);
	}

	// Host-side vault of secrets moved out of a workspace (until the broker imports them)
	// and the record of "open anyway" secret exceptions. Both 0600, outside every tab.
	private sideFile(tabId: string, kind: 'vault' | 'exceptions'): string {
		return path.join(this.tabsDir, `${assertTabId(tabId)}.${kind}.json`);
	}

	readSide<T>(tabId: string, kind: 'vault' | 'exceptions'): T[] {
		try {
			const v = JSON.parse(fs.readFileSync(this.sideFile(tabId, kind), 'utf8'));
			return Array.isArray(v) ? v as T[] : [];
		} catch {
			return [];
		}
	}

	writeSide<T>(tabId: string, kind: 'vault' | 'exceptions', entries: readonly T[]): void {
		const file = this.sideFile(tabId, kind);
		const tmp = `${file}.${process.pid}.tmp`;
		fs.writeFileSync(tmp, JSON.stringify(entries), { mode: 0o600 });
		fs.renameSync(tmp, file);
	}

	writeLease(tabId: string, pid: number): void {
		fs.writeFileSync(this.leaseFile(tabId), String(pid), { mode: 0o600 });
	}

	/** Last use (start or connect), for garbage collection of stopped tabs. */
	touch(tabId: string): void {
		fs.writeFileSync(path.join(this.tabsDir, `${assertTabId(tabId)}.used`), new Date().toISOString(), { mode: 0o600 });
	}

	/** Last use in ms since the epoch; tabs never used since this existed count from creation. */
	lastUsed(r: TabRecord): number {
		try {
			const t = Date.parse(fs.readFileSync(path.join(this.tabsDir, `${assertTabId(r.tabId)}.used`), 'utf8'));
			if (Number.isFinite(t)) {
				return t;
			}
		} catch { /* never touched */ }
		const c = Date.parse(r.createdAt);
		return Number.isFinite(c) ? c : Date.now();
	}

	leaseHolder(tabId: string): number | undefined {
		try {
			const pid = Number(fs.readFileSync(this.leaseFile(tabId), 'utf8'));
			return Number.isInteger(pid) && pid > 0 ? pid : undefined;
		} catch {
			return undefined;
		}
	}

	clearLease(tabId: string, onlyIfPid?: number): void {
		if (onlyIfPid === undefined || this.leaseHolder(tabId) === onlyIfPid) {
			fs.rmSync(this.leaseFile(tabId), { force: true });
		}
	}

	private recordFile(tabId: string): string {
		return path.join(this.tabsDir, `${assertTabId(tabId)}.json`);
	}

	private writeRecord(r: TabRecord): void {
		const file = this.recordFile(r.tabId);
		const tmp = `${file}.${process.pid}.tmp`;
		fs.writeFileSync(tmp, JSON.stringify(r), { mode: 0o600 });
		fs.renameSync(tmp, file);
	}
}
