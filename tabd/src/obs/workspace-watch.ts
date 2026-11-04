// Trusted workspace watcher (ADR tab-observability §2): the tab writes its workspace through
// virtiofs (sbx) or a bind mount (OCI); the host sees the same directory. Paths are
// tab-chosen: they are only joined under the workspace root, lstat'ed (never followed), and a
// file is read (package.json, to diff its scripts) only when its realpath stays inside the root.

import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { isHostExecutablePath } from './detect.ts';
import type { ObsHub } from './hub.ts';

const QUIET = /(?:^|\/)(?:\.git\/objects|\.git\/logs|node_modules|\.seclab-evidence)(?:\/|$)/;
const MAX_PENDING = 2000;
const MAX_INDIVIDUAL = 50;
const MAX_JSON = 256 * 1024;

export class WorkspaceWatcher {
	private readonly tabId: string;
	private readonly root: string;
	private readonly realRoot: string;
	private readonly hub: ObsHub;
	private watcher?: fs.FSWatcher;
	private readonly pending = new Map<string, number>();
	private timer?: NodeJS.Timeout;
	private bulk = new Map<string, number>();
	private overflow = 0;
	private readonly scripts = new Map<string, string>();

	constructor(tabId: string, root: string, hub: ObsHub) {
		this.tabId = tabId;
		this.root = root;
		this.realRoot = fs.realpathSync.native(root);
		this.hub = hub;
	}

	start(): void {
		this.scripts.set('package.json', this.scriptsHash('package.json') ?? '');
		try {
			this.watcher = fs.watch(this.root, { recursive: true, persistent: false }, (_type, name) => this.onEvent(name));
			this.watcher.on('error', e => this.status('warning', `workspace watcher error: ${e.message}`));
		} catch (e) {
			this.status('warning', `workspace watcher unavailable: ${(e as Error).message}`);
			return;
		}
		this.timer = setInterval(() => this.flush(), 500);
		this.timer.unref?.();
	}

	stop(): void {
		this.watcher?.close();
		clearInterval(this.timer);
		this.flush();
	}

	private status(priority: string, summary: string): void {
		this.hub.emit(this.tabId, { source: 'workspace-watch', integrity: 'trusted', class: 'sensor.status', priority, summary, detail: { status: 'workspace-watch' } });
	}

	private onEvent(name: string | Buffer | null): void {
		if (name === null) {
			return;
		}
		const rel = (Buffer.isBuffer(name) ? name.toString('utf8') : name).split(path.sep).join('/');
		if (!rel || rel.startsWith('/') || rel.split('/').includes('..') || rel.includes('\0')) {
			return;
		}
		if (this.pending.size >= MAX_PENDING && !this.pending.has(rel)) {
			this.overflow++;
			return;
		}
		this.pending.set(rel, Date.now());
	}

	private flush(): void {
		const now = Date.now();
		let individual = 0;
		const overflowExec: string[] = [];
		for (const [rel, at] of this.pending) {
			if (now - at < 300) {
				continue; // let bursts of writes to one file settle
			}
			this.pending.delete(rel);
			if (QUIET.test(rel) || !isHostExecutablePath(rel)) {
				const top = rel.split('/').slice(0, 2).join('/');
				this.bulk.set(top, (this.bulk.get(top) ?? 0) + 1);
				continue;
			}
			// Host-executable paths are never folded into the anonymous bulk (review OR-5): up to
			// MAX_INDIVIDUAL writes per flush are reported one by one (deletions don't count), the
			// rest in a warning that names them and still feeds the detector.
			if (individual >= MAX_INDIVIDUAL) {
				overflowExec.push(rel);
				continue;
			}
			if (this.report(rel) !== 'deleted') {
				individual++;
			}
		}
		if (overflowExec.length) {
			// Hidden config paths (.git/hooks, .envrc, .vscode/…) first: they are the usual targets.
			overflowExec.sort((a, b) => Number(!/(^|\/)\./.test(a)) - Number(!/(^|\/)\./.test(b)) || a.localeCompare(b));
			const shown = overflowExec.slice(0, 10);
			this.hub.emit(this.tabId, {
				source: 'workspace-watch', integrity: 'trusted', class: 'workspace.change', priority: 'warning',
				summary: `${overflowExec.length} more host-executable files changed at once: ${shown.join(', ')}${overflowExec.length > shown.length ? ', …' : ''}`,
				file: { path: path.join(this.root, overflowExec[0]), op: 'overflow' }, detail: { change: 'overflow', count: overflowExec.length, paths: shown.join(', ') },
			});
		}
		if (this.bulk.size && (this.pending.size === 0 || this.bulk.size > 50)) {
			const total = [...this.bulk.values()].reduce((a, b) => a + b, 0);
			const top = [...this.bulk].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([d, n]) => `${d} (${n})`).join(', ');
			this.hub.emit(this.tabId, { source: 'workspace-watch', integrity: 'trusted', class: 'workspace.change', priority: 'debug', summary: `${total} workspace changes: ${top}`, file: { path: this.root, op: 'bulk' }, detail: { change: 'bulk', count: total } });
			this.bulk = new Map();
		}
		if (this.overflow) {
			this.status('warning', `workspace watcher dropped ${this.overflow} changes (too many at once)`);
			this.overflow = 0;
		}
	}

	private report(rel: string): string {
		const abs = path.join(this.root, rel);
		let change: string;
		let mode = 0;
		try {
			const st = fs.lstatSync(abs);
			change = st.isSymbolicLink() ? 'symlink' : st.isFile() ? 'written' : st.isDirectory() ? 'directory' : 'other';
			mode = st.mode;
		} catch {
			change = 'deleted';
		}
		const detail: Record<string, string | number | boolean> = { change, executable: (mode & 0o111) !== 0 && change === 'written' };
		if (rel === 'package.json' || rel.endsWith('/package.json')) {
			const h = change === 'written' ? this.scriptsHash(rel) : undefined;
			const before = this.scripts.get(rel);
			if (h !== undefined && before !== undefined && h !== before) {
				detail.scriptsChanged = true;
			}
			if (h !== undefined) {
				this.scripts.set(rel, h);
			}
		}
		this.hub.emit(this.tabId, {
			source: 'workspace-watch', integrity: 'trusted', class: 'workspace.change', priority: change === 'deleted' ? 'informational' : 'notice',
			summary: `workspace ${change}: ${rel}${detail.scriptsChanged ? ' (scripts changed)' : ''}`, file: { path: abs, op: change }, detail,
		});
		return change;
	}

	/** Hash of package.json "scripts", read only when it is a regular file inside the root. */
	private scriptsHash(rel: string): string | undefined {
		const abs = path.join(this.root, rel);
		let fd: number | undefined;
		try {
			const real = fs.realpathSync.native(abs);
			if (!real.startsWith(`${this.realRoot}/`)) {
				return undefined;
			}
			const before = fs.lstatSync(real);
			fd = fs.openSync(real, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
			const st = fs.fstatSync(fd);
			// A parent swapped for a symlink between realpath and open lands on another inode.
			if (!st.isFile() || st.size > MAX_JSON || st.dev !== before.dev || st.ino !== before.ino) {
				return undefined;
			}
			const doc = JSON.parse(fs.readFileSync(fd, 'utf8')) as { scripts?: unknown };
			return createHash('sha256').update(JSON.stringify(doc?.scripts ?? null)).digest('hex');
		} catch {
			return undefined;
		} finally {
			if (fd !== undefined) {
				fs.closeSync(fd);
			}
		}
	}
}
