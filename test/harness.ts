// Shared harness helpers: lets several worktrees (and sessions) run the suites at once.
//   SECLAB_BEACON_PORT  host-loopback beacon port (default: a free port picked per run)
//   SECLAB_EVIDENCE_DIR level B fixture dir (default: <repo>/.work/containment-editor)

import { createHash, createHmac } from 'node:crypto';
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';

export const repoRoot = path.resolve(import.meta.dirname, '..');

/** Third-party images the harness runs, pinned by digest (build/check-pins.ts enforces it). */
export const NODE_IMAGE = 'node:24.22.1-trixie@sha256:f1e034976f948cf212ef1f659c12e5dd58ac7eab947831813e81a62401ca38be';
export const NGINX_IMAGE = 'nginx:alpine@sha256:785835ea65db4bba6f021acc0f3be91b0fef76a53fe41f8588c6698d2aed0606';

/** Short, stable id for this worktree: keeps global names (docker containers) apart. */
export const worktreeId = createHash('sha256').update(repoRoot).digest('hex').slice(0, 8);

/** SECLAB_BEACON_PORT, or a free loopback port. */
export async function beaconPort(): Promise<number> {
	const fixed = Number(process.env.SECLAB_BEACON_PORT ?? 0);
	if (Number.isInteger(fixed) && fixed > 0 && fixed < 65536) {
		return fixed;
	}
	return new Promise((resolve, reject) => {
		const s = net.createServer();
		s.once('error', reject);
		s.listen(0, '127.0.0.1', () => {
			const port = (s.address() as net.AddressInfo).port;
			s.close(() => resolve(port));
		});
	});
}

/**
 * One run per directory at a time: an exclusive lockfile with our pid. A lock left by a
 * dead process is taken over. Released on exit.
 */
export function lockRun(dir: string): void {
	fs.mkdirSync(dir, { recursive: true });
	const lock = path.join(dir, 'run.lock');
	for (let attempt = 0; attempt < 2; attempt++) {
		try {
			fs.writeFileSync(lock, String(process.pid), { flag: 'wx' });
			process.on('exit', () => fs.rmSync(lock, { force: true }));
			return;
		} catch {
			const pid = Number(fs.readFileSync(lock, 'utf8'));
			let alive = false;
			try {
				process.kill(pid, 0);
				alive = pid > 0;
			} catch { /* not running */ }
			if (alive) {
				throw new Error(`another run (pid ${pid}) holds ${lock}`);
			}
			fs.rmSync(lock, { force: true });
		}
	}
	throw new Error(`could not take ${lock}`);
}

/**
 * Electron's main IPC socket lives in the user-data dir; macOS caps unix socket paths at
 * 104 bytes, so a deep path (e.g. inside a worktree's .work/) makes the editor exit at
 * start. Fail early with a hint instead. Test profiles must also be isolated: never a real
 * editor profile (they hold auth sessions and settings with secrets).
 */
export function checkUserDataDir(userData: string): void {
	checkIsolatedProfile(userData);
	if (process.platform === 'darwin' && path.join(userData, '1.14-main.sock').length >= 104) {
		throw new Error(`user-data-dir too long for macOS unix sockets (${userData}); use a short one such as ~/.seclab-test/<name>`);
	}
}

/** Test profiles live only under ~/.seclab-test/ or this worktree's .work/ (never a real profile), also after resolving links (R-3). */
export function checkIsolatedProfile(userData: string): void {
	const home = os.homedir();
	const roots = [path.join(home, '.seclab-test'), path.join(repoRoot, '.work')];
	const under = (p: string, rs: string[]) => rs.some(r => p.startsWith(r + path.sep));
	if (!under(userData, roots)) {
		throw new Error(`test user-data-dir must be under ~/.seclab-test/ or this worktree's .work/ (isolated profile), got ${userData}`);
	}
	// The deepest existing ancestor, resolved, must still be inside a resolved root.
	let p = userData;
	while (!fs.existsSync(p) && path.dirname(p) !== p) {
		p = path.dirname(p);
	}
	const real = fs.realpathSync.native(p);
	const realRoots = roots.filter(r => fs.existsSync(r)).map(r => fs.realpathSync.native(r));
	if (!realRoots.some(r => real === r || real.startsWith(r + path.sep))) {
		throw new Error(`test user-data-dir resolves outside the test roots (symlink?): ${userData} -> ${real}`);
	}
}

/** Host paths a payload that escaped containment might touch. Stat only: never read. */
const WATCHED = ['.ssh', '.gitconfig', '.zshrc', '.zprofile', '.zshenv', '.bashrc', '.bash_profile', '.profile', 'Library/LaunchAgents', '.config/git',
	'.aws', '.npmrc', '.netrc', '.git-credentials', '.vimrc', '.tmux.conf', '.config/fish', '.config/autostart', '.config/starship.toml',
	'.config/nvim/init.lua', '.config/nvim/init.vim'];

const PRESENCE = ['', '.config'];
// Entries tools create under normal use during a long (level B) run: not a tripwire.
const PRESENCE_NOISE = new Set(['.DS_Store', '.lesshst', '.viminfo', '.zsh_history', '.zsh_sessions', '.bash_history', '.python_history',
	'.node_repl_history', '.cache', '.Trash', '.CFUserTextEncoding']);

export type Snapshot = Record<string, string>;

/**
 * Stat-only snapshot of the watched paths, recursing into directories (FS-6). Entry names
 * inside them (e.g. key file names in the SSH directory) are never stored: they're HMAC'd
 * with a per-run key (T-7: no precomputed dictionary), and a change is reported against the
 * watched top-level path. Only snapshots taken with the same key are comparable.
 */
export function hostSnapshot(key: string): Snapshot {
	const out: Snapshot = {};
	const h = (s: string) => createHmac('sha256', key).update(s).digest('hex').slice(0, 16);
	const visit = (top: string, rel: string, depth: number) => {
		const p = path.join(os.homedir(), rel);
		const k = rel === top ? top : `${top}#${h(rel)}`;
		let st: fs.Stats;
		try {
			st = fs.lstatSync(p);
		} catch {
			out[k] = 'absent';
			return;
		}
		out[k] = `${st.ino}:${st.size}:${st.mtimeMs}`;
		if (st.isDirectory()) {
			let entries: string[] = [];
			try {
				entries = fs.readdirSync(p);
			} catch { /* unreadable: the dir's own stat still counts */ }
			if (depth >= 4 || entries.length > 500) {
				out[`${top}#capped`] = 'snapshot depth/size cap reached: not fully watched';
				process.stderr.write(`harness: host snapshot cap reached under ~/${top}; entries beyond it are not watched\n`);
			}
			if (depth < 4) {
				for (const e of entries.slice(0, 500)) {
					visit(top, path.join(rel, e), depth + 1);
				}
			}
		}
	};
	for (const rel of WATCHED) {
		visit(rel, rel, 0);
	}
	// New entries directly in $HOME or ~/.config (dropped dotfiles, persistence): presence
	// only, names hashed. Their mtimes change under normal use, so they aren't recorded.
	for (const rel of PRESENCE) {
		let entries: string[] = [];
		try {
			entries = fs.readdirSync(path.join(os.homedir(), rel));
		} catch { /* absent */ }
		for (const e of entries) {
			if (!PRESENCE_NOISE.has(e)) {
				out[`${rel || '.'}#${h(path.join(rel, e))}`] = 'present';
			}
		}
	}
	return out;
}

export function snapshotDiff(before: Snapshot, after: Snapshot): string[] {
	const changed = new Set(Object.keys({ ...before, ...after }).filter(k => before[k] !== after[k]).map(k => `~/${k.split('#')[0]}`));
	return [...changed];
}

