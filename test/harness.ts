// Shared harness helpers: lets several worktrees (and sessions) run the suites at once.
//   SECLAB_BEACON_PORT  host-loopback beacon port (default: a free port picked per run)
//   SECLAB_EVIDENCE_DIR level B fixture dir (default: <repo>/.work/containment-editor)

import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as path from 'node:path';

export const repoRoot = path.resolve(import.meta.dirname, '..');

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
 * start. Fail early with a hint instead.
 */
export function checkUserDataDir(userData: string): void {
	if (process.platform === 'darwin' && path.join(userData, '1.14-main.sock').length >= 104) {
		throw new Error(`user-data-dir too long for macOS unix sockets (${userData}); use a short one such as ~/.seclab-test/<name>`);
	}
}
