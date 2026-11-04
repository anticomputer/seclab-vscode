// Process spawning for runtime CLIs. No shell, ever. Minimal, explicit environment.

import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

// Only these variables pass from the supervisor's env to runtime CLIs. PATH is fixed.
// In particular ELECTRON_*, NODE_*, VSCODE_*, SSH_AUTH_SOCK, *_TOKEN/*_KEY and proxy
// settings never pass through.
const ENV_ALLOW = ['HOME', 'USER', 'LOGNAME', 'LANG', 'TMPDIR', 'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG'];
const SEARCH_DIRS = ['/opt/homebrew/bin', '/usr/local/bin', '/usr/bin', '/bin', '/Applications/Docker.app/Contents/Resources/bin'];

export function cleanEnv(src: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
	const env: NodeJS.ProcessEnv = { PATH: SEARCH_DIRS.join(path.delimiter) };
	for (const k of ENV_ALLOW) {
		const v = src[k];
		if (typeof v === 'string') {
			env[k] = v;
		}
	}
	return env;
}

/**
 * Resolve a runtime CLI to an absolute path from fixed system directories only (never
 * the inherited PATH, which a workspace-influenced environment could poison).
 * Override with SECLAB_<NAME> (absolute path to an executable file).
 */
export function resolveBinary(name: 'sbx' | 'docker', env: NodeJS.ProcessEnv = process.env): string | undefined {
	const override = env[`SECLAB_${name.toUpperCase()}`];
	if (override) {
		return path.isAbsolute(override) && isExecutable(override) ? override : undefined;
	}
	for (const d of SEARCH_DIRS) {
		const p = path.join(d, name);
		if (isExecutable(p)) {
			return p;
		}
	}
	return undefined;
}

function isExecutable(p: string): boolean {
	try {
		fs.accessSync(p, fs.constants.X_OK);
		return fs.statSync(p).isFile();
	} catch {
		return false;
	}
}

export interface RunResult {
	readonly code: number | null;
	readonly stdout: string;
	readonly stderr: string;
}

export type Auditor = (action: string, outcome: string, detail: Record<string, unknown>) => void;

/** Audit records never carry secrets: 32+ hex chars or long base64 runs are redacted. */
export function redactArgs(args: readonly string[]): string[] {
	return args.map(a => a.replace(/[0-9a-f]{32,}/gi, '<redacted>').replace(/[A-Za-z0-9+/=_-]{40,}/g, '<redacted>'));
}

export interface Runner {
	run(bin: string, args: readonly string[], opts?: { input?: string; timeoutMs?: number }): Promise<RunResult>;
	spawnStream(bin: string, args: readonly string[]): ChildProcessWithoutNullStreams;
}

export function createRunner(audit: Auditor, env: NodeJS.ProcessEnv = cleanEnv(), cwd?: string): Runner {
	return {
		run(bin, args, opts = {}) {
			const argv = [...args];
			return new Promise((resolve) => {
				const child = spawn(bin, argv, { env, cwd, shell: false, stdio: ['pipe', 'pipe', 'pipe'] });
				let stdout = '', stderr = '';
				const cap = 4 << 20;
				child.stdout.on('data', d => { if (stdout.length < cap) { stdout += d; } });
				child.stderr.on('data', d => { if (stderr.length < cap) { stderr += d; } });
				const timer = setTimeout(() => child.kill('SIGKILL'), opts.timeoutMs ?? 120_000);
				child.on('error', err => {
					clearTimeout(timer);
					audit('spawn', 'error', { bin: path.basename(bin), args: redactArgs(argv), error: String(err) });
					resolve({ code: null, stdout, stderr: stderr + String(err) });
				});
				child.on('close', code => {
					clearTimeout(timer);
					audit('spawn', code === 0 ? 'ok' : 'fail', { bin: path.basename(bin), args: redactArgs(argv), code });
					resolve({ code, stdout, stderr });
				});
				child.stdin.on('error', () => { /* child exited before reading stdin */ });
				child.stdin.end(opts.input ?? '');
			});
		},
		spawnStream(bin, args) {
			const argv = [...args];
			audit('spawn-stream', 'start', { bin: path.basename(bin), args: redactArgs(argv) });
			return spawn(bin, argv, { env, cwd, shell: false, stdio: ['pipe', 'pipe', 'pipe'] });
		},
	};
}
