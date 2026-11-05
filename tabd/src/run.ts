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
export function resolveBinary(name: 'sbx' | 'docker' | 'git', env: NodeJS.ProcessEnv = process.env): string | undefined {
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
	/** Raw stdout bytes (as captured, up to the cap). */
	readonly stdoutBytes?: Buffer;
	/** stdout exceeded the cap and was cut. */
	readonly truncated?: boolean;
}

export type Auditor = (action: string, outcome: string, detail: Record<string, unknown>) => void;

/** Audit records never carry secrets: 32+ hex chars or long base64 runs are redacted. */
export function redactArgs(args: readonly string[]): string[] {
	return args.map(a => a.replace(/[0-9a-f]{32,}/gi, '<redacted>').replace(/[A-Za-z0-9+/=_-]{40,}/g, '<redacted>'));
}

/** Byte-accurate output capture with a hard cap (chunks are never decoded mid-character). */
function capture(cap: number) {
	const chunks: Buffer[] = [];
	let size = 0;
	let truncated = false;
	return {
		add(d: Buffer) {
			if (size >= cap) {
				truncated = true;
				return;
			}
			const take = d.subarray(0, cap - size);
			truncated ||= take.length < d.length;
			chunks.push(take);
			size += take.length;
		},
		bytes: () => Buffer.concat(chunks),
		get truncated() { return truncated; },
	};
}

export interface Runner {
	run(bin: string, args: readonly string[], opts?: { input?: string; timeoutMs?: number; maxOutputBytes?: number }): Promise<RunResult>;
	spawnStream(bin: string, args: readonly string[]): ChildProcessWithoutNullStreams;
}

export function createRunner(audit: Auditor, env: NodeJS.ProcessEnv = cleanEnv(), cwd?: string): Runner {
	return {
		run(bin, args, opts = {}) {
			const argv = [...args];
			return new Promise((resolve) => {
				const child = spawn(bin, argv, { env, cwd, shell: false, stdio: ['pipe', 'pipe', 'pipe'] });
				const cap = opts.maxOutputBytes ?? 4 << 20;
				const out = capture(cap), err = capture(4 << 20);
				child.stdout.on('data', (d: Buffer) => out.add(d));
				child.stderr.on('data', (d: Buffer) => err.add(d));
				const timer = setTimeout(() => child.kill('SIGKILL'), opts.timeoutMs ?? 120_000);
				const result = (code: number | null, extra = ''): RunResult => {
					const bytes = out.bytes();
					return { code, stdout: bytes.toString('utf8'), stderr: err.bytes().toString('utf8') + extra, stdoutBytes: bytes, truncated: out.truncated };
				};
				child.on('error', e => {
					clearTimeout(timer);
					audit('spawn', 'error', { bin: path.basename(bin), args: redactArgs(argv), error: String(e) });
					resolve(result(null, String(e)));
				});
				child.on('close', code => {
					clearTimeout(timer);
					audit('spawn', code === 0 ? 'ok' : 'fail', { bin: path.basename(bin), args: redactArgs(argv), code, ...(out.truncated ? { truncated: true } : {}) });
					resolve(result(code));
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
