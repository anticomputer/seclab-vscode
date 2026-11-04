// Pre-mount secret scanning (ADR 20261104-pre-mount-secret-scan). Runs gitleaks from a
// digest-pinned image in a throwaway, network-less, read-only container BEFORE a workspace
// is mounted into a tab. Secret values are held only in supervisor memory (for "move to
// broker"); clients and logs only ever see redacted findings.

import { createHash, randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Runner } from './run.ts';

export const GITLEAKS_IMAGE = 'ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f'; // v8.30.1

// Default rules plus our test canary shape (test/canary/canary.ts).
const CONFIG = `[extend]
useDefault = true

[[rules]]
id = "seclab-canary"
description = "seclab canary secret (tests)"
regex = '''seclabcanary_[A-Z0-9]{0,16}_[0-9a-f]{32}'''
`;

export interface Finding {
	readonly id: string;
	readonly source: 'worktree' | 'git-config' | 'history';
	/** Path relative to the workspace root. */
	readonly file: string;
	readonly line: number;
	readonly rule: string;
	readonly commit?: string;
	/** Can be rewritten in place (current files only, not history). */
	readonly movable: boolean;
}

export interface ScanResult {
	readonly complete: boolean;
	readonly error?: string;
	readonly findings: Finding[];
	/** finding id -> secret value. Never serialised. */
	readonly secrets: Map<string, string>;
}

interface RawFinding { File?: unknown; StartLine?: unknown; RuleID?: unknown; Commit?: unknown; Secret?: unknown }

export async function scanWorkspace(runner: Runner, docker: string, hostPath: string): Promise<ScanResult> {
	const findings: Finding[] = [];
	const secrets = new Map<string, string>();
	const base = ['run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
		'--user', '65534:65534', '--pids-limit', '256', '--memory', '1g',
		// The workspace is hostile: no system/global git config, no textconv/ext-diff (see log-opts).
		'-e', 'GIT_CONFIG_NOSYSTEM=1', '-e', 'GIT_CONFIG_GLOBAL=/dev/null',
		'-e', 'GIT_CONFIG_COUNT=1', '-e', 'GIT_CONFIG_KEY_0=safe.directory', '-e', 'GIT_CONFIG_VALUE_0=*',
		'-e', `GITLEAKS_CONFIG_TOML=${CONFIG}`,
		'--mount', `type=bind,src=${hostPath},dst=/scan,readonly`, GITLEAKS_IMAGE];
	const tail = ['--no-banner', '--report-format', 'json', '--report-path', '-', '--exit-code', '0'];
	const passes: Array<[Finding['source'], string[]]> = [['worktree', ['dir', '/scan']]];
	if (fs.existsSync(path.join(hostPath, '.git', 'config'))) {
		passes.push(['git-config', ['dir', '/scan/.git/config']]);
	}
	if (fs.existsSync(path.join(hostPath, '.git'))) {
		passes.push(['history', ['git', '/scan', '--log-opts=--all --no-textconv --no-ext-diff']]);
	}
	for (const [source, mode] of passes) {
		const r = await runner.run(docker, [...base, ...mode, ...tail], { timeoutMs: 180_000 });
		let raw: RawFinding[];
		try {
			raw = JSON.parse(r.stdout) as RawFinding[];
			if (r.code !== 0 || !Array.isArray(raw)) {
				throw new Error(`exit ${r.code}`);
			}
		} catch (e) {
			return { complete: false, error: `secret scan (${source}) failed: ${(e as Error).message}`, findings, secrets };
		}
		for (const f of raw) {
			const file = relativeFile(String(f.File ?? ''));
			const line = Number(f.StartLine);
			const rule = String(f.RuleID ?? 'unknown').replace(/[^A-Za-z0-9._-]/g, '').slice(0, 64);
			const commit = typeof f.Commit === 'string' && /^[0-9a-f]{7,40}$/.test(f.Commit) ? f.Commit : undefined;
			if (!file || !Number.isInteger(line) || line < 1) {
				continue;
			}
			const id = createHash('sha256').update(`${source}\0${file}\0${line}\0${rule}\0${commit ?? ''}`).digest('hex').slice(0, 16);
			if (secrets.has(id)) {
				continue;
			}
			findings.push({ id, source, file, line, rule, commit, movable: source !== 'history' });
			secrets.set(id, String(f.Secret ?? ''));
		}
	}
	return { complete: true, findings, secrets };
}

function relativeFile(f: string): string {
	const rel = f.startsWith('/scan/') ? f.slice('/scan/'.length) : f;
	const norm = path.posix.normalize(rel);
	return norm.startsWith('..') || path.posix.isAbsolute(norm) || /[\u0000-\u001f]/.test(norm) ? '' : norm;
}

export interface VaultEntry {
	readonly id: string;
	readonly file: string;
	readonly line: number;
	readonly rule: string;
	readonly sentinel: string;
	readonly secret: string;
	readonly bind: { readonly host: string; readonly path: string };
	readonly movedAt: string;
}

export function mintSentinel(rule: string): string {
	return `seclab_sentinel_${rule.replace(/[^a-z0-9]/gi, '').slice(0, 24)}_${randomBytes(16).toString('hex')}`;
}

/**
 * Replace `secret` with `sentinel` on `line` of `file` inside the workspace. Refuses
 * anything that is not a regular, non-symlinked file inside the workspace, and anything
 * where the secret is no longer on that line. Atomic (temp file + rename), mode kept.
 */
export function rewriteSecret(hostPath: string, file: string, line: number, secret: string, sentinel: string): void {
	if (!secret || secret.length < 8) {
		throw new Error('refusing to rewrite: secret value unavailable');
	}
	const abs = path.resolve(hostPath, file);
	if (!abs.startsWith(hostPath + path.sep)) {
		throw new Error('refusing to rewrite outside the workspace');
	}
	const st = fs.lstatSync(abs);
	if (!st.isFile() || st.size > 10 << 20 || fs.realpathSync.native(abs) !== abs) {
		throw new Error(`refusing to rewrite ${file}: not a regular non-symlinked file`);
	}
	const lines = fs.readFileSync(abs, 'utf8').split('\n');
	const i = line - 1;
	if (i < 0 || i >= lines.length || !lines[i].includes(secret)) {
		throw new Error(`secret no longer at ${file}:${line}; rescan`);
	}
	lines[i] = lines[i].replace(secret, sentinel);
	const tmp = `${abs}.seclab-${randomBytes(4).toString('hex')}`;
	fs.writeFileSync(tmp, lines.join('\n'), { mode: st.mode & 0o777, flag: 'wx' });
	fs.renameSync(tmp, abs);
}
