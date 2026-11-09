// Input validation for everything that can reach a runtime argv or the filesystem.
// Security-critical: see docs/tabd/PROTOCOL.md §7. Keep patterns strict; widen only
// with a security review.

import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

export const TAB_ID_RE = /^t-[a-z2-7]{26}$/;
export const SANDBOX_NAME_RE = /^seclab-t-[a-z2-7]{26}$/;
export const TEMPLATE_NAME_RE = /^[a-z][a-z0-9-]{0,31}$/;
// Image refs: registry/repo:tag or @sha256 digest; no leading '-', no whitespace.
export const IMAGE_REF_RE = /^[a-z0-9][a-z0-9._/:@-]{0,254}$/;
// sbx network resources as printed by `sbx policy ls --json`: host or glob, optional :port.
export const POLICY_RESOURCE_RE = /^(?:\*\*|[a-z0-9*?[\]!_](?:[a-z0-9*?[\]!._-]{0,252}))(?::[0-9]{1,5})?$/i;
export const CONNECTION_TOKEN_RE = /^[0-9a-f]{64}$/;

const B32 = 'abcdefghijklmnopqrstuvwxyz234567';

export class ValidationError extends Error { }

export function base32(bytes: Uint8Array): string {
	let bits = 0, value = 0, out = '';
	for (const b of bytes) {
		value = ((value << 8) | b) & 0xffff;
		bits += 8;
		while (bits >= 5) {
			out += B32[(value >>> (bits - 5)) & 31];
			bits -= 5;
		}
	}
	if (bits > 0) {
		out += B32[(value << (5 - bits)) & 31];
	}
	return out;
}

export function mintTabId(): string {
	return `t-${base32(randomBytes(16))}`; // 128 bits -> 26 chars
}

export function mintConnectionToken(): string {
	return randomBytes(32).toString('hex');
}

export function assertTabId(v: unknown): string {
	if (typeof v !== 'string' || !TAB_ID_RE.test(v)) {
		throw new ValidationError('invalid tab id');
	}
	return v;
}

export function sandboxNameFor(tabId: string): string {
	const name = `seclab-${assertTabId(tabId)}`;
	if (!SANDBOX_NAME_RE.test(name)) {
		throw new ValidationError('invalid sandbox name');
	}
	return name;
}

export function assertPolicyResource(v: unknown): string {
	if (typeof v !== 'string' || !POLICY_RESOURCE_RE.test(v)) {
		throw new ValidationError(`invalid policy resource: ${JSON.stringify(v)}`);
	}
	return v;
}

export function assertImageRef(v: unknown): string {
	if (typeof v !== 'string' || !IMAGE_REF_RE.test(v)) {
		throw new ValidationError('invalid image reference');
	}
	return v;
}

/**
 * Canonicalise and vet a workspace host path. Returns the canonical path, which is
 * also the in-sandbox mount path (sbx mounts at the same absolute path).
 * Rejects: non-absolute, control chars, ':' ',' '=' (sbx PATH[:ro|:dst] and docker
 * --mount CSV syntax), symlinked components (path must equal its realpath),
 * non-directories, sensitive roots, paths inside sensitive dirs, and ancestors of
 * sensitive dirs. Comparisons are case-folded and NFC-normalised (APFS is
 * case- and normalisation-insensitive by default).
 */
export interface PathPolicy {
	readonly home?: string;
	/** Extra sensitive paths (editor user-data, extensions dir, app bundle, state dir). */
	readonly sensitive?: readonly string[];
	/** If non-empty, the workspace must be inside one of these roots. */
	readonly allowedRoots?: readonly string[];
}

export function foldPath(p: string): string {
	return p.normalize('NFC').toLowerCase();
}

function within(child: string, parent: string): boolean {
	const c = foldPath(child), p = foldPath(parent);
	return c === p || c.startsWith(p.endsWith(path.sep) ? p : p + path.sep);
}

export function canonicalWorkspacePath(input: unknown, policy: PathPolicy = {}): string {
	if (typeof input !== 'string' || input.length === 0 || input.length > 1024) {
		throw new ValidationError('workspace path must be a non-empty string');
	}
	if (/[\u0000-\u001f\u007f]/.test(input) || /[:,=]/.test(input)) {
		throw new ValidationError('workspace path contains forbidden characters');
	}
	if (!path.isAbsolute(input)) {
		throw new ValidationError('workspace path must be absolute');
	}
	const normalized = path.resolve(input);
	let real: string;
	try {
		real = fs.realpathSync.native(normalized);
	} catch {
		throw new ValidationError('workspace path does not exist');
	}
	if (real !== normalized) {
		throw new ValidationError(`workspace path must not traverse symlinks (resolves to ${real})`);
	}
	if (!fs.statSync(real).isDirectory()) {
		throw new ValidationError('workspace path is not a directory');
	}
	const realHome = safeRealpath(policy.home ?? os.homedir());
	// Exact matches refused: system roots and the home directory itself.
	const exact = ['/', '/Users', '/home', '/root', '/private', '/System', '/Library',
		'/Applications', '/Volumes', '/etc', '/var', '/usr', '/opt', '/bin', '/sbin', '/tmp', '/dev', '/proc', '/run'];
	// Refused at, below, and above (ancestors) these.
	const sensitive: string[] = ['/private', '/System', '/Library', '/etc', '/var', '/usr', '/bin', '/sbin', '/dev', '/proc', '/run', '/root'];
	if (realHome) {
		exact.push(realHome);
		for (const sub of ['.ssh', '.docker', '.config', '.aws', '.azure', '.gnupg', '.kube', 'Library', '.local',
			'.gitconfig', '.netrc', '.npmrc', '.seclab-vscode', '.seclab-vscode-server', '.vscode', '.vscode-oss',
			// Directories host tools execute from or load code/config from.
			'bin', '.cargo', '.rustup', '.nvm', '.pyenv', '.rbenv', '.bun', '.deno', '.oh-my-zsh', '.gradle', '.m2', '.sdkman',
			'.zshrc', '.zprofile', '.bashrc', '.bash_profile', '.profile',
			// Agent CLI configs (MCP servers = host commands). Files, so only the file and its
			// ancestors are refused; project dirs below e.g. ~/.copilot stay openable.
			'.copilot/mcp-config.json', '.copilot/config.json', '.claude/settings.json', '.claude.json',
			'.codex/config.toml', '.cursor/mcp.json']) {
			sensitive.push(path.join(realHome, sub));
		}
	}
	// Host binary locations (tabd executes sbx/docker from here): a tab must never mount them.
	for (const d of ['/opt/homebrew', '/usr/local', '/Applications']) {
		sensitive.push(d);
	}
	for (const s of policy.sensitive ?? []) {
		if (path.isAbsolute(s)) {
			sensitive.push(safeRealpath(s) ?? s);
		}
	}
	if (exact.some(e => foldPath(e) === foldPath(real))) {
		throw new ValidationError(`refusing to open a sensitive directory as a tab: ${real}`);
	}
	for (const s of sensitive) {
		if (within(real, s)) {
			throw new ValidationError(`refusing to open a path inside ${s}`);
		}
		if (within(s, real)) {
			throw new ValidationError(`refusing to open a directory that contains ${s}`);
		}
	}
	const roots = policy.allowedRoots ?? [];
	if (roots.length === 0) {
		// Fail closed: tabs may only be opened under explicitly configured project roots.
		throw new ValidationError('no allowed roots configured (seclab.tabs.allowedRoots / --allowed-root)');
	}
	// Roots get the same vetting as workspaces (and no dot-directories under $HOME), so an
	// over-broad or sensitive root can't widen what the allowlist admits.
	for (const r of roots) {
		const rr = path.isAbsolute(r) ? (safeRealpath(r) ?? r) : '';
		if (!rr || exact.some(e => foldPath(e) === foldPath(rr)) || sensitive.some(s => within(rr, s) || within(s, rr))) {
			throw new ValidationError(`allowed root ${r} is too broad or sensitive`);
		}
		// A dot-directory directly under $HOME (~/.claude, ~/.npm, ...) is tool state, not a projects folder.
		if (realHome && foldPath(path.dirname(rr)) === foldPath(realHome) && path.basename(rr).startsWith('.')) {
			throw new ValidationError(`allowed root ${r} is a dot-directory in the home directory`);
		}
	}
	if (!roots.some(r => path.isAbsolute(r) && within(real, safeRealpath(r) ?? r))) {
		throw new ValidationError(`workspace is outside the allowed roots`);
	}
	return real;
}

function safeRealpath(p: string): string | undefined {
	try {
		return fs.realpathSync.native(p);
	} catch {
		return undefined;
	}
}
