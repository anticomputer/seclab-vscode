// The host-side CFS feed config (EDR cfs-config-outside-repo). The real feed URLs and GUIDs are
// never committed: the tree holds example values only, and tabd and local builds read the real
// ones from a file outside any repository. Missing or malformed means CFS is off; nothing falls
// back to a value in the tree. This module is the one validator (pure: fs, os, path); the CLI
// that writes the file from `gh cfs` is build/cfs-config.ts, host only. pip-fetch.py mirrors
// the `pypiIndex` rule, and both run broker/tools/cfs-config.vectors.json.
//
// File: $SECLAB_CFS_CONFIG or ~/.config/seclab/cfs.json, mode 0600. Refused when it sits inside
// a git repository, is a symlink or not a regular file, is not owned by the user, or is
// accessible by group or others.

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

export interface CfsConfig { version: 1; npmRegistry: string; pypiIndex: string; pypiDownload: string; tenant: string }
export const CFS_FIELDS = ['npmRegistry', 'pypiIndex', 'pypiDownload', 'tenant'] as const;
export type CfsField = typeof CFS_FIELDS[number];

const SEG = '[A-Za-z0-9._-]{1,64}';
const GUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const BASE = 'https://pkgs\\.dev\\.azure\\.com/[A-Za-z0-9-]{1,64}';
export const CFS_HOST = 'pkgs.dev.azure.com';
/** Per-field shapes. Anchored; JS `$` is end of input without the m flag. */
export const CFS_RULES: Record<CfsField, RegExp> = {
	npmRegistry: new RegExp(`^${BASE}/${SEG}/_packaging/${SEG}/npm/registry/$`),
	pypiIndex: new RegExp(`^${BASE}/${SEG}/_packaging/${SEG}/pypi/simple/$`),
	pypiDownload: new RegExp(`^${BASE}/${GUID}/_packaging/${GUID}/pypi/download/$`),
	tenant: new RegExp(`^${GUID}$`),
};
/** The GUID shape, for callers that extract one from tool output. */
export const CFS_GUID = GUID;

export class CfsConfigError extends Error {}

/** Validate a parsed config. Messages name the field, never its value. */
export function validateCfsConfig(obj: unknown): CfsConfig {
	if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
		throw new CfsConfigError('not a JSON object');
	}
	const o = obj as Record<string, unknown>;
	if (o.version !== 1) {
		throw new CfsConfigError('not a version 1 config');
	}
	if (Object.keys(o).some(k => k !== 'version' && !(CFS_FIELDS as readonly string[]).includes(k))) {
		throw new CfsConfigError('unknown key');
	}
	for (const f of CFS_FIELDS) {
		const v = o[f];
		// `.` and `..` pass the segment class, so dot segments are refused separately.
		if (typeof v !== 'string' || !CFS_RULES[f].test(v) || v.split('/').some(s => s === '.' || s === '..')) {
			throw new CfsConfigError(`${f} is missing or malformed`);
		}
	}
	const orgs = new Set([o.npmRegistry, o.pypiIndex, o.pypiDownload].map(u => String(u).split('/')[3]));
	if (orgs.size !== 1) {
		throw new CfsConfigError('the feeds name different organisations');
	}
	return o as unknown as CfsConfig;
}

export function cfsConfigPath(env: NodeJS.ProcessEnv = process.env): string {
	return path.resolve(env.SECLAB_CFS_CONFIG || path.join(os.homedir(), '.config', 'seclab', 'cfs.json'));
}

const missing = (p: string) => new CfsConfigError(`no config at ${p}: run ./seclab cfs config (CFS stays off)`);

/** Refuse a file the user doesn't solely control, or one inside any git repository. */
function checkFile(p: string): void {
	let dir: string;
	try {
		dir = fs.realpathSync(path.dirname(p));
	} catch {
		throw missing(p);
	}
	for (let d = dir; ; d = path.dirname(d)) {
		if (fs.existsSync(path.join(d, '.git'))) {
			throw new CfsConfigError('the config must live outside any repository');
		}
		if (path.dirname(d) === d) {
			break;
		}
	}
	let st: fs.Stats;
	try {
		st = fs.lstatSync(p);
	} catch {
		throw missing(p);
	}
	if (st.isSymbolicLink() || !st.isFile()) {
		throw new CfsConfigError(`${p} is not a regular file`);
	}
	if (typeof process.getuid === 'function' && st.uid !== process.getuid()) {
		throw new CfsConfigError(`${p} is not owned by this user`);
	}
	if (st.mode & 0o077) {
		throw new CfsConfigError(`${p} is accessible by group or others (chmod 600)`);
	}
}

/** Load and validate the user's config; throws CfsConfigError (CFS off) on any problem. */
export function loadCfsConfig(p: string = cfsConfigPath()): CfsConfig {
	checkFile(p);
	let obj: unknown;
	try {
		obj = JSON.parse(fs.readFileSync(p, 'utf8'));
	} catch {
		throw new CfsConfigError(`${p} is not valid JSON`);
	}
	return validateCfsConfig(obj);
}
