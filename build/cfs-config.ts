// CLI for the host-side CFS feed config (EDR cfs-config-outside-repo). The validator is
// tabd/src/cfs-config.ts (pure; it ships with tabd); this file is host only: it writes the config
// from `gh cfs` and runs the shared vectors.
//
//   node build/cfs-config.ts check            validate (exit 1 with a reason; never a value)
//   node build/cfs-config.ts get FIELD        print one validated field
//   node build/cfs-config.ts write            (re)write it from `gh cfs guide npm|pip` and one
//                                             CFS `pip download -v` (the download path); prints
//                                             no value. Host only: needs gh, az and pip3.
//   node build/cfs-config.ts --self-test      the shared vectors, and the file refusals

import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
	CFS_FIELDS, CFS_GUID, CFS_HOST, CFS_RULES, CfsConfigError, cfsConfigPath, loadCfsConfig, validateCfsConfig, type CfsField,
} from '../tabd/src/cfs-config.ts';

const REPO = path.resolve(import.meta.dirname, '..');

/** Exactly one distinct match of `re` in `text`, or fail naming `what`. */
function one(re: RegExp, text: string, what: string): string {
	const all = new Set([...text.matchAll(new RegExp(re.source.replace(/^\^|\$$/g, ''), 'g'))].map(m => m[0]));
	if (all.size !== 1) {
		throw new CfsConfigError(`could not read ${what} from gh cfs`);
	}
	return [...all][0];
}

function write(p: string): void {
	const run = (args: string[]) => execFileSync('gh', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 16 << 20 });
	const guides = run(['cfs', 'guide', 'npm']) + run(['cfs', 'guide', 'pip']);
	const npmRegistry = one(CFS_RULES.npmRegistry, guides, 'the npm registry');
	const pypiIndex = one(CFS_RULES.pypiIndex, guides, 'the PyPI index');
	const tenants = [...guides.matchAll(new RegExp(`tenant[^0-9a-f]{0,16}(${CFS_GUID})`, 'gi'))].map(m => m[1]).join('\n');
	const tenant = one(CFS_RULES.tenant, tenants, 'the tenant');
	// Where the index links its files (the feed's GUID path), from one wheel's URL.
	const scratch = path.join(REPO, '.work', 'cfs-config');
	fs.rmSync(scratch, { recursive: true, force: true });
	fs.mkdirSync(scratch, { recursive: true });
	let log: string;
	try {
		log = execFileSync('gh', ['cfs', '--', 'pip3', 'download', '--no-deps', '--only-binary=:all:', '--index-url', pypiIndex,
			'--dest', 'dl', '-v', 'six==1.16.0'], { cwd: scratch, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 64 << 20 });
	} catch (e) {
		throw new CfsConfigError(`CFS pip download failed (is az logged in?): exit ${(e as { status?: number }).status ?? '?'}`);
	} finally {
		fs.rmSync(scratch, { recursive: true, force: true });
	}
	const pypiDownload = one(CFS_RULES.pypiDownload, log, 'the PyPI download path');
	if ([npmRegistry, pypiIndex, pypiDownload].some(u => new URL(u).host !== CFS_HOST)) {
		throw new CfsConfigError(`gh cfs named a feed host other than ${CFS_HOST}`);
	}
	const cfg = validateCfsConfig({ version: 1, npmRegistry, pypiIndex, pypiDownload, tenant });
	fs.mkdirSync(path.dirname(p), { recursive: true, mode: 0o700 });
	const tmp = `${p}.new`;
	fs.rmSync(tmp, { force: true });
	fs.writeFileSync(tmp, JSON.stringify(cfg, null, 1) + '\n', { mode: 0o600, flag: 'wx' });
	fs.renameSync(tmp, p);
	loadCfsConfig(p);
}

function selfTest(): void {
	const vectors = JSON.parse(fs.readFileSync(path.join(REPO, 'broker', 'tools', 'cfs-config.vectors.json'), 'utf8')) as {
		valid: Record<string, unknown>[]; invalid: { why: string; patch: Record<string, unknown> }[];
	};
	const fails: string[] = [];
	for (const v of vectors.valid) {
		try {
			validateCfsConfig(v);
		} catch (e) {
			fails.push(`valid vector refused: ${(e as Error).message}`);
		}
	}
	for (const { why, patch } of vectors.invalid) {
		const v: Record<string, unknown> = { ...vectors.valid[0] };
		for (const [k, x] of Object.entries(patch)) {
			if (x === null) {
				delete v[k];
			} else {
				v[k] = x;
			}
		}
		try {
			validateCfsConfig(v);
			fails.push(`invalid vector accepted: ${why}`);
		} catch {
			// expected
		}
	}
	// File refusals, in a scratch dir outside any repository.
	const dir = fs.mkdtempSync(path.join(os.homedir(), '.cache', 'seclab-cfs-selftest-'));
	try {
		const good = path.join(dir, 'cfs.json');
		fs.writeFileSync(good, JSON.stringify(vectors.valid[0]), { mode: 0o600 });
		loadCfsConfig(good);
		const expectRefused = (p: string, why: string, reason: string) => {
			try {
				loadCfsConfig(p);
				fails.push(`file accepted: ${why}`);
			} catch (e) {
				if (!(e instanceof CfsConfigError) || !e.message.includes(reason)) {
					fails.push(`file ${why}: ${String(e)}`);
				}
			}
		};
		fs.chmodSync(good, 0o640);
		expectRefused(good, 'group-readable', 'group or others');
		fs.chmodSync(good, 0o604);
		expectRefused(good, 'world-readable', 'group or others');
		fs.chmodSync(good, 0o600);
		const link = path.join(dir, 'link.json');
		fs.symlinkSync(good, link);
		expectRefused(link, 'symlink', 'not a regular file');
		expectRefused(path.join(dir, 'missing.json'), 'missing', 'no config');
		const bad = path.join(dir, 'bad.json');
		fs.writeFileSync(bad, '{', { mode: 0o600 });
		expectRefused(bad, 'not JSON', 'not valid JSON');
		// Refused on the path alone, before the file is read (nothing is written in the repo).
		expectRefused(path.join(REPO, 'cfs.json'), 'inside the repo', 'outside any repository');
	} finally {
		fs.rmSync(dir, { recursive: true, force: true });
	}
	// Not owned by the user: only checkable as root, against another uid.
	if (fails.length) {
		console.error(fails.join('\n'));
		process.exit(1);
	}
	console.log(`cfs-config self-test: ok (${vectors.valid.length} valid, ${vectors.invalid.length} invalid vectors; 6 file refusals)`);
}

if (import.meta.main) {
	const [cmd, arg] = process.argv.slice(2);
	try {
		if (cmd === '--self-test') {
			fs.mkdirSync(path.join(os.homedir(), '.cache'), { recursive: true });
			selfTest();
		} else if (cmd === 'check') {
			loadCfsConfig();
			console.log('cfs-config: ok');
		} else if (cmd === 'get' && (CFS_FIELDS as readonly string[]).includes(arg ?? '')) {
			process.stdout.write(loadCfsConfig()[arg as CfsField]);
		} else if (cmd === 'write') {
			write(cfsConfigPath());
			console.log(`cfs-config: wrote ${cfsConfigPath()}`);
		} else {
			console.error('usage: node build/cfs-config.ts check | get FIELD | write | --self-test');
			process.exit(2);
		}
	} catch (e) {
		console.error(`cfs-config: ${e instanceof CfsConfigError ? e.message : 'failed'}`);
		process.exit(1);
	}
}
