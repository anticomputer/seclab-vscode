// Which build a run launches (EDR fetched-app-binding). A fetched macOS app carries the
// build-info.json its fetch verified (`./seclab fetch macos`, `macos-branch`, `macos-<variant>`).
// Every harness and driver launch checks that the app's recorded commit is the one the run was
// asked to test, so an app left over from an earlier fetch is never mistaken for the new one.
//
// The commit a run is asked to test:
//   SECLAB_APP_SHA=<40 hex>   that commit, whatever the app's location;
//   otherwise, a branch or test-variant build (anything but the release location) must be the
//   HEAD of the checkout it was fetched into (this one, or one nested in its .work, such as an A/B
//   run's baseline worktree), and the release app (.work/app) a build of a commit on origin/main.
// A test build (build info with `testBuild`) runs only from .work/test-builds/ (review FAB-4, FAB-8).
// A Linux editor without a fetched build-info.json is one this checkout built (./seclab build
// linux editor) and is not checked here.

import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

const HEX40 = /^[0-9a-f]{40}$/;

function readInfo(file: string): { repoSha?: unknown } | string {
	let fd: number;
	try {
		fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
	} catch (e) {
		return `${file} can't be opened (${(e as NodeJS.ErrnoException).code})`;
	}
	try {
		const st = fs.fstatSync(fd);
		if (!st.isFile() || st.size > 64 * 1024) {
			return `${file} is not a small regular file`;
		}
		const info = JSON.parse(fs.readFileSync(fd, 'utf8'));
		return info && typeof info === 'object' && !Array.isArray(info) ? info : `${file} is not a JSON object`;
	} catch {
		return `${file} is not valid JSON`;
	} finally {
		fs.closeSync(fd);
	}
}

/** Why `app` must not be launched by this run, or undefined when it may. */
export function appBuildProblem(app: string, opts: { repoRoot: string; expect?: string; platform?: string }): string | undefined {
	const dir = real(path.dirname(path.resolve(app)));
	// A test variant's app keeps its info as build-info-app.json (its REH's is beside it).
	const file = ['build-info-app.json', 'build-info.json'].map(f => path.join(dir, f)).find(f => fs.existsSync(f) || isLink(f));
	if (!file) {
		return (opts.platform ?? process.platform) === 'darwin'
			? `${app}: no build-info.json beside it, so the build it is can't be checked; fetch it with ./seclab fetch`
			: undefined;
	}
	const info = readInfo(file);
	if (typeof info === 'string') {
		return info;
	}
	// A local Linux build info names its targets; one without the editor is a later REH build's.
	if ('targets' in info && !/\beditor\b/.test(String((info as { targets?: unknown }).targets))) {
		return `${file} is from a build without the editor (targets ${JSON.stringify((info as { targets?: unknown }).targets)}), not this app's`;
	}
	const sha = info.repoSha;
	if (typeof sha !== 'string' || !HEX40.test(sha)) {
		return `${file} records no commit (repoSha)`;
	}
	// The checkout the app was fetched into: this one, or a checkout nested in its .work (an A/B
	// run's baseline worktree builds its own commit). Its HEAD is the commit under test.
	const checkout = owningCheckout(dir, real(opts.repoRoot));
	// No inherited GIT_DIR and the like: HEAD is that checkout's (review FAB-7).
	const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^GIT_/.test(k)));
	const git = (...args: string[]) => execFileSync('git', ['-C', checkout, ...args], { encoding: 'utf8', env, stdio: ['ignore', 'pipe', 'ignore'] }).trim();
	if ('testBuild' in info && !isUnder(dir, real(path.join(checkout, '.work', 'test-builds')))) {
		return `${app} is a test build (its build info has testBuild): it runs only from .work/test-builds/`;
	}
	if (opts.expect !== undefined) {
		if (!HEX40.test(opts.expect)) {
			return 'SECLAB_APP_SHA must be a full 40-hex commit';
		}
		return sha === opts.expect ? undefined : `${app} was built from ${sha}, not ${opts.expect} (SECLAB_APP_SHA): a stale or different build`;
	}
	let head: string;
	try {
		head = git('rev-parse', 'HEAD');
	} catch {
		return `can't read the HEAD of ${checkout} to check ${app}; set SECLAB_APP_SHA`;
	}
	// The release rule is for the release location itself, not wherever a symlink there points.
	const releasePath = path.join(checkout, '.work', 'app');
	if (!isLink(releasePath) && dir === real(releasePath)) {
		if (fs.existsSync(path.join(checkout, '.work', 'app-fetch-pending')) || isLink(path.join(checkout, '.work', 'app-fetch-pending'))) {
			return `${app}: the last ./seclab fetch macos didn't complete (.work/app-fetch-pending), so this may not be the build asked for; fetch again, or set SECLAB_APP_SHA`;
		}
		try {
			git('merge-base', '--is-ancestor', sha, 'refs/remotes/origin/main');
			return undefined;
		} catch {
			return `${app} was built from ${sha}, which isn't on origin/main (fetch it, or set SECLAB_APP_SHA to test that commit)`;
		}
	}
	return sha === head ? undefined
		: `${app} was built from ${sha}, not the HEAD ${head} of ${checkout}: a stale or different build. Fetch the build of HEAD, or set SECLAB_APP_SHA to the commit this run tests`;
}

/** The nearest directory at or above `dir` holding a .git entry, if it is `root` or inside it; else `root`. */
function owningCheckout(dir: string, root: string): string {
	for (let d = dir; ; d = path.dirname(d)) {
		if (fs.existsSync(path.join(d, '.git'))) {
			return d === root || isUnder(d, root) ? d : root;
		}
		if (path.dirname(d) === d) {
			return root;
		}
	}
}

/** The canonical path (case and symlinks resolved), or the path itself when it doesn't exist (review FAB-6). */
function real(p: string): string {
	try {
		return fs.realpathSync.native(p);
	} catch {
		return p;
	}
}

function isUnder(p: string, root: string): boolean {
	const r = path.relative(root, p);
	return r !== '' && !r.startsWith('..') && !path.isAbsolute(r);
}

function isLink(f: string): boolean {
	try {
		return fs.lstatSync(f).isSymbolicLink();
	} catch {
		return false;
	}
}

/** Throws unless `app` is the build this run was asked to test. */
export function requireAppBuild(app: string, repoRoot: string): void {
	const p = appBuildProblem(app, { repoRoot, expect: process.env.SECLAB_APP_SHA || undefined });
	if (p) {
		throw new Error(`refusing to launch: ${p}`);
	}
}
