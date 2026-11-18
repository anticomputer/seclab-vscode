// appBuildProblem (test/app-build.ts): a run launches only the build it was asked to test.
import { strict as assert } from 'node:assert';
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { test } from 'node:test';
import { appBuildProblem } from './app-build.ts';

const scratchRoot = path.join(import.meta.dirname, '..', '.work', 'test-scratch');

function repo(tag = ''): { root: string; head: string; old: string } {
	fs.mkdirSync(scratchRoot, { recursive: true });
	const root = fs.mkdtempSync(path.join(scratchRoot, 'app-build-'));
	const git = (...a: string[]) => execFileSync('git', ['-C', root, '-c', 'user.name=t', '-c', 'user.email=t@t.invalid', '-c', 'commit.gpgsign=false', ...a], { encoding: 'utf8' }).trim();
	git('init', '-q');
	git('commit', '-q', '--allow-empty', '-m', 'old');
	const old = git('rev-parse', 'HEAD');
	git('commit', '-q', '--allow-empty', '-m', `head${tag}`);
	git('update-ref', 'refs/remotes/origin/main', old);
	return { root, head: git('rev-parse', 'HEAD'), old };
}

function app(dir: string, info?: unknown, file = 'build-info.json'): string {
	const a = path.join(dir, 'seclab-vscode.app');
	fs.mkdirSync(path.join(a, 'Contents', 'MacOS'), { recursive: true });
	if (info !== undefined) {
		fs.writeFileSync(path.join(dir, file), JSON.stringify(info));
	}
	return a;
}

test('fetched-app binding: a stale branch build is refused, the build of HEAD is launched', () => {
	const r = repo();
	const branch = path.join(r.root, '.work', 'app-branch');
	const darwin = { repoRoot: r.root, platform: 'darwin' };
	assert.match(appBuildProblem(app(branch, { repoSha: r.old }), darwin) ?? '', /stale or different build/);
	assert.equal(appBuildProblem(app(branch, { repoSha: r.head }), darwin), undefined);
	// An explicit commit wins either way.
	assert.equal(appBuildProblem(app(branch, { repoSha: r.old }), { ...darwin, expect: r.old }), undefined);
	assert.match(appBuildProblem(app(branch, { repoSha: r.head }), { ...darwin, expect: r.old }) ?? '', /SECLAB_APP_SHA/);
	assert.match(appBuildProblem(app(branch, { repoSha: r.head }), { ...darwin, expect: r.head.slice(0, 12) }) ?? '', /full 40-hex/);
});

test('fetched-app binding: the release app must be a build of a commit on origin/main', () => {
	const r = repo();
	const release = path.join(r.root, '.work', 'app');
	const o = { repoRoot: r.root, platform: 'darwin' };
	assert.equal(appBuildProblem(app(release, { repoSha: r.old }), o), undefined);
	// A release fetch that didn't complete leaves its marker: the old app isn't taken as asked for (FAB2-1).
	fs.writeFileSync(path.join(r.root, '.work', 'app-fetch-pending'), 'run 1\n');
	assert.match(appBuildProblem(path.join(release, 'seclab-vscode.app'), o) ?? '', /didn't complete/);
	fs.rmSync(path.join(r.root, '.work', 'app-fetch-pending'));
	// HEAD (a branch commit) isn't on origin/main (review FAB-4).
	assert.match(appBuildProblem(app(release, { repoSha: r.head }), o) ?? '', /isn't on origin\/main/);
	assert.match(appBuildProblem(app(release, { repoSha: 'a'.repeat(40) }), o) ?? '', /isn't on origin\/main/);
	// A symlinked release location doesn't get the release rule (review FAB-6).
	fs.rmSync(release, { recursive: true });
	const elsewhere = path.join(r.root, 'elsewhere');
	const e = app(elsewhere, { repoSha: r.old });
	fs.symlinkSync(elsewhere, release);
	assert.match(appBuildProblem(path.join(release, path.basename(e)), o) ?? '', /stale or different build/);
});

test('fetched-app binding: a test build runs only from .work/test-builds, and GIT_DIR is ignored', () => {
	const r = repo();
	const o = { repoRoot: r.root, platform: 'darwin' };
	const tb = { repoSha: r.head, testBuild: { variant: 'containment' } };
	// Even when SECLAB_APP_SHA names its commit (review FAB-4, FAB-8).
	assert.match(appBuildProblem(app(path.join(r.root, '.work', 'app-branch'), tb), { ...o, expect: r.head }) ?? '', /is a test build/);
	assert.match(appBuildProblem(app(path.join(r.root, '.work', 'app'), { ...tb, repoSha: r.old }), o) ?? '', /is a test build/);
	assert.equal(appBuildProblem(app(path.join(r.root, '.work', 'test-builds', 'containment'), tb, 'build-info-app.json'), o), undefined);
	// An inherited GIT_DIR doesn't move HEAD to another repository (review FAB-7).
	const other = repo('-other');
	assert.notEqual(other.head, r.head);
	const saved = process.env.GIT_DIR;
	process.env.GIT_DIR = path.join(other.root, '.git');
	try {
		assert.equal(appBuildProblem(app(path.join(r.root, '.work', 'app-branch2'), { repoSha: r.head }), o), undefined);
	} finally {
		if (saved === undefined) {
			delete process.env.GIT_DIR;
		} else {
			process.env.GIT_DIR = saved;
		}
	}
});

test('fetched-app binding: missing, unreadable or commitless build info', () => {
	const r = repo();
	const o = { repoRoot: r.root, platform: 'darwin' };
	assert.match(appBuildProblem(app(path.join(r.root, 'none')), o) ?? '', /no build-info.json/);
	assert.equal(appBuildProblem(app(path.join(r.root, 'linux')), { ...o, platform: 'linux' }), undefined);
	// A Linux build info from a later REH-only build isn't the editor's (review FAB2-6).
	const lo = { ...o, platform: 'linux' };
	assert.match(appBuildProblem(app(path.join(r.root, 'lreh'), { repoSha: r.head, targets: 'reh' }), lo) ?? '', /without the editor/);
	assert.equal(appBuildProblem(app(path.join(r.root, 'led'), { repoSha: r.head, targets: 'editor' }), lo), undefined);
	assert.match(appBuildProblem(app(path.join(r.root, 'nosha'), { upstreamSha: r.head }), o) ?? '', /records no commit/);
	assert.match(appBuildProblem(app(path.join(r.root, 'arr'), [r.head]), o) ?? '', /not a JSON object/);
	const linked = path.join(r.root, 'linked');
	const a = app(linked);
	fs.writeFileSync(path.join(r.root, 'real.json'), JSON.stringify({ repoSha: r.head }));
	fs.symlinkSync(path.join(r.root, 'real.json'), path.join(linked, 'build-info.json'));
	assert.match(appBuildProblem(a, o) ?? '', /can't be opened/);
	// A test variant's app info is build-info-app.json, and it is the one read.
	const variant = path.join(r.root, '.work', 'test-builds', 'containment');
	const v = app(variant, { repoSha: r.old }, 'build-info-app.json');
	fs.writeFileSync(path.join(variant, 'build-info.json'), JSON.stringify({ repoSha: r.head }));
	assert.match(appBuildProblem(v, o) ?? '', /stale or different build/);
});

test('fetched-app binding: a build in a nested checkout is that checkout HEAD build (A/B baseline)', () => {
	const r = repo();
	const nested = path.join(r.root, '.work', 'ubranch');
	fs.mkdirSync(nested, { recursive: true });
	const git = (...a: string[]) => execFileSync('git', ['-C', nested, '-c', 'user.name=t', '-c', 'user.email=t@t.invalid', '-c', 'commit.gpgsign=false', ...a], { encoding: 'utf8' }).trim();
	git('init', '-q');
	git('commit', '-q', '--allow-empty', '-m', 'baseline');
	const base = git('rev-parse', 'HEAD');
	const o = { repoRoot: r.root, platform: 'darwin' };
	const dir = path.join(nested, '.work', 'test-builds', 'agentic-browser');
	assert.equal(appBuildProblem(app(dir, { repoSha: base, testBuild: {} }, 'build-info-app.json'), o), undefined);
	assert.match(appBuildProblem(app(dir, { repoSha: r.head, testBuild: {} }, 'build-info-app.json'), o) ?? '', /stale or different build/);
});

test('fetched-app binding: a .git planted beside an app does not choose its HEAD (FAB3-2)', () => {
	const r = repo();
	const o = { repoRoot: r.root, platform: 'darwin' };
	// A repository whose HEAD is the stale commit, and .git files pointing at it.
	const stale = path.join(r.root, 'stale-repo');
	execFileSync('git', ['clone', '-q', r.root, stale]);
	execFileSync('git', ['-C', stale, 'checkout', '-q', r.old]);
	for (const at of [path.join('.work', 'app-branch'), '.work']) {
		const dir = path.join(r.root, '.work', 'app-branch');
		const a = app(dir, { repoSha: r.old });
		fs.writeFileSync(path.join(r.root, at, '.git'), `gitdir: ${path.join(stale, '.git')}\n`);
		assert.match(appBuildProblem(a, o) ?? '', /stale or different build/, at);
		fs.rmSync(path.join(r.root, at, '.git'));
	}
	// The release location keeps its rule and its marker with a .git planted in it.
	const rel = app(path.join(r.root, '.work', 'app'), { repoSha: r.old });
	fs.writeFileSync(path.join(r.root, '.work', 'app', '.git'), `gitdir: ${path.join(stale, '.git')}\n`);
	fs.writeFileSync(path.join(r.root, '.work', 'app-fetch-pending'), 'run 1\n');
	assert.match(appBuildProblem(rel, o) ?? '', /didn't complete/);
});
