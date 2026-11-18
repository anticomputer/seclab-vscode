// appBuildProblem (test/app-build.ts): a run launches only the build it was asked to test.
import { strict as assert } from 'node:assert';
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { test } from 'node:test';
import { appBuildProblem } from './app-build.ts';

const scratchRoot = path.join(import.meta.dirname, '..', '.work', 'test-scratch');

function repo(): { root: string; head: string; old: string } {
	fs.mkdirSync(scratchRoot, { recursive: true });
	const root = fs.mkdtempSync(path.join(scratchRoot, 'app-build-'));
	const git = (...a: string[]) => execFileSync('git', ['-C', root, '-c', 'user.name=t', '-c', 'user.email=t@t.invalid', '-c', 'commit.gpgsign=false', ...a], { encoding: 'utf8' }).trim();
	git('init', '-q');
	git('commit', '-q', '--allow-empty', '-m', 'old');
	const old = git('rev-parse', 'HEAD');
	git('commit', '-q', '--allow-empty', '-m', 'head');
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

test('fetched-app binding: the release app must be in HEAD history', () => {
	const r = repo();
	const release = path.join(r.root, '.work', 'app');
	const o = { repoRoot: r.root, platform: 'darwin' };
	assert.equal(appBuildProblem(app(release, { repoSha: r.old }), o), undefined);
	assert.match(appBuildProblem(app(release, { repoSha: 'a'.repeat(40) }), o) ?? '', /isn't in this checkout's history/);
});

test('fetched-app binding: missing, unreadable or commitless build info', () => {
	const r = repo();
	const o = { repoRoot: r.root, platform: 'darwin' };
	assert.match(appBuildProblem(app(path.join(r.root, 'none')), o) ?? '', /no build-info.json/);
	assert.equal(appBuildProblem(app(path.join(r.root, 'linux')), { ...o, platform: 'linux' }), undefined);
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
