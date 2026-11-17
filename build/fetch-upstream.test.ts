// Review FU: fetch-upstream makes the build tree exactly the pinned commit, and the install stamp
// follows every lockfile and the pin. Drives build/fetch-upstream.sh and build/linux/install-stamp.sh
// against a local file:// "upstream" with two tagged releases (no network).
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { test } from 'node:test';

const repo = path.join(import.meta.dirname, '..');
const scratch = path.join(repo, '.work', 'test-scratch', `fetch-upstream-${process.pid}`);
const env = { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@example.invalid', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@example.invalid', GIT_CONFIG_NOSYSTEM: '1', HOME: scratch,
	// Repository discovery stops above the scratch tree (a worktree checkout's .git is a file
	// that can name a path outside the container).
	GIT_CEILING_DIRECTORIES: path.dirname(scratch) };
const git = (cwd: string, ...args: string[]) => execFileSync('git', ['-C', cwd, ...args], { encoding: 'utf8', env }).trim();
const put = (root: string, rel: string, text: string) => {
	fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
	fs.writeFileSync(path.join(root, rel), text);
};

/** A fake ROOT holding the real script, a lock for TAG, and an upstream with tags v1 and v2. */
function setup(): { root: string; dest: string; sha: Record<string, string>; fetch: (tag: string) => string } {
	fs.rmSync(scratch, { recursive: true, force: true });
	const up = path.join(scratch, 'upstream');
	fs.mkdirSync(up, { recursive: true });
	git(up, 'init', '-q', '-b', 'main');
	put(up, '.gitignore', 'node_modules/\n.build/\n');
	put(up, 'src/vs/a.ts', 'a1\n');
	put(up, 'package-lock.json', '{"v":1}\n');
	put(up, 'extensions/git/package-lock.json', '{"g":1}\n');
	git(up, 'add', '-A'); git(up, 'commit', '-qm', 'v1'); git(up, 'tag', 'v1');
	put(up, 'src/vs/a.ts', 'a2\n');
	git(up, 'commit', '-qam', 'v2'); git(up, 'tag', 'v2');
	const sha = { v1: git(up, 'rev-parse', 'v1'), v2: git(up, 'rev-parse', 'v2') };
	const root = path.join(scratch, 'root');
	fs.mkdirSync(path.join(root, 'build'), { recursive: true });
	fs.copyFileSync(path.join(repo, 'build', 'fetch-upstream.sh'), path.join(root, 'build', 'fetch-upstream.sh'));
	const dest = path.join(scratch, 'vscode');
	const fetch = (tag: string) => {
		fs.writeFileSync(path.join(root, 'upstream.lock'), `UPSTREAM_REPO=file://${up}\nUPSTREAM_TAG=${tag}\nUPSTREAM_SHA=${sha[tag as 'v1' | 'v2']}\n`);
		return execFileSync('bash', [path.join(root, 'build', 'fetch-upstream.sh'), dest], { encoding: 'utf8', env, cwd: scratch, stdio: ['ignore', 'pipe', 'pipe'] });
	};
	return { root, dest, sha, fetch };
}

test('fetch-upstream: a pin change drops files earlier patches added, keeps ignored build state', () => {
	try {
		const { dest, sha, fetch } = setup();
		fetch('v1');
		put(dest, 'src/vs/patchCreated.ts', 'from an earlier patch queue\n');
		put(dest, 'product.json.seclab-test', '{}');
		put(dest, 'resources/stray.txt', 'x');
		put(dest, 'node_modules/pkg/index.js', 'cached');
		fetch('v2');
		assert.equal(git(dest, 'rev-parse', 'HEAD'), sha.v2);
		assert.ok(!fs.existsSync(path.join(dest, 'src/vs/patchCreated.ts')), 'patch-created file removed');
		assert.ok(!fs.existsSync(path.join(dest, 'product.json.seclab-test')), 'test-variant leftover removed');
		assert.ok(!fs.existsSync(path.join(dest, 'resources/stray.txt')), 'untracked file outside the old path list removed');
		assert.equal(fs.readFileSync(path.join(dest, 'node_modules/pkg/index.js'), 'utf8'), 'cached', 'ignored install kept');
		assert.equal(fs.readFileSync(path.join(dest, 'src/vs/a.ts'), 'utf8'), 'a2\n');
	} finally {
		fs.rmSync(scratch, { recursive: true, force: true });
	}
});

test('fetch-upstream: same pin, a tracked file hidden by skip-worktree or sparse state is restored', () => {
	try {
		const { dest, fetch } = setup();
		fetch('v2');
		git(dest, 'update-index', '--skip-worktree', 'src/vs/a.ts');
		put(dest, 'src/vs/a.ts', 'tampered\n');
		put(dest, 'src/vs/stray.ts', 'x');
		fetch('v2');
		assert.equal(fs.readFileSync(path.join(dest, 'src/vs/a.ts'), 'utf8'), 'a2\n', 'skip-worktree edit undone');
		assert.ok(!fs.existsSync(path.join(dest, 'src/vs/stray.ts')));
		assert.equal(git(dest, 'ls-files', '-v').split('\n').filter(l => /^[a-zS]/.test(l)).length, 0, 'no skip-worktree or assume-unchanged entry left');

		git(dest, 'config', 'core.sparseCheckout', 'true');
		put(dest, '.git/info/sparse-checkout', 'package-lock.json\n');
		put(dest, 'src/vs/a.ts', 'tampered again\n');
		fetch('v2');
		assert.equal(fs.readFileSync(path.join(dest, 'src/vs/a.ts'), 'utf8'), 'a2\n', 'sparse state dropped, file restored');
		assert.equal(git(dest, 'status', '--porcelain'), '');
	} finally {
		fs.rmSync(scratch, { recursive: true, force: true });
	}
});

test('install stamp: changes with any lockfile (extensions included) and with the pin, not with node_modules', () => {
	try {
		const { dest, fetch } = setup();
		const stamp = () => execFileSync('bash', ['-euo', 'pipefail', '-c', `. "${path.join(repo, 'build', 'linux', 'install-stamp.sh')}"; install_stamp cfs1 "$1"`, 'x', dest], { encoding: 'utf8', env }).trim();
		fetch('v1');
		const s1 = stamp();
		assert.match(s1, /^cfs1-[0-9a-f]{16}$/);
		put(dest, 'node_modules/x/package-lock.json', '{"ignored":1}\n');
		assert.equal(stamp(), s1, 'lockfiles inside node_modules are not inputs');
		put(dest, 'extensions/git/package-lock.json', '{"g":2}\n');
		const s2 = stamp();
		assert.notEqual(s2, s1, 'a built-in extension lockfile is an input');
		fetch('v1');
		assert.equal(stamp(), s1, 'deterministic for the same tree');
		fetch('v2');
		assert.notEqual(stamp(), s1, 'the pinned commit is an input');
	} finally {
		fs.rmSync(scratch, { recursive: true, force: true });
	}
});

test('fetch-upstream: excludes and config on the volume or in user config hide nothing (FU-10)', () => {
	try {
		const { dest, fetch } = setup();
		fetch('v2');
		put(dest, 'src/vs/planted.ts', 'x');
		put(dest, '.git/info/exclude', 'src/vs/planted.ts\n');
		git(dest, 'config', 'status.showUntrackedFiles', 'no');
		put(scratch, '.gitconfig', `[core]\n\texcludesFile = ${path.join(scratch, 'ignore')}\n\tsparseCheckout = true\n`);
		put(scratch, 'ignore', 'src/vs/planted2.ts\n');
		put(dest, 'src/vs/planted2.ts', 'y');
		fetch('v2');
		assert.ok(!fs.existsSync(path.join(dest, 'src/vs/planted.ts')), 'a file hidden by info/exclude is removed');
		assert.ok(!fs.existsSync(path.join(dest, 'src/vs/planted2.ts')), 'a file hidden by a global excludesFile is removed');
		assert.equal(fs.readFileSync(path.join(dest, 'src/vs/a.ts'), 'utf8'), 'a2\n');
	} finally {
		fs.rmSync(scratch, { recursive: true, force: true });
	}
});

test('fetch-upstream: a .git that is a file (another repository) is refused (FU-9)', () => {
	try {
		const { dest, fetch } = setup();
		fetch('v2');
		const elsewhere = path.join(scratch, 'elsewhere.git');
		fs.renameSync(path.join(dest, '.git'), elsewhere);
		fs.writeFileSync(path.join(dest, '.git'), `gitdir: ${elsewhere}\n`);
		assert.throws(() => fetch('v2'), /not a directory/);
		fs.rmSync(path.join(dest, '.git'));
		fs.symlinkSync(elsewhere, path.join(dest, '.git'));
		assert.throws(() => fetch('v2'), /not a directory/);
	} finally {
		fs.rmSync(scratch, { recursive: true, force: true });
	}
});

test('install stamp: a symlinked lockfile is refused; a lockfile under an odd path still counts (FU-11)', () => {
	try {
		const { dest, fetch } = setup();
		const stamp = () => execFileSync('bash', ['-euo', 'pipefail', '-c', `. "${path.join(repo, 'build', 'linux', 'install-stamp.sh')}"; install_stamp cfs1 "$1"`, 'x', dest], { encoding: 'utf8', env, stdio: ['ignore', 'pipe', 'pipe'] }).trim();
		fetch('v1');
		put(dest, 'extensions/odd\nname/package-lock.json', '{"o":1}\n');
		const s1 = stamp();
		put(dest, 'extensions/odd\nname/package-lock.json', '{"o":2}\n');
		assert.notEqual(stamp(), s1, 'a lockfile under a path with a newline is an input');
		fs.symlinkSync(path.join(dest, 'package-lock.json'), path.join(dest, 'extensions', 'package-lock.json'));
		assert.throws(stamp, /symlinked/);
	} finally {
		fs.rmSync(scratch, { recursive: true, force: true });
	}
});

test('fetch-upstream: the volume\'s own config, attributes and hooks are not honoured (PR 25 review)', () => {
	try {
		const { dest, fetch } = setup();
		fetch('v1');
		// A clean/smudge filter: the tree would hold smudged bytes while status cleans them back.
		git(dest, 'config', 'filter.evil.smudge', 'sed s/a/EVIL/');
		git(dest, 'config', 'filter.evil.clean', 'sed s/EVIL/a/');
		put(dest, '.git/info/attributes', 'src/vs/a.ts filter=evil\n');
		// A hook that a checkout would run.
		put(dest, '.git/hooks/post-checkout', `#!/bin/sh\necho ran > ${path.join(scratch, 'hook-ran')}\n`);
		fs.chmodSync(path.join(dest, '.git/hooks/post-checkout'), 0o755);
		fetch('v1');
		assert.equal(fs.readFileSync(path.join(dest, 'src/vs/a.ts'), 'utf8'), 'a1\n', 'same pin: no smudge');
		fetch('v2');
		assert.equal(fs.readFileSync(path.join(dest, 'src/vs/a.ts'), 'utf8'), 'a2\n', 'new pin: no smudge');
		assert.ok(!fs.existsSync(path.join(scratch, 'hook-ran')), 'no hook ran');
		assert.doesNotMatch(fs.readFileSync(path.join(dest, '.git', 'config'), 'utf8'), /filter/, 'filter config gone');
	} finally {
		fs.rmSync(scratch, { recursive: true, force: true });
	}
});

test('fetch-upstream: a kept core.worktree can\'t redirect the reset and clean (PR 25 review)', () => {
	try {
		const { dest, fetch } = setup();
		fetch('v2');
		const other = path.join(scratch, 'other');
		put(other, 'keep.txt', 'not ours');
		git(dest, 'config', 'core.worktree', other);
		put(dest, 'src/vs/stray.ts', 'x');
		fetch('v2');
		assert.equal(fs.readFileSync(path.join(other, 'keep.txt'), 'utf8'), 'not ours', 'the other tree is untouched');
		assert.ok(!fs.existsSync(path.join(dest, 'src/vs/stray.ts')), 'DEST itself was cleaned');
		assert.equal(fs.readFileSync(path.join(dest, 'src/vs/a.ts'), 'utf8'), 'a2\n');
	} finally {
		fs.rmSync(scratch, { recursive: true, force: true });
	}
});

test('fetch-upstream: a linked .git/config or .git/info reaches nothing outside DEST (PR 25 review)', () => {
	for (const [what, link] of [
		['symlinked config', (dest: string, out: string) => { fs.rmSync(path.join(dest, '.git/config')); fs.symlinkSync(path.join(out, 'victim'), path.join(dest, '.git/config')); }],
		['symlinked info dir', (dest: string, out: string) => { fs.rmSync(path.join(dest, '.git/info'), { recursive: true, force: true }); fs.mkdirSync(path.join(out, 'info')); put(out, 'info/exclude', 'keep'); fs.symlinkSync(path.join(out, 'info'), path.join(dest, '.git/info')); }],
		['hard-linked config', (dest: string, out: string) => { fs.rmSync(path.join(dest, '.git/config')); fs.linkSync(path.join(out, 'victim'), path.join(dest, '.git/config')); }],
	] as Array<[string, (dest: string, out: string) => void]>) {
		try {
			const { dest, fetch } = setup();
			fetch('v2');
			const out = path.join(scratch, 'outside');
			put(out, 'victim', 'not ours\n');
			link(dest, out);
			try {
				fetch('v2');
			} catch { /* a refusal is fine; what matters is what happened outside */ }
			assert.equal(fs.readFileSync(path.join(out, 'victim'), 'utf8'), 'not ours\n', `${what}: the outside file is untouched`);
			if (fs.existsSync(path.join(out, 'info'))) {
				assert.equal(fs.readFileSync(path.join(out, 'info/exclude'), 'utf8'), 'keep', `${what}: the outside directory is untouched`);
			}
		} finally {
			fs.rmSync(scratch, { recursive: true, force: true });
		}
	}
});
