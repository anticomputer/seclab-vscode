// Write-back gate engine against a hostile upper layer (ADR 20261104-write-back-gate).
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { test } from 'node:test';
import { fileIdentity } from '../src/state.ts';
import { checkRel, globMatch, WriteBackEngine, type UpperChange } from '../src/writeback.ts';

const SCRATCH = path.resolve(import.meta.dirname, '../../.work/test-scratch/writeback');
/** Fixture .git dirs aren't real repos: tests inject the host-ignore answer (real git: see Z-1 test). */
const NONE_IGNORED = () => new Set<string>();

function setup(name: string) {
	const dir = path.join(SCRATCH, name);
	fs.rmSync(dir, { recursive: true, force: true });
	const root = path.join(dir, 'ws');
	fs.mkdirSync(path.join(root, '.git', 'hooks'), { recursive: true });
	fs.writeFileSync(path.join(root, 'README.md'), 'hello\n');
	fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'x', scripts: { test: 'node --test' }, dependencies: {} }));
	fs.writeFileSync(path.join(root, '.git', 'config'), '[core]\n\tbare = false\n');
	const statePath = path.join(dir, 'writeback.json');
	const mk = () => new WriteBackEngine({ root, rootIdentity: fileIdentity(root), statePath, ignoredBy: NONE_IGNORED });
	return { root, dir, statePath, mk };
}
const file = (p: string, s: string, mode = 0o644): UpperChange => ({ path: p, kind: 'file', content: Buffer.from(s, 'latin1'), mode });
const u32 = (n: number) => {
	const b = Buffer.alloc(4);
	b.writeUInt32BE(n);
	return b;
};
const EMPTY_INDEX = Buffer.concat([Buffer.from('DIRC'), u32(2), u32(0), Buffer.alloc(20)]);
const exists = (p: string) => {
	try {
		fs.lstatSync(p);
		return true;
	} catch {
		return false;
	}
};

test('writeback: paths are validated (no .., absolute, NUL, empty segments)', () => {
	for (const bad of ['../x', 'a/../../x', '/etc/passwd', 'a//b', './a', 'a/./b', 'a\0b', '', 'C:/x', 'a/' + 'x'.repeat(256)]) {
		assert.throws(() => checkRel(bad), /invalid path/, bad);
	}
	assert.equal(checkRel('src/a.ts'), 'src/a.ts');
	const { mk, root } = setup('paths');
	const r = mk().sync([file('../escape.txt', 'x'), file('/abs', 'x'), file('ok.txt', 'fine')]);
	assert.equal(r.refused.length, 2);
	assert.deepEqual(r.applied, ['ok.txt']);
	assert.ok(!exists(path.join(root, '..', 'escape.txt')));
});

test('writeback: globs', () => {
	assert.ok(globMatch('.git/**', '.git/hooks/pre-commit'));
	assert.ok(globMatch('**/conftest.py', 'conftest.py') && globMatch('**/conftest.py', 'a/b/conftest.py'));
	assert.ok(globMatch('*.sh', 'build.sh') && !globMatch('*.sh', 'scripts/build.sh'));
	assert.ok(!globMatch('.git/**', '.github/workflows/x.yml'));
});

test('writeback: ordinary files auto, code-running paths held, .git default-hold', () => {
	const { mk, root } = setup('classes');
	const obj = `.git/objects/ab/${'c'.repeat(38)}`;
	const r = mk().sync([
		file('src/app.ts', 'export {};\n'),
		file(obj, 'blob'), file('.git/refs/heads/main', 'abc\n'), file('.git/index', EMPTY_INDEX.toString('latin1')),
		file('.git/hooks/pre-commit', '#!/bin/sh\nexit 0\n', 0o755), file('.git/config', '[core]\n\tfsmonitor = sh x\n'), file('.git/info/attributes', '* filter=x'),
		file('.git/modules/sub/config', '[core]\n'), file('.envrc', 'echo hi\n'), file('.vscode/tasks.json', '{}'), file('Makefile', 'all:\n'),
		file('.husky/pre-commit', 'x'), file('node_modules/.bin/eslint', 'x'), file('.github/workflows/ci.yml', 'on: push'), file('run.sh', 'x'),
		file('.git/objects/info/alternates', '/elsewhere'), file('.git/objects/ab/cdef', 'short name'),
	]);
	assert.deepEqual(r.applied.sort(), ['.git/index', '.git/refs/heads/main', obj, 'src/app.ts'].sort());
	assert.deepEqual(r.held.map(h => h.path).sort(), ['.envrc', '.git/config', '.git/hooks/pre-commit', '.git/info/attributes', '.git/modules/sub/config',
		'.git/objects/ab/cdef', '.git/objects/info/alternates', '.github/workflows/ci.yml', '.husky/pre-commit', '.vscode/tasks.json', 'Makefile', 'run.sh']);
	assert.deepEqual(r.refused.map(x => x.path), ['node_modules/.bin/eslint'], 'installed trees are tab-local (Y-3)');
	assert.ok(!exists(path.join(root, '.git', 'hooks', 'pre-commit')) && !exists(path.join(root, '.envrc')));
	assert.equal(fs.readFileSync(path.join(root, '.git', 'config'), 'utf8'), '[core]\n\tbare = false\n');
	assert.equal(fs.readFileSync(path.join(root, 'src', 'app.ts'), 'utf8'), 'export {};\n');
});

test('writeback: W-1 nested .git, gitfiles, gitdirs in disguise, gitlink index entries are held', () => {
	const { mk, root } = setup('w1');
	fs.mkdirSync(path.join(root, 'vendor', 'lib'), { recursive: true });
	const gitlinkIndex = Buffer.concat([Buffer.from('DIRC'), u32(2), u32(1), Buffer.alloc(24), u32(0o160000), Buffer.alloc(32), Buffer.from([0, 3]),
		Buffer.from('sub\0'), Buffer.alloc(2), Buffer.alloc(20)]);
	const r = mk().sync([
		file('vendor/lib/.git', 'gitdir: ../.x\n'), file('vendor/.x/HEAD', 'ref: refs/heads/main\n'), file('vendor/.x/config', '[core]\n\tfsmonitor = sh x\n'),
		file('sub/.git/config', '[core]\n'), file('.git', 'gitdir: /elsewhere\n'), file('docs/notes', 'gitdir: ../../evil\n'),
		file('.git/index', gitlinkIndex.toString('latin1')),
	]);
	assert.equal(r.applied.length, 0, JSON.stringify(r.applied));
	assert.equal(r.held.length, 7);
});

test('writeback: W-2 content of host-executable files, venvs, config-as-code, non-registry deps are held', () => {
	const { mk, root } = setup('w2');
	fs.mkdirSync(path.join(root, 'bin'));
	fs.writeFileSync(path.join(root, 'bin', 'dev'), '#!/bin/sh\necho dev\n', { mode: 0o755 });
	const e = mk();
	const r = e.sync([file('bin/dev', '#!/bin/sh\necho pwned\n', 0o755), file('.venv/lib/python3.12/site-packages/x.pth', 'import os'),
		file('eslint.config.mjs', 'export default []'), file('.yarn/releases/yarn.cjs', 'x'), file('.pnp.cjs', 'x'),
		file('package.json', JSON.stringify({ name: 'x', scripts: { test: 'node --test' }, dependencies: { evil: 'git+https://example.test/e.git' } }))]);
	assert.equal(r.applied.length, 0, JSON.stringify(r.applied));
	assert.equal(r.held.length, 6);
	assert.throws(() => e.alwaysAllow('bin/dev'), /not available/);
});

test('writeback: W-3 approval is bound to mode and link target', () => {
	const { mk, root } = setup('w3');
	const e = mk();
	e.sync([file('.git/hooks/pre-commit', 'inert text\n', 0o644), { path: 'docs/l', kind: 'symlink', target: 'a.txt' }]);
	assert.throws(() => e.approve('.git/hooks/pre-commit', file('.git/hooks/pre-commit', 'inert text\n', 0o755)), /changed this entry/);
	assert.throws(() => e.approve('docs/l', { path: 'docs/l', kind: 'symlink', target: 'payload.sh' }), /changed this entry/);
	e.approve('.git/hooks/pre-commit', file('.git/hooks/pre-commit', 'inert text\n', 0o644));
	assert.equal(fs.statSync(path.join(root, '.git', 'hooks', 'pre-commit')).mode & 0o111, 0);
});

test('writeback: W-4 host edits after the tab started are conflicts; case collisions are held', () => {
	const { mk, root } = setup('w4');
	const e = mk(); // baseline seeded now
	fs.writeFileSync(path.join(root, 'README.md'), 'host edited after tab start\n');
	assert.equal(e.sync([file('README.md', 'tab version\n')]).held[0]?.kind, 'conflict');
	assert.equal(fs.readFileSync(path.join(root, 'README.md'), 'utf8'), 'host edited after tab start\n');
	const r = e.sync([file('docs/Guide.md', 'a'), file('docs/guide.md', 'b')]);
	assert.equal(r.held.length, 2);
});

test('writeback: W-6/W-7/W-11 git deletes, mass deletes, invisible names, duplicate manifest keys', () => {
	const { mk, root } = setup('w6');
	fs.mkdirSync(path.join(root, '.git', 'refs', 'heads'), { recursive: true });
	fs.writeFileSync(path.join(root, '.git', 'refs', 'heads', 'main'), 'abc\n');
	const e = mk();
	assert.equal(e.sync([{ path: '.git/refs/heads/main', kind: 'deleted' }]).held.length, 1);
	const many: UpperChange[] = Array.from({ length: 105 }, (_, i) => ({ path: `gone${i}.txt`, kind: 'deleted' as const }));
	assert.equal(e.sync(many).held.length, 5);
	assert.equal(e.sync([file('.g\u200cit/hooks/pre-commit', 'x'), file('.git\u200b/config', 'x'), file('GIT~1/config', 'x')]).applied.length, 0);
	assert.equal(e.sync([file('package.json', '{"name":"x","scripts":{"test":"node --test"},"dependencies":{},"scripts":{}}')]).held.length, 1);
});

test('writeback: W-9 a worktree checkout (.git is a gitfile) still syncs ordinary files', () => {
	const { root, statePath } = setup('w9');
	fs.rmSync(path.join(root, '.git'), { recursive: true });
	fs.writeFileSync(path.join(root, '.git'), 'gitdir: /somewhere/.git/worktrees/x\n');
	const e = new WriteBackEngine({ root, rootIdentity: fileIdentity(root), statePath, ignoredBy: NONE_IGNORED });
	assert.deepEqual(e.sync([file('src/a.ts', 'x')]).applied, ['src/a.ts']);
	assert.equal(e.sync([file('.git', 'gitdir: /evil\n')]).held.length, 1);
});

test('writeback: case and Unicode variants of held paths are held (APFS)', () => {
	const { mk } = setup('fold');
	const nfd = '.vscode'.normalize('NFD');
	const r = mk().sync([file('.Git/hooks/pre-commit', 'x'), file('.VSCODE/tasks.json', '{}'), file('MAKEFILE', 'x'), file('.ENVRC', 'x'),
		file(`${nfd}/settings.json`, '{}'), file('.GIT/objects/aa/bb', 'x')]);
	assert.equal(r.applied.length, 0, JSON.stringify(r.applied));
	assert.equal(r.held.length, 6);
});

test('writeback: new exec bit, symlinks, hardlinks, special files are held regardless of path', () => {
	const { mk, root } = setup('structural');
	const r = mk().sync([file('tools/x.py', 'print(1)', 0o755), { path: 'docs/link', kind: 'symlink', target: '../../etc' },
		{ ...file('src/h.ts', 'x'), nlink: 2 }, { path: 'src/fifo', kind: 'special' }]);
	assert.equal(r.applied.length, 0);
	assert.deepEqual(r.held.map(h => h.reasons[0]).sort(), ['hardlink', 'newly executable', 'special file', 'symlink']);
	assert.ok(!exists(path.join(root, 'docs', 'link')));
});

test('writeback: package.json held when scripts/bin or dependencies change', () => {
	const { mk, root } = setup('pkg');
	const e = mk();
	const r1 = e.sync([file('package.json', JSON.stringify({ name: 'x', description: 'docs only', scripts: { test: 'node --test' }, dependencies: {} }))]);
	assert.deepEqual(r1.applied, ['package.json']);
	const r2 = e.sync([file('package.json', JSON.stringify({ name: 'x', scripts: { test: 'node --test', postinstall: 'sh evil' }, dependencies: {} }))]);
	assert.equal(r2.held.length, 1);
	assert.ok(!fs.readFileSync(path.join(root, 'package.json'), 'utf8').includes('postinstall'));
	const r3 = e.sync([file('sub/package.json', '{not json')]);
	assert.equal(r3.held.length, 1, 'unparsable manifest is held');
	// X-2: a new registry dependency runs install scripts on the host's next npm install.
	const r4 = e.sync([file('package.json', JSON.stringify({ name: 'x', description: 'docs only', scripts: { test: 'node --test' }, dependencies: { 'evil-pkg': '^1.0.0' } }))]);
	assert.match(r4.held[0]?.reasons.join() ?? '', /evil-pkg/);
	assert.equal(e.sync([file('package-lock.json', '{}')]).held.length, 1);
});

test('writeback: X-1/X-3 agent instructions and config, build files, IDE config are held; never "always"', () => {
	const { mk } = setup('x1');
	const e = mk();
	const r = e.sync(['AGENTS.md', 'docs/CLAUDE.md', '.github/copilot-instructions.md', '.claude/settings.json', '.mcp.json', '.cursor/rules/x.mdc',
		'pom.xml', 'CMakeLists.txt', 'BUILD.bazel', 'app.csproj', '.idea/workspace.xml', '.zed/tasks.json', '.gitlab-ci.yml'].map(p => file(p, 'x')));
	assert.equal(r.applied.length, 0, JSON.stringify(r.applied));
	assert.equal(r.held.length, 13);
	for (const p of ['AGENTS.md', '.claude/settings.json', '.mcp.json', '.vscode/tasks.json']) {
		assert.throws(() => e.alwaysAllow(p), /not available/, p);
	}
	assert.equal(e.sync([file('src/main.c', 'int main(){}')]).applied.length, 1);
});

test('writeback: X-4 includes by absolute path and from a gitfile checkout\'s real gitdir', () => {
	const { root, statePath, dir } = setup('x4');
	const gitdir = path.join(dir, 'main.git', 'worktrees', 'w');
	fs.mkdirSync(gitdir, { recursive: true });
	fs.writeFileSync(path.join(gitdir, 'commondir'), '../..\n');
	fs.writeFileSync(path.join(dir, 'main.git', 'config'), `[include]\n\tpath = ${path.join(root, 'shared.gitconfig')}\n[core]\n\thooksPath = tools/hooks\n`);
	fs.rmSync(path.join(root, '.git'), { recursive: true });
	fs.writeFileSync(path.join(root, '.git'), `gitdir: ${gitdir}\n`);
	const e = new WriteBackEngine({ root, rootIdentity: fileIdentity(root), statePath, ignoredBy: NONE_IGNORED });
	const r = e.sync([file('shared.gitconfig', '[core]\n\tfsmonitor = x\n'), file('tools/hooks/pre-push', 'x'), file('src/ok.ts', 'x')]);
	assert.deepEqual(r.applied, ['src/ok.ts']);
	assert.equal(r.held.length, 2);
});

test('writeback: X-5 deletions are rate-limited across syncs; W-11 escaped duplicate keys', () => {
	const { mk, root } = setup('x5');
	for (let i = 0; i < 260; i++) {
		fs.writeFileSync(path.join(root, `f${i}.txt`), 'x');
	}
	const e = mk();
	let applied = 0;
	for (let b = 0; b < 3; b++) {
		applied += e.sync(Array.from({ length: 80 }, (_, i) => ({ path: `f${b * 80 + i}.txt`, kind: 'deleted' as const }))).applied.length;
	}
	assert.equal(applied, 200);
	// MM-1: the brake is sticky and persisted: after the window drains, and across a restart,
	// further deletions stay held until the user confirms.
	const later = mk();
	assert.equal(later.sync([{ path: 'f250.txt', kind: 'deleted' }]).held.length, 1, 'still held after a restart');
	later.clearDeleteHold();
	assert.equal(later.sync([{ path: 'f251.txt', kind: 'deleted' }]).applied.length, 1, 'released by confirmation');
	assert.equal(e.sync([file('package.json', '{"name":"x","scripts":{"test":"node --test"},"dependencies":{},"scr\\u0069pts":{}}')]).held.length, 1);
});

test('writeback: never writes through a host symlink component; root identity is pinned', () => {
	const { mk, root, dir } = setup('links');
	fs.mkdirSync(path.join(dir, 'outside'));
	fs.symlinkSync(path.join(dir, 'outside'), path.join(root, 'linked'));
	const r = mk().sync([file('linked/pwn.txt', 'x')]);
	assert.equal(r.refused.length, 1, JSON.stringify(r));
	assert.ok(!exists(path.join(dir, 'outside', 'pwn.txt')));
	// Replaced root: refuse.
	const e = mk();
	fs.renameSync(root, `${root}.old`);
	fs.mkdirSync(root);
	assert.equal(e.sync([file('a.txt', 'x')]).refused[0]?.reason, 'workspace root identity changed; refusing to write');
});

test('writeback: conflicts are surfaced, never overwritten; held deletes', () => {
	const { mk, root } = setup('conflict');
	fs.writeFileSync(path.join(root, '.envrc'), 'export A=1\n');
	const e = mk();
	assert.deepEqual(e.sync([file('notes.txt', 'tab v1')]).applied, ['notes.txt']);
	fs.writeFileSync(path.join(root, 'notes.txt'), 'host edit\n');
	const r = e.sync([file('notes.txt', 'tab v2')]);
	assert.equal(r.held[0]?.kind, 'conflict');
	assert.equal(fs.readFileSync(path.join(root, 'notes.txt'), 'utf8'), 'host edit\n');
	const d = e.sync([{ path: '.envrc', kind: 'deleted' }]);
	assert.equal(d.held[0]?.kind, 'deleted');
	assert.ok(exists(path.join(root, '.envrc')));
	assert.deepEqual(e.sync([{ path: 'README.md', kind: 'deleted' }]).applied, ['README.md']);
});

test('writeback: fail closed: pending survives restart and is never auto-applied; approve/reject/always', () => {
	const { mk, root } = setup('pending');
	const hook = file('.git/hooks/pre-commit', '#!/bin/sh\nexit 0\n', 0o755);
	mk().sync([hook, file('.envrc', 'export X=1\n')]);
	const again = mk(); // "tabd restarted"
	assert.deepEqual(again.pending().map(p => p.path).sort(), ['.envrc', '.git/hooks/pre-commit']);
	again.sync([]); // a later sync applies nothing held
	assert.ok(!exists(path.join(root, '.git', 'hooks', 'pre-commit')));
	// Approval must match what was shown.
	assert.throws(() => again.approve('.git/hooks/pre-commit', file('.git/hooks/pre-commit', '#!/bin/sh\ncurl x\n', 0o755)), /changed this entry/);
	again.approve('.git/hooks/pre-commit', hook);
	assert.equal(fs.statSync(path.join(root, '.git', 'hooks', 'pre-commit')).mode & 0o111, 0o111, 'exec bit only by approval');
	assert.equal(again.reject('.envrc').content, null);
	assert.equal(again.pending().length, 0);
	again.alwaysAllow('Makefile');
	assert.deepEqual(again.sync([file('Makefile', 'all:\n')]).applied, ['Makefile']);
	assert.equal(again.sync([{ path: 'Makefile', kind: 'symlink', target: 'x' }]).held.length, 1, 'always never waives a link');
	assert.equal(fs.readdirSync(path.join(root)).filter(f => f.startsWith('.seclab-wb.')).length, 0, 'no temp files left');
});

test('writeback: host core.hooksPath is held', () => {
	const { mk, root } = setup('hookspath');
	fs.writeFileSync(path.join(root, '.git', 'config'), '[core]\n\thooksPath = tools/hooks\n');
	assert.equal(mk().sync([file('tools/hooks/pre-push', 'x')]).held.length, 1);
	assert.equal(mk().sync([file('tools/other.txt', 'x')]).applied.length, 1);
});

test('writeback: caps hold the excess (never drop), rate limit', async () => {
	const { root, statePath } = setup('caps');
	const policy = { ...(await import('../src/writeback-policy.ts')).WRITEBACK_POLICY };
	const caps = { ...policy.caps, maxFilesPerSync: 2, maxSyncsPerMinute: 3 };
	let t = 0;
	const e = new WriteBackEngine({ root, rootIdentity: fileIdentity(root), statePath, policy: { ...policy, caps } as never, now: () => t, ignoredBy: NONE_IGNORED });
	const r = e.sync([file('a', '1'), file('b', '2'), file('c', '3')]);
	assert.deepEqual(r.applied, ['a', 'b']);
	assert.equal(r.held[0]?.path, 'c');
	e.sync([]);
	e.sync([]);
	assert.throws(() => e.sync([]), /rate limit/);
	t += 61_000;
	e.sync([]);
});

test('writeback: Y-1 Copilot hooks/skills and other agents\' config are held and never "always"', () => {
	const { mk } = setup('y1');
	const e = mk();
	const paths = ['.github/hooks/x.json', '.github/hooks/run.sh', '.github/skills/s/SKILL.md', '.agents/skills/s/run.py', 'sub/AGENT.md',
		'opencode.json', '.opencode/agent/x.md', '.junie/guidelines.md', '.goosehints', '.github/ISSUE_TEMPLATE/bug.md'];
	const r = e.sync(paths.map(p => file(p, 'x')));
	assert.equal(r.applied.length, 0, JSON.stringify(r.applied));
	for (const p of paths) {
		assert.throws(() => e.alwaysAllow(p), /not available/, p);
	}
});

test('writeback: Y-2/Y-3 bytecode caches and installed trees are tab-local; vendored trees held', () => {
	const { mk, root } = setup('y2');
	fs.writeFileSync(path.join(root, 'foo.py'), 'x = 1\n');
	const r = mk().sync([file('src/__pycache__/foo.cpython-312.pyc', 'evil'), file('foo.pyc', 'evil'), file('node_modules/eslint/lib/cli.js', 'evil'),
		file('pkgs/a/node_modules/x/index.js', 'evil'), { path: 'node_modules/old/index.js', kind: 'deleted' },
		file('vendor/autoload.php', 'evil'), file('.bundle/config', 'evil'), file('.gradle/init.d/x.gradle', 'evil')]);
	assert.equal(r.applied.length, 0, JSON.stringify(r.applied));
	assert.equal(r.refused.filter(x => /tab-local/.test(x.reason)).length, 5);
	assert.equal(r.held.length, 3);
	assert.ok(!exists(path.join(root, 'src', '__pycache__')) && !exists(path.join(root, 'node_modules')));
	assert.equal(mk().pending().filter(p => /node_modules|pycache/.test(p.path)).length, 0, 'tab-local never becomes approvable');
});

test('writeback: Y-4 non-object dependency section held; Y-6 "always" never waives manifest key holds', () => {
	const { mk } = setup('y4');
	const e = mk();
	assert.equal(e.sync([file('package.json', JSON.stringify({ name: 'x', scripts: { test: 'node --test' }, dependencies: 'evil-pkg' }))]).held.length, 1);
	e.reject('package.json');
	e.alwaysAllow('package.json');
	assert.equal(e.sync([file('package.json', JSON.stringify({ name: 'x', description: 'd', scripts: { test: 'node --test' }, dependencies: {} }))]).applied.length, 1);
	const r = e.sync([file('package.json', JSON.stringify({ name: 'x', scripts: { test: 'node --test', postinstall: 'sh x' }, dependencies: {} }))]);
	assert.equal(r.held.length, 1, 'always on package.json does not waive scripts');
});

test('writeback: Y-5 git config: recursive includes, same-line keys, continuations, case-folded root', async () => {
	const { mk, root } = setup('y5');
	const { parseGitConfig } = await import('../src/writeback.ts');
	assert.deepEqual(parseGitConfig(['[include] path = a.cfg', '[core]', '\thooksPath = "to\\', 'ols/h" # c']).map(e => `${e.section}.${e.key}=${e.value}`),
		['include.path=a.cfg', 'core.hookspath=tools/h']);
	fs.writeFileSync(path.join(root, '.git', 'config'), `[include] path = ../first.cfg\n[includeIf "gitdir:x"]\n\tpath = ${root.toUpperCase() === root ? root : root.replace(/ws$/, 'WS')}/third.cfg\n`);
	fs.writeFileSync(path.join(root, 'first.cfg'), '[include]\n\tpath = second.cfg\n');
	const r = mk().sync([file('first.cfg', 'x'), file('second.cfg', 'x'), file('third.cfg', 'x'), file('fourth.cfg', 'x')]);
	assert.deepEqual(r.applied, ['fourth.cfg']);
	assert.equal(r.held.length, 3);
});

test('writeback: Z-1 native modules are held (structural); host-ignored files are tab-local; unknown ignore state holds', () => {
	const { root, statePath, mk } = setup('z1');
	fs.writeFileSync(path.join(root, 'foo.py'), 'x = 1\n');
	const r = mk().sync([file('src/foo.cpython-312-darwin.so', 'x'), file('foo.abi3.so', 'x'), file('lib/x.node', 'x'), file('a.dylib', 'x'), file('b.so.1.2', 'x')]);
	assert.equal(r.applied.length, 0);
	assert.ok(r.held.every(h => h.reasons.includes('native code module')));
	const ignoring = new WriteBackEngine({ root, rootIdentity: fileIdentity(root), statePath: statePath + '.2', ignoredBy: (_r, ps) => new Set(ps.filter(p => p.startsWith('target/') || p === '.vscode/settings.json')) });
	const r2 = ignoring.sync([file('target/classes/A.class', 'x'), file('src/a.ts', 'x'), file('.vscode/settings.json', '{}')]);
	assert.deepEqual(r2.applied, ['src/a.ts']);
	assert.deepEqual(r2.refused.map(x => x.path), ['target/classes/A.class']);
	assert.deepEqual(r2.held.map(x => x.path), ['.vscode/settings.json'], 'held paths are prompted even when ignored');
	const unknown = new WriteBackEngine({ root, rootIdentity: fileIdentity(root), statePath: statePath + '.3', ignoredBy: () => null });
	const r3 = unknown.sync([file('src/b.ts', 'x')]);
	assert.equal(r3.held[0]?.reasons.includes('could not check the host\'s .gitignore'), true, 'fail closed');
	assert.equal(mk().sync([file('.gitignore', 'evil.py\n')]).held.length, 1, '.gitignore is held (it decides what review can see)');
});

test('writeback: Z-1 hostGitIgnored against a real git checkout (literal paths, no index)', async t => {
	const { hostGitIgnored } = await import('../src/gitignore.ts');
	const { resolveBinary } = await import('../src/run.ts');
	if (!resolveBinary('git')) {
		t.skip('git not available');
		return;
	}
	const dir = path.join(SCRATCH, 'z1-git');
	fs.rmSync(dir, { recursive: true, force: true });
	fs.mkdirSync(path.join(dir, '.git', 'objects'), { recursive: true });
	fs.mkdirSync(path.join(dir, '.git', 'refs'), { recursive: true });
	fs.writeFileSync(path.join(dir, '.git', 'HEAD'), 'ref: refs/heads/main\n');
	fs.writeFileSync(path.join(dir, '.git', 'config'), '[core]\n\trepositoryformatversion = 0\n\tbare = false\n');
	fs.writeFileSync(path.join(dir, '.gitignore'), '*.so\ntarget/\n');
	const got = hostGitIgnored(dir, ['x.so', 'target/A.class', 'src/a.ts', ':(top)x.so', '*.so', ':(glob)**', ':!x']);
	assert.ok(got, 'git answered (magic-looking names do not fail the batch)');
	assert.deepEqual([...got].sort(), ['*.so', ':(top)x.so', 'target/A.class', 'x.so'].sort(), 'names are literal');
	fs.rmSync(path.join(dir, '.git', 'HEAD'));
	assert.equal(hostGitIgnored(dir, ['a']), null, 'broken repo: unknown');
});

test('writeback: Z-2 code-running config is held at any depth; Z-3 git config parser edge cases', async () => {
	const { mk } = setup('z2');
	const e = mk();
	const paths = ['packages/x/.github/hooks/h.json', 'packages/x/.claude/settings.json', 'packages/x/.vscode/tasks.json', 'packages/x/Makefile',
		'packages/x/setup.py', 'packages/x/.husky/pre-commit', 'packages/x/.agents/s.md', 'a/b/node_modules/x.js'];
	const r = e.sync(paths.map(p => file(p, 'x')));
	assert.equal(r.applied.length, 0, JSON.stringify(r.applied));
	for (const p of paths.slice(0, 3)) {
		assert.throws(() => e.alwaysAllow(p), /not available/, p);
	}
	const { parseGitConfig } = await import('../src/writeback.ts');
	const kv = (ls: string[]) => parseGitConfig(ls).map(x => `${x.section}.${x.key}=${x.value}`);
	assert.deepEqual(kv(['[include]', '# note \\', 'path = a.cfg']), ['include.path=a.cfg'], 'comments never continue');
	assert.deepEqual(kv(['[include]', 'path = a\\\\', 'path = b']), ['include.path=a\\', 'include.path=b'], 'even backslashes: no continuation');
	assert.deepEqual(kv(['[include]', 'path = "e\\tf.cfg"']), ['include.path=e\tf.cfg']);
	assert.deepEqual(kv(['[include]', '[broken', 'path = c']), [], 'malformed header resets the section');
	assert.deepEqual(kv(['[include]', 'path = x ; c \\', 'path = y']), ['include.path=x', 'include.path=y'], 'inline comments never continue (AA-3)');
	assert.deepEqual(kv(['[include]', 'path = "a;b" \\', 'c']), ['include.path=a;b c'], 'quoted ; is not a comment');
});

test('writeback: AA-1 subfolder of a host repo is checked against the parent; a broken HEAD is held, not "nothing ignored"', async t => {
	const { hostGitIgnored } = await import('../src/gitignore.ts');
	const { resolveBinary } = await import('../src/run.ts');
	if (!resolveBinary('git')) {
		t.skip('git not available');
		return;
	}
	const dir = path.join(SCRATCH, 'aa1-git');
	fs.rmSync(dir, { recursive: true, force: true });
	fs.mkdirSync(path.join(dir, '.git', 'objects'), { recursive: true });
	fs.mkdirSync(path.join(dir, '.git', 'refs'), { recursive: true });
	fs.mkdirSync(path.join(dir, 'packages', 'app'), { recursive: true });
	fs.writeFileSync(path.join(dir, '.git', 'HEAD'), 'ref: refs/heads/main\n');
	fs.writeFileSync(path.join(dir, '.git', 'config'), '[core]\n\trepositoryformatversion = 0\n\tbare = false\n');
	fs.writeFileSync(path.join(dir, '.gitignore'), 'dist/\n*.so\n!keep.so\n');
	const sub = path.join(dir, 'packages', 'app');
	assert.deepEqual([...(hostGitIgnored(sub, ['dist/index.js', 'src/a.ts', 'keep.so', 'x.so']) ?? ['null'])].sort(), ['dist/index.js', 'x.so'], 'parent .gitignore applies; negation respected');
	fs.mkdirSync(path.join(dir, 'ignored-area', 'ws'), { recursive: true });
	fs.appendFileSync(path.join(dir, '.gitignore'), 'ignored-area/\n');
	assert.deepEqual([...(hostGitIgnored(path.join(dir, 'ignored-area', 'ws'), ['a.txt', 'x.so']) ?? ['null'])], [], 'a workspace the enclosing repo ignores is not part of it');
	fs.writeFileSync(path.join(dir, '.git', 'HEAD'), 'garbage\n');
	assert.equal(hostGitIgnored(dir, ['dist/a']), null, 'own .git broken → unknown (held)');
	const { mk } = setup('aa1-head');
	assert.equal(mk().sync([file('.git/HEAD', 'garbage\n')]).held.length, 1, 'a HEAD that is not a ref or hash is held');
	assert.equal(mk().sync([file('.git/HEAD', 'ref: refs/heads/dev\n')]).applied.length, 1);
	// BB-1: the enclosing repo's hooksPath and includes that point into the subfolder are held.
	fs.writeFileSync(path.join(dir, '.git', 'HEAD'), 'ref: refs/heads/main\n');
	fs.writeFileSync(path.join(dir, '.git', 'config'), '[core]\n\tbare = false\n\thooksPath = packages/app/hooks\n[include]\n\tpath = ../packages/app/inc.cfg\n');
	const e = new WriteBackEngine({ root: sub, rootIdentity: fileIdentity(sub), statePath: path.join(dir, 'wb.json'), ignoredBy: NONE_IGNORED });
	const r = e.sync([file('hooks/pre-commit', 'x'), file('inc.cfg', 'x'), file('src/ok.ts', 'x')]);
	assert.deepEqual(r.applied, ['src/ok.ts']);
	assert.equal(r.held.length, 2);
});
