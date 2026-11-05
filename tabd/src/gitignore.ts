// Which tab changes the HOST's git ignores (write-back gate, review Z-1). An ignored file is
// invisible to `git status`/`git diff`, so the user could never review it: the engine keeps
// such files tab-local. Read-only, no shell, scrubbed env, `./`-prefixed paths (no pathspec
// magic), no index read
// (`--no-index`: the index is tab-written), fsmonitor and hooks off. The ignore sources are
// host-owned or held (.gitignore, .git/info/exclude, core.excludesFile).

import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { cleanEnv, resolveBinary } from './run.ts';

/** Paths (workspace-relative) git would ignore; empty if the root isn't in a git checkout; null if unknown. */
export function hostGitIgnored(root: string, paths: readonly string[]): Set<string> | null {
	if (paths.length === 0) {
		return new Set();
	}
	let ownGitDir = true;
	try {
		fs.lstatSync(path.join(root, '.git'));
	} catch {
		ownGitDir = false; // maybe a subfolder of a host repo: let git discover upward (review AA-1)
	}
	const git = resolveBinary('git');
	if (!git) {
		return null;
	}
	// check-ignore rejects GIT_LITERAL_PATHSPECS; a `./` prefix makes any `:(magic)` literal instead.
	// --verbose --non-matching: one record per input, in order, so results are matched by
	// position, never by git's spelling of the path (AA-2: precomposeUnicode on macOS).
	const env: NodeJS.ProcessEnv = { ...cleanEnv(), LC_ALL: 'C', LANGUAGE: '', GIT_OPTIONAL_LOCKS: '0', GIT_TERMINAL_PROMPT: '0' };
	if (ownGitDir) {
		// No discovery: a tab-broken HEAD must fail, not fall through to an enclosing repo.
		env.GIT_DIR = path.join(root, '.git');
		env.GIT_WORK_TREE = root;
	}
	const argv = ['-C', root, '-c', 'core.fsmonitor=false', '-c', 'core.untrackedCache=false', '-c', 'core.hooksPath=/dev/null',
		'check-ignore', '--no-index', '--stdin', '-z', '--verbose', '--non-matching'];
	// Without our own .git, git discovers an enclosing repo. If that repo ignores the workspace
	// root itself, the workspace isn't part of it: treat it as not in a checkout (nothing hidden),
	// rather than letting the outer ignore rule make every file tab-local. "./" probes the root.
	const all = ownGitDir ? [...paths] : ['', ...paths];
	const r = spawnSync(git, argv, { env, input: all.map(p => `./${p}\0`).join(''), timeout: 10_000, maxBuffer: 64 << 20, shell: false });
	if (r.error || r.signal) {
		return null;
	}
	if (r.status !== 0 && r.status !== 1) {
		// Not inside any repo → nothing is hidden from git. With the root's own .git present this
		// is an error instead: a tab-written HEAD must not turn "unknown" into "nothing ignored".
		return !ownGitDir && /not a git repository/.test(r.stderr.toString('utf8')) ? new Set() : null;
	}
	const f = r.stdout.toString('utf8').split('\0');
	if (f.length !== all.length * 4 + 1 || f[f.length - 1] !== '') {
		return null;
	}
	const ignoredAt = (i: number) => f[i * 4 + 2] !== '' && !f[i * 4 + 2].startsWith('!');
	if (!ownGitDir && ignoredAt(0)) {
		return new Set();
	}
	const out = new Set<string>();
	all.forEach((p, i) => {
		if ((ownGitDir || i > 0) && ignoredAt(i)) {
			out.add(p);
		}
	});
	return out;
}
