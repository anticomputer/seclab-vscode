// Teardown and host-integrity check for a harness run. One implementation, shared by
// every suite (level A runners, level B editor runs, the RPC-lockdown probe runs).
//
//   node test/containment/teardown.ts snapshot <run-dir>   before the run
//   node test/containment/teardown.ts verify   <run-dir>   after it (also on failure)
//
// A run records what it owns in <run-dir>/run.json (writeManifest): its unique
// user-data-dir, tabd state dirs, tab ids and helper containers. `verify` then:
//   1. stops every process tree whose command line carries one of those unique paths
//      (never matched by program name: the user may be running their own editor), SIGTERM
//      then SIGKILL, and fails if any survives. The 2026-11-04 RPC proof run left an
//      editor with the armed rogue extension orphaned on the user's desktop while its
//      check reported clean; this is the regression for that (teardown.test.ts);
//   2. removes the run's tabs (sbx sandboxes, OCI containers, networks, home volumes)
//      and fails if any remain;
//   3. deletes the user-data-dir, which holds the armed rogue extension;
//   4. checks the run-scoped keychain item and recorded artefacts;
//   5. diffs the stat-only host snapshot (harness.ts): nothing outside the run dir changed.
// It is a tripwire, not a guarantee. Scope is this run only: a concurrent run in another
// worktree owns other resources (`./seclab clean-host` is the global sweep).

import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { checkIsolatedProfile, editorPortableDir, hostSnapshot, snapshotDiff, type Snapshot } from '../harness.ts';
import { avFindings } from '../safety/av-shape.ts';

/** The profile's portable sibling (test/harness.ts editorPortableDir): checked as isolated, removed. */
function removePortable(userDataDir: string, problems: string[]): void {
	const p = editorPortableDir(path.resolve(userDataDir));
	if (!fs.existsSync(p) && !fs.lstatSync(p, { throwIfNoEntry: false })) {
		return;
	}
	try {
		checkIsolatedProfile(p);
		fs.rmSync(p, { recursive: true, force: true }); // the user-data link is removed, not followed
	} catch (err) {
		problems.push(`could not remove the portable dir: ${err instanceof Error ? err.message : String(err)}`);
	}
}

export interface RunManifest {
	userDataDir?: string;
	/** tabd state dirs: tabd carries `--state-dir <dir>`; tab ids are also read from them. */
	stateDirs?: string[];
	tabs?: string[];
	/** Helper containers the run started (loopback services). */
	containers?: string[];
	/** Runtime the run's tabs use: its listing must work for the run to verify clean. */
	driver?: 'sbx' | 'oci';
	/** Extra process command-line fragments owned by the run (each must name the run dir), e.g. `beacon.ts start <run-dir>`. */
	commandMarks?: string[];
	/** Fixture workspaces the run materialised (strictly inside the run dir); deleted by teardown. */
	workspaces?: string[];
	startedAt?: string;
}

export interface TeardownCheck { name: string; ok: boolean; detail: string }

const TAB_RE = /^t-[a-z2-7]{26}$/;
const HELPER_RE = /^seclab-containment-hostsvc-(sbx|oci)-[0-9a-f]{8}$/;
const SBX = fs.existsSync('/opt/homebrew/bin/sbx') ? '/opt/homebrew/bin/sbx' : 'sbx';

const manifestFile = (runDir: string) => path.join(runDir, 'run.json');
const snapshotFile = (runDir: string) => path.join(runDir, 'host-snapshot.json');
const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const within = (p: string, dir: string) => path.resolve(p) === path.resolve(dir) || path.resolve(p).startsWith(path.resolve(dir) + path.sep);

/** Text files of a tree, keyed by posix path relative to `root` (for the AV-shape check). */
export function treeTexts(root: string, max = 4000): Map<string, string> {
	const out = new Map<string, string>();
	const walk = (dir: string, rel: string): void => {
		for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
			if (out.size >= max) {
				throw new Error(`${root}: more than ${max} files; refusing to judge (or copy) it`);
			}
			const p = path.join(dir, e.name);
			const r = rel ? `${rel}/${e.name}` : e.name;
			if (e.isDirectory() && e.name !== 'node_modules' && e.name !== '.git') {
				walk(p, r);
			} else if (e.isFile() && fs.statSync(p).size < 2 << 20) {
				out.set(r, fs.readFileSync(p, 'utf8'));
			}
		}
	};
	walk(root, '');
	return out;
}

/** What materialiseFixture copies: exactly what treeTexts checked (SS-8). */
function copyable(src: string): boolean {
	const st = fs.lstatSync(src);
	return st.isDirectory() ? !['node_modules', '.git'].includes(path.basename(src)) : st.isFile() && st.size < 2 << 20;
}

/** Marker in every materialised copy: clean-host deletes only provable harness copies (SS-1). */
export const MATERIALISED_MARKER = '.seclab-materialised';

/**
 * The only way a harness puts a fixture workspace on the host: refuses a source that carries an
 * AV loader shape (those are stored as *.parts.json and assembled inside the tab), records the
 * destination in run.json first, so teardown deletes it even if the run dies, then copies
 * exactly the files it checked (no symlinks, nothing skipped by the check) and marks the copy.
 */
export function materialiseFixture(runDir: string, src: string, dst: string): void {
	const findings = avFindings(treeTexts(src));
	if (findings.length) {
		throw new Error(`refusing to copy ${src} onto the host (AV loader shape; EDR fixture-safety):\n  ${findings.join('\n  ')}`);
	}
	fs.mkdirSync(runDir, { recursive: true });
	writeManifest(runDir, { workspaces: [path.resolve(dst)] });
	fs.cpSync(src, dst, { recursive: true, filter: copyable });
	fs.writeFileSync(path.join(dst, MATERIALISED_MARKER), `${path.resolve(runDir)}\n`);
}

export function readManifest(runDir: string): RunManifest {
	try {
		return JSON.parse(fs.readFileSync(manifestFile(runDir), 'utf8')) as RunManifest;
	} catch {
		return {};
	}
}

/**
 * Stop whatever a previous run in this directory left behind, before the directory is
 * wiped. The manifest is the only record of a run's helpers, so a harness that deletes the
 * run directory first orphans them: an aborted `prepare` left its beacon listening on the
 * host, and the next `prepare` wrote a manifest naming a different port, so nothing could
 * name the old one again.
 *
 * It reports rather than fails silently. A refusal here means the caller is about to wipe
 * the only record of a run it could not reap, which is the incident this exists to prevent,
 * so the caller must stop instead of continuing.
 */
export function reapPreviousRun(runDir: string): ReapResult {
	const m = readManifest(runDir);
	if (!m.userDataDir && !(m.stateDirs ?? []).length && !(m.commandMarks ?? []).length && !(m.tabs ?? []).length) {
		return { stopped: [], refused: false, problems: [], survivors: [] };
	}
	// The same rules verify applies, including R-2: a malformed previous manifest must not
	// become a licence to delete, and must not be quietly skipped either.
	const problems = [...runDirProblems(runDir, m), ...manifestProblems(runDir, m)];
	if (problems.length) {
		return { stopped: [], refused: true, problems, survivors: [] };
	}
	const stopped = stopRunProcesses(runDir, m);
	// Its tabs and helper runtimes too, and its profile: that profile holds the armed rogue
	// extension, so leaving it is the same hazard the teardown gate exists to prevent.
	try {
		removeRunResources(runDir, m);
	} catch (err) {
		problems.push(`could not remove the previous run's runtime resources: ${err instanceof Error ? err.message : String(err)}`);
	}
	if (m.userDataDir && fs.existsSync(m.userDataDir)) {
		try {
			checkIsolatedProfile(path.resolve(m.userDataDir));
			fs.rmSync(m.userDataDir, { recursive: true, force: true });
		} catch (err) {
			problems.push(`could not remove the previous run's profile: ${err instanceof Error ? err.message : String(err)}`);
		}
	}
	if (m.userDataDir) {
		removePortable(m.userDataDir, problems);
	}
	// Anything still alive after SIGTERM then SIGKILL. The caller must not wipe over it.
	const survivors = runProcesses(runDir, m);
	return { stopped, refused: problems.length > 0 || survivors.length > 0, problems, survivors };
}

export interface ReapResult {
	/** Processes this reap stopped. */
	readonly stopped: Proc[];
	/** True when the caller must not wipe the run directory. */
	readonly refused: boolean;
	readonly problems: string[];
	/** Processes still alive after the stop. */
	readonly survivors: Proc[];
}

/** Merge into run.json. Write it before starting anything the run must later clean up. */
export function writeManifest(runDir: string, add: RunManifest): RunManifest {
	const m = readManifest(runDir);
	const uniq = (a?: string[], b?: string[]) => [...new Set([...(a ?? []), ...(b ?? [])])];
	const next: RunManifest = {
		userDataDir: add.userDataDir ?? m.userDataDir,
		stateDirs: uniq(m.stateDirs, add.stateDirs),
		tabs: uniq(m.tabs, add.tabs),
		containers: uniq(m.containers, add.containers),
		driver: add.driver ?? m.driver,
		commandMarks: uniq(m.commandMarks, add.commandMarks),
		workspaces: uniq(m.workspaces, add.workspaces),
		startedAt: m.startedAt ?? new Date().toISOString(),
	};
	fs.mkdirSync(runDir, { recursive: true });
	fs.writeFileSync(manifestFile(runDir), JSON.stringify(next, null, 2));
	return next;
}

/**
 * run.json drives kills and deletes, so it is re-validated before use (T-4): the profile
 * must be an isolated test profile, state dirs inside the run dir or the profile, helper
 * containers the harness's own, and command marks must name the run dir.
 */
export function manifestProblems(runDir: string, m: RunManifest): string[] {
	const out: string[] = [];
	if (m.userDataDir) {
		try {
			checkIsolatedProfile(path.resolve(m.userDataDir));
		} catch (e) {
			out.push((e as Error).message);
		}
	}
	for (const sd of m.stateDirs ?? []) {
		if (!path.isAbsolute(sd) || !(within(sd, runDir) || (m.userDataDir && within(sd, m.userDataDir)))) {
			out.push(`state dir outside the run: ${sd}`);
		}
	}
	for (const c of m.containers ?? []) {
		if (!HELPER_RE.test(c)) {
			out.push(`not a harness helper container: ${c}`);
		}
	}
	for (const t of m.tabs ?? []) {
		if (!TAB_RE.test(t)) {
			out.push(`not a tab id: ${t}`);
		}
	}
	for (const k of m.commandMarks ?? []) {
		// A program token plus arguments naming the run dir; never the bare run dir (R-1).
		if (k === runDir || !/^\S+\s+\S/.test(k) || (!k.includes(runDir + path.sep) && !k.endsWith(` ${runDir}`))) {
			out.push(`command mark must be "<program> … <run-dir>…": ${k}`);
		}
	}
	for (const w of m.workspaces ?? []) {
		if (!path.isAbsolute(w) || path.resolve(w) === runDir || !within(w, runDir)) {
			out.push(`workspace outside the run: ${w}`);
		}
	}
	return out;
}

/**
 * verify acts only on a real harness run (R-2): a run.json written by writeManifest, in a
 * run dir under this worktree's .work/ or ~/.seclab-test/. A mistyped `verify ~/src` must
 * not remove tabs of real projects.
 */
export function runDirProblems(runDir: string, m: RunManifest): string[] {
	if (!fs.existsSync(manifestFile(runDir)) || !m.startedAt) {
		return [`no run.json from a harness run in ${runDir}`];
	}
	try {
		checkIsolatedProfile(path.join(runDir, 'x'));
	} catch {
		return [`not a harness run dir (must be under this worktree's .work/ or ~/.seclab-test/): ${runDir}`];
	}
	return [];
}

/** Tab ids the run owns: recorded ones plus every tab in its tabd state (T-2b), read before the state is deleted. */
export function runTabs(m: RunManifest): string[] {
	const ids = new Set((m.tabs ?? []).filter(t => TAB_RE.test(t)));
	const dirs = [...(m.stateDirs ?? [])];
	if (m.userDataDir) {
		dirs.push(path.join(m.userDataDir, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd'));
	}
	for (const d of dirs) {
		let entries: string[] = [];
		try {
			entries = fs.readdirSync(path.join(d, 'tabs'));
		} catch { /* none */ }
		for (const e of entries) {
			const id = /^(t-[a-z2-7]{26})\.json$/.exec(e)?.[1];
			if (id) {
				ids.add(id);
			}
		}
	}
	return [...ids];
}

export function writeSnapshot(runDir: string): void {
	fs.mkdirSync(runDir, { recursive: true });
	fs.writeFileSync(snapshotFile(runDir), JSON.stringify((() => {
		const key = randomBytes(32).toString('hex'); // per run: names are HMAC'd, comparable only within the run
		return { v: 2, key, entries: hostSnapshot(key) };
	})()), { mode: 0o600 });
}

interface Proc { pid: number; ppid: number; args: string }

function processTable(): Proc[] {
	const ps = spawnSync('ps', ['-axo', 'pid=,ppid=,stat=,args='], { encoding: 'utf8' });
	const out: Proc[] = [];
	for (const line of (ps.stdout ?? '').split('\n')) {
		const m = /^\s*(\d+)\s+(\d+)\s+(\S+)\s+(.*)$/.exec(line);
		if (m && !m[3].startsWith('Z')) {
			out.push({ pid: Number(m[1]), ppid: Number(m[2]), args: m[4] });
		}
	}
	return out;
}

/**
 * This run's processes: roots whose command line carries one of the run's options with its
 * exact value (`--user-data-dir <profile>`, `--state-dir <dir>`, bounded by whitespace so
 * `~/.seclab-test/ud` never matches `…/ud2`) or a recorded command mark; plus all their
 * descendants (Electron helpers, tabd's `sbx exec` streams). Never a bare path mention (the
 * user's own editor or a `tail` on a run log), never this process or its ancestors (T-1).
 */
export function runProcesses(runDir: string, m: RunManifest = readManifest(runDir)): Proc[] {
	const res: RegExp[] = [];
	if (m.userDataDir) {
		res.push(new RegExp(`(^|\\s)--user-data-dir(=|\\s+)${esc(path.resolve(m.userDataDir))}/?(?=\\s|$)`));
	}
	for (const sd of m.stateDirs ?? []) {
		res.push(new RegExp(`(^|\\s)--state-dir(=|\\s+)${esc(path.resolve(sd))}/?(?=\\s|$)`));
	}
	for (const k of m.commandMarks ?? []) {
		res.push(new RegExp(`(^|\\s)${esc(k)}(?=\\s|$)`));
	}
	const table = processTable();
	const byPid = new Map(table.map(p => [p.pid, p]));
	const spare = new Set<number>([process.pid]);
	for (let p = byPid.get(process.pid)?.ppid; p && !spare.has(p); p = byPid.get(p)?.ppid) {
		spare.add(p);
	}
	spare.add(process.ppid);
	const hit = new Set(table.filter(p => !spare.has(p.pid) && res.some(r => r.test(p.args))).map(p => p.pid));
	for (let grew = true; grew;) {
		grew = false;
		for (const p of table) {
			if (!hit.has(p.pid) && !spare.has(p.pid) && hit.has(p.ppid)) {
				hit.add(p.pid);
				grew = true;
			}
		}
	}
	return table.filter(p => hit.has(p.pid));
}

function sleep(seconds: number): void {
	spawnSync('sleep', [String(seconds)]);
}

/**
 * SIGTERM the run's process trees, wait, SIGKILL what is left. Individual pids only. Every
 * process seen is tracked (pid + argv) to the end: a helper orphaned when its parent dies
 * is reparented to launchd and no longer looks like a descendant.
 */
export function stopRunProcesses(runDir: string, m: RunManifest = readManifest(runDir)): Proc[] {
	const seen = new Map<number, string>();
	const current = () => {
		for (const p of runProcesses(runDir, m)) {
			seen.set(p.pid, p.args);
		}
		return processTable().filter(p => seen.get(p.pid) === p.args);
	};
	const first = current();
	if (first.length) {
		console.log(`stopping ${first.length} process(es) from this run`);
		for (const p of first) {
			try {
				process.kill(p.pid, 'SIGTERM');
			} catch { /* gone */ }
		}
		const deadline = Date.now() + 15_000;
		while (Date.now() < deadline && current().length) {
			sleep(0.5);
		}
		for (const p of current()) {
			try {
				process.kill(p.pid, 'SIGKILL');
			} catch { /* gone */ }
		}
		sleep(1);
	}
	return current();
}

function sbxList(): Array<{ name: string; status?: string; workspaces?: string[] }> | undefined {
	const r = spawnSync(SBX, ['ls', '--json'], { encoding: 'utf8' });
	if (r.error || r.status !== 0) {
		return undefined;
	}
	try {
		return JSON.parse(r.stdout);
	} catch {
		return undefined;
	}
}

function dockerLines(args: string[]): string[] | undefined {
	const r = spawnSync('docker', args, { encoding: 'utf8' });
	return r.error || r.status !== 0 ? undefined : r.stdout.split('\n').map(s => s.trim()).filter(Boolean);
}

/** Every runtime resource this run still owns; `unknown` lists runtimes that could not be listed. */
export function runLeftovers(runDir: string, m: RunManifest = readManifest(runDir), tabs: string[] = runTabs(m)): { left: string[]; unknown: string[] } {
	const left: string[] = [];
	const unknown = new Set<string>();
	const needSbx = m.driver === 'sbx' || (m.driver === undefined && tabs.length > 0);
	const needDocker = m.driver === 'oci' || (m.containers ?? []).length > 0;
	const sbx = sbxList();
	if (!sbx && needSbx) {
		unknown.add('sbx');
	}
	for (const s of sbx ?? []) {
		if (tabs.some(t => s.name === `seclab-${t}`) || (s.workspaces ?? []).some(w => within(w, runDir))) {
			left.push(`sbx ${s.name} (${s.status ?? '?'})`);
		}
	}
	const docker = (args: string[]) => {
		const r = dockerLines(args);
		if (!r && needDocker) {
			unknown.add('docker');
		}
		return r ?? [];
	};
	for (const t of tabs) {
		for (const c of docker(['ps', '-a', '--filter', `label=seclab.tab=${t}`, '--format', '{{.Names}}'])) {
			left.push(`container ${c}`);
		}
		for (const n of docker(['network', 'ls', '--filter', `label=seclab.tab=${t}`, '--format', '{{.Name}}'])) {
			left.push(`network ${n}`);
		}
		// Also by name: a tab's networks (pod `-net`, broker `-egress`) even if unlabelled.
		for (const n of tabNetworksByName(docker, t)) {
			if (!left.includes(`network ${n}`)) {
				left.push(`network ${n}`);
			}
		}
		for (const v of docker(['volume', 'ls', '--filter', `name=seclab-${t}-home`, '--format', '{{.Name}}'])) {
			if (v === `seclab-${t}-home`) {
				left.push(`volume ${v}`);
			}
		}
	}
	for (const c of m.containers ?? []) {
		if (docker(['ps', '-a', '--filter', `name=${c}`, '--format', '{{.Names}}']).includes(c)) {
			left.push(`container ${c}`);
		}
	}
	// Host-side observability sensor (OCI Falco) that tabd started for this run's state dirs.
	for (const tag of falcoStateTags(m)) {
		for (const c of docker(['ps', '-a', '--filter', 'label=seclab.obs=falco', '--filter', `label=seclab.state=${tag}`, '--format', '{{.Names}}'])) {
			left.push(`container ${c}`);
		}
	}
	return { left, unknown: [...unknown] };
}

/** tabd labels its Falco container with sha256(state dir)[0:8] (tabd/src/main.ts). */
function falcoStateTags(m: RunManifest): string[] {
	return (m.stateDirs ?? []).map(d => createHash('sha256').update(d).digest('hex').slice(0, 8));
}

/** Networks named for this tab: `seclab-<tab>-<suffix>` (docker's name filter is a substring match). */
function tabNetworksByName(docker: (args: string[]) => string[], tab: string): string[] {
	const prefix = `seclab-${tab}-`;
	return docker(['network', 'ls', '--filter', `name=${prefix}`, '--format', '{{.Name}}'])
		.filter(n => n.startsWith(prefix) && /^[a-z0-9-]+$/.test(n.slice(prefix.length)));
}

/** Remove the run's tabs and helpers directly in the runtimes (after tabd is gone). */
export function removeRunResources(runDir: string, m: RunManifest = readManifest(runDir), tabs: string[] = runTabs(m)): void {
	for (const t of tabs) {
		spawnSync(SBX, ['rm', '--force', `seclab-${t}`], { stdio: 'ignore' });
		const cs = dockerLines(['ps', '-aq', '--filter', `label=seclab.tab=${t}`]) ?? [];
		if (cs.length) {
			spawnSync('docker', ['rm', '-f', ...cs], { stdio: 'ignore' });
		}
		spawnSync('docker', ['network', 'rm', `seclab-${t}-net`], { stdio: 'ignore' });
		// Every other network labelled for this tab (e.g. a sbx tab's broker egress network), and
		// any named for it (`seclab-<tab>-*`) even without the label.
		const nets = new Set([...dockerLines(['network', 'ls', '--filter', `label=seclab.tab=${t}`, '--format', '{{.Name}}']) ?? [],
			...tabNetworksByName(a => dockerLines(a) ?? [], t)]);
		for (const n of nets) {
			spawnSync('docker', ['network', 'rm', n], { stdio: 'ignore' });
		}
		spawnSync('docker', ['volume', 'rm', `seclab-${t}-home`], { stdio: 'ignore' });
	}
	for (const c of m.containers ?? []) {
		spawnSync('docker', ['rm', '-f', c], { stdio: 'ignore' });
	}
	for (const tag of falcoStateTags(m)) {
		const cs = dockerLines(['ps', '-aq', '--filter', 'label=seclab.obs=falco', '--filter', `label=seclab.state=${tag}`]) ?? [];
		if (cs.length) {
			spawnSync('docker', ['rm', '-f', ...cs], { stdio: 'ignore' });
		}
	}
}

/**
 * The full post-run check. `snapshot: false` skips the host diff when the caller already
 * asserted it. Never throws: every failure is a check.
 */
export function verifyTeardown(runDir: string, opts: { snapshot?: boolean } = {}): TeardownCheck[] {
	runDir = path.resolve(runDir);
	const m = readManifest(runDir);
	const checks: TeardownCheck[] = [];
	const add = (ok: boolean, name: string, detail = '') => checks.push({ name, ok, detail });

	const bad = [...runDirProblems(runDir, m), ...manifestProblems(runDir, m)];
	if (bad.length) {
		add(false, 'run.json is valid (refusing to kill or delete anything on its say-so)', bad.join('; '));
		return checks;
	}
	const tabs = runTabs(m); // before the profile (and its tabd state) is deleted

	const survivors = stopRunProcesses(runDir, m);
	add(survivors.length === 0, 'no process from this run is still alive (editor, tabd, streams)',
		survivors.map(p => `${p.pid}: ${p.args.slice(0, 90)}`).join(' | '));

	removeRunResources(runDir, m, tabs);
	const { left, unknown } = runLeftovers(runDir, m, tabs);
	add(left.length === 0, 'no sandbox, container, network or volume from this run remains', left.join(', '));
	add(unknown.length === 0, 'runtimes could be listed (leftovers otherwise unknown)', unknown.length ? `could not list: ${unknown.join(', ')}` : '');

	if (m.userDataDir) {
		// The focus watcher (test/window.ts) logs any second the editor was the frontmost app (UU-2).
		const steals = path.join(m.userDataDir, 'seclab-focus-steals.log');
		const log = fs.existsSync(steals) ? fs.readFileSync(steals, 'utf8').trim() : '';
		add(log === '', 'the editor never took focus from the user during the run', log.split('\n').slice(0, 3).join(' | '));
	}
	if (m.userDataDir && fs.existsSync(m.userDataDir)) {
		fs.rmSync(m.userDataDir, { recursive: true, force: true });
	}
	if (m.userDataDir) {
		const portableProblems: string[] = [];
		removePortable(m.userDataDir, portableProblems);
		add(!fs.existsSync(m.userDataDir) && !fs.existsSync(editorPortableDir(m.userDataDir)), 'run user-data-dir and its portable dir removed (it holds the armed rogue extension)', [m.userDataDir, ...portableProblems].join('; '));
	}
	// Generated fixture workspaces never outlive the run: copies on the host are what endpoint
	// protection scans (EDR fixture-safety). Only after every process and tab is gone.
	for (const w of m.workspaces ?? []) {
		fs.rmSync(w, { recursive: true, force: true });
	}
	if (m.workspaces?.length) {
		const left = m.workspaces.filter(w => fs.existsSync(w));
		add(left.length === 0, 'generated fixture workspaces removed from the host', left.join(', '));
	}

	let nonce = '';
	try {
		nonce = fs.readFileSync(path.join(runDir, '.seclab-probe-nonce'), 'utf8').trim();
	} catch { /* not an RPC probe run */ }
	if (nonce && process.platform === 'darwin') {
		const r = spawnSync('security', ['find-generic-password', '-s', `seclab-probe-${nonce.slice(0, 16)}`], { stdio: 'ignore' });
		add(r.status !== 0, 'no run-scoped keychain item left behind', r.status === 0 ? 'still present' : '');
	}
	const artefacts = path.join(runDir, 'probe-artefacts.txt');
	if (fs.existsSync(artefacts)) {
		const outside = fs.readFileSync(artefacts, 'utf8').split('\n').filter(Boolean)
			.filter(a => !path.resolve(a).startsWith(runDir + path.sep));
		add(outside.length === 0, 'every recorded artefact is inside the run directory', outside.join(', '));
	}

	if (opts.snapshot !== false) {
		if (!fs.existsSync(snapshotFile(runDir))) {
			add(false, 'host snapshot exists', 'run `teardown.ts snapshot` before the run');
		} else {
			const snap = JSON.parse(fs.readFileSync(snapshotFile(runDir), 'utf8')) as { v?: number; key?: string; entries?: Snapshot };
			if (snap.v !== 2 || typeof snap.key !== 'string' || !snap.entries) {
				add(false, 'host snapshot is current', 'old snapshot format; re-run `teardown.ts snapshot` before the run');
			} else {
				const changed = snapshotDiff(snap.entries, hostSnapshot(snap.key));
				add(changed.length === 0, 'nothing outside the run directory changed (watched host paths, stat only)', changed.join(', '));
			}
		}
	}
	return checks;
}

export function printChecks(checks: TeardownCheck[]): boolean {
	for (const c of checks) {
		console.log(`${c.ok ? 'OK  ' : 'FAIL'}  ${c.name}${c.detail ? `  -> ${c.detail}` : ''}`);
	}
	const bad = checks.filter(c => !c.ok).length;
	console.log(bad === 0
		? 'teardown clean: no surviving process, no runtime resource, nothing outside the run directory changed'
		: `${bad} teardown problem(s)`);
	return bad === 0;
}

/** End-of-run gate for the suites: prints the checks, false if anything was left behind. */
export function teardownGate(runDir: string): boolean {
	if (process.env.KEEP === '1') {
		// Not verified, so not a pass (T-5): the run's tabs and profile are still live.
		console.log(`KEEP=1: teardown NOT verified, run resources kept; run \`node test/containment/teardown.ts verify ${runDir}\` when done`);
		return false;
	}
	return printChecks(verifyTeardown(runDir));
}

/** Wait for a child (e.g. tabd) to exit, at most `ms`: teardown kills it anyway if it hangs. */
export function exitedOrTimeout(exit: Promise<unknown>, ms = 20_000): Promise<unknown> {
	let t: NodeJS.Timeout | undefined;
	return Promise.race([exit, new Promise(res => {
		t = setTimeout(res, ms);
	})]).finally(() => clearTimeout(t));
}

if (import.meta.main) {
	const [mode, runDirArg] = process.argv.slice(2);
	if ((mode !== 'snapshot' && mode !== 'verify') || !runDirArg) {
		console.error('usage: teardown.ts snapshot|verify <run-dir>');
		process.exit(2);
	}
	const runDir = path.resolve(runDirArg);
	if (mode === 'snapshot') {
		writeSnapshot(runDir);
		console.log('host snapshot written');
		process.exit(0);
	}
	process.exit(printChecks(verifyTeardown(runDir)) ? 0 : 1);
}
