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
import { checkIsolatedProfile, editorPortableDir, focusWatchLog, focusWatchProblem, hostSnapshot, repoRoot, snapshotDiff, type Snapshot } from '../harness.ts';
import { sensorOwner } from '../../tabd/src/obs/falco.ts';
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
// SECLAB_SBX: a test's stand-in, so a reap test never reaches the real sbx.
const SBX = process.env.SECLAB_SBX ?? (fs.existsSync('/opt/homebrew/bin/sbx') ? '/opt/homebrew/bin/sbx' : 'sbx');

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
	if (!m.userDataDir && !(m.stateDirs ?? []).length && !(m.commandMarks ?? []).length && !(m.tabs ?? []).length && !(m.containers ?? []).length) {
		return { stopped: [], refused: false, problems: [], survivors: [] };
	}
	// The same rules verify applies, including R-2: a malformed previous manifest must not
	// become a licence to delete, and must not be quietly skipped either.
	const problems = [...runDirProblems(runDir, m), ...manifestProblems(runDir, m)];
	if (problems.length) {
		return { stopped: [], refused: true, problems, survivors: [] };
	}
	const runPids = new Set(runProcesses(runDir, m).map(p => p.pid));
	const tabs = runTabs(m); // before the profile (and its tabd state) is deleted
	const stopped = stopRunProcesses(runDir, m);
	// Its tabs and helper runtimes too, and its profile: that profile holds the armed rogue
	// extension, so leaving it is the same hazard the teardown gate exists to prevent.
	try {
		removeRunResources(runDir, m, tabs, runPids);
	} catch (err) {
		problems.push(`could not remove the previous run's runtime resources: ${err instanceof Error ? err.message : String(err)}`);
	}
	// Removal ignores command failures, so check what is left. A runtime that remains, or one that
	// can't be listed, refuses before the profile and its tabd state (the record of the tabs) go.
	const { left, unknown } = runLeftovers(runDir, m, tabs, runPids);
	if (left.length) {
		problems.push(`the previous run's runtime resources remain: ${left.join(', ')}`);
	}
	if (unknown.length) {
		problems.push(`could not list the previous run's runtimes: ${unknown.join(', ')}`);
	}
	if (problems.length) {
		return { stopped, refused: true, problems, survivors: runProcesses(runDir, m) };
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

/**
 * For a harness about to wipe its run directory: reap the previous run first, from the manifest
 * in that directory, its only record. A refusal exits the process: wiping the record of a run
 * that could not be reaped would orphan its tabs and processes (PR review, 2026-11-17).
 */
export function reapOrRefuse(runDir: string, who: string): void {
	const reaped = reapPreviousRun(runDir);
	if (reaped.refused) {
		for (const p of reaped.problems) {
			console.error(`${who}: ${p}`);
		}
		for (const p of reaped.survivors) {
			console.error(`${who}: a process from the previous run is still alive: ${p.pid} ${p.args.slice(0, 200)}`);
		}
		console.error(`${who}: refusing to wipe ${runDir}: the previous run could not be reaped. Resolve it (./seclab clean-host) and retry.`);
		process.exit(1);
	}
	if (reaped.stopped.length) {
		console.log(`${who}: reaped ${reaped.stopped.length} process(es) from the previous run`);
	}
}

/**
 * Ctrl+C or SIGTERM end the process through `exit`, so a harness's exit handler (its teardown
 * gate) runs on interruption too. Node's default for both signals skips `exit` handlers and
 * pending `finally` blocks (PR review, 2026-11-17).
 */
export function exitOnSignals(): void {
	process.on('SIGINT', () => process.exit(130));
	process.on('SIGTERM', () => process.exit(143));
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

/** Every tabd state dir of the run: recorded ones plus the Tab Manager's under the run's profile. */
function runStateDirs(m: RunManifest): string[] {
	const dirs = [...(m.stateDirs ?? [])];
	if (m.userDataDir) {
		dirs.push(path.join(m.userDataDir, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd'));
	}
	return dirs;
}

/** Tab ids the run owns: recorded ones plus every tab in its tabd state (T-2b), read before the state is deleted. */
export function runTabs(m: RunManifest): string[] {
	const ids = new Set((m.tabs ?? []).filter(t => TAB_RE.test(t)));
	for (const d of runStateDirs(m)) {
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
	return processTableOrUndefined(false) ?? [];
}

/** The process table; with `strict`, undefined unless `ps` ran to completion (PS-3: a partial table must never read as "dead"). */
function processTableOrUndefined(strict: boolean): Proc[] | undefined {
	const ps = spawnSync('ps', ['-axo', 'pid=,ppid=,stat=,args='], { encoding: 'utf8' });
	if (strict && (ps.error || ps.status !== 0 || ps.signal)) {
		return undefined;
	}
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
export function runLeftovers(runDir: string, m: RunManifest = readManifest(runDir), tabs: string[] = runTabs(m), runPids: ReadonlySet<number> = new Set()): { left: string[]; unknown: string[] } {
	const left: string[] = [];
	const unknown = new Set<string>();
	const needSbx = m.driver === 'sbx' || (m.driver === undefined && tabs.length > 0);
	// Every tab owns Docker resources: an OCI pod, or an sbx tab's broker container and egress network.
	const needDocker = m.driver === 'oci' || tabs.length > 0 || (m.containers ?? []).length > 0;
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
	// Host-side observability sensor (OCI Falco) that tabd started for this run's state dirs:
	// the run's own, and unlabelled ones it can't prove aren't (CR16-2). Another namespace's is not.
	const falco = runFalcoSensors(m, runPids);
	if (!falco && needDocker) {
		unknown.add('docker');
	}
	for (const c of [...falco?.own ?? [], ...falco?.unproven ?? []]) {
		left.push(`container ${c}`);
	}
	return { left, unknown: [...unknown] };
}

/**
 * tabd labels its Falco container with sha256(state dir)[0:8] (tabd/src/main.ts). The editor's
 * tabd keeps its state under the profile, so that dir counts too (PS-1: an editor run's Falco
 * outlived it for hours because only `stateDirs` was hashed).
 */
function falcoStateTags(m: RunManifest): string[] {
	return runStateDirs(m).map(d => createHash('sha256').update(d).digest('hex').slice(0, 8));
}

/** True when a sensor's owner labels name this namespace and boot (clock slack 10 s; a larger step keeps it). */
function sameSensorOwner(host: string | undefined, boot: string | undefined, me: { host: string | undefined; boot: number }): boolean {
	return !!me.host && host === me.host && /^[0-9]{1,12}$/.test(boot ?? '') && Math.abs(Number(boot) - me.boot) <= 10;
}

/** A tabd command line, as `ps` shows it (the harnesses' `main.ts`, the Tab Manager's `dist/tabd.js`). */
export const TABD_ARGV = /(^|\/)(tabd\/src\/main\.ts|dist\/tabd\.js)(\s|$)/;
const FALCO_NAME = /^seclab-falco-[0-9a-f]{8}-([0-9]{1,10})$/;

/**
 * Falco sensors whose tabd is gone (PS-1). tabd runs Falco as `docker run -i --rm`; when tabd is
 * SIGKILLed (teardown's escalation, a crash) its docker client dies with it and the container
 * keeps running with nobody reading it. A sensor is live while the pid in its name and
 * `seclab.pid` label is a running tabd; a dead pid, or one reused by any other program, is an
 * orphan. Only sensors labelled with this host's pid namespace, uid and boot can be judged
 * (PS-2): another namespace's tabd is invisible to our `ps`. Pure, so the decision is
 * testable: `sensors` are `name\tpid\thost\tboot` lines from `docker ps --filter
 * label=seclab.obs=falco`, `procs` the complete host process table. Unlabelled sensors, labels
 * that disagree with the name, and other names are never claimed.
 */
export function falcoOrphans(sensors: string[], procs: Array<{ pid: number; args: string }>, me: { host: string | undefined; boot: number } = sensorOwner()): Array<{ name: string; pid: number; why: string }> {
	return classifyFalco(sensors, procs, me).filter(c => c.orphan);
}

/**
 * Every Falco sensor, judged: `orphan` (remove), or kept with the reason. `unjudged` marks one
 * whose pid isn't in our table but whose owner labels aren't ours (another namespace, an older
 * tabd without labels): it may be an orphan, but only a person can tell (PS-6).
 */
export function classifyFalco(sensors: string[], procs: Array<{ pid: number; args: string }>, me: { host: string | undefined; boot: number }): Array<{ name: string; pid: number; orphan: boolean; unjudged: boolean; why: string }> {
	const byPid = new Map(procs.map(p => [p.pid, p.args]));
	const out: Array<{ name: string; pid: number; orphan: boolean; unjudged: boolean; why: string }> = [];
	for (const l of sensors) {
		const [name, label, host, boot] = l.split('\t');
		const pid = Number(FALCO_NAME.exec(name ?? '')?.[1]);
		if (!pid || label !== String(pid)) {
			out.push({ name, pid, orphan: false, unjudged: false, why: 'not tabd\'s name and pid label' });
			continue;
		}
		const args = byPid.get(pid);
		const gone = args === undefined ? `its tabd (pid ${pid}) is dead` : !TABD_ARGV.test(args) ? `pid ${pid} is no longer a tabd` : '';
		if (!sameSensorOwner(host, boot, me)) {
			out.push({ name, pid, orphan: false, unjudged: !!gone, why: host ? 'owner labels name another namespace or boot' : 'no owner labels (an older tabd)' });
		} else {
			out.push({ name, pid, orphan: !!gone, unjudged: false, why: gone || 'its tabd is running' });
		}
	}
	return out;
}

/**
 * Whether a process is alive, from `ps -o stat= -p <pid>` and a `kill(pid, 0)` probe (CR16-8).
 * A zombie is gone. When `ps` gives no answer (failed, signalled, or found nothing), only ESRCH
 * from the probe proves absence: EPERM or any other error means it may still run.
 */
export function pidAliveFrom(ps: { status: number | null; stdout?: string | null; error?: Error; signal?: NodeJS.Signals | null }, probe: () => unknown): boolean {
	// A `ps` that failed to spawn may have no stdout at all (CR16-11).
	const st = (ps.stdout ?? '').trim();
	if (!ps.error && !ps.signal && ps.status === 0 && st) {
		return !st.startsWith('Z');
	}
	try {
		probe();
		return true;
	} catch (err) {
		return (err as NodeJS.ErrnoException).code !== 'ESRCH';
	}
}

/**
 * Whether `clean-host` may remove a judged sensor now: an orphan, and if its tabd was one the
 * same pass set out to kill, only once that tabd has really exited (CR16-3: a kill can fail).
 */
export function falcoRemovable(c: { orphan: boolean; pid: number }, killed: ReadonlySet<number>, pidAlive: (pid: number) => boolean): boolean {
	return c.orphan && !(killed.has(c.pid) && pidAlive(c.pid));
}

/** `docker ps` format for {@link falcoOrphans}. */
export const FALCO_PS_FORMAT = '{{.Names}}\t{{.Label "seclab.pid"}}\t{{.Label "seclab.host"}}\t{{.Label "seclab.boot"}}';

/** Orphaned Falco sensors on this host now; undefined when docker or ps can't be listed in full (never guess). */
export function hostFalcoOrphans(): Array<{ name: string; pid: number; why: string }> | undefined {
	const sensors = dockerLines(['ps', '-a', '--filter', 'label=seclab.obs=falco', '--format', FALCO_PS_FORMAT]);
	if (!sensors) {
		return undefined;
	}
	if (!sensors.length) {
		return [];
	}
	const procs = processTableOrUndefined(true);
	return procs?.length ? falcoOrphans(sensors, procs) : undefined;
}

/** Sensors that look orphaned but aren't provably ours to judge (PS-6); [] when unknown. */
export function hostFalcoUnjudged(): string[] {
	const sensors = dockerLines(['ps', '-a', '--filter', 'label=seclab.obs=falco', '--format', FALCO_PS_FORMAT]) ?? [];
	const procs = sensors.length ? processTableOrUndefined(true) : undefined;
	return procs?.length ? classifyFalco(sensors, procs, sensorOwner()).filter(c => c.unjudged).map(c => `${c.name}: ${c.why}`) : [];
}

/** Networks named for this tab: `seclab-<tab>-<suffix>` (docker's name filter is a substring match). */
function tabNetworksByName(docker: (args: string[]) => string[], tab: string): string[] {
	const prefix = `seclab-${tab}-`;
	return docker(['network', 'ls', '--filter', `name=${prefix}`, '--format', '{{.Name}}'])
		.filter(n => n.startsWith(prefix) && /^[a-z0-9-]+$/.test(n.slice(prefix.length)));
}

/** Remove the run's tabs and helpers directly in the runtimes (after tabd is gone). */
export function removeRunResources(runDir: string, m: RunManifest = readManifest(runDir), tabs: string[] = runTabs(m), runPids: ReadonlySet<number> = new Set()): void {
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
	for (const c of runFalcoSensors(m, runPids)?.own ?? []) {
		spawnSync('docker', ['rm', '-f', '--', c], { stdio: 'ignore' });
	}
}

/**
 * The run's Falco sensors (CR16-2). The state tag hashes a path, and another pid namespace on a
 * shared engine can use the same profile path, so the tag alone never makes a sensor the run's:
 * `own` also carries this namespace's owner labels, or is named for one of the run's processes
 * (captured before they were stopped). `unproven` are unlabelled (an older tabd) and not named
 * for a run process: reported, never removed. Undefined when docker can't be listed.
 */
export function runFalcoSensors(m: RunManifest, runPids: ReadonlySet<number>, me: { host: string | undefined; boot: number } = sensorOwner()): { own: string[]; unproven: string[]; unjudged: string[] } | undefined {
	const tags = new Set(falcoStateTags(m));
	if (!tags.size) {
		return { own: [], unproven: [], unjudged: [] };
	}
	const rows = dockerLines(['ps', '-a', '--filter', 'label=seclab.obs=falco', '--format', `${FALCO_PS_FORMAT}\t{{.Label "seclab.state"}}`]);
	const procs = processTableOrUndefined(true);
	return rows ? classifyRunFalco(rows, tags, runPids, me, procs && new Set(procs.map(p => p.pid))) : undefined;
}

/** Pure half of {@link runFalcoSensors}: rows are `name\tpid\thost\tboot\tstate`. */
export function classifyRunFalco(rows: string[], tags: ReadonlySet<string>, runPids: ReadonlySet<number>, me: { host: string | undefined; boot: number }, procs?: ReadonlySet<number>): { own: string[]; unproven: string[]; unjudged: string[] } {
	const own: string[] = [], unproven: string[] = [], unjudged: string[] = [];
	for (const r of rows) {
		const [name, label, host, boot, state] = r.split('\t');
		const pid = Number(FALCO_NAME.exec(name ?? '')?.[1]);
		if (!pid || label !== String(pid) || !tags.has(state ?? '')) {
			continue;
		}
		// A run pid proves ownership only for an unlabelled sensor: foreign labels never yield to a
		// pid collision (CR16-4). Foreign-labelled ones whose pid isn't running here may be the
		// run's own after label drift (a clock step, a renamed Linux host), or another namespace's:
		// noted, not failed and never removed (CR16-5).
		if (sameSensorOwner(host, boot, me) || (!host && runPids.has(pid))) {
			own.push(name);
		} else if (!host) {
			unproven.push(name);
		} else if (!procs?.has(pid)) {
			unjudged.push(name);
		}
	}
	return { own, unproven, unjudged };
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

	const runPids = new Set(runProcesses(runDir, m).map(p => p.pid)); // names the run's own Falco sensors (CR16-2)
	const survivors = stopRunProcesses(runDir, m);
	add(survivors.length === 0, 'no process from this run is still alive (editor, tabd, streams)',
		survivors.map(p => `${p.pid}: ${p.args.slice(0, 90)}`).join(' | '));

	removeRunResources(runDir, m, tabs, runPids);
	const { left, unknown } = runLeftovers(runDir, m, tabs, runPids);
	add(left.length === 0, 'no sandbox, container, network or volume from this run remains', left.join(', '));
	add(unknown.length === 0, 'runtimes could be listed (leftovers otherwise unknown)', unknown.length ? `could not list: ${unknown.join(', ')}` : '');
	// Any run's Falco sensor whose tabd is gone has no reader and no owner left to stop it (PS-1).
	for (const o of hostFalcoOrphans() ?? []) {
		spawnSync('docker', ['rm', '-f', '--', o.name], { stdio: 'ignore' });
	}
	const orphans = hostFalcoOrphans();
	add(orphans ? orphans.length === 0 : m.driver !== 'oci', 'no Falco sensor outlives its tabd (this run or an earlier one)',
		orphans ? orphans.map(o => `${o.name}: ${o.why}`).join(', ') : 'could not list docker or processes');
	const runUnjudged = runFalcoSensors(m, runPids)?.unjudged ?? [];
	if (runUnjudged.length) {
		add(true, 'note: sensors with this run\'s state tag but another owner\'s labels, pid not running here (check by hand)', runUnjudged.join(', '));
	}
	const unjudged = hostFalcoUnjudged();
	if (unjudged.length) {
		add(true, 'note: Falco sensors whose tabd is not in our process table but which this host can\'t judge (check by hand)', unjudged.join(', '));
	}

	if (m.userDataDir) {
		// The focus watcher (test/window.ts) logs any second the editor was the frontmost app (UU-2).
		const steals = path.join(m.userDataDir, 'seclab-focus-steals.log');
		const log = fs.existsSync(steals) ? fs.readFileSync(steals, 'utf8').trim() : '';
		add(log === '', 'the editor never took focus from the user during the run', log.split('\n').slice(0, 3).join(' | '));
		// No steal log only means "clean" if the watcher watched the editor to the end (GATE-10).
		const unwatched = focusWatchProblem(m.userDataDir);
		add(!unwatched, 'the focus watcher watched the editor for its whole run', unwatched ?? '');
		fs.rmSync(focusWatchLog(m.userDataDir), { force: true });
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
/**
 * Helper processes still running from THIS worktree, found without consulting any manifest.
 *
 * The manifest is not a safety net, because a helper has to be spawned before it can be
 * recorded, and anything that goes wrong in between leaves a process nothing knows about. That
 * happened: a beacon was spawned, its liveness probe failed, the runner exited on that failure
 * BEFORE `writeManifest`, and the listener survived with no record of it anywhere. Teardown and
 * `clean-host` both reported the host clean, because both ask the manifest what to look for.
 *
 * So this asks the process table instead, keyed on this worktree's absolute path, which is
 * ours by construction: another session's worktree has a different path, so this can never
 * claim a process it did not create (AGENTS.md: found by unique path, never by program name).
 */
/** Long-lived helpers a run starts on the HOST, as the printed procedures invoke them. */
export const HOST_HELPERS = ['test/containment/beacon.ts', 'test/agentic/browser/run.ts'];

export function strayHelpers(root: string = repoRoot): Proc[] {
	// Absolute AND relative forms. Every invocation the harness prints is relative
	// (`node test/agentic/browser/run.ts listen …`), so matching only the absolute path left
	// the one long-lived helper this design adds invisible to the net meant to catch it. The
	// relative form is accepted only for a node process running one of OUR scripts, which
	// keeps it from claiming another worktree's run: a relative argv has no worktree in it,
	// so it is additionally required to be a known helper script path.
	const abs = `${path.resolve(root)}${path.sep}test${path.sep}`;
	const isOurs = (args: string): boolean => {
		if (args.includes(abs)) {
			return true;
		}
		return /(^|\/)node(\s|$)/.test(args)
			&& HOST_HELPERS.some(rel => new RegExp(`(^|\\s)${rel.replace(/[./]/g, m => `\\${m}`)}(\\s|$)`).test(args));
	};
	const table = processTable();
	const byPid = new Map(table.map(p => [p.pid, p]));
	// Only OURSELVES and our ANCESTORS are spared, never our descendants. A helper we
	// started is precisely what has to be reported here: by the time this runs the run is
	// over, so a live child is a leak whether it has been reparented to init yet or not.
	// Sparing descendants was the first version of this, and it made the regression test
	// below pass while the real leak (a reparented beacon) would still have escaped a run
	// that ended before reparenting.
	const spare = new Set<number>([process.pid, process.ppid]);
	for (let p = byPid.get(process.pid)?.ppid; p && !spare.has(p); p = byPid.get(p)?.ppid) {
		spare.add(p);
	}
	return table.filter(p => !spare.has(p.pid) && isOurs(p.args));
}

export function teardownGate(runDir: string): boolean {
	if (process.env.KEEP === '1') {
		// Not verified, so not a pass (T-5): the run's tabs and profile are still live.
		console.log(`KEEP=1: teardown NOT verified, run resources kept; run \`node test/containment/teardown.ts verify ${runDir}\` when done`);
		return false;
	}
	const checks = verifyTeardown(runDir);
	// The manifest-independent net, run LAST so it also covers anything the checks above
	// started. A helper that outlived its run is a finding whatever the manifest says.
	// A short grace first: this gate has just killed the run's processes, and a helper that
	// watches the editor (test/window.ts) exits when the editor does, a moment later. Without
	// it the gate reports a helper that is already on its way out.
	let strays = strayHelpers();
	for (let i = 0; i < 20 && strays.length; i++) {
		spawnSync('sleep', ['0.5']);
		strays = strayHelpers();
	}
	checks.push({
		name: 'no helper from this worktree is still running (manifest or not)',
		ok: strays.length === 0,
		detail: strays.length ? strays.map(p => `${p.pid} ${p.args.slice(0, 140)}`).join('; ') : 'none',
	});
	return printChecks(checks);
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
