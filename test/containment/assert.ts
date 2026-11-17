// Containment assertions shared by the automated runner (run.ts) and the editor-driven
// check (check-evidence.ts). Evidence comes from fixtures/malicious-workspace/.seclab/probe.sh.

import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

/**
 * One vector's evidence, as written by a hostile fixture. Every field is therefore
 * `unknown`: `readEvidence` parses attacker-chosen JSON, so the declared shape is a
 * claim, not a fact, and typing it as `string` made the compiler bless
 * `ev.secret_env.trim()` on a value that could be `null` (review round 9 alert 2).
 * Narrow before use.
 */
export interface Evidence {
	vector?: unknown;
	hostname?: unknown;
	uid?: unknown;
	seclab_tab_env?: unknown;
	canary_read?: unknown;
	othertab_read?: unknown;
	docker_sock_writable?: unknown;
	sudo?: unknown;
	secret_env?: unknown;
	ui_bridge?: unknown;
	http_proxy?: unknown;
	HTTPS_PROXY?: unknown;
	egress?: unknown;
}

/**
 * `knownGap`: a documented, accepted-until-fixed gap (e.g. "M4"). A failing check with a
 * known gap prints XFAIL and does not fail the run; when it starts passing it prints XPASS
 * so the marker gets removed. Never use it to hide an unexplained failure.
 */
export interface Check { vector: string; name: string; ok: boolean; detail: string; knownGap?: string }

const BLOCKED = new Set(['000', '403', '']);

/** Evidence for one vector. `read` reads a workspace file through the tab (the write-back
 *  gate keeps tab writes out of the host checkout until reviewed); default: the host file. */
export function readEvidence(ws: string, vector: string, read?: (p: string) => string | undefined): Evidence | undefined {
	const f = path.join(ws, '.seclab-evidence', `${vector}.json`);
	const text = read ? read(f) : (fs.existsSync(f) ? fs.readFileSync(f, 'utf8') : undefined);
	try {
		return text ? JSON.parse(text) as Evidence : undefined;
	} catch {
		return undefined;
	}
}

/** Assertions for one vector. `expectHostname` is the tab's hostname when known. `proxy`: what
 *  the tab's egress must point at: its own broker (`broker:8080` on the OCI pod network, or
 *  `host.docker.internal:<port>` from an sbx VM, plan tabd-broker-wiring B2) or the blackhole
 *  (`--broker none`); exactly that, never either (review XX-4). */
export type ProxyExpectation = 'oci-broker' | 'sbx-broker' | 'blackhole';
export const brokerProxy = (driver: string): ProxyExpectation => driver === 'oci' ? 'oci-broker' : 'sbx-broker';
const PROXY_RE: Record<ProxyExpectation, RegExp> = {
	'oci-broker': /^http:\/\/seclab:[A-Za-z0-9_-]{32}@broker:8080$/,
	'sbx-broker': /^http:\/\/seclab:[A-Za-z0-9_-]{32}@host\.docker\.internal:[1-9][0-9]{0,4}$/,
	'blackhole': /^http:\/\/127\.0\.0\.1:9$/,
};
export function checkEvidence(ev: Evidence | undefined, vector: string, opts: { marker: string; expectHostname?: string; proxy: ProxyExpectation }): Check[] {
	const c = (name: string, ok: boolean, detail = ''): Check => ({ vector, name, ok, detail });
	// Every field below is fixture-authored. `readEvidence` guards JSON.parse but not the
	// SHAPE, so `{"egress":null}` or an omitted `secret_env` is valid JSON that used to
	// throw a TypeError out of this function (review round 9 alert 2). A missing or
	// wrong-typed field is a failing check with the raw value shown, never a crash: the
	// harness must not be steerable by the thing it is assessing.
	const str = (v: unknown): string => typeof v === 'string' ? v : '';

	// The probe writes its marker only into the run directory, which exists only on the host, so
	// this one check is a host fact: it stands even when the tab withholds its evidence.
	const hostMarker = c('cannot write host file outside the workspace', !fs.existsSync(`${opts.marker}.${vector}`), `${opts.marker}.${vector}`);
	if (!ev) {
		return [c('ran (evidence written into the workspace)', false, 'no evidence file'), hostMarker];
	}
	const out: Check[] = [c('ran (evidence written into the workspace)', true)];
	// A present field of the wrong type is malformed evidence, not the benign value.
	// Without this, `"ui_bridge": 7` read as "" and passed the credential-bridge check:
	// narrowing must not silently convert an unparseable claim into a reassuring one.
	const STRING_FIELDS = ['hostname', 'uid', 'seclab_tab_env', 'canary_read', 'othertab_read',
		'docker_sock_writable', 'sudo', 'secret_env', 'ui_bridge', 'http_proxy', 'HTTPS_PROXY'] as const;
	const illTyped = STRING_FIELDS.filter(k => ev[k] !== undefined && typeof ev[k] !== 'string');
	if (illTyped.length > 0) {
		out.push(c('evidence fields are well-typed', false, `not strings: ${illTyped.join(', ')}`));
	}
	out.push(c('ran inside the tab, not on the host', typeof ev.hostname === 'string' && ev.hostname !== os.hostname() && ev.seclab_tab_env === '1' &&
		(opts.expectHostname === undefined || ev.hostname === opts.expectHostname), `hostname=${str(ev.hostname)} SECLAB_TAB=${str(ev.seclab_tab_env)}`));
	out.push(c('cannot read host file outside the workspace (canary)', ev.canary_read === 'no', str(ev.canary_read)));
	out.push(c('cannot read another tab\'s workspace', ev.othertab_read === 'no', str(ev.othertab_read)));
	out.push(hostMarker);
	out.push(c('no writable docker.sock', ev.docker_sock_writable === 'no', str(ev.docker_sock_writable)));
	out.push(c('no sudo', ev.sudo === 'no', str(ev.sudo)));
	out.push(c('no host secrets / agent sockets in env', typeof ev.secret_env === 'string' && ev.secret_env.trim() === '', str(ev.secret_env)));
	// The REH's git extension exports an askpass socket (VSCODE_GIT_IPC_HANDLE) inside the
	// tab; through it git can reach the UI-side auth providers. Only the RPC capability
	// filter (M4) closes that; until then it's an explicit known gap, not a silent pass.
	const bridge = str(ev.ui_bridge).trim();
	out.push({ ...c('no tab-to-UI credential bridge in env (git askpass)', bridge === '', bridge),
		knownGap: bridge ? 'M4 RPC capability filter (docs/adr/20261104-rpc-capability-filter.md)' : undefined });
	// Egress points at exactly what this tab must use: its own broker or the blackhole. The
	// runtime-injected value never wins, and both cases agree.
	const want = PROXY_RE[opts.proxy];
	out.push(c(`runtime-injected proxy env never wins (both cases point at the ${opts.proxy})`, want.test(str(ev.http_proxy)) && str(ev.http_proxy) === str(ev.HTTPS_PROXY),
		`http_proxy=${str(ev.http_proxy).replace(/:[^:@/]+@/, ':***@')} HTTPS_PROXY=${str(ev.HTTPS_PROXY).replace(/:[^:@/]+@/, ':***@')}`));
	const egress = ev.egress && typeof ev.egress === 'object' && !Array.isArray(ev.egress) ? ev.egress as Record<string, unknown> : undefined;
	if (!egress) {
		out.push(c('recorded its egress probes', false, `egress=${JSON.stringify(ev.egress ?? null).slice(0, 120)}`));
	}
	for (const [k, raw] of Object.entries((egress ?? {}) as Record<string, unknown>)) {
		const v = str(raw);
		if (k === 'dns_external') {
			out.push(c('no external DNS', v === 'blocked', v));
		} else {
			out.push(c(`egress blocked: ${k}`, BLOCKED.has(v), `http_code=${v}`));
		}
	}
	return out;
}

export function report(checks: Check[]): boolean {
	let ok = true;
	for (const ch of checks) {
		ok &&= ch.ok || !!ch.knownGap;
		const tag = ch.ok ? (ch.knownGap ? 'XPASS' : 'PASS') : (ch.knownGap ? 'XFAIL' : 'FAIL');
		console.log(`${tag}  [${ch.vector}] ${ch.name}${ch.ok ? '' : `  -> ${ch.detail}`}${ch.knownGap ? `  (known gap: ${ch.knownGap})` : ''}`);
	}
	const failed = checks.filter(c => !c.ok && !c.knownGap).length;
	const xfail = checks.filter(c => !c.ok && c.knownGap).length;
	console.log(`\n${checks.length - failed - xfail}/${checks.length} checks passed${xfail ? `, ${xfail} known gap(s) (XFAIL)` : ''}${failed ? `, ${failed} FAILED` : ''}`);
	return ok;
}

/** One line of the trusted-side RPC filter decision log (patch 0005). */
export interface RpcDecision {
	source?: string;
	class?: string;
	priority?: string;
	summary?: string;
	detail?: { surface?: string; ref?: string; verdict?: string; reason?: string; constraint?: string; claimedExtensionId?: string; count?: number };
}

/**
 * Every decision the RPC filter logged in a profile's window logs. Host-side: the filter
 * writes through ILoggerService into `<userData>/logs/<session>/window<N>/seclabRpcFilter.log`,
 * which nothing inside a tab can reach, so a denial read from here is observed rather than
 * inferred from an absent marker. Unparseable lines are skipped, never guessed at: the file is
 * trusted-side but its `ref` and `claimedExtensionId` fields carry tab-chosen strings, so
 * callers must match on exact fields and never on free text (EDR prompt-injection-hygiene).
 */
export function rpcDecisions(userDataDir: string): RpcDecision[] {
	const logs = path.join(userDataDir, 'logs');
	const files: string[] = [];
	const walk = (dir: string, depth: number): void => {
		if (depth > 4) {
			return;
		}
		for (const e of (() => { try { return fs.readdirSync(dir, { withFileTypes: true }); } catch { return []; } })()) {
			const p = path.join(dir, e.name);
			if (e.isDirectory()) {
				walk(p, depth + 1);
			} else if (e.isFile() && e.name === 'seclabRpcFilter.log') {
				files.push(p);
			}
		}
	};
	walk(logs, 0);
	const out: RpcDecision[] = [];
	for (const f of files) {
		for (const line of fs.readFileSync(f, 'utf8').split('\n')) {
			const i = line.indexOf('{'); // ILoggerService prefixes each entry with a timestamp and level
			if (i < 0) {
				continue;
			}
			try {
				const d = JSON.parse(line.slice(i)) as RpcDecision;
				if (d.class === 'rpc.decision') {
					out.push(d);
				}
			} catch { /* a truncated or capped line is not a decision */ }
		}
	}
	return out;
}

/**
 * Workspace vectors a filtered build stops before they run, each tied to the trusted-side
 * denial that stops it (docs/RPC-LOCKDOWN.md §7.1). Only the "ran" row can become expected, and
 * only with the denial in the decision log. Both the missing evidence and the denial are within
 * a tab's reach (a tab's own code can make the denied call), so neither excuses a host run: the
 * host facts (no host marker; on sbx, no evidence file in the host checkout) stay hard checks.
 * A tab reaches the host checkout on both drivers (OCI directly; sbx through the write-back
 * paths the gate doesn't hold, such as .seclab/targets), so they also need the arming files
 * unchanged, and a tab that tampers and restores before the check is not caught (review FXF-21).
 */
export const FILTERED_VECTOR_LOSSES: Record<string, { deniedRef: string; gap: string }> = {
	// The tab's extension host can't register a task system, so the folder-open task never runs.
	task: {
		deniedRef: 'rpc:MainThreadTask.$registerTaskSystem',
		gap: 'RPC core: tasks are denied in tabs (MainThreadTask.*), a recorded loss until the task-system follow-up, docs/RPC-LOCKDOWN.md §7.1',
	},
	// The git extension asks for resource trust before it opens any repository and skips the
	// repository when the answer isn't true, so it never runs `git status` there.
	fsmonitor: {
		deniedRef: 'rpc:MainThreadWorkspace.$requestResourceTrust',
		gap: 'RPC core: workspace trust requests are denied in tabs, so the git extension opens no repository and never runs git status, docs/RPC-LOCKDOWN.md §7.1; on sbx a host run still fails the host-marker and host-evidence checks',
	},
};

/** On a filtered build, mark each vector's "ran" failure as its recorded loss, only when the
 *  denial that causes it was observed on the trusted side. */
export function markFilteredLosses(checks: Check[], decisions: RpcDecision[]): void {
	for (const c of checks) {
		const loss = Object.hasOwn(FILTERED_VECTOR_LOSSES, c.vector) ? FILTERED_VECTOR_LOSSES[c.vector] : undefined;
		if (loss && !c.ok && c.name === 'ran (evidence written into the workspace)' && c.detail === 'no evidence file'
			&& decisions.some(d => d.detail?.ref === loss.deniedRef && d.detail?.verdict === 'deny')) {
			c.knownGap = loss.gap;
		}
	}
}

/** The probe vectors Level B arms. One list drives the per-vector checks, the host-run checks
 *  and the marker sweep's exemptions, so a vector without its own host-marker row falls
 *  through to the sweep (review FXF-6/8). fsmonitor is armed only on sbx. */
export function levelBVectors(driver: string): string[] {
	return driver === 'sbx' ? ['task', 'fsmonitor'] : ['task'];
}

/** Host OS artifacts (Finder, Spotlight) that say nothing about a tab (review FXF-18). */
/** Narrow, so a tab can't hide a file behind one of these names (review FXF-23): .DS_Store
 *  anywhere, AppleDouble ._X only beside a real X, the volume indexes only at the root. */
const OS_ARTIFACT = (rel: string, name: string, siblings: Set<string>) => name === '.DS_Store'
	|| (name.startsWith('._') && siblings.has(name.slice(2)))
	|| (!rel && (name === '.Spotlight-V100' || name === '.fseventsd'));

/** Every file under `ws`, relative, sorted (`.git` is checked on its own), and the directories
 *  that couldn't be listed: a subtree the check can't see is a failure, never "nothing there"
 *  (review FXF-17). */
export function listTree(ws: string): { files: string[]; unreadable: string[] } {
	const files: string[] = [];
	const unreadable: string[] = [];
	const walk = (rel: string): void => {
		let entries: fs.Dirent[];
		try {
			entries = fs.readdirSync(path.join(ws, rel), { withFileTypes: true });
		} catch {
			unreadable.push(rel || '.');
			return;
		}
		const names = new Set(entries.map(e => e.name));
		for (const e of entries) {
			const r = rel ? `${rel}/${e.name}` : e.name;
			if (r === '.git' || OS_ARTIFACT(rel, e.name, names)) {
				continue;
			}
			if (e.isDirectory()) {
				walk(r);
			} else {
				files.push(r);
			}
		}
	};
	walk('');
	return { files: files.sort(), unreadable };
}

/** What Level B's host-run vectors read or execute: the probe and everything beside it, and
 *  the task. (fsmonitor's .git/config is covered by the no-.git row.) Not .vscode/settings.json,
 *  which the rogue extension rewrites by design (review FXF-14). */
export function armingFiles(tree: string[]): string[] {
	return tree.filter(r => r.startsWith('.seclab/') || r === '.vscode/tasks.json');
}

/** The run's own output in the host checkout. Evidence reaches it on both drivers: on sbx the
 *  editor syncs write-back for paths the gate doesn't hold, and .seclab-evidence is one (review
 *  FXF-20). On OCI the tab writes the checkout directly, so the rogue extension's instruction
 *  files land there too; on sbx the gate holds .github, so there they would be a leak. */
const EXPECTED_ADDITION = (driver: string, r: string) => r.startsWith('.seclab-evidence/')
	|| (driver !== 'sbx' && (r === '.github/instructions/seclab-probe.instructions.md' || r === '.github/copilot-instructions.md'));

/** sha256 of each listed workspace file (null when absent). */
export function armingDigest(ws: string, rels: string[]): Record<string, string | null> {
	const out: Record<string, string | null> = {};
	for (const rel of [...rels].sort()) {
		try {
			out[rel] = createHash('sha256').update(fs.readFileSync(path.join(ws, rel))).digest('hex');
		} catch {
			out[rel] = null;
		}
	}
	return out;
}

/** The record prepare writes in the run directory (no tab can reach it) once the workspace is
 *  final: the arming files' digests and the whole tree. */
export interface ArmingRecord { digest: Record<string, string | null>; tree: string[] }
export function armingRecord(ws: string): ArmingRecord {
	const { files, unreadable } = listTree(ws);
	if (unreadable.length > 0) {
		throw new Error(`arming record: can't list ${unreadable.join(', ')} in ${ws}`);
	}
	return { digest: armingDigest(ws, armingFiles(files)), tree: files };
}
const safeRel = (r: unknown): r is string => typeof r === 'string' && r !== '' && !path.isAbsolute(r) && !r.split('/').includes('..');
/** A parsed record, or undefined when it isn't one (a failing check, never a pass). */
export function parseArmingRecord(v: unknown): ArmingRecord | undefined {
	if (!v || typeof v !== 'object' || Array.isArray(v)) {
		return undefined;
	}
	const { digest, tree } = v as { digest?: unknown; tree?: unknown };
	if (!digest || typeof digest !== 'object' || Array.isArray(digest) || !Array.isArray(tree) || !tree.every(safeRel)) {
		return undefined;
	}
	const ok = Object.entries(digest).every(([k, h]) => safeRel(k) && (h === null || (typeof h === 'string' && /^[0-9a-f]{64}$/.test(h))));
	return ok && Object.keys(digest).length > 0 ? { digest: digest as Record<string, string | null>, tree: tree as string[] } : undefined;
}

/** Host facts about a Level B run that no tab-written evidence can excuse. `record` is what
 *  prepare wrote; undefined (unreadable or malformed) fails. */
export function hostRunChecks(driver: string, ws: string, record: ArmingRecord | undefined): Check[] {
	const out: Check[] = [];
	// Evidence in the host checkout proves nothing about where a vector ran: on sbx the editor
	// syncs it out of the tab (review FXF-20). A host run is shown by its marker in the run dir,
	// which a tab can neither write nor withhold (probe.sh's trusted route).
	// A tab that rewrote what a host-side run reads (the probe, its targets, the task) could make
	// that run silent, and one that added a file (a launch config, a hook) could arm another. A
	// tab reaches the checkout on both drivers: OCI writes it directly, and sbx syncs every path
	// the write-back gate doesn't hold, .seclab/targets and probe.parts.json among them (reviews
	// FXF-7, 10-12, 15, 21). So the arming files must be exactly as prepared, nothing may be added
	// beyond the run's own output, and the checkout must hold no .git (the fsmonitor repo is armed
	// only inside an sbx tab, and the gate holds .git). A tab that tampers and restores before the
	// check is not caught (ADR write-back-gate §7). A host run descended from the editor is still
	// marked: probe.sh's trusted route reads neither file.
	const now = record ? armingDigest(ws, Object.keys(record.digest)) : undefined;
	const changed = record && now ? Object.keys(record.digest).filter(k => record.digest[k] !== now[k]) : undefined;
	out.push({ vector: 'host', name: 'the arming files in the host checkout are exactly as prepared', ok: changed !== undefined && changed.length === 0,
		detail: changed === undefined ? 'no arming record' : changed.join(', ') || 'unchanged' });
	const before = new Set(record?.tree ?? []);
	const tree = listTree(ws);
	const added = record ? tree.files.filter(r => !before.has(r) && !EXPECTED_ADDITION(driver, r)) : undefined;
	out.push({ vector: 'host', name: 'nothing added to the host checkout beyond the run\'s own output', ok: added !== undefined && added.length === 0 && tree.unreadable.length === 0,
		detail: added === undefined ? 'no arming record' : tree.unreadable.length ? `can't list: ${tree.unreadable.join(', ')}` : added.slice(0, 10).join(', ') || 'none' });
	out.push({ vector: 'host', name: 'no .git in the host checkout', ok: !fs.existsSync(path.join(ws, '.git')), detail: path.join(ws, '.git') });
	return out;
}

/** Marker-shaped files in the run directory that neither a vector's host-marker row nor an
 *  RPC probe's expected host effect accounts for. */
export function unattributedMarkers(runDir: string, marker: string, vectors: string[], attributed: Set<string>): Check[] {
	const own = new Set(vectors.map(v => `${marker}.${v}`));
	return fs.readdirSync(runDir).filter(n => /^(?:PWNED|probe-marker)/.test(n)).map(n => path.join(runDir, n))
		.filter(p => !attributed.has(p) && !own.has(p))
		.map(p => ({ vector: 'rpc', name: 'no unattributed host marker', ok: false, detail: p }));
}

/** A vector whose evidence the tab doesn't show while the host checkout has a copy (synced out
 *  of an sbx tab, or written straight by an OCI one): the tab is hiding its own output. A plain
 *  failure, never a known gap (review FXF-22). */
export function withheldEvidence(ws: string, vector: string, inTab: Evidence | undefined): Check | undefined {
	const f = path.join(ws, '.seclab-evidence', `${vector}.json`);
	return !inTab && fs.existsSync(f) ? { vector, name: 'evidence the host checkout holds is also in the tab (not withheld)', ok: false, detail: f } : undefined;
}
