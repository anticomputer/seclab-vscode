// Containment suite, level B: the real editor triggers the vectors.
//   prepare <user-data-dir> [sbx|oci]  create the fixture workspace, claim its tab in the
//                                      editor's tabd state, preinstall the rogue extension
//                                      into the tab, write test user settings
//   check   <user-data-dir>            assert the evidence the editor-run vectors left behind,
//                                      then tear the run down (teardown.ts): stops the editor,
//                                      removes the tab and the profile; fails on leftovers
// In between, open the tab with the fork in the background (never activated; AGENTS.md):
//   node test/window.ts launch --env ... <dir> <printed folder uri>   (prepare prints the exact line)

import { execFileSync, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import { deserialize, mintCanary, scan, serialize } from '../canary/canary.ts';
import { beaconPort, checkUserDataDir, editorLaunchCommand, lockRun } from '../harness.ts';
import { brokerProxy, checkEvidence, readEvidence, report, rpcDecisions, type Check } from './assert.ts';
import { materialiseFixture, readManifest, runTabs, teardownGate, writeManifest, writeSnapshot } from './teardown.ts';

const [mode, userDataArg, driverArg] = process.argv.slice(2);
if ((mode !== 'prepare' && mode !== 'check') || !userDataArg) {
	console.error('usage: check-evidence.ts prepare|check <user-data-dir> [sbx|oci]');
	process.exit(2);
}
const driver = driverArg ?? 'sbx';
const repo = path.resolve(import.meta.dirname, '../..');
const userData = path.resolve(userDataArg);
checkUserDataDir(userData);
const base = path.resolve(process.env.SECLAB_EVIDENCE_DIR ?? path.join(repo, '.work', 'containment-editor'));
lockRun(path.join(base, '..', `${path.basename(base)}.lock.d`));
const ws = path.join(base, 'ws-editor');
const canary = path.join(base, 'canary', 'secret.txt');
const marker = path.join(base, 'PWNED');
// The newLocal + sendSequence chain writes its own marker, so the proof that
// patches 0007/0008 closed it does not rest on the shared one. The shared
// marker is written by several vectors, so its absence after a patch cannot
// distinguish "this chain was denied" from "some other vector did not run".
const newLocalMarker = path.join(base, 'PWNED-newlocal');
// One marker per server-initiated _remoteCLI vector. They shared the generic
// PWNED marker before, and the shared check fails for every vector at once:
// any one escape masked the state of the others, and fixing one read as fixing
// all three.
const execCommandMarkers: ReadonlyArray<readonly [string, string]> = [
	['windowOpen', path.join(base, 'PWNED-windowopen')],
	['manageExtensions', path.join(base, 'PWNED-manageextensions')],
	['openExternal', path.join(base, 'PWNED-openexternal')],
];
const stateDir = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');
// Evidence is written by a hostile fixture, so its size is attacker-chosen. Reads are
// bounded: a 2 GiB "evidence" file must fail this check, not the harness (review round 9
// alert 2). Real evidence files are a few KiB.
const EVIDENCE_MAX_BYTES = 4 << 20;

if (mode === 'prepare') {
	// A previous run's claim points at the old fixture (a new folder has a new inode, which
	// tabd rightly refuses): remove its tabs and sandboxes, then start from clean state.
	if (fs.existsSync(stateDir)) {
		const old = new TabdClient({
			command: process.execPath,
			args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', driver, '--allowed-root', base],
			env: { HOME: process.env.HOME, USER: process.env.USER },
		});
		await old.initialize('containment-editor-cleanup', '0');
		for (const t of (await old.request<{ tabs: Array<{ metadata: { name: string } }> }>('tab.list')).tabs) {
			await old.request('tab.remove', { tabId: t.metadata.name }).catch(() => undefined);
		}
		old.dispose();
		fs.rmSync(stateDir, { recursive: true, force: true });
	}
	fs.rmSync(base, { recursive: true, force: true });
	fs.mkdirSync(path.dirname(canary), { recursive: true });
	fs.writeFileSync(canary, 'HOST-SECRET-CANARY\n');
	materialiseFixture(base, path.join(import.meta.dirname, 'fixtures', 'malicious-workspace'), ws);
	const port = await beaconPort();
	// Per-run arming nonce: the fixture is inert anywhere but inside this run dir.
	const arm = randomBytes(16).toString('hex');
	// Armed for a bounded window only (FS-3): a prepared hostile repo shouldn't stay live.
	const until = Math.floor(Date.now() / 1000) + Number(process.env.SECLAB_ARM_SECONDS ?? 4 * 3600);
	// Anchor the arming nonce on the host side too: probe-safety's env route and
	// teardown's keychain check both read it, and a missing anchor must fail
	// loudly rather than silently skip those checks.
	fs.mkdirSync(base, { recursive: true });
	fs.writeFileSync(path.join(base, '.seclab-probe-nonce'), arm);
	fs.writeFileSync(path.join(ws, '.seclab', 'targets'), `canary=${canary}\nmarker=${marker}\nloopback=${port}\narm=${arm}\nrun=${base}\nuntil=${until}\n`
		+ (process.env.SECLAB_CANARY_CLIPBOARD === '1' ? 'clipboard=1\n' : ''));
	writeSnapshot(base);
	// What this run owns, for teardown.ts: the editor and its tabd are found by the unique
	// user-data-dir (never by program name), the tab by id.
	writeManifest(base, {
		driver: driver as 'sbx' | 'oci', userDataDir: userData, stateDirs: [stateDir],
		// The RPC-lockdown probe runs start an egress beacon at this path. It is
		// not a tab, so teardown only reaps it if the run claims it: a mark must
		// name a program plus arguments containing the run dir.
		commandMarks: [`beacon.ts start ${path.join(base, 'beacon.log')}`],
	});
	// Git repo with a hostile core.fsmonitor. Only `init` and `config` run on the host;
	// neither reads core.fsmonitor. Nothing here may run `git status` on the host.
	execFileSync('git', ['-C', ws, 'init', '-q']);
	execFileSync('git', ['-C', ws, 'config', 'core.fsmonitor', 'sh .seclab/probe.sh fsmonitor']);
	// Disarm on EVERY exit, not just a clean `check`. An aborted or crashed
	// prepare used to leave a host git repo whose core.fsmonitor runs probe.sh
	// on the next `git status` -- from the user's own editor, a watcher or a
	// grep. Probe safety review 2026-11-04, finding 5.
	const disarm = (): void => {
		try { fs.rmSync(path.join(ws, '.git'), { recursive: true, force: true }); } catch { /* best effort */ }
	};
	process.on('exit', disarm);
	process.on('SIGINT', () => { disarm(); process.exit(130); });
	process.on('SIGTERM', () => { disarm(); process.exit(143); });
	process.on('uncaughtException', err => { disarm(); console.error(err); process.exit(2); });
	// Test profile: Workspace Trust off and automatic tasks on, i.e. the worst case for us
	// (trust is UX, not a boundary). Plus editor-side canaries (shared canary harness):
	// user settings (incl. a secret-bearing setting) and, only if opted in, the clipboard
	// (seeding it overwrites the user's real clipboard: SECLAB_CANARY_CLIPBOARD=1).
	// The RPC escape probes are armed by the same arm=/run=/until= fields this
	// harness already writes into .seclab/targets. One arming mechanism, not two.
	const canaries = [mintCanary('user-settings'), mintCanary('user-settings-proxy-auth'), mintCanary('clipboard'), mintCanary('editor-env')];
	fs.writeFileSync(path.join(base, 'canaries.json'), serialize(canaries));
	fs.mkdirSync(path.join(userData, 'User'), { recursive: true });
	fs.writeFileSync(path.join(userData, 'User', 'settings.json'), JSON.stringify({
		'security.workspace.trust.enabled': false,
		'task.allowAutomaticTasks': 'on',
		'seclab.tabs.driver': driver,
		'seclab.tabs.allowedRoots': [base],
		'seclab.test.canary': canaries[0].value,
		'http.proxyAuthorization': `Basic ${canaries[1].value}`,
	}, null, '\t'));
	if (process.env.SECLAB_CANARY_CLIPBOARD === '1') {
		// Opt-in only, and put the user's clipboard back afterwards: it is
		// commonly a password or token, which is exactly why clipboard-read is
		// a probe at all (probe safety review, finding 7).
		const savedClipboard = spawnSync('pbpaste', [], { encoding: 'utf8' }).stdout ?? '';
		process.on('exit', () => {
			try { spawnSync('pbcopy', [], { input: savedClipboard }); } catch { /* best effort */ }
		});
		spawnSync('pbcopy', [], { input: canaries[2].value });
	}
	// Package the rogue extension (vsce in a container) and preinstall it into the tab.
	// The guards live in one place (test/containment/probe-safety.js) but must
	// ship inside the .vsix: a require() reaching outside the extension root
	// throws at activation, which silently produced no probe evidence at all.
	// Copied at package time so there is still a single source of truth; the
	// lint asserts the copies match.
	for (const dir of ['rogue-extension', 'rogue-reh']) {
		fs.copyFileSync(path.join(import.meta.dirname, 'probe-safety.js'),
			path.join(import.meta.dirname, dir, 'probe-safety.js'));
	}
	const vsixDir = path.join(ws, '.seclab');
	// vsce comes from a local image whose npm fetch went through GitHub CFS (EDR cfs-local-builds);
	// it packages with no token and no network.
	const VSCE_IMAGE = 'seclab-vsce:3.9.2';
	if (spawnSync('docker', ['image', 'inspect', VSCE_IMAGE], { stdio: 'ignore' }).status !== 0) {
		execFileSync('gh', ['cfs', '--', 'docker', 'build', '-q', '-t', VSCE_IMAGE, path.join(repo, 'build', 'vsce')], { stdio: 'inherit' });
	}
	// The rogue extension, and the POSITIVE CONTROL beside it. A suite made only of
	// "the bad thing did not happen" cannot tell containment from a broken editor: the
	// first patched build denied the extension host's own error and activation plumbing,
	// so nothing activated, no marker was written, and it read as success
	// (docs/edr/20261106-rpc-core-proof-run.md). The benign extension must ACTIVATE AND
	// WORK in the same window the rogue one is contained in.
	// SECLAB_BENIGN_ONLY=1 leaves the rogue extension out, so a boot can be measured
	// with nothing hostile in it. That is how the extension-host plumbing entries are
	// derived: the denial set of a clean boot, read from a log that has not capped.
	// Never set for a proof run -- check asserts the rogue evidence.
	const benignOnly = process.env.SECLAB_BENIGN_ONLY === '1';
	const bundles = (benignOnly ? [] : [['rogue-extension', 'rogue.vsix']]).concat([['benign-extension', 'benign.vsix']]);
	for (const [dir, vsix] of bundles as ReadonlyArray<readonly [string, string]>) {
		execFileSync('docker', ['run', '--rm', '--network', 'none', '--user', `${process.getuid!()}:${process.getgid!()}`, '-v', `${path.join(import.meta.dirname, dir)}:/ext:ro`, '-v', `${vsixDir}:/out`,
			VSCE_IMAGE, 'sh', '-c', `cp -r /ext /tmp/e && cd /tmp/e && vsce package --allow-missing-repository --skip-license -o /out/${vsix}`], { stdio: 'inherit' });
	}
	const client = new TabdClient({
		command: process.execPath,
		args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', driver, '--allowed-root', base],
		env: { HOME: process.env.HOME, USER: process.env.USER },
	});
	await client.initialize('containment-editor', '0');
	const { tab } = await client.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
	writeManifest(base, { tabs: [tab.metadata.name], driver });
	await client.request('tab.ensureRunning', { tabId: tab.metadata.name });
	const name = `seclab-${tab.metadata.name}`;
	const runtime = driver === 'sbx' ? '/opt/homebrew/bin/sbx' : 'docker';
	const user = driver === 'sbx' ? ['-u', 'agent'] : [];
	for (const vsix of benignOnly ? ['benign.vsix'] : ['rogue.vsix', 'benign.vsix']) {
		const r = spawnSync(runtime, ['exec', ...user, name, '/opt/seclab/bin/seclab-tab-env',
			'/opt/seclab-reh/bin/seclab-code-server', '--install-extension', path.join(vsixDir, vsix)], { encoding: 'utf8' });
		console.log(r.stdout.trim(), r.stderr.trim());
	}
	client.dispose(); // stops the tab; the editor restarts it (extensions persist in the tab)
	await new Promise(res => client.once('exit', res));
	console.log(`\nprepared tab ${tab.metadata.name} for ${ws}`);
	console.log(`\nnow open the TAB directly (never the local path: a local window must not open this hostile workspace).`);
	console.log(`Keep --user-data-dir SHORT: macOS caps unix socket paths at 104 bytes and a deep path silently fails to open a window.\n`);
	console.log(`  ${editorLaunchCommand(userData, `vscode-remote://seclab+${tab.metadata.name}${ws}`, {
		SECLAB_EDITOR_CANARY: canaries[3].value, SECLAB_PROBE_NONCE: arm, SECLAB_PROBE_RUNDIR: base, SECLAB_PROBE_BEACON_PORT: String(port),
	})}`);
} else {
	const checks: Check[] = [];
	// The run is torn down even if this branch throws. Every byte read below is
	// tab-authored, and `prepare` is the only branch that registered handlers, so an
	// exception here used to skip report(), the .git disarm and teardownGate() --
	// leaving the editor running, the tab up and the profile holding the armed rogue
	// .vsix on the host. A hostile fixture must not be able to veto its own teardown
	// (review round 9 alert 2; AGENTS.md "a run leaves nothing behind").
	let tornDown = false;
	const disarmAndTeardown = (): boolean => {
		if (tornDown) {
			return true;
		}
		tornDown = true;
		try { fs.rmSync(path.join(ws, '.git'), { recursive: true, force: true }); } catch { /* best effort */ }
		return teardownGate(base);
	};
	process.on('uncaughtException', err => {
		console.error('check failed before its own teardown; tearing down anyway');
		console.error(err);
		disarmAndTeardown();
		process.exit(2);
	});
	process.on('unhandledRejection', err => {
		console.error('check failed before its own teardown; tearing down anyway');
		console.error(err);
		disarmAndTeardown();
		process.exit(2);
	});
	// Evidence is written by the fixture INSIDE the tab's workspace. It reaches the host
	// checkout only when tabd's write-back gate syncs it, and the gate may hold, defer or
	// (for anything the host's git ignores) permanently refuse a path. So "the fixture ran"
	// must never be read from the host copy: an absent file would be indistinguishable from
	// a fixture that never started, which is exactly how the first patched run produced a
	// clean-looking result with 13 of 32 checks. Read the tab's own view instead, the way
	// the automated runner (run.ts) already does. The write-back gate is not weakened and
	// is not under test here; the trusted-side denial log is host-side regardless.
	const manifest = readManifest(base);
	const runDriver = manifest.driver ?? driver;
	const tabId = runTabs(manifest)[0];
	const runtime = runDriver === 'sbx' ? '/opt/homebrew/bin/sbx' : 'docker';
	const tabUser = runDriver === 'sbx' ? ['-u', 'agent'] : [];
	const container = tabId ? `seclab-${tabId}` : undefined;
	const inTab = (argv: string[]): string | undefined => {
		if (!container) {
			return undefined;
		}
		const r = spawnSync(runtime, ['exec', ...tabUser, container, ...argv],
			{ encoding: 'utf8', timeout: 30_000, maxBuffer: EVIDENCE_MAX_BYTES });
		return r.status === 0 ? r.stdout : undefined;
	};
	/** A workspace file as the TAB sees it, falling back to the host copy if the tab is gone. */
	const readInTab = (p: string): string | undefined => {
		try {
			const text = inTab(['cat', p])
				?? (fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : undefined);
			return text !== undefined && text.length <= EVIDENCE_MAX_BYTES ? text : undefined;
		} catch {
			// Every byte here is tab-authored. A read that throws (oversize,
			// vanished mid-run, unreadable) is "no evidence", never a crash:
			// see readJsonInTab for why that distinction matters.
			return undefined;
		}
	};
	/**
	 * Tab-authored JSON, or `undefined`. Review round 9 alert 2: these reads were
	 * `JSON.parse(...)` with no `try`, and the `check` branch registers none of the
	 * `uncaughtException`/`exit` handlers `prepare` has. One malformed byte written by
	 * the rogue extension therefore skipped `report()`, the `.git` disarm and
	 * `teardownGate()` -- so the hostile fixture could veto its own teardown and stay
	 * live on the host, armed.
	 */
	const readJsonInTab = (p: string): Record<string, unknown> | undefined => {
		const text = readInTab(p);
		if (text === undefined) {
			return undefined;
		}
		try {
			const v: unknown = JSON.parse(text);
			return v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : undefined;
		} catch {
			return undefined;
		}
	};
	const evDir = path.join(ws, '.seclab-evidence');
	/** Evidence file names as the tab sees them, union the host's (neither alone is complete). */
	const listEvidence = (): string[] => {
		const inner = (inTab(['sh', '-c', `ls -1 ${evDir} 2>/dev/null`]) ?? '').split('\n').filter(Boolean);
		const outer = (() => { try { return fs.existsSync(evDir) ? fs.readdirSync(evDir) : []; } catch { return []; } })();
		// A name is tab-chosen: anything with a separator is not a file in this
		// directory and must never be joined onto it.
		return [...new Set([...inner, ...outer])].filter(f => f !== '' && !f.includes('/') && f !== '.' && f !== '..');
	};
	checks.push({ vector: 'rogue-extension', name: 'the run recorded a tab to read evidence from', ok: Boolean(container), detail: container ?? 'no tab in run.json' });
	// Only `task` is a level-B vector. The editor's auto-task runs probe.sh on folder open,
	// so `.seclab-evidence/task.json` is produced by the run under test.
	//
	// `fsmonitor` and `rogue-extension` were asserted here too, and could never pass:
	// - nothing in the editor-driven run executes `git status` inside the tab, which is what
	//   makes the hostile `core.fsmonitor` fire;
	// - the rogue extension deliberately does NOT spawn probe.sh (see
	//   test/containment/rogue-extension/extension.js: on an unpatched build it can land
	//   host-side, and probe.sh makes external calls and writes an unconstrained marker).
	// Both are triggered, in the tab, by level A (`./seclab test containment`), which is where
	// they belong. Asserting them here produced two permanent FAILs that said nothing about
	// the build under test, and made a real regression one line harder to see.
	// The rogue extension's own evidence is asserted below, from the files it does write.
	for (const vector of ['task']) {
		checks.push(...checkEvidence(readEvidence(ws, vector, readInTab), vector, { marker, proxy: brokerProxy(runDriver) }));
	}
	const host = readJsonInTab(path.join(evDir, 'rogue-extension-host.json'));
	checks.push({ vector: 'rogue-extension', name: 'ui-kind rogue extension was forced into the tab (remoteName=seclab)', ok: host?.remoteName === 'seclab' && host?.seclabTab === '1', detail: JSON.stringify(host) });
	// No trusted-side extension agents in tab windows: the same ui-declared extension
	// registered a chat participant and called vscode.lm, and that code ran in the tab.
	const agent = readJsonInTab(path.join(evDir, 'rogue-agent.json'));
	checks.push({ vector: 'rogue-extension', name: 'ui-declared chat participant / vscode.lm caller ran in the tab, not trusted-side', ok: agent?.ranIn === 'tab' && agent?.remoteName === 'seclab',
		detail: JSON.stringify(agent ?? 'no rogue-agent.json') });
	checks.push({ vector: 'host', name: 'canary intact', ok: fs.readFileSync(canary, 'utf8') === 'HOST-SECRET-CANARY\n', detail: '' });
	// POSITIVE CONTROL. Everything else in this file asserts that something did NOT
	// happen, and a build whose extension host cannot start satisfies all of it. The
	// benign extension must have activated in the tab and completed every ordinary
	// operation a workspace extension performs. If this fails while the rogue checks
	// pass, the filter has broken the editor, not contained it -- which is exactly the
	// state the first patched build was in, and read as success.
	const benign = readJsonInTab(path.join(evDir, 'benign.json'));
	const benignWhere = benign?.where as { remoteName?: unknown; seclabTab?: unknown } | undefined;
	checks.push({
		vector: 'positive-control',
		name: 'an ordinary workspace extension activated in the tab',
		ok: benign?.activated === true && benignWhere?.remoteName === 'seclab' && benignWhere?.seclabTab === '1',
		detail: benign === undefined ? 'no benign.json: the extension host could not run it' : JSON.stringify(benignWhere),
	});
	const benignFailed = Array.isArray(benign?.failed) ? benign.failed as unknown[] : undefined;
	checks.push({
		vector: 'positive-control',
		name: 'every ordinary extension operation succeeded in the tab',
		ok: benignFailed !== undefined && benignFailed.length === 0,
		detail: benignFailed === undefined ? 'no step results'
			: `${benignFailed.length} failed: ${benignFailed.join(', ')} | ${JSON.stringify(benign?.results).slice(0, 600)}`,
	});
	checks.push({
		vector: 'rpc-probes',
		name: 'workbench.action.terminal.newLocal + sendSequence did not reach the host',
		ok: !fs.existsSync(newLocalMarker),
		detail: fs.existsSync(newLocalMarker) ? `host marker written: ${newLocalMarker}` : '',
	});
	// Proof condition 2: the denial is OBSERVED on the trusted side, not inferred from an
	// absent marker. An absent marker alone is equally consistent with a probe that never
	// ran. `seclabInstallDecisionLog` (patch 0005) writes every verdict to the window's own
	// log through ILoggerService, host-side, where a tab cannot reach it. Until this check
	// existed the log had a producer and no consumer, which is the pattern that made four
	// other artefacts in this increment look complete while never running.
	const decisions = rpcDecisions(userData);
	const denied = decisions.filter(d => d.detail?.ref === 'cmd:workbench.action.terminal.newLocal' && d.detail?.verdict === 'deny');
	checks.push({
		vector: 'rpc-probes',
		name: 'the trusted side recorded the newLocal denial (seclabRpcFilter.log)',
		ok: denied.length > 0,
		detail: denied.length > 0 ? JSON.stringify(denied[0])
			: `${decisions.length} decision line(s) in ${userData}/logs/**/seclabRpcFilter.log`,
	});
	// The host shell environment must not be readable through the pty host's
	// variable-resolution reverse request. The marker holds the editor-env
	// canary, which the REH can only have obtained from the trusted side.
	const resolveVarsMarker = path.join(base, 'PWNED-resolvevars');
	checks.push({
		vector: 'reh-probes',
		name: 'pty host variable resolution did not return the host environment',
		ok: !fs.existsSync(resolveVarsMarker),
		detail: fs.existsSync(resolveVarsMarker)
			? `host env canary returned to the tab: ${resolveVarsMarker}` : '',
	});
	for (const [command, m] of execCommandMarkers) {
		checks.push({
			vector: 'reh-probes',
			name: `server-initiated onExecuteCommand did not run _remoteCLI.${command} on the host`,
			ok: !fs.existsSync(m),
			detail: fs.existsSync(m) ? `host marker written: ${m}` : '',
		});
	}
	// Shared canary harness, editor side: nothing the rogue extension observed through the
	// API (env, configuration, clipboard, auth sessions, secrets) nor any evidence may
	// contain an editor-side canary in any encoding.
	const canaries = deserialize(fs.readFileSync(path.join(base, 'canaries.json'), 'utf8'));
	const observedOk = readInTab(path.join(evDir, 'rogue-observed.json')) !== undefined;
	checks.push({ vector: 'canary', name: 'rogue extension recorded its API observations', ok: observedOk, detail: '' });
	// Stores the rogue extension can still read through the extension API until the RPC
	// capability filter (M4) lands: configuration (user settings) and the clipboard.
	const M4 = 'M4 RPC capability filter (docs/adr/20261104-rpc-capability-filter.md)';
	const knownUntilM4 = new Set(['user-settings', 'clipboard']);
	for (const f of listEvidence()) {
		const body = readInTab(path.join(evDir, f));
		for (const h of scan(canaries, f, Buffer.from(body ?? '', 'utf8'))) {
			checks.push({ vector: 'canary', name: `no ${h.store} canary in tab-observable data`, ok: false, detail: `${h.encoding} in ${h.source}`,
				knownGap: knownUntilM4.has(h.store) ? M4 : undefined });
		}
	}
	checks.push({ vector: 'canary', name: 'no editor-side canary observed by the tab (outside known gaps)', ok: !checks.some(c => c.vector === 'canary' && !c.ok && !c.knownGap), detail: '' });
	const ok = report(checks);
	// Disarm the hostile git config, then end the run: stop the editor (by its
	// user-data-dir) and everything it started, remove the tab, delete the profile
	// holding the armed rogue extension, diff the host. Same path the exception
	// handlers above take, so there is one teardown, not two.
	const clean = disarmAndTeardown();
	process.exit(ok && clean ? 0 : 1);
}
