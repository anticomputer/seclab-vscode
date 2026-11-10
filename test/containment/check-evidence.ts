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
import { createHash, randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import { deserialize, mintCanary, scan, serialize } from '../canary/canary.ts';
import { beaconPort, checkUserDataDir, editorLaunchCommand, editorLaunchRecord, editorPid, lockRun } from '../harness.ts';
import { brokerProxy, checkEvidence, readEvidence, report, rpcDecisions, type Check } from './assert.ts';
import { materialiseFixture, readManifest, teardownGate, writeManifest, writeSnapshot } from './teardown.ts';
import { partitionFindings, seedTabManagerState, stateItems } from './state-db.ts';

const [mode, userDataArg, driverArg] = process.argv.slice(2);
if ((mode !== 'prepare' && mode !== 'check') || !userDataArg) {
	console.error('usage: check-evidence.ts prepare|check <user-data-dir> [sbx|oci]');
	process.exit(2);
}
const driver = driverArg ?? 'sbx';
// A test-variant build pairs with its own REH, which only ships as an OCI image
// (docs/edr/20261106-test-build-variants.md): SECLAB_TAB_IMAGE=seclab-tab-oci:test-containment.
// Only our own tab images are accepted; the editor's Tab Manager gets the same image.
const tabImage = process.env.SECLAB_TAB_IMAGE || undefined;
if (tabImage !== undefined && !/^seclab-tab(-oci)?:[a-z0-9][a-z0-9._-]{0,63}$/.test(tabImage)) {
	console.error(`SECLAB_TAB_IMAGE must name a seclab-tab image, got ${JSON.stringify(tabImage)}`);
	process.exit(2);
}
const imageArgs = tabImage ? ['--image', tabImage] : [];
const repo = path.resolve(import.meta.dirname, '../..');
const userData = path.resolve(userDataArg);
checkUserDataDir(userData);
const base = path.resolve(process.env.SECLAB_EVIDENCE_DIR ?? path.join(repo, '.work', 'containment-editor'));
lockRun(path.join(base, '..', `${path.basename(base)}.lock.d`));
const ws = path.join(base, 'ws-editor');
const canary = path.join(base, 'canary', 'secret.txt');
// probe.sh appends the vector (<marker>.task); the rogue extension's RPC probes write their own
// markers under PWNED (probe-safety.js), so no marker can be credited to the wrong probe.
const marker = path.join(base, 'probe-marker');
const stateDir = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');

if (mode === 'prepare') {
	// A previous run's claim points at the old fixture (a new folder has a new inode, which
	// tabd rightly refuses): remove its tabs and sandboxes, then start from clean state.
	if (fs.existsSync(stateDir)) {
		const old = new TabdClient({
			command: process.execPath,
			args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', driver, ...imageArgs, '--allowed-root', base],
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
	fs.writeFileSync(path.join(ws, '.seclab', 'targets'), `canary=${canary}\nmarker=${marker}\nloopback=${port}\narm=${arm}\nrun=${base}\nuntil=${until}\nuserdata=${userData}\n`
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
	// The hostile git repo (core.fsmonitor) is armed inside the tab, after it starts: the
	// editor's git extension polls `git status` there. Never on the host, where any tool's
	// `git status` would run probe.sh (probe safety review 2026-11-04, finding 5). Only on sbx,
	// whose write-back gate keeps .git/config in the tab; an OCI tab writes straight through.
	// Defense in depth: remove any host .git on exit.
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
	const canaries = [mintCanary('user-settings'), mintCanary('user-settings-proxy-auth'), mintCanary('clipboard'), mintCanary('editor-env'), mintCanary('tab-manager-state')];
	fs.writeFileSync(path.join(base, 'canaries.json'), serialize(canaries));
	fs.mkdirSync(path.join(userData, 'User'), { recursive: true });
	// The Tab Manager's real globalState holds a canary, so a tab that can name its id
	// (probe state-claim-tab-manager-read) shows up in the canary scan of its evidence.
	seedTabManagerState(userData, { seclabProbeCanary: canaries[4].value });
	fs.writeFileSync(path.join(userData, 'User', 'settings.json'), JSON.stringify({
		'security.workspace.trust.enabled': false,
		'task.allowAutomaticTasks': 'on',
		'seclab.tabs.driver': driver,
		...(tabImage ? { 'seclab.tabs.image': tabImage } : {}),
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
	// with nothing hostile in it. Never set for a proof run.
	const benignOnly = process.env.SECLAB_BENIGN_ONLY === '1';
	const bundles = (benignOnly ? [] : [['rogue-extension', 'rogue.vsix']]).concat([['benign-extension', 'benign.vsix']]);
	for (const [dir, vsix] of bundles as ReadonlyArray<readonly [string, string]>) {
		execFileSync('docker', ['run', '--rm', '--network', 'none', '--user', `${process.getuid!()}:${process.getgid!()}`, '-v', `${path.join(import.meta.dirname, dir)}:/ext:ro`, '-v', `${vsixDir}:/out`,
			VSCE_IMAGE, 'sh', '-c', `cp -r /ext /tmp/e && cd /tmp/e && vsce package --allow-missing-repository --skip-license -o /out/${vsix}`], { stdio: 'inherit' });
	}
	const client = new TabdClient({
		command: process.execPath,
		args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', driver, ...imageArgs, '--allowed-root', base],
		env: { HOME: process.env.HOME, USER: process.env.USER },
	});
	await client.initialize('containment-editor', '0');
	const { tab } = await client.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
	writeManifest(base, { tabs: [tab.metadata.name] });
	await client.request('tab.ensureRunning', { tabId: tab.metadata.name });
	const name = `seclab-${tab.metadata.name}`;
	const runtime = driver === 'sbx' ? '/opt/homebrew/bin/sbx' : 'docker';
	const user = driver === 'sbx' ? ['-u', 'agent'] : [];
	for (const vsix of bundles.map(([, v]) => v)) {
		const r = spawnSync(runtime, ['exec', ...user, name, '/opt/seclab/bin/seclab-tab-env',
			'/opt/seclab-reh/bin/seclab-code-server', '--install-extension', path.join(vsixDir, vsix)], { encoding: 'utf8' });
		console.log(r.stdout.trim(), r.stderr.trim());
	}
	if (driver === 'sbx') {
		const g = spawnSync(runtime, ['exec', ...user, '-w', ws, name, 'sh', '-c', 'git init -q . && git config core.fsmonitor "sh .seclab/probe.sh fsmonitor"'], { encoding: 'utf8' });
		if (g.status !== 0) {
			console.error(`could not arm the fsmonitor repo in the tab: ${g.stderr.trim()}`);
			process.exit(1);
		}
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
	// Any host .git (an OCI tab writes straight through) is removed on every exit (NNN-3).
	const disarm = (): void => {
		try { fs.rmSync(path.join(ws, '.git'), { recursive: true, force: true }); } catch { /* best effort */ }
	};
	process.on('exit', disarm);
	process.on('SIGINT', () => { disarm(); process.exit(130); });
	process.on('SIGTERM', () => { disarm(); process.exit(143); });
	// Evidence is read through the tab: on sbx the tab's writes stay in its write-back overlay and
	// never reach the host checkout (the RPC proof reads the same way).
	const tabId = (readManifest(base).tabs ?? [])[0];
	const runtime = driver === 'sbx' ? '/opt/homebrew/bin/sbx' : 'docker';
	const inTabUser = driver === 'sbx' ? ['-u', 'agent'] : [];
	const readInTab = (p: string): string | undefined => {
		if (!tabId) {
			return undefined;
		}
		const r = spawnSync(runtime, ['exec', ...inTabUser, `seclab-${tabId}`, 'cat', p], { encoding: 'utf8', timeout: 30_000, maxBuffer: 64 << 20 });
		return r.status === 0 ? r.stdout : undefined;
	};
	const listInTab = (dir: string): string[] => {
		const r = tabId ? spawnSync(runtime, ['exec', ...inTabUser, `seclab-${tabId}`, 'ls', '-1A', dir], { encoding: 'utf8', timeout: 30_000 }) : undefined;
		return r?.status === 0 ? r.stdout.split('\n').filter(Boolean) : [];
	};
	const json = (p: string): Record<string, unknown> | undefined => {
		try {
			const t = readInTab(p);
			return t ? JSON.parse(t) as Record<string, unknown> : undefined;
		} catch {
			return undefined;
		}
	};
	// The rogue extension deliberately never runs probe.sh (it can land host-side on an
	// unpatched build): its own evidence is checked below, not a probe vector.
	const expectHostname = driver === 'sbx' ? `seclab-${tabId}` : 'tab';
	for (const vector of driver === 'sbx' ? ['task', 'fsmonitor'] : ['task']) {
		checks.push(...checkEvidence(readEvidence(ws, vector, readInTab), vector, { marker, expectHostname, proxy: brokerProxy(driver) }));
	}
	if (driver !== 'sbx') {
		checks.push({ vector: 'fsmonitor', name: 'ran (armed in the tab)', ok: false, detail: 'not armed on OCI',
			knownGap: 'an OCI tab writes .git/config straight to the host checkout (no write-back gate, docs/adr/20261104-write-back-gate.md); Level A covers fsmonitor on OCI' });
	}
	// The RPC escape probes' host effects, one row each, from the probes' own expectations
	// (rpc-filter/probes/expectations.json), plus the negative control. Without the RPC
	// capability filter (patch 0005) these paths are open on purpose: a known gap. With it, a
	// host effect is a failure. Which build ran comes from this run's launch record, and the
	// product.json stamp must match the repo's policy table, or the build is unknown (a failure).
	let filtered: boolean | undefined;
	try {
		const launch = JSON.parse(fs.readFileSync(editorLaunchRecord(userData), 'utf8')) as { app?: unknown; pid?: unknown };
		if (typeof launch.app === 'string' && launch.pid === editorPid(userData)) {
			const product = JSON.parse(fs.readFileSync(path.join(launch.app, 'Contents', 'Resources', 'app', 'product.json'), 'utf8')) as { seclabRpcPolicy?: { sha256?: unknown } };
			if (!product.seclabRpcPolicy) {
				filtered = false;
			} else {
				const policy = path.join(repo, 'rpc-filter', 'patch-src', 'seclabPolicyData.ts');
				const want = fs.existsSync(policy) ? createHash('sha256').update(fs.readFileSync(policy)).digest('hex') : undefined;
				filtered = want !== undefined && product.seclabRpcPolicy.sha256 === want ? true : undefined;
			}
		}
	} catch {
		filtered = undefined;
	}
	checks.push({ vector: 'rpc', name: 'the build under test is known (launch record; RPC filter stamp absent, or matching the repo)', ok: filtered !== undefined, detail: String(filtered) });
	const effects = new Map<string, string[]>([[path.join(base, 'PWNED.rpcwrite'), ['host-fs-write-file-scheme (negative control)']]]);
	const expectations = JSON.parse(fs.readFileSync(path.join(repo, 'rpc-filter', 'probes', 'expectations.json'), 'utf8')) as { probes: Record<string, { hostEffect?: unknown; hostEffectAbsolute?: unknown }> };
	for (const [id, p] of Object.entries(expectations.probes)) {
		const rel = typeof p.hostEffect === 'string' ? /^marker(\.[a-z0-9-]+)?$/.exec(p.hostEffect) : null;
		const abs = typeof p.hostEffectAbsolute === 'string' ? /^userDataDir:(\/[\w./-]+)$/.exec(p.hostEffectAbsolute) : null;
		// The RPC and REH probes name their own run-dir marker (probe-safety.js markerCommand
		// suffixes): PWNED-newlocal, PWNED-resolvevars, PWNED-windowopen, ...
		const own = [p.hostEffect, p.hostEffectAbsolute].find((v): v is string => typeof v === 'string' && /^PWNED-[a-z0-9-]+$/.test(v));
		const at = rel ? path.join(base, `PWNED${rel[1] ?? ''}`) : abs && !abs[1].includes('..') ? path.join(userData, abs[1]) : own ? path.join(base, own) : undefined;
		if (at) {
			effects.set(at, [...(effects.get(at) ?? []), id]);
		}
	}
	for (const [p, ids] of effects) {
		const hit = fs.existsSync(p);
		checks.push({ vector: 'rpc', name: `${ids.join(' + ')}: no host effect`, ok: !hit, detail: p, knownGap: hit && filtered === false ? 'open without the RPC capability filter (patch 0005), docs/RPC-LOCKDOWN.md' : undefined });
	}
	// Anything marker-shaped in the run dir that no row above or below accounts for.
	const vectorMarkers = new Set(['task', 'fsmonitor'].map(v => `${marker}.${v}`));
	for (const f of fs.readdirSync(base).filter(n => /^(?:PWNED|probe-marker)/.test(n))) {
		const p = path.join(base, f);
		if (!effects.has(p) && !vectorMarkers.has(p)) {
			checks.push({ vector: 'rpc', name: 'no unattributed host marker', ok: false, detail: p });
		}
	}
	const evDir = path.join(ws, '.seclab-evidence');
	const host = json(path.join(evDir, 'rogue-extension-host.json'));
	checks.push({ vector: 'rogue-extension', name: 'ui-kind rogue extension was forced into the tab (remoteName=seclab)', ok: host?.remoteName === 'seclab' && host?.seclabTab === '1', detail: JSON.stringify(host) });
	// No trusted-side extension agents in tab windows: the same ui-declared extension
	// registered a chat participant and called vscode.lm, and that code ran in the tab.
	const agent = json(path.join(evDir, 'rogue-agent.json'));
	checks.push({ vector: 'rogue-extension', name: 'ui-declared chat participant / vscode.lm caller ran in the tab, not trusted-side', ok: agent?.ranIn === 'tab' && agent?.remoteName === 'seclab',
		detail: JSON.stringify(agent ?? 'no rogue-agent.json') });
	checks.push({ vector: 'host', name: 'canary intact', ok: fs.readFileSync(canary, 'utf8') === 'HOST-SECRET-CANARY\n', detail: '' });
	// POSITIVE CONTROL. Everything else in this file asserts that something did NOT
	// happen, and a build whose extension host cannot start satisfies all of it. The
	// benign extension must have activated in the tab and completed every ordinary
	// operation a workspace extension performs. If this fails while the rogue checks
	// pass, the filter has broken the editor, not contained it.
	const benign = json(path.join(evDir, 'benign.json'));
	const benignResults = benign?.results as Record<string, unknown> | undefined;
	const benignWhere = (benignResults && typeof benignResults === 'object' ? benignResults.where : undefined) as { remoteName?: unknown; seclabTab?: unknown } | undefined;
	checks.push({
		vector: 'positive-control',
		name: 'an ordinary workspace extension activated in the tab',
		ok: benign?.activated === true && benignWhere?.remoteName === 'seclab' && benignWhere?.seclabTab === '1',
		detail: benign === undefined ? 'no benign.json: the extension host could not run it' : JSON.stringify(benignWhere),
	});
	const benignFailed = Array.isArray(benign?.failed) ? benign.failed as unknown[] : undefined;
	// Known, user-accepted failures (2026-11-10), each pinned to the exact way it fails AND to
	// the host-side decision that causes it: benign.json is tab-written, so its error string
	// alone is not evidence (review round 14). An unfiltered build has no decision log, so
	// there the tolerance never applies. Residual until the search follow-up (round 15).
	const decisions = rpcDecisions(userData);
	const EXPECTED_BENIGN_FAILURES: Record<string, { error: string; deniedRef: string; reason: string }> = {
		findFiles: {
			error: 'timed out after 20000 ms: the call never settled',
			deniedRef: 'rpc:MainThreadSearch.$registerFileSearchProvider',
			reason: 'MainThreadSearch.$registerFileSearchProvider is denied: inside a tab the extension host registers its own file search provider for vscode-remote, so the search service waits forever for a provider and $startFileSearch never returns. First follow-up (docs/RPC-LOCKDOWN.md §7.1).',
		},
	};
	const unexpected = (benignFailed ?? []).filter(k => {
		const want = EXPECTED_BENIGN_FAILURES[String(k)];
		const got = (benignResults?.[String(k)] as { error?: unknown } | undefined)?.error;
		return !want || got !== want.error
			|| !decisions.some(d => d.detail?.ref === want.deniedRef && d.detail?.verdict === 'deny');
	});
	const expectedSeen = (benignFailed ?? []).filter(k => !unexpected.includes(k));
	checks.push({
		vector: 'positive-control',
		name: 'every ordinary extension operation succeeded in the tab (bar recorded, user-accepted losses)',
		ok: benignFailed !== undefined && unexpected.length === 0,
		detail: benignFailed === undefined ? 'no step results'
			: `${unexpected.length} unexpected failure(s): ${unexpected.join(', ') || 'none'}`
			+ (expectedSeen.length ? `; expected: ${expectedSeen.map(k => `${k} (${EXPECTED_BENIGN_FAILURES[String(k)].reason})`).join('; ')}` : '')
			+ (unexpected.length ? ` | ${JSON.stringify(benign?.results).slice(0, 600)}` : ''),
	});
	// The denial is OBSERVED on the trusted side, not inferred from an absent marker: an
	// absent marker alone is equally consistent with a probe that never ran. Only a filtered
	// build writes the log, so this row applies only there.
	if (filtered === true) {
		const denied = decisions.filter(d => d.detail?.ref === 'cmd:workbench.action.terminal.newLocal' && d.detail?.verdict === 'deny');
		checks.push({
			vector: 'rpc',
			name: 'the trusted side recorded the newLocal denial (seclabRpcFilter.log)',
			ok: denied.length > 0,
			detail: denied.length > 0 ? JSON.stringify(denied[0]) : `${decisions.length} decision line(s) in ${userData}/logs/**/seclabRpcFilter.log`,
		});
		// Per-tab state partition (patch 0032): the rogue probes wrote state and a secret under
		// the Tab Manager's id. Where they landed is read from the profile's own database,
		// host-side; the tab cannot write this file.
		for (const f of partitionFindings(stateItems(userData), tabId ?? '')) {
			checks.push({ vector: 'state-partition', name: f.name, ok: f.ok, detail: f.detail });
		}
	}
	// Shared canary harness, editor side: nothing the rogue extension observed through the
	// API (env, configuration, clipboard, auth sessions, secrets) nor any evidence may
	// contain an editor-side canary in any encoding.
	const canaries = deserialize(fs.readFileSync(path.join(base, 'canaries.json'), 'utf8'));
	const evFiles = listInTab(evDir);
	checks.push({ vector: 'canary', name: 'rogue extension recorded its API observations', ok: evFiles.includes('rogue-observed.json'), detail: '' });
	// Stores the rogue extension can still read through the extension API until the RPC
	// capability filter (M4) lands: configuration (user settings) and the clipboard.
	const M4 = 'M4 RPC capability filter (docs/adr/20261104-rpc-capability-filter.md)';
	const knownUntilM4 = new Set(['user-settings', 'clipboard']);
	for (const f of evFiles) {
		// A file the tab lists but won't let us read (oversized, unreadable, odd name) is a
		// failure, never a quiet skip: it could hide a canary (review NNN-1).
		const text = /^[\w.-]+$/.test(f) ? readInTab(path.join(evDir, f)) : undefined;
		if (text === undefined) {
			checks.push({ vector: 'canary', name: 'every evidence file could be scanned', ok: false, detail: JSON.stringify(f).slice(0, 120) });
			continue;
		}
		for (const h of scan(canaries, f, Buffer.from(text))) {
			checks.push({ vector: 'canary', name: `no ${h.store} canary in tab-observable data`, ok: false, detail: `${h.encoding} in ${h.source}`,
				knownGap: knownUntilM4.has(h.store) ? M4 : undefined });
		}
	}
	checks.push({ vector: 'canary', name: 'no editor-side canary observed by the tab (outside known gaps)', ok: !checks.some(c => c.vector === 'canary' && !c.ok && !c.knownGap), detail: '' });
	const ok = report(checks);
	// Disarm the hostile git config left in the host work dir.
	fs.rmSync(path.join(ws, '.git'), { recursive: true, force: true });
	// End of run: stop the editor (by its user-data-dir) and everything it started, remove
	// the tab, delete the profile holding the armed rogue extension, diff the host.
	const clean = teardownGate(base);
	process.exit(ok && clean ? 0 : 1);
}
