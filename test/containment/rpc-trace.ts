// Measure which extension-host -> window RPC calls an ORDINARY session makes, in one run.
//
//   node test/containment/rpc-trace.ts prepare <user-data-dir> [sbx|oci]
//       benign workspace (fake data) + the benign extension only, in a claimed tab;
//       prints the background launch line (with --rpc-trace)
//   node test/containment/rpc-trace.ts check <user-data-dir>
//       derives the call list from the raw trace, DELETES the raw trace, then tears the
//       run down (teardown gate)
//   node test/containment/rpc-trace.ts derive <raw-log>      (offline, for tests: prints JSON)
//
// Why: every patched build so far uncovered one more layer of denied plumbing, because a
// denial stops the code path that would have made the next call. Upstream already has a
// trusted-side tracer (--logExtensionHostCommunication -> RPCLogger, extensionHostManager.ts
// L252) that logs every Ext -> Win request; on an UNFILTERED build that is the complete set
// in one pass. The trace is what a session needs, not what is safe: every method on it still
// needs its own classification (rpc-filter/AGENTS.md section 4).
//
// The raw log carries argument values, so it lives only under this checkout's .work/ and is
// deleted as soon as the list is derived. The derived file records method names, counts and
// command ids (the policy key of $executeCommand), never argument values.
// Benign fixtures only: this harness refuses to install anything but the benign extension.

import { execFileSync, spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import { checkUserDataDir, editorLaunchCommand, lockRun } from '../harness.ts';
import { materialiseFixture, readManifest, reapPreviousRun, runTabs, teardownGate, writeManifest, writeSnapshot } from './teardown.ts';

export interface TraceCall { kind: string; ref: string; count: number }
export interface TraceSummary { remote: TraceCall[]; local: TraceCall[]; lines: number; requests: number }

/** A command id as the policy keys it; anything else is not recorded (it would be a value). */
const COMMAND_ID = /^[A-Za-z_$][\w.$:/-]{0,127}$/;
// The console line is the RPCLogger's format string followed by its four `color: …` style
// arguments, then the call's own arguments (extensionHostManager.ts RPCLogger._log).
const REQUEST = /\[(Remote|LocalProcess|LocalWebWorker)\]\[Ext (?:\u2192|->|\\u2192) Win\].*?receiveRequest ([A-Za-z][A-Za-z0-9]*)\.(\$[A-Za-z0-9_]+)\((?:\s*color: \S+){4}\s*(\S*)/;

/** Method names (and $executeCommand ids) with counts. Never argument values. */
export function deriveTrace(raw: string): TraceSummary {
	const counts = { Remote: new Map<string, number>(), Local: new Map<string, number>() };
	let lines = 0;
	let requests = 0;
	for (const line of raw.split('\n')) {
		lines++;
		const m = REQUEST.exec(line);
		if (!m) {
			continue;
		}
		requests++;
		const [, kind, sid, method, firstArg] = m;
		let ref = `rpc:${sid}.${method}`;
		if (sid === 'MainThreadCommands' && method === '$executeCommand') {
			const id = firstArg.replace(/[,)"']+$/, '').replace(/^["']/, '');
			ref = COMMAND_ID.test(id) ? `cmd:${id}` : 'cmd:<unrecognised>';
		}
		const bucket = kind === 'Remote' ? counts.Remote : counts.Local;
		bucket.set(ref, (bucket.get(ref) ?? 0) + 1);
	}
	const list = (m: Map<string, number>, kind: string): TraceCall[] =>
		[...m].map(([ref, count]) => ({ kind, ref, count })).sort((a, b) => a.ref.localeCompare(b.ref));
	return { remote: list(counts.Remote, 'remote'), local: list(counts.Local, 'local'), lines, requests };
}

interface Policy {
	default_verdict: string;
	rpc: Record<string, { service_default?: string; methods?: Record<string, { verdict: string; constraint?: string }> }>;
	commands: { exact: Record<string, { verdict: string }> };
}

/** What the CURRENT policy table says about a traced call (mirrors seclabRpcFilter's resolution). */
export function policyVerdict(policy: Policy, ref: string): string {
	if (ref.startsWith('cmd:')) {
		const id = ref.slice(4);
		if (id.startsWith('seclab.')) {
			return 'deny';
		}
		return policy.commands.exact[id]?.verdict ?? policy.default_verdict;
	}
	const [sid, method] = ref.slice(4).split('.');
	const svc = policy.rpc[sid];
	const e = svc?.methods?.[method];
	return e ? (e.constraint ? `${e.verdict} (${e.constraint.slice(0, 40)}…)` : e.verdict) : (svc?.service_default ?? policy.default_verdict);
}

const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
	await main();
}

async function main(): Promise<void> {
	const [mode, arg, opt] = process.argv.slice(2);
	if (mode === 'derive' && arg) {
		console.log(JSON.stringify(deriveTrace(fs.readFileSync(arg, 'utf8')), null, 2));
		return;
	}
	if ((mode !== 'prepare' && mode !== 'check') || !arg) {
		console.error('usage: rpc-trace.ts prepare <user-data-dir> [sbx|oci] | check <user-data-dir> | derive <raw-log>');
		process.exit(2);
	}
	const repo = path.resolve(import.meta.dirname, '../..');
	const userData = path.resolve(arg);
	checkUserDataDir(userData);
	const base = path.join(repo, '.work', 'rpc-trace');
	lockRun(path.join(base, '..', 'rpc-trace.lock.d'));
	const ws = path.join(base, 'ws-trace');
	const rawLog = path.join(base, 'raw', 'rpc-trace.log');
	const stateDir = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');

	if (mode === 'prepare') {
		const driver = opt ?? 'sbx';
		const reap = reapPreviousRun(base);
		if (reap.refused) {
			console.error(`a previous run in ${base} could not be reaped; not wiping it:\n  ${reap.problems.join('\n  ')}`);
			process.exit(1);
		}
		fs.rmSync(base, { recursive: true, force: true });
		fs.rmSync(userData, { recursive: true, force: true });
		materialiseFixture(base, path.join(import.meta.dirname, 'fixtures', 'trace-workspace'), ws);
		writeSnapshot(base);
		writeManifest(base, { driver: driver as 'sbx' | 'oci', userDataDir: userData, stateDirs: [stateDir] });
		// An ordinary repository so the git built-in activates. No hooks, no config beyond identity.
		const git = (...a: string[]) => execFileSync('git', ['-C', ws, ...a], { stdio: 'ignore' });
		git('init', '-q');
		git('add', '-A');
		git('-c', 'user.name=seclab-test', '-c', 'user.email=seclab-test@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'trace fixture');
		fs.mkdirSync(path.dirname(rawLog), { recursive: true });
		fs.mkdirSync(path.join(userData, 'User'), { recursive: true });
		fs.writeFileSync(path.join(userData, 'User', 'settings.json'), JSON.stringify({
			'security.workspace.trust.enabled': false,
			'seclab.tabs.driver': driver,
			'seclab.tabs.allowedRoots': [base],
		}, null, '\t'));
		const vsixDir = path.join(ws, '.seclab');
		fs.mkdirSync(vsixDir, { recursive: true });
		const VSCE_IMAGE = 'seclab-vsce:3.9.2';
		if (spawnSync('docker', ['image', 'inspect', VSCE_IMAGE], { stdio: 'ignore' }).status !== 0) {
			execFileSync('gh', ['cfs', '--', 'docker', 'build', '-q', '-t', VSCE_IMAGE, path.join(repo, 'build', 'vsce')], { stdio: 'inherit' });
		}
		execFileSync('docker', ['run', '--rm', '--network', 'none', '--user', `${process.getuid!()}:${process.getgid!()}`,
			'-v', `${path.join(import.meta.dirname, 'benign-extension')}:/ext:ro`, '-v', `${vsixDir}:/out`,
			VSCE_IMAGE, 'sh', '-c', 'cp -r /ext /tmp/e && cd /tmp/e && vsce package --allow-missing-repository --skip-license -o /out/benign.vsix'], { stdio: 'inherit' });
		const client = new TabdClient({
			command: process.execPath,
			args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', driver, '--allowed-root', base],
			env: { HOME: process.env.HOME, USER: process.env.USER },
		});
		await client.initialize('rpc-trace', '0');
		const { tab } = await client.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
		writeManifest(base, { tabs: [tab.metadata.name] });
		await client.request('tab.ensureRunning', { tabId: tab.metadata.name });
		const runtime = driver === 'sbx' ? '/opt/homebrew/bin/sbx' : 'docker';
		const user = driver === 'sbx' ? ['-u', 'agent'] : [];
		const r = spawnSync(runtime, ['exec', ...user, `seclab-${tab.metadata.name}`, '/opt/seclab/bin/seclab-tab-env',
			'/opt/seclab-reh/bin/seclab-code-server', '--install-extension', path.join(vsixDir, 'benign.vsix')], { encoding: 'utf8' });
		console.log(r.stdout.trim(), r.stderr.trim());
		client.dispose();
		await new Promise(res => client.once('exit', res));
		console.log(`\nprepared tab ${tab.metadata.name} for ${ws}\n\n  ${editorLaunchCommand(userData,
			`vscode-remote://seclab+${tab.metadata.name}${ws}`, {}, undefined, rawLog)}\n`);
		return;
	}

	// check: derive, delete the raw trace, tear down. Teardown runs whatever happens above it.
	let failed = false;
	try {
		const m = readManifest(base);
		const tabId = runTabs(m)[0];
		const runtime = m.driver === 'oci' ? 'docker' : '/opt/homebrew/bin/sbx';
		const user = m.driver === 'oci' ? [] : ['-u', 'agent'];
		const benignRaw = tabId ? spawnSync(runtime, ['exec', ...user, `seclab-${tabId}`, 'cat', path.join(ws, '.seclab-evidence', 'benign.json')],
			{ encoding: 'utf8', timeout: 30_000, maxBuffer: 1 << 20 }).stdout : '';
		let benign: { activated?: unknown; failed?: unknown } | undefined;
		try { benign = JSON.parse(benignRaw) as typeof benign; } catch { benign = undefined; }
		console.log(`benign control: ${benign?.activated === true ? `activated, failed steps: ${JSON.stringify(benign.failed)}` : 'DID NOT RUN'}`);
		if (!fs.existsSync(rawLog)) {
			console.error(`no raw trace at ${rawLog}: the logging flags did not take (fall back to the rpc-audit variant)`);
			failed = true;
		} else {
			const summary = deriveTrace(fs.readFileSync(rawLog, 'utf8'));
			const policy = JSON.parse(fs.readFileSync(path.join(repo, 'rpc-filter', 'policy', 'policy.json'), 'utf8')) as Policy;
			const derived = {
				$comment: 'Derived by test/containment/rpc-trace.ts from an unfiltered build: method names, counts and command ids only. The verdict column is the policy table at derivation time.',
				build: process.env.SECLAB_TRACE_BUILD ?? 'unrecorded',
				benignActivated: benign?.activated === true,
				lines: summary.lines, requests: summary.requests,
				remote: summary.remote.map(c => ({ ...c, verdict: policyVerdict(policy, c.ref) })),
				localKinds: summary.local.length,
			};
			const out = path.join(base, 'derived.json');
			fs.writeFileSync(out, JSON.stringify(derived, null, '\t') + '\n');
			console.log(`${summary.requests} requests in ${summary.lines} log lines; ${summary.remote.length} distinct remote calls -> ${out}`);
			for (const c of derived.remote) {
				console.log(`${String(c.count).padStart(7)}  ${c.verdict.padEnd(24)} ${c.ref}`);
			}
			if (summary.requests === 0) {
				console.error('the trace has no requests: the console did not reach the log file');
				failed = true;
			}
		}
	} finally {
		// The raw trace holds argument values: it never outlives the derivation.
		fs.rmSync(path.dirname(rawLog), { recursive: true, force: true });
		if (!teardownGate(base)) {
			failed = true;
		}
	}
	process.exit(failed ? 1 : 0);
}
