// Docker Sandboxes (sbx) driver. Primary PoC runtime: one microVM per tab.
// Every argv element is either a constant, a validated value (validate.ts), or a
// canonicalised host path. In-sandbox commands are fixed paths baked into our template.

import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import { checkFence, parsePolicyJson, resourcesToMirror } from '../fence.ts';
import type { Runner } from '../run.ts';
import { assertImageRef, assertPolicyResource, SANDBOX_NAME_RE, CONNECTION_TOKEN_RE } from '../validate.ts';
import type { UpperReader } from '../writeback-feed.ts';
import { DriverError, type Driver, type DriverInfo, type FenceReport, type PolicyLogEntry, type SensorHooks, type TabRuntimeSpec } from './types.ts';

const MIN_VERSION = [0, 51, 0];
const REH_CONNECT = '/opt/seclab/bin/seclab-reh-connect';
const OBS_COLLECT = '/opt/seclab/bin/seclab-obs-collect';
const WB_FEED = '/opt/seclab/bin/seclab-wb-feed';
// The REH relay runs as its own fixed uid:gid (template), so the tab user cannot ptrace it.
// Always both ids: a bare uid would take the passwd lookup's gid, and gid 999 is docker.
const RELAY_USER = '990:990';
// Destinations that must never be reachable from a tab; probed on every verify.
const CANARY_TARGETS = ['example.com:443', 'localhost:22'];

interface SbxListEntry { name: string; status: string; workspaces?: string[] }

export class SbxDriver implements Driver {
	readonly name = 'sbx';
	private readonly sbx: string;
	private readonly runner: Runner;

	constructor(sbxPath: string, runner: Runner) {
		this.sbx = sbxPath;
		this.runner = runner;
	}

	async probe(): Promise<DriverInfo> {
		const capabilities = {
			isolationClass: 'microvm', networkFence: 'sbx-policy', liveMounts: false, holdAndResume: false,
			fileWatch: 'virtiofs', sameAbsolutePathMount: true, writeBack: 'gated',
		} as const;
		const r = await this.runner.run(this.sbx, ['version'], { timeoutMs: 15_000 });
		const m = /v(\d+)\.(\d+)\.(\d+)/.exec(r.stdout);
		if (r.code !== 0 || !m) {
			return { name: this.name, available: false, reason: 'sbx version failed', capabilities };
		}
		const v = [Number(m[1]), Number(m[2]), Number(m[3])];
		const ok = v[0] > MIN_VERSION[0] || (v[0] === MIN_VERSION[0] && (v[1] > MIN_VERSION[1] || (v[1] === MIN_VERSION[1] && v[2] >= MIN_VERSION[2])));
		return { name: this.name, available: ok, version: v.join('.'), reason: ok ? undefined : `sbx >= ${MIN_VERSION.join('.')} required`, capabilities };
	}

	private async list(): Promise<SbxListEntry[]> {
		const r = await this.runner.run(this.sbx, ['ls', '--json'], { timeoutMs: 30_000 });
		if (r.code !== 0) {
			throw new DriverError(-32003, `sbx ls failed: ${r.stderr.trim()}`);
		}
		const doc = JSON.parse(r.stdout || '[]');
		const arr: unknown[] = Array.isArray(doc) ? doc : (Array.isArray(doc?.sandboxes) ? doc.sandboxes : []);
		return arr.filter((e): e is SbxListEntry => typeof (e as SbxListEntry)?.name === 'string' && typeof (e as SbxListEntry)?.status === 'string');
	}

	private async policyRules() {
		const r = await this.runner.run(this.sbx, ['policy', 'ls', '--wide', '--json'], { timeoutMs: 30_000 });
		if (r.code !== 0) {
			throw new DriverError(-32010, `sbx policy ls failed: ${r.stderr.trim()}`);
		}
		return parsePolicyJson(r.stdout);
	}

	/**
	 * No real secret ever enters a tab (ADR 20261104-no-real-secret-in-a-tab). sbx can inject
	 * stored service/custom secrets into sandboxes through its proxy; refuse to run a tab if
	 * any stored secret could apply to it. Fails closed on unknown output.
	 */
	private async secretProblems(spec: TabRuntimeSpec): Promise<string[]> {
		const r = await this.runner.run(this.sbx, ['secret', 'ls', '--json'], { timeoutMs: 30_000 });
		if (r.code !== 0) {
			return [`sbx secret ls failed: ${tail(r.stderr)}`];
		}
		let doc: Record<string, unknown>;
		try {
			doc = JSON.parse(r.stdout) as Record<string, unknown>;
		} catch {
			return ['sbx secret ls output is not JSON'];
		}
		const problems: string[] = [];
		for (const key of ['secrets', 'custom_secrets']) {
			const list = doc[key];
			if (!Array.isArray(list)) {
				problems.push(`sbx secret ls: ${key} missing`);
				continue;
			}
			for (const s of list as Array<Record<string, unknown>>) {
				const scopedElsewhere = typeof s?.sandbox === 'string' && s.sandbox !== '' && s.sandbox !== spec.sandboxName;
				if (!scopedElsewhere) {
					problems.push(`sbx ${key} entry ${JSON.stringify(s?.name ?? s?.service ?? '?')} could apply to this tab`);
				}
			}
		}
		// Supervisor runs sbx with a scrubbed environment, so this must be zero.
		if (typeof doc.env_only_count === 'number' && doc.env_only_count > 0) {
			problems.push(`sbx sees ${doc.env_only_count} secret-like variable(s) in the supervisor environment`);
		}
		return problems;
	}

	async ensureRunning(spec: TabRuntimeSpec, connectionToken: string, sensor?: SensorHooks): Promise<void> {
		checkSpec(spec);
		if (!CONNECTION_TOKEN_RE.test(connectionToken)) {
			throw new DriverError(-32602, 'invalid connection token');
		}
		const existing = (await this.list()).find(e => e.name === spec.sandboxName);
		if (existing) {
			const ws = existing.workspaces ?? [];
			if (ws.length !== 1 || ws[0] !== spec.hostPath) {
				throw new DriverError(-32011, `sandbox ${spec.sandboxName} has unexpected workspaces ${JSON.stringify(ws)}`);
			}
		} else {
			await this.create(spec);
		}
		// Mirror at every start, not only at create: global allows may have been added since.
		await this.syncDenies(spec);
		const fence = await this.verifyFence(spec);
		if (!fence.ok) {
			throw new DriverError(-32010, `fence verification failed: ${fence.problems.join('; ')}`);
		}
		// The REH starts under the observability collector (root in the VM, strace + seccomp
		// guard), so every tab process is traced from birth. No collector, no REH (fail closed).
		// The token goes over stdin, never argv. exec starts a stopped sandbox.
		if (!sensor?.startCollector) {
			throw new DriverError(-32012, 'sbx tabs require the observability collector');
		}
		try {
			await sensor.startCollector(() => this.runner.spawnStream(this.sbx, ['exec', '-i', '-u', 'root', '-w', '/', spec.sandboxName, OBS_COLLECT]), connectionToken);
		} catch (e) {
			throw new DriverError(-32012, `REH failed to start: ${(e as Error).message}`);
		}
	}

	private async create(spec: TabRuntimeSpec): Promise<void> {
		const t = spec.template.spec;
		const secretProblems = await this.secretProblems(spec);
		if (secretProblems.length) {
			throw new DriverError(-32010, `refusing to create tab: ${secretProblems.join('; ')}`);
		}
		const mirror = resourcesToMirror(await this.policyRules());
		const args = ['create', '--name', spec.sandboxName, '--no-progress', '--pull', 'never', '-t', assertImageRef(t.image)];
		if (t.resources?.cpus !== undefined) {
			const cpus = t.resources.cpus;
			if (!Number.isInteger(cpus) || cpus < 1 || cpus > 16) {
				throw new DriverError(-32602, 'invalid cpus');
			}
			args.push('--cpus', String(cpus));
		}
		if (t.resources?.memory !== undefined) {
			if (!/^[1-9][0-9]{0,4}[mg]$/.test(t.resources.memory)) {
				throw new DriverError(-32602, 'invalid memory');
			}
			args.push('--memory', t.resources.memory);
		}
		// Mirror every global allow as a per-sandbox deny at creation, so the sandbox
		// never runs without the fence (docs/edr/20261104-sbx-fence-spike.md).
		for (const res of mirror) {
			args.push('--deny-network', assertPolicyResource(res));
		}
		args.push('--', 'shell', spec.hostPath);
		const r = await this.runner.run(this.sbx, args, { timeoutMs: 300_000 });
		if (r.code !== 0) {
			throw new DriverError(-32011, `sbx create failed: ${tail(r.stderr || r.stdout)}`);
		}
		if (spec.brokerPort !== undefined) {
			const a = await this.runner.run(this.sbx, ['policy', 'allow', 'network', '--sandbox', spec.sandboxName, `localhost:${spec.brokerPort}`]);
			if (a.code !== 0) {
				throw new DriverError(-32011, `broker allow failed: ${tail(a.stderr)}`);
			}
		}
		// sbx attaches sandbox-scoped kit allows at create time; deny those too before the
		// sandbox ever starts (the fence check would otherwise refuse every new tab).
		await this.syncDenies(spec);
	}

	/** Add a per-sandbox deny for every allow (global or scoped to it) not yet denied for this sandbox. Needs no consent. */
	private async syncDenies(spec: TabRuntimeSpec): Promise<void> {
		const rules = await this.policyRules();
		const scoped = `sandbox:${spec.sandboxName}`;
		const denied = new Set<string>();
		for (const r of rules) {
			if (r.resource_type === 'network' && r.decision === 'deny' && r.applies_to === scoped && r.status === 'active') {
				for (const res of r.resources) {
					denied.add(res);
				}
			}
		}
		for (const res of resourcesToMirror(rules, spec.sandboxName, spec.brokerPort)) {
			if (!denied.has(res)) {
				const d = await this.runner.run(this.sbx, ['policy', 'deny', 'network', '--sandbox', spec.sandboxName, '--', assertPolicyResource(res)]);
				if (d.code !== 0) {
					throw new DriverError(-32010, `could not mirror deny for ${res}: ${tail(d.stderr)}`);
				}
			}
		}
	}

	async quarantine(spec: TabRuntimeSpec): Promise<void> {
		checkSpec(spec);
		try {
			await this.syncDenies(spec);
		} finally {
			await this.runner.run(this.sbx, ['stop', spec.sandboxName], { timeoutMs: 60_000 });
		}
	}

	async verifyFence(spec: TabRuntimeSpec): Promise<FenceReport> {
		checkSpec(spec);
		const checkedAt = new Date().toISOString();
		try {
			const rules = await this.policyRules();
			const problems = checkFence(rules, spec.sandboxName, spec.brokerPort);
			problems.push(...await this.secretProblems(spec));
			const probes: Array<[string, boolean]> = CANARY_TARGETS.map(t => [t, false]);
			// Plus a few concrete (non-glob) global allows: these must be denied for the tab.
			for (const res of resourcesToMirror(rules, spec.sandboxName, spec.brokerPort).filter(r => !/[*?[\]]/.test(r)).slice(0, 3)) {
				probes.push([res, false]);
			}
			if (spec.brokerPort !== undefined) {
				probes.push([`localhost:${spec.brokerPort}`, true]);
			}
			const results = await Promise.all(probes.map(async ([target, want]) => {
				const r = await this.runner.run(this.sbx, ['policy', 'check', 'network', '--sandbox', spec.sandboxName, '--json', '--', target], { timeoutMs: 15_000 });
				let allowed: unknown;
				try {
					allowed = JSON.parse(r.stdout).allowed;
				} catch {
					allowed = undefined;
				}
				return typeof allowed === 'boolean' && allowed === want ? undefined : `probe ${target}: expected allowed=${want}, got ${String(allowed)}`;
			}));
			for (const p of results) {
				if (p) {
					problems.push(p);
				}
			}
			return { ok: problems.length === 0, problems, checkedAt };
		} catch (e) {
			return { ok: false, problems: [`verification error: ${(e as Error).message}`], checkedAt };
		}
	}

	connectReh(spec: TabRuntimeSpec): ChildProcessWithoutNullStreams {
		checkSpec(spec);
		return this.runner.spawnStream(this.sbx, ['exec', '-i', '-u', RELAY_USER, spec.sandboxName, REH_CONNECT]);
	}

	/** `sbx policy log <tab> --json`: untrusted CLI output, validated field by field. */
	/** Write-back gate: `seclab-wb-feed` as root in the VM (fixed argv; stdin carries requests). */
	upperReader(spec: TabRuntimeSpec): UpperReader {
		return {
			feed: async (mode, input) => {
				const r = await this.runner.run(this.sbx, ['exec', '-i', '-u', 'root', '-w', '/', spec.sandboxName, WB_FEED, mode],
					{ input: input ?? '', timeoutMs: 120_000, maxOutputBytes: 96 << 20 });
				if (r.code !== 0 || r.truncated) {
					throw new DriverError(-32013, `write-back feed ${mode} failed${r.truncated ? ' (output over the cap)' : ''}: ${r.stderr.trim().slice(-200)}`);
				}
				return r.stdout;
			},
		};
	}

	async policyLog(spec: TabRuntimeSpec): Promise<PolicyLogEntry[]> {
		checkSpec(spec);
		const r = await this.runner.run(this.sbx, ['policy', 'log', spec.sandboxName, '--json', '--limit', '500'], { timeoutMs: 30_000, maxOutputBytes: 2 << 20 });
		if (r.code !== 0) {
			throw new DriverError(-32003, `sbx policy log failed: ${tail(r.stderr)}`);
		}
		const doc = JSON.parse(r.stdout || '{}') as Record<string, unknown>;
		const out: PolicyLogEntry[] = [];
		for (const decision of ['allowed', 'blocked'] as const) {
			const list = Array.isArray(doc[decision]) ? doc[decision] as Array<Record<string, unknown>> : [];
			for (const e of list.slice(0, 1000)) {
				if (e?.sandbox_id !== spec.sandboxName || typeof e.host !== 'string' || typeof e.count !== 'number' || !Number.isSafeInteger(e.count)) {
					continue;
				}
				out.push({
					decision, host: e.host.slice(0, 300), count: e.count, proxyType: typeof e.proxy_type === 'string' ? e.proxy_type.slice(0, 32) : '?',
					reason: typeof e.reason === 'string' ? e.reason.slice(0, 200) : undefined, lastSeen: typeof e.last_seen === 'string' ? e.last_seen.slice(0, 40) : undefined,
				});
			}
		}
		return out;
	}

	async runningSandboxes(): Promise<Set<string>> {
		return new Set((await this.list()).filter(e => e.status === 'running' && SANDBOX_NAME_RE.test(e.name)).map(e => e.name));
	}

	async stop(spec: TabRuntimeSpec): Promise<void> {
		checkSpec(spec);
		await this.runner.run(this.sbx, ['stop', spec.sandboxName], { timeoutMs: 60_000 });
	}

	async remove(spec: TabRuntimeSpec): Promise<void> {
		checkSpec(spec);
		await this.runner.run(this.sbx, ['rm', '--force', spec.sandboxName], { timeoutMs: 120_000 });
		// Remove fence rules only once the sandbox is confirmed gone.
		if ((await this.list()).some(e => e.name === spec.sandboxName)) {
			throw new DriverError(-32011, `sandbox ${spec.sandboxName} still exists; fence rules kept`);
		}
		for (const r of await this.policyRules()) {
			if (r.applies_to === `sandbox:${spec.sandboxName}` && /^[0-9a-f-]{36}$/.test(r.id)) {
				await this.runner.run(this.sbx, ['policy', 'rm', 'network', '--force', '--sandbox', spec.sandboxName, '--id', r.id]);
			}
		}
	}
}

function checkSpec(spec: TabRuntimeSpec): void {
	if (!SANDBOX_NAME_RE.test(spec.sandboxName) || !spec.hostPath.startsWith('/')) {
		throw new DriverError(-32602, 'invalid runtime spec');
	}
}

function tail(s: string): string {
	return s.trim().split('\n').slice(-5).join(' | ').slice(0, 800);
}
