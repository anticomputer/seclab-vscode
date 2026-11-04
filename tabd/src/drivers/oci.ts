// OCI driver (Docker or Podman CLI). Second runtime: Linux, CI and the containment
// suite. A tab is a pod: workspace container + broker sidecar on an --internal network.

import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import type { Runner } from '../run.ts';
import { assertImageRef, SANDBOX_NAME_RE, CONNECTION_TOKEN_RE } from '../validate.ts';
import { DriverError, type Driver, type DriverInfo, type FenceReport, type TabRuntimeSpec } from './types.ts';

const REH_START = '/opt/seclab/bin/seclab-reh-start';
const REH_CONNECT = '/opt/seclab/bin/seclab-reh-connect';
const UID = '1000:1000';

export interface OciOptions {
	/** Image for the broker sidecar slot. The real broker (M2) replaces the placeholder. */
	readonly brokerImage: string;
	/** Extra `docker run` runtime, e.g. 'runsc' for gVisor; validated. */
	readonly runtime?: string;
}

export class OciDriver implements Driver {
	readonly name = 'oci';
	private readonly docker: string;
	private readonly runner: Runner;
	private readonly opts: OciOptions;

	constructor(dockerPath: string, runner: Runner, opts: OciOptions) {
		this.docker = dockerPath;
		this.runner = runner;
		this.opts = opts;
		assertImageRef(opts.brokerImage);
		if (opts.runtime !== undefined && !/^[a-z][a-z0-9-]{0,31}$/.test(opts.runtime)) {
			throw new DriverError(-32602, 'invalid runtime');
		}
	}

	async probe(): Promise<DriverInfo> {
		const capabilities = {
			isolationClass: 'namespaces', networkFence: 'internal-network', liveMounts: false, holdAndResume: false,
			fileWatch: 'native', sameAbsolutePathMount: true,
		} as const;
		const r = await this.runner.run(this.docker, ['version', '--format', '{{.Server.Version}}'], { timeoutMs: 15_000 });
		return r.code === 0
			? { name: this.name, available: true, version: r.stdout.trim().slice(0, 32), capabilities }
			: { name: this.name, available: false, reason: 'docker daemon unavailable', capabilities };
	}

	private names(spec: TabRuntimeSpec) {
		if (!SANDBOX_NAME_RE.test(spec.sandboxName) || !spec.hostPath.startsWith('/')) {
			throw new DriverError(-32602, 'invalid runtime spec');
		}
		return {
			ws: spec.sandboxName,
			broker: `${spec.sandboxName}-broker`,
			net: `${spec.sandboxName}-net`,
			home: `${spec.sandboxName}-home`,
		};
	}

	private async exists(kind: 'container' | 'network', name: string): Promise<boolean> {
		const r = await this.runner.run(this.docker, [kind, 'inspect', '--format', '{{.Name}}', '--', name], { timeoutMs: 15_000 });
		return r.code === 0;
	}

	async ensureRunning(spec: TabRuntimeSpec, connectionToken: string): Promise<void> {
		if (!CONNECTION_TOKEN_RE.test(connectionToken)) {
			throw new DriverError(-32602, 'invalid connection token');
		}
		const n = this.names(spec);
		const label = `seclab.tab=${spec.tabId}`;
		if (!await this.exists('network', n.net)) {
			await this.must(['network', 'create', '--internal', '--label', label, '--', n.net], 'network create');
		}
		if (!await this.exists('container', n.broker)) {
			await this.must(['run', '-d', '--name', n.broker, '--label', label, '--network', n.net,
				'--network-alias', 'broker', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
				'--read-only', '--pids-limit', '64', '--memory', '256m', '--', assertImageRef(this.opts.brokerImage)], 'broker run');
		}
		if (!await this.exists('container', n.ws)) {
			const t = spec.template.spec;
			const args = ['run', '-d', '--init', '--name', n.ws, '--hostname', 'tab', '--label', label,
				'--network', n.net, '--user', UID,
				'--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
				'--pids-limit', '2048', '--memory', t.resources?.memory && /^[1-9][0-9]{0,4}[mg]$/.test(t.resources.memory) ? t.resources.memory : '4g',
				'--read-only', '--tmpfs', '/tmp:rw,nosuid,nodev,size=1g', '--tmpfs', '/run/seclab:rw,nosuid,nodev,uid=1000,gid=1000,mode=0700',
				// hostPath is canonical and contains no ',' or ':' (validate.ts), so --mount parsing is unambiguous.
				'--mount', `type=bind,src=${spec.hostPath},dst=${spec.hostPath}`,
				'--mount', `type=volume,src=${n.home},dst=/home/agent`,
				'--workdir', spec.hostPath];
			if (this.opts.runtime) {
				args.push('--runtime', this.opts.runtime);
			}
			args.push('--', assertImageRef(t.image), 'sleep', 'infinity');
			await this.must(args, 'workspace run');
		} else {
			await this.runner.run(this.docker, ['start', '--', n.broker]);
			await this.runner.run(this.docker, ['start', '--', n.ws]);
		}
		const fence = await this.verifyFence(spec);
		if (!fence.ok) {
			throw new DriverError(-32010, `fence verification failed: ${fence.problems.join('; ')}`);
		}
		const r = await this.runner.run(this.docker, ['exec', '-i', '-u', UID, '--', n.ws, REH_START], { input: connectionToken + '\n', timeoutMs: 90_000 });
		if (r.code !== 0) {
			throw new DriverError(-32012, `REH failed to start: ${r.stderr.trim().slice(-800)}`);
		}
	}

	private async must(args: string[], what: string): Promise<void> {
		const r = await this.runner.run(this.docker, args, { timeoutMs: 180_000 });
		if (r.code !== 0) {
			throw new DriverError(-32011, `${what} failed: ${r.stderr.trim().slice(-800)}`);
		}
	}

	async verifyFence(spec: TabRuntimeSpec): Promise<FenceReport> {
		const n = this.names(spec);
		const checkedAt = new Date().toISOString();
		const problems: string[] = [];
		const net = await this.runner.run(this.docker, ['network', 'inspect', '--format', '{{.Internal}}', '--', n.net]);
		if (net.code !== 0 || net.stdout.trim() !== 'true') {
			problems.push(`network ${n.net} is not --internal`);
		}
		const ins = await this.runner.run(this.docker, ['container', 'inspect', '--format',
			'{{json .NetworkSettings.Networks}}|{{.HostConfig.Privileged}}|{{json .HostConfig.CapAdd}}|{{json .HostConfig.PortBindings}}|{{.Config.User}}', '--', n.ws]);
		if (ins.code !== 0) {
			problems.push('workspace container not inspectable');
		} else {
			const [nets, priv, capAdd, ports, user] = ins.stdout.trim().split('|');
			let netNames: string[] = [];
			try {
				netNames = Object.keys(JSON.parse(nets));
			} catch { /* empty */ }
			if (netNames.length !== 1 || netNames[0] !== n.net) {
				problems.push(`workspace attached to networks ${JSON.stringify(netNames)}`);
			}
			if (priv !== 'false') {
				problems.push('workspace is privileged');
			}
			if (capAdd !== 'null' && capAdd !== '[]') {
				problems.push(`workspace has added caps ${capAdd}`);
			}
			if (ports !== '{}' && ports !== 'null') {
				problems.push('workspace publishes ports');
			}
			if (user !== UID) {
				problems.push(`workspace user is ${user}`);
			}
		}
		return { ok: problems.length === 0, problems, checkedAt };
	}

	connectReh(spec: TabRuntimeSpec): ChildProcessWithoutNullStreams {
		const n = this.names(spec);
		return this.runner.spawnStream(this.docker, ['exec', '-i', '-u', UID, '--', n.ws, REH_CONNECT]);
	}

	async runningSandboxes(): Promise<Set<string>> {
		const r = await this.runner.run(this.docker, ['ps', '--filter', 'label=seclab.tab', '--format', '{{.Names}}'], { timeoutMs: 30_000 });
		if (r.code !== 0) {
			throw new DriverError(-32003, 'docker ps failed');
		}
		return new Set(r.stdout.split('\n').map(s => s.trim()).filter(s => SANDBOX_NAME_RE.test(s)));
	}

	async quarantine(spec: TabRuntimeSpec): Promise<void> {
		const n = this.names(spec);
		await this.runner.run(this.docker, ['stop', '--', n.ws, n.broker], { timeoutMs: 60_000 });
	}

	async stop(spec: TabRuntimeSpec): Promise<void> {
		const n = this.names(spec);
		await this.runner.run(this.docker, ['stop', '--', n.ws, n.broker], { timeoutMs: 60_000 });
	}

	async remove(spec: TabRuntimeSpec): Promise<void> {
		const n = this.names(spec);
		await this.runner.run(this.docker, ['rm', '-f', '--', n.ws, n.broker], { timeoutMs: 60_000 });
		await this.runner.run(this.docker, ['network', 'rm', '--', n.net], { timeoutMs: 30_000 });
		await this.runner.run(this.docker, ['volume', 'rm', '--', n.home], { timeoutMs: 30_000 });
	}
}
