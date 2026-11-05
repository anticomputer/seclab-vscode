// OCI driver (Docker or Podman CLI). Second runtime: Linux, CI and the containment
// suite. A tab is a pod: workspace container + broker sidecar on an --internal network.

import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import * as fs from 'node:fs';
import type { Runner } from '../run.ts';
import { assertImageRef, SANDBOX_NAME_RE, CONNECTION_TOKEN_RE } from '../validate.ts';
import { BROKER_DIR, brokerInstallInput, INSTALL_BROKER } from './broker-install.ts';
import { DriverError, type BrokerHooks, type BrokerSetup, type Driver, type DriverInfo, type FenceReport, type SensorHooks, type TabRuntimeSpec } from './types.ts';

const REH_START = '/opt/seclab/bin/seclab-reh-start';
const REH_CONNECT = '/opt/seclab/bin/seclab-reh-connect';
const IMAGE_UID = '1000:1000';
/** The broker's proxy port on the pod network (docs/broker-protocol.md §7). */
const BROKER_PROXY = 'broker:8080';

/**
 * The tab's uid:gid. Docker Desktop (macOS) maps bind-mount ownership, so the image user
 * works. A native Linux engine does not: the tab runs as the workspace owner so it can
 * write its own folder (never as root).
 */
function tabUser(spec: TabRuntimeSpec): string {
	if (process.platform !== 'linux') {
		return IMAGE_UID;
	}
	const st = fs.statSync(spec.hostPath);
	if (st.uid === 0 || st.gid === 0) {
		throw new DriverError(-32602, 'refusing a root-owned workspace');
	}
	return `${st.uid}:${st.gid}`;
}

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
			fileWatch: 'native', sameAbsolutePathMount: true, writeBack: 'ungated',
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
			egress: `${spec.sandboxName}-egress`,
			home: `${spec.sandboxName}-home`,
		};
	}

	private async exists(kind: 'container' | 'network', name: string): Promise<boolean> {
		const r = await this.runner.run(this.docker, [kind, 'inspect', '--format', '{{.Name}}', '--', name], { timeoutMs: 15_000 });
		return r.code === 0;
	}

	async ensureRunning(spec: TabRuntimeSpec, connectionToken: string, sensor?: SensorHooks, broker?: BrokerHooks): Promise<void> {
		if (!CONNECTION_TOKEN_RE.test(connectionToken)) {
			throw new DriverError(-32602, 'invalid connection token');
		}
		const n = this.names(spec);
		const label = `seclab.tab=${spec.tabId}`;
		const realBroker = spec.template.spec.broker === 'required';
		if (realBroker && !broker) {
			throw new DriverError(-32011, 'the template requires a broker, but no broker setup was supplied');
		}
		if (!await this.exists('network', n.net)) {
			await this.must(['network', 'create', '--internal', '--label', label, '--', n.net], 'network create');
		}
		if (realBroker) {
			// docs/broker-protocol.md §6: the broker's own egress network (ICC off), plus the pod's
			// --internal network under the alias `broker`, both attached before it starts (the
			// upstream address guard reads the routing table once, at start).
			if (!await this.exists('network', n.egress)) {
				await this.must(['network', 'create', '-o', 'com.docker.network.bridge.enable_icc=false', '--label', label, '--', n.egress], 'egress network create');
			}
			if (!await this.exists('container', n.broker)) {
				await this.must(['create', '--pull', 'never', '--name', n.broker, '--label', label, '--network', n.egress,
					'--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '256', '--memory', '512m',
					'--tmpfs', '/run/seclab:rw,nosuid,nodev,noexec,size=16m,uid=1000,gid=1000,mode=0700',
					'--env', `SECLAB_TAB_ID=${spec.tabId}`, '--', assertImageRef(this.opts.brokerImage)], 'broker create');
				await this.must(['network', 'connect', '--alias', 'broker', '--', n.net, n.broker], 'broker network connect');
			}
			await this.must(['start', '--', n.broker], 'broker start');
		} else if (!await this.exists('container', n.broker)) {
			await this.must(['run', '-d', '--pull', 'never', '--name', n.broker, '--label', label, '--network', n.net,
				'--network-alias', 'broker', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
				'--read-only', '--pids-limit', '64', '--memory', '256m', '--', assertImageRef(this.opts.brokerImage)], 'broker run');
		}
		if (!await this.exists('container', n.ws)) {
			const t = spec.template.spec;
			const user = tabUser(spec);
			const [uid, gid] = user.split(':');
			if (user !== IMAGE_UID) {
				// The per-tab home volume is populated from the image as uid 1000: hand it to the
				// tab user. Throwaway, no network, only this tab's own volume mounted.
				await this.must(['run', '--rm', '--pull', 'never', '--user', '0:0', '--network', 'none', '--cap-drop', 'ALL', '--cap-add', 'CHOWN', '--cap-add', 'DAC_READ_SEARCH',
					'--security-opt', 'no-new-privileges', '--mount', `type=volume,src=${n.home},dst=/home/agent`,
					'--entrypoint', 'chown', '--', assertImageRef(t.image), '-R', user, '/home/agent'], 'home volume chown');
			}
			const args = ['run', '-d', '--pull', 'never', '--init', '--name', n.ws, '--hostname', 'tab', '--label', label,
				'--network', n.net, '--user', user, '--env', 'HOME=/home/agent',
				'--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
				'--pids-limit', '2048', '--memory', t.resources?.memory && /^[1-9][0-9]{0,4}[mg]$/.test(t.resources.memory) ? t.resources.memory : '4g',
				'--read-only', '--tmpfs', '/tmp:rw,nosuid,nodev,size=1g', '--tmpfs', `/run/user/${uid}:rw,nosuid,nodev,uid=${uid},gid=${gid},mode=0700`,
				'--tmpfs', `${BROKER_DIR}:rw,nosuid,nodev,noexec,size=1m,mode=0755`,
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
		// Observability (ADR tab-observability): the host sensor must watch the container before
		// the REH starts. Fail closed if it can't.
		if (sensor?.beforeReh) {
			const id = await this.runner.run(this.docker, ['container', 'inspect', '--format', '{{.Id}}', '--', n.ws]);
			const containerId = id.stdout.trim();
			if (id.code !== 0 || !/^[0-9a-f]{64}$/.test(containerId)) {
				throw new DriverError(-32012, 'could not read the workspace container id');
			}
			try {
				await sensor.beforeReh({ containerId });
			} catch (e) {
				throw new DriverError(-32012, `observability sensor failed: ${(e as Error).message}`);
			}
		}
		if (realBroker) {
			// Plan tabd-broker-wiring B1: the supervisor connects, authenticates and loads policy;
			// the workspace gets the CA and the proxy URL before anything in it starts.
			const setup: BrokerSetup = await broker!.configure(() => this.runner.spawnStream(this.docker, ['exec', '-i', '--', n.broker, 'seclab-broker', 'control']))
				.catch((e: unknown) => {
					throw new DriverError(-32013, `broker setup failed: ${(e as Error).message}`);
				});
			const w = await this.runner.run(this.docker, ['exec', '-i', '-u', '0:0', '--', n.ws, 'sh', '-c', INSTALL_BROKER], { input: brokerInstallInput(setup, BROKER_PROXY), timeoutMs: 30_000 });
			if (w.code !== 0) {
				throw new DriverError(-32013, `could not install the broker CA in the workspace (created before brokers? remove the tab): ${w.stderr.trim().slice(-300)}`);
			}
		}
		const r = await this.runner.run(this.docker, ['exec', '-i', '-u', tabUser(spec), '--', n.ws, REH_START], { input: connectionToken + '\n', timeoutMs: 90_000 });
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
			if (user !== tabUser(spec)) {
				problems.push(`workspace user is ${user}`);
			}
		}
		return { ok: problems.length === 0, problems, checkedAt };
	}

	connectReh(spec: TabRuntimeSpec): ChildProcessWithoutNullStreams {
		const n = this.names(spec);
		return this.runner.spawnStream(this.docker, ['exec', '-i', '-u', tabUser(spec), '--', n.ws, REH_CONNECT]);
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
		if (await this.exists('network', n.egress)) {
			await this.runner.run(this.docker, ['network', 'rm', '--', n.egress], { timeoutMs: 30_000 });
		}
		await this.runner.run(this.docker, ['volume', 'rm', '--', n.home], { timeoutMs: 30_000 });
	}
}
