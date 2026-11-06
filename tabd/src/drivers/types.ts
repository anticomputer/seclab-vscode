// Driver contract: the narrow interface every sandbox runtime implements.
// See docs/adr/20261104-tab-supervisor.md.

import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import type { UpperReader } from '../writeback-feed.ts';

export interface DriverCapabilities {
	readonly isolationClass: 'microvm' | 'namespaces' | 'vm' | 'remote';
	readonly networkFence: 'sbx-policy' | 'internal-network' | 'none';
	readonly liveMounts: boolean;
	readonly holdAndResume: boolean;
	readonly fileWatch: 'native' | 'virtiofs' | 'polling';
	readonly sameAbsolutePathMount: boolean;
	/**
	 * Whether tab writes reach the host checkout only through the write-back gate (ADR
	 * write-back-gate). `ungated`: the tab writes the host directly (OCI on Docker Desktop);
	 * the editor must say "write-back not gated" for such tabs.
	 */
	readonly writeBack: 'gated' | 'ungated';
}

export interface DriverInfo {
	readonly name: string;
	readonly available: boolean;
	readonly version?: string;
	readonly reason?: string;
	readonly capabilities: DriverCapabilities;
}

export interface TabTemplate {
	readonly kind: 'TabTemplate';
	readonly metadata: { readonly name: string };
	readonly spec: {
		readonly driver: string;
		readonly image: string;
		readonly resources?: { readonly cpus?: number; readonly memory?: string };
		readonly envVarsInjectionPolicy: 'Disallowed';
		readonly fence: 'required';
		readonly broker: 'required' | 'none';
	};
}

/** What a driver needs to know about a tab. Built by the supervisor from validated state. */
export interface TabRuntimeSpec {
	readonly tabId: string;
	readonly sandboxName: string;
	readonly hostPath: string;
	readonly template: TabTemplate;
	/** Loopback port of this tab's broker, if any (the only fence allow). */
	readonly brokerPort?: number;
}

export interface FenceReport {
	readonly ok: boolean;
	/** Human-readable reasons when !ok. */
	readonly problems: readonly string[];
	readonly checkedAt: string;
}

/**
 * Observability hooks the supervisor hands to a driver (ADR tab-observability). The driver
 * only knows how to spawn its sensor; the supervisor owns parsing, state and fail-closed policy.
 */
export interface SensorHooks {
	/**
	 * sbx: start (or reuse) the in-VM collector and have it start the REH under tracing.
	 * Resolves once the REH is up; rejects (fail closed) otherwise.
	 */
	startCollector?(spawnCollector: () => ChildProcessWithoutNullStreams, connectionToken: string): Promise<void>;
	/** OCI: the workspace container exists; make sure the host sensor watches it before the REH starts. */
	beforeReh?(info: { containerId: string }): Promise<void>;
	/**
	 * The tab's broker endpoint as seen from inside the tab (port, and addresses when the driver
	 * knows them), so detection can tell broker connects from bypass attempts. Driver-supplied.
	 */
	brokerEndpoint?(ep: { port: number; addrs?: readonly string[] }): void;
}

/** What the workspace needs from its configured broker (docs/broker-protocol.md §7). */
export interface BrokerSetup {
	/** The tab CA's public certificate (`ca.get`). */
	readonly caPem: string;
	/** Proxy credentials the tab presents to its own broker (`proxy.auth.set`). */
	readonly proxyUser: string;
	readonly proxyPassword: string;
	/** CFS package feeds (B4): the tab's cfs sentinel when enabled; its npm/pip config is written with it. */
	readonly feedSentinel?: string;
}

/**
 * Broker bring-up the supervisor performs between broker start and REH start (plan
 * tabd-broker-wiring, B1). The driver only knows how to reach the broker's control bridge; the
 * supervisor owns the protocol, the policy and the connection's lifetime.
 */
export interface BrokerHooks {
	/** The broker is running: connect, check, authenticate, load policy, return what the tab needs. */
	configure(openControl: () => ChildProcessWithoutNullStreams, image?: { version: string }): Promise<BrokerSetup>;
}

export interface Driver {
	readonly name: string;
	probe(): Promise<DriverInfo>;
	/** Create if missing (with fence applied atomically where possible), start, install token, start REH. */
	ensureRunning(spec: TabRuntimeSpec, connectionToken: string, sensor?: SensorHooks, broker?: BrokerHooks): Promise<void>;
	/** Re-read the effective network policy and check it against the fence invariant. Must fail closed. */
	verifyFence(spec: TabRuntimeSpec): Promise<FenceReport>;
	/** On fence failure: re-apply whatever fence rules are missing, then stop the sandbox. */
	quarantine(spec: TabRuntimeSpec): Promise<void>;
	/** Open a byte stream to the REH socket inside the sandbox (fixed in-sandbox argv). */
	connectReh(spec: TabRuntimeSpec): ChildProcessWithoutNullStreams;
	/** Names of this driver's sandboxes that are currently running. */
	runningSandboxes(): Promise<Set<string>>;
	stop(spec: TabRuntimeSpec): Promise<void>;
	remove(spec: TabRuntimeSpec): Promise<void>;
	/** Trusted egress decisions the runtime itself made for this tab (sbx: `sbx policy log`). */
	policyLog?(spec: TabRuntimeSpec): Promise<PolicyLogEntry[]>;
	/** Write-back gate (capability writeBack: gated): read the tab's upper layer, as root, directly. */
	upperReader?(spec: TabRuntimeSpec): UpperReader;
	/** CFS package feeds (B4) on a running tab: write (or remove, with no sentinel) its npm/pip config as root. */
	installFeed?(spec: TabRuntimeSpec, sentinel: string | undefined): Promise<void>;
}

export interface PolicyLogEntry {
	readonly decision: 'allowed' | 'blocked';
	readonly host: string;
	readonly proxyType: string;
	readonly count: number;
	readonly reason?: string;
	readonly lastSeen?: string;
}

export class DriverError extends Error {
	readonly code: number;
	constructor(code: number, message: string) {
		super(message);
		this.code = code;
	}
}
