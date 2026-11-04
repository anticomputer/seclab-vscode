// Driver contract: the narrow interface every sandbox runtime implements.
// See docs/adr/20261104-tab-supervisor.md.

import type { ChildProcessWithoutNullStreams } from 'node:child_process';

export interface DriverCapabilities {
	readonly isolationClass: 'microvm' | 'namespaces' | 'vm' | 'remote';
	readonly networkFence: 'sbx-policy' | 'internal-network' | 'none';
	readonly liveMounts: boolean;
	readonly holdAndResume: boolean;
	readonly fileWatch: 'native' | 'virtiofs' | 'polling';
	readonly sameAbsolutePathMount: boolean;
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

export interface Driver {
	readonly name: string;
	probe(): Promise<DriverInfo>;
	/** Create if missing (with fence applied atomically where possible), start, install token, start REH. */
	ensureRunning(spec: TabRuntimeSpec, connectionToken: string): Promise<void>;
	/** Re-read the effective network policy and check it against the fence invariant. Must fail closed. */
	verifyFence(spec: TabRuntimeSpec): Promise<FenceReport>;
	/** On fence failure: re-apply whatever fence rules are missing, then stop the sandbox. */
	quarantine(spec: TabRuntimeSpec): Promise<void>;
	/** Open a byte stream to the REH socket inside the sandbox (fixed in-sandbox argv). */
	connectReh(spec: TabRuntimeSpec): ChildProcessWithoutNullStreams;
	stop(spec: TabRuntimeSpec): Promise<void>;
	remove(spec: TabRuntimeSpec): Promise<void>;
}

export class DriverError extends Error {
	readonly code: number;
	constructor(code: number, message: string) {
		super(message);
		this.code = code;
	}
}
