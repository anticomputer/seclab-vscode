// seclab-tabd entry point. Speaks docs/tabd/PROTOCOL.md over stdin/stdout.
// Usage: seclab-tabd --state-dir ABS [--driver sbx|oci] [--image REF] [--broker required|none]
//                    [--broker-image REF] [--broker-dev]
//                    [--allowed-root ABS]... [--sensitive ABS]... [--cpus N] [--memory 4g]

import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { parseArgs } from 'node:util';
import { OciDriver } from './drivers/oci.ts';
import { SbxDriver } from './drivers/sbx.ts';
import type { Driver, TabTemplate } from './drivers/types.ts';
import { FalcoSensor } from './obs/falco.ts';
import type { ObsHub } from './obs/hub.ts';
import { cleanEnv, createRunner, resolveBinary } from './run.ts';
import { TabStore } from './state.ts';
import { scanWorkspace } from './scan.ts';
import { Supervisor } from './supervisor.ts';
import { assertImageRef } from './validate.ts';
import { tabPolicy } from './broker-policy.ts';
import { CfsTokenSource, loadCfsFeeds } from './cfs.ts';
import { BrokerImagePin } from './broker-image.ts';

// 1. Only the framer may write to stdout; everything else goes to stderr.
const realStdoutWrite = process.stdout.write.bind(process.stdout);
process.stdout.write = ((chunk: unknown, ...rest: unknown[]) => process.stderr.write(chunk as string, ...(rest as []))) as typeof process.stdout.write;
for (const k of ['log', 'info', 'warn', 'error', 'debug'] as const) {
	console[k] = (...a: unknown[]) => { process.stderr.write(a.map(String).join(' ') + '\n'); };
}

// 2. Wipe the inherited environment (it may carry tokens, ELECTRON_RUN_AS_NODE, ...).
const childEnv = cleanEnv(process.env);
const sbxPath = resolveBinary('sbx');
const dockerPath = resolveBinary('docker');
for (const k of Object.keys(process.env)) {
	delete process.env[k];
}

const { values } = parseArgs({
	options: {
		'state-dir': { type: 'string' },
		'driver': { type: 'string', default: 'sbx' },
		'image': { type: 'string' },
		'broker-image': { type: 'string' },
		// `required` (the default): each tab gets a real broker (plan tabd-broker-wiring B1 OCI,
		// B2 sbx). `none` keeps the placeholder (OCI) and blackhole egress.
		'broker': { type: 'string' },
		// Accept a broker image built from uncommitted broker sources (a `-dirty` revision).
		'broker-dev': { type: 'boolean' },
		'allowed-root': { type: 'string', multiple: true, default: [] },
		'sensitive': { type: 'string', multiple: true, default: [] },
		'cpus': { type: 'string' },
		'memory': { type: 'string' },
		'fence-reverify-ms': { type: 'string' },
		// Stopped tabs unused this long are removed at initialize (0 disables).
		'gc-days': { type: 'string', default: '30' },
	},
	strict: true,
});

function die(msg: string): never {
	process.stderr.write(`seclab-tabd: ${msg}\n`);
	process.exit(2);
}

const stateDir = values['state-dir'];
if (!stateDir || !path.isAbsolute(stateDir)) {
	die('--state-dir must be an absolute path');
}
fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
process.chdir(stateDir);
const auditLog = fs.openSync(path.join(stateDir, 'audit.log'), 'a', 0o600);

const runner = createRunner((action, outcome, detail) => {
	fs.writeSync(auditLog, JSON.stringify({ ts: new Date().toISOString(), action, outcome, ...detail }) + '\n');
}, childEnv, stateDir);

const drivers = new Map<string, Driver>();
let hostSensor: ((hub: ObsHub) => FalcoSensor) | undefined;
const driverName = values.driver;
// The real broker's image, resolved once to its content-addressed ID and checked against the
// labels broker/build.sh stamps (review XX-6); every broker container is created by that ID.
const brokerRef = assertImageRef(values['broker-image'] ?? 'seclab-broker:dev');
const brokerPin = dockerPath ? new BrokerImagePin(runner, dockerPath, brokerRef, { allowDirty: values['broker-dev'] === true }) : undefined;
if (driverName === 'sbx') {
	if (!sbxPath) {
		die('sbx not found in system locations');
	}
	// Plan tabd-broker-wiring B2: the broker runs on Docker Desktop beside the sbx VM.
	drivers.set('sbx', new SbxDriver(sbxPath, runner, { docker: dockerPath, brokerPin }));
} else if (driverName === 'oci') {
	if (!dockerPath) {
		die('docker not found in system locations');
	}
	// `--broker none` runs the placeholder (`--broker-image` names it in that mode).
	const placeholder = values.broker === 'none' && values['broker-image'] ? brokerRef : 'seclab-broker-placeholder:local';
	drivers.set('oci', new OciDriver(dockerPath, runner, { brokerImage: placeholder, brokerPin }));
	// Tab observability: Falco on the Docker host, only while OCI tabs run (ADR tab-observability).
	const stateTag = createHash('sha256').update(stateDir).digest('hex').slice(0, 8);
	hostSensor = hub => new FalcoSensor({
		hub, rulesDir: path.join(stateDir, 'falco'), name: `seclab-falco-${stateTag}-${process.pid}`,
		labels: { 'seclab.obs': 'falco', 'seclab.state': stateTag, 'seclab.pid': String(process.pid) },
		spawnDocker: args => runner.spawnStream(dockerPath, args),
		runDocker: args => runner.run(dockerPath, args, { timeoutMs: 60_000 }),
		pidAlive: pid => {
			try {
				process.kill(pid, 0);
				return true;
			} catch (e) {
				return (e as NodeJS.ErrnoException).code === 'EPERM';
			}
		},
	});
} else {
	die(`unknown driver ${driverName}`);
}

const image = assertImageRef(values.image ?? (driverName === 'sbx' ? 'seclab-tab:local' : 'seclab-tab-oci:local'));
const cpus = values.cpus !== undefined ? Number(values.cpus) : undefined;
const brokerArg = values.broker ?? 'required';
const brokerMode = brokerArg === 'required' ? 'required' : brokerArg === 'none' ? 'none' : die('--broker must be none or required');
if (brokerMode === 'required' && driverName === 'sbx' && !dockerPath) {
	die('--broker required on sbx needs docker (the broker runs on Docker Desktop)');
}
const template: TabTemplate = {
	kind: 'TabTemplate',
	metadata: { name: 'default' },
	spec: { driver: driverName, image, resources: { cpus, memory: values.memory }, envVarsInjectionPolicy: 'Disallowed', fence: 'required', broker: brokerMode },
};

const cfsLoaded = loadCfsFeeds();
if ('problem' in cfsLoaded) {
	// Feeds stay off; the message names the reason, never a value (EDR cfs-config-outside-repo).
	process.stderr.write(`tabd: CFS package feeds off: ${cfsLoaded.problem}\n`);
}
const supervisor = new Supervisor({
	drivers,
	templates: new Map([['default', template]]),
	store: new TabStore(stateDir),
	write: chunk => { realStdoutWrite(chunk); },
	onFatal: reason => {
		process.stderr.write(`seclab-tabd: fatal protocol error: ${reason}\n`);
		void supervisor.clientGone().finally(() => process.exit(3));
	},
	audit: entry => fs.writeSync(auditLog, JSON.stringify(entry) + '\n'),
	eventsDir: path.join(stateDir, 'events'),
	writebackDir: path.join(stateDir, 'writeback'),
	outputBacklog: () => process.stdout.writableLength,
	hostSensor,
	fenceReverifyMs: values['fence-reverify-ms'] ? Number(values['fence-reverify-ms']) : undefined,
	gcDays: /^[0-9]{1,4}$/.test(values['gc-days']!) ? Number(values['gc-days']) : die('--gc-days must be a whole number of days'),
	pathPolicy: {
		allowedRoots: values['allowed-root'],
		// The state dir and the real locations of the runtime CLIs we execute.
		sensitive: [stateDir, ...values.sensitive!, ...[sbxPath, dockerPath].flatMap(p => {
			if (!p) {
				return [];
			}
			const real = fs.realpathSync.native(p);
			return [path.dirname(p), path.dirname(real)];
		})],
	},
	// Pre-mount secret scan (gitleaks in a network-less container). Without docker the
	// scan is unavailable and opens fail closed unless the user records an exception.
	scan: dockerPath ? (hostPath: string) => scanWorkspace(runner, dockerPath, hostPath) : undefined,
	// The user's broker policy from this state dir, else deny-all (plan tabd-broker-wiring, decision 1).
	brokerPolicy: (tabId, o) => tabPolicy(stateDir, tabId, o.prompts),
	// CFS package feeds (B4): the host's CFS config names the feeds; its az mints the token, in
	// memory only; off per tab until the user enables it, and off everywhere without a config.
	...('feeds' in cfsLoaded ? { cfs: new CfsTokenSource(cfsLoaded.feeds) } : {}),
});

process.stdin.on('data', (d: Buffer) => supervisor.receive(d));
process.stdin.on('end', () => {
	void supervisor.clientGone().finally(() => process.exit(0));
});
process.on('SIGTERM', () => {
	void supervisor.clientGone().finally(() => process.exit(0));
});
