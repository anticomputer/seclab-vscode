// seclab-tabd entry point. Speaks docs/tabd/PROTOCOL.md over stdin/stdout.
// Usage: seclab-tabd --state-dir ABS [--driver sbx|oci] [--image REF] [--broker-image REF]
//                    [--allowed-root ABS]... [--sensitive ABS]... [--cpus N] [--memory 4g]

import * as fs from 'node:fs';
import * as path from 'node:path';
import { parseArgs } from 'node:util';
import { OciDriver } from './drivers/oci.ts';
import { SbxDriver } from './drivers/sbx.ts';
import type { Driver, TabTemplate } from './drivers/types.ts';
import { cleanEnv, createRunner, resolveBinary } from './run.ts';
import { TabStore } from './state.ts';
import { scanWorkspace } from './scan.ts';
import { Supervisor } from './supervisor.ts';
import { assertImageRef } from './validate.ts';

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
		'broker-image': { type: 'string', default: 'seclab-broker-placeholder:local' },
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
const driverName = values.driver;
if (driverName === 'sbx') {
	if (!sbxPath) {
		die('sbx not found in system locations');
	}
	drivers.set('sbx', new SbxDriver(sbxPath, runner));
} else if (driverName === 'oci') {
	if (!dockerPath) {
		die('docker not found in system locations');
	}
	drivers.set('oci', new OciDriver(dockerPath, runner, { brokerImage: values['broker-image']! }));
} else {
	die(`unknown driver ${driverName}`);
}

const image = assertImageRef(values.image ?? (driverName === 'sbx' ? 'seclab-tab:local' : 'seclab-tab-oci:local'));
const cpus = values.cpus !== undefined ? Number(values.cpus) : undefined;
const template: TabTemplate = {
	kind: 'TabTemplate',
	metadata: { name: 'default' },
	spec: { driver: driverName, image, resources: { cpus, memory: values.memory }, envVarsInjectionPolicy: 'Disallowed', fence: 'required', broker: 'none' },
};

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
	outputBacklog: () => process.stdout.writableLength,
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
});

process.stdin.on('data', (d: Buffer) => supervisor.receive(d));
process.stdin.on('end', () => {
	void supervisor.clientGone().finally(() => process.exit(0));
});
process.on('SIGTERM', () => {
	void supervisor.clientGone().finally(() => process.exit(0));
});
