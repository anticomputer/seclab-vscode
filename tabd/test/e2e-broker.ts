// End-to-end: an OCI tab with a real broker (plan tabd-broker-wiring B1). Local or CI; needs
// docker, seclab-tab-oci:local (./seclab image oci) and a broker image (broker/build.sh).
// Usage: node tabd/test/e2e-broker.ts [broker-image]
// Proves, from inside the tab: an unlisted host is denied by the broker (403), a direct route
// does not exist, a host the user policy allows works through the broker with its CA, the
// proxy refuses requests without the tab's credentials (407), the proxy password is in no log,
// and removing the tab removes the broker's egress network.

import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../src/client.ts';
import { teardownGate, writeManifest, writeSnapshot } from '../../test/containment/teardown.ts';

const brokerImage = process.argv[2] ?? 'seclab-broker:dev';
const repo = path.resolve(import.meta.dirname, '../..');
const work = path.join(repo, '.work', 'e2e-broker');
const state = path.join(work, 'state');
const ws = path.join(work, 'tabs', 'ws1');
fs.mkdirSync(ws, { recursive: true });
fs.mkdirSync(state, { recursive: true, mode: 0o700 });
// The user policy (decision 1: tabd's own state dir, never the workspace): one allowed host.
const ALLOWED = 'api.github.com';
fs.writeFileSync(path.join(state, 'broker-policy.json'), JSON.stringify({
	version: 1, baseline: false, prompt: { enabled: false }, allow: [{ host: ALLOWED, methods: ['GET'] }],
}), { mode: 0o600 });
writeSnapshot(work);
writeManifest(work, { driver: 'oci', stateDirs: [state] });
process.on('exit', code => {
	if (!teardownGate(work) && code === 0) {
		process.exitCode = 1;
	}
});

const client = new TabdClient({
	command: process.execPath,
	args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', state, '--driver', 'oci', '--broker', 'required',
		'--broker-image', brokerImage, '--allowed-root', path.join(work, 'tabs')],
	env: { HOME: process.env.HOME, USER: process.env.USER, PATH: '/usr/bin:/bin' },
});
client.on('stderr', (s: string) => process.stderr.write(`[tabd] ${s}`));

await client.initialize('e2e-broker', '0');
const { tab } = await client.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
const tabId = tab.metadata.name;
writeManifest(work, { tabs: [tabId] });
const ctr = `seclab-${tabId}`;
let failed = false;
try {
	await client.request('tab.ensureRunning', { tabId });
	/** Run a shell snippet in the tab, as the tab user, with the tab's own environment. */
	const inTab = (script: string) => spawnSync('docker', ['exec', '-u', '1000:1000', '--', ctr, '/opt/seclab/bin/seclab-tab-env', 'sh', '-c', script], { encoding: 'utf8', timeout: 60_000 });
	const check = (name: string, fn: () => void) => {
		try {
			fn();
			console.log(`ok   ${name}`);
		} catch (e) {
			failed = true;
			console.log(`FAIL ${name}: ${(e as Error).message}`);
		}
	};

	const env = inTab('printf "%s\\n%s\\n" "$HTTPS_PROXY" "$NODE_EXTRA_CA_CERTS"');
	const [proxyUrl, caPath] = env.stdout.trim().split('\n');
	check('tab environment points at its broker, with the broker CA', () => {
		assert.match(proxyUrl, /^http:\/\/seclab:[A-Za-z0-9_-]{32}@broker:8080$/);
		assert.equal(caPath, '/run/seclab-broker/ca.pem');
	});
	check('an unlisted host is denied by the broker (403, X-Seclab-Broker: denied)', () => {
		const r = inTab('curl -sS -o /dev/null -D - --max-time 20 https://example.com/');
		assert.match(r.stdout, /^HTTP\/[0-9.]+ 403/m, r.stdout + r.stderr);
		assert.match(r.stdout, /^x-seclab-broker: denied/im);
	});
	check('there is no direct route (no proxy: connection fails)', () => {
		const r = inTab(`curl -sS -o /dev/null --noproxy '*' --max-time 10 https://${ALLOWED}/zen`);
		assert.notEqual(r.status, 0, 'direct connection must fail');
	});
	check('the allowed host works through the broker, TLS trusted via the tab CA', () => {
		const r = inTab(`curl -sS -o /dev/null -w '%{http_code}' --max-time 30 https://${ALLOWED}/zen`);
		assert.equal(r.stdout.trim(), '200', r.stderr);
	});
	check('the broker refuses the proxy without the tab credentials (407)', () => {
		const r = inTab(`curl -sS -o /dev/null -w '%{http_code}' --max-time 20 -x http://broker:8080 --proxy-user seclab:wrong-password-xxxxxxxx https://${ALLOWED}/zen`);
		assert.match(r.stdout.trim() + r.stderr, /407/);
	});
	check('a POST to the allowed host is denied (methods are enforced)', () => {
		const r = inTab(`curl -sS -o /dev/null -w '%{http_code}' --max-time 20 -X POST https://${ALLOWED}/zen`);
		assert.equal(r.stdout.trim(), '403');
	});
	check('the proxy password is in no tabd log', () => {
		const pw = /:([A-Za-z0-9_-]{32})@/.exec(proxyUrl)?.[1];
		assert.ok(pw);
		for (const f of fs.readdirSync(state, { recursive: true }) as string[]) {
			const p = path.join(state, f);
			if (fs.statSync(p).isFile()) {
				assert.ok(!fs.readFileSync(p, 'utf8').includes(pw!), `password found in ${f}`);
			}
		}
	});
} finally {
	await client.request('tab.remove', { tabId }).catch(e => {
		failed = true;
		console.log(`remove: ${(e as Error).message}`);
	});
	const nets = execFileSync('docker', ['network', 'ls', '--format', '{{.Name}}'], { encoding: 'utf8' });
	if (nets.includes(`${ctr}-egress`) || nets.includes(`${ctr}-net`)) {
		failed = true;
		console.log('FAIL tab networks left behind after remove');
	}
	client.dispose();
}
console.log(failed ? 'e2e-broker: FAILED' : 'e2e-broker: all checks passed');
process.exitCode = failed ? 1 : 0;
