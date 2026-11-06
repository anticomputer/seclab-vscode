// End-to-end: a tab with a real broker (plan tabd-broker-wiring B1 OCI, B2 sbx). Local or CI;
// needs docker, a broker image (broker/build.sh), and seclab-tab-oci:local (./seclab image oci)
// or the sbx template (./seclab template sbx).
// Usage: node tabd/test/e2e-broker.ts [oci|sbx] [broker-image]   (default: oci seclab-broker:dev)
// Proves, from inside the tab: an unlisted host is denied by the broker (403), a direct route
// does not exist, a host the user policy allows works through the broker with its CA, the
// proxy refuses requests without the tab's credentials (407), the proxy password is in no log,
// and removing the tab removes the broker and its egress network. B3: with prompts on and a
// scripted decider, a prompt before user action carries that flag and a deny holds; a risky
// destination before user action is denied unprompted; an unanswered prompt times out denied;
// after `tab.userAction`, allow-once lets a request through.

import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../src/client.ts';
import { checkFence, parsePolicyJson } from '../src/fence.ts';
import { teardownGate, writeManifest, writeSnapshot } from '../../test/containment/teardown.ts';

const argv = process.argv.slice(2);
const driver = argv[0] === 'sbx' || argv[0] === 'oci' ? argv.shift()! : 'oci';
const brokerImage = argv[0] ?? 'seclab-broker:dev';
const SBX = '/opt/homebrew/bin/sbx';
const repo = path.resolve(import.meta.dirname, '../..');
const work = path.join(repo, '.work', `e2e-broker-${driver}`);
const state = path.join(work, 'state');
const ws = path.join(work, 'tabs', 'ws1');
fs.mkdirSync(ws, { recursive: true });
fs.mkdirSync(state, { recursive: true, mode: 0o700 });
// The user policy (decision 1: tabd's own state dir, never the workspace): one allowed host.
// Prompts on, with a short timeout: this client declares the approvals capability and answers
// them with a scripted decider (B3).
const ALLOWED = 'api.github.com';
const PROMPT_TIMEOUT_S = 8;
fs.writeFileSync(path.join(state, 'broker-policy.json'), JSON.stringify({
	version: 1, baseline: false, prompt: { enabled: true, timeoutSeconds: PROMPT_TIMEOUT_S }, allow: [{ host: ALLOWED, methods: ['GET'] }],
}), { mode: 0o600 });
writeSnapshot(work);
writeManifest(work, { driver, stateDirs: [state] });
process.on('exit', code => {
	if (!teardownGate(work) && code === 0) {
		process.exitCode = 1;
	}
});

const client = new TabdClient({
	command: process.execPath,
	args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', state, '--driver', driver, '--broker', 'required',
		'--broker-image', brokerImage, '--allowed-root', path.join(work, 'tabs')],
	env: { HOME: process.env.HOME, USER: process.env.USER, PATH: '/usr/bin:/bin' },
});
client.on('stderr', (s: string) => process.stderr.write(`[tabd] ${s}`));

await client.initialize('e2e-broker', '0', { approvals: true });
// A host loopback listener standing in for another tab's broker (review ZZ-6): the tab must not
// reach it, directly or as a proxy. A separate process (the checks block this event loop),
// logging each request to a file.
const hitsFile = path.join(work, 'other-listener.hits');
fs.writeFileSync(hitsFile, '');
const other = spawn(process.execPath, ['-e', `const fs=require('fs');const s=require('http').createServer((q,r)=>{fs.appendFileSync(${JSON.stringify(hitsFile)},'hit\\n');r.end('ok')});s.listen(0,'127.0.0.1',()=>console.log(s.address().port))`], { stdio: ['ignore', 'pipe', 'inherit'] });
const otherPort = await new Promise<number>((resolve, reject) => {
	other.stdout.once('data', (d: Buffer) => resolve(Number(d.toString().trim())));
	other.once('exit', () => reject(new Error('listener exited')));
});
const otherHits = () => fs.readFileSync(hitsFile, 'utf8').split('\n').filter(Boolean).length;
process.on('exit', () => other.kill());
const { tab } = await client.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
const tabId = tab.metadata.name;
writeManifest(work, { tabs: [tabId] });
const ctr = `seclab-${tabId}`;
// The scripted decider (B3): answers this tab's prompts by host; null leaves one to time out.
interface Seen { host: string; method: string; flags: string[]; decisions: string[]; resolvedBy?: string; decision?: string }
const seen = new Map<string, Seen>();
const DECIDE: Record<string, string | null> = { 'example.com': 'deny', 'example.org': 'allow-once', 'example.net': null };
client.on('notification', (method: string, p: Record<string, unknown>) => {
	if (p?.tabId !== tabId) {
		return;
	}
	if (method === 'tab.approval') {
		const a = p.approval as { approvalId: string; request: { host: string; method: string }; risk: { flags: string[] }; decisions: string[] };
		seen.set(a.approvalId, { host: a.request.host, method: a.request.method, flags: a.risk.flags, decisions: a.decisions });
		const d = a.request.host in DECIDE ? DECIDE[a.request.host] : 'deny';
		if (d) {
			client.request('tab.approval.decide', { tabId, approvalId: a.approvalId, decision: d }).catch(e => console.log(`decide ${a.request.host}: ${(e as Error).message}`));
		}
	} else if (method === 'tab.approval.resolved') {
		const s = seen.get(String(p.approvalId));
		if (s) {
			s.resolvedBy = String(p.by);
			s.decision = String(p.decision);
		}
	}
});
const prompted = (host: string) => [...seen.values()].filter(s => s.host === host);
let failed = false;
try {
	await client.request('tab.ensureRunning', { tabId });
	/** Run a shell snippet in the tab, as the tab user, with the tab's own environment. */
	const inTab = (script: string) => driver === 'sbx'
		? spawnSync(SBX, ['exec', '-u', 'agent', ctr, '/opt/seclab/bin/seclab-tab-env', 'sh', '-c', script], { encoding: 'utf8', timeout: 60_000 })
		: spawnSync('docker', ['exec', '-u', '1000:1000', '--', ctr, '/opt/seclab/bin/seclab-tab-env', 'sh', '-c', script], { encoding: 'utf8', timeout: 60_000 });
	const check = (name: string, fn: () => void) => {
		try {
			fn();
			console.log(`ok   ${name}`);
		} catch (e) {
			failed = true;
			console.log(`FAIL ${name}: ${(e as Error).message}`);
		}
	};
	/** As `inTab`, without blocking this event loop, so the decider answers prompts meanwhile. */
	const inTabAsync = (script: string) => new Promise<{ status: number | null; stdout: string; stderr: string }>(resolve => {
		const argv = driver === 'sbx'
			? [SBX, 'exec', '-u', 'agent', ctr, '/opt/seclab/bin/seclab-tab-env', 'sh', '-c', script]
			: ['docker', 'exec', '-u', '1000:1000', '--', ctr, '/opt/seclab/bin/seclab-tab-env', 'sh', '-c', script];
		const p = spawn(argv[0], argv.slice(1), { stdio: ['ignore', 'pipe', 'pipe'], timeout: 60_000 });
		let stdout = '';
		let stderr = '';
		p.stdout.on('data', (d: Buffer) => stdout += d.toString('utf8'));
		p.stderr.on('data', (d: Buffer) => stderr += d.toString('utf8'));
		p.on('close', status => resolve({ status, stdout, stderr }));
	});
	const checkAsync = async (name: string, fn: () => Promise<void>) => {
		try {
			await fn();
			console.log(`ok   ${name}`);
		} catch (e) {
			failed = true;
			console.log(`FAIL ${name}: ${(e as Error).message}`);
		}
	};
	const code = async (url: string, extra = '') => (await inTabAsync(`curl -sS -o /dev/null -w '%{http_code}' --max-time 30 ${extra} ${url}`)).stdout.trim();

	const env = inTab('printf "%s\\n%s\\n" "$HTTPS_PROXY" "$NODE_EXTRA_CA_CERTS"');
	const [proxyUrl, caPath] = env.stdout.trim().split('\n');
	const proxyHost = driver === 'sbx' ? /@(host\.docker\.internal:[0-9]{1,5})$/.exec(proxyUrl ?? '')?.[1] : 'broker:8080';
	check('the broker runs the checked image, by ID (XX-6)', () => {
		const want = execFileSync('docker', ['image', 'inspect', '--format', '{{.Id}}', '--', brokerImage], { encoding: 'utf8' }).trim();
		const got = execFileSync('docker', ['container', 'inspect', '--format', '{{.Image}}|{{.Config.Image}}', '--', `${ctr}-broker`], { encoding: 'utf8' }).trim();
		assert.equal(got, `${want}|${want}`);
	});
	check('tab environment points at its broker, with the broker CA', () => {
		assert.match(proxyUrl, driver === 'sbx' ? /^http:\/\/seclab:[A-Za-z0-9_-]{32}@host\.docker\.internal:[1-9][0-9]{0,4}$/ : /^http:\/\/seclab:[A-Za-z0-9_-]{32}@broker:8080$/);
		assert.equal(caPath, '/run/seclab-broker/ca.pem');
	});
	if (driver === 'sbx') {
		check('the broker is published on loopback only, and the fence allows exactly its port', () => {
			const port = Number(proxyHost!.split(':')[1]);
			const published = execFileSync('docker', ['port', '--', `${ctr}-broker`, '8080/tcp'], { encoding: 'utf8' }).trim();
			assert.equal(published, `127.0.0.1:${port}`);
			const rules = parsePolicyJson(execFileSync(SBX, ['policy', 'ls', '--wide', '--json'], { encoding: 'utf8' }));
			assert.deepEqual(checkFence(rules, ctr, port), [], 'every allow but the broker port is denied for this tab');
			const uncovered = checkFence(rules, ctr);
			assert.equal(uncovered.length, 1, uncovered.join('; '));
			assert.ok(uncovered[0].includes(`localhost:${port}`), uncovered[0]);
		});
		check('another loopback port on the host is unreachable from the tab (cross-tab broker isolation)', () => {
			// Control: the listener answers on the host.
			const ctl = spawnSync('curl', ['-sS', '--max-time', '5', `http://127.0.0.1:${otherPort}/`], { encoding: 'utf8' });
			assert.equal(ctl.stdout, 'ok', `control: ${ctl.stderr}`);
			const before = otherHits();
			const r = inTab(`curl -sS -o /dev/null -w '%{http_code}' --max-time 15 --noproxy '*' http://host.docker.internal:${otherPort}/ ; curl -sS -o /dev/null -w '%{http_code}' --max-time 15 -x http://host.docker.internal:${otherPort} http://example.com/`);
			assert.ok(!r.stdout.includes('200') && otherHits() === before, `stdout=${r.stdout} hits=${otherHits() - before}`);
		});
	}
	await checkAsync('B3: an unlisted host is prompted before any user action; the decider denies it (403, X-Seclab-Broker: denied)', async () => {
		const r = await inTabAsync('curl -sS -o /dev/null -D - --max-time 30 https://example.com/');
		assert.match(r.stdout, /^HTTP\/[0-9.]+ 403/m, r.stdout + r.stderr);
		assert.match(r.stdout, /^x-seclab-broker: denied/im);
		const [s] = prompted('example.com');
		assert.ok(s, 'prompted');
		assert.ok(s.flags.includes('no-user-action-yet'), `flags ${s.flags}`);
		assert.deepEqual([s.decision, s.resolvedBy], ['deny', 'controller']);
	});
	await checkAsync('B3: a risky destination before user action is denied without a prompt', async () => {
		assert.equal(await code('https://pastebin.com/'), '403');
		assert.equal(prompted('pastebin.com').length, 0);
	});
	await checkAsync('B3: an unanswered prompt times out and is denied', async () => {
		const t0 = Date.now();
		assert.equal(await code('https://example.net/'), '403');
		assert.ok(Date.now() - t0 >= (PROMPT_TIMEOUT_S - 1) * 1000, 'held until the timeout');
		const [s] = prompted('example.net');
		assert.deepEqual([s?.decision, s?.resolvedBy], ['deny', 'timeout']);
	});
	await checkAsync('a POST to the allowed host is not covered by its GET rule: prompted and denied (methods are enforced)', async () => {
		assert.equal(await code(`https://${ALLOWED}/zen`, '-X POST'), '403');
		assert.ok(prompted(ALLOWED).some(s => s.method === 'POST' && s.decision === 'deny'));
	});
	await checkAsync('B3: after user activity, a prompt carries no "no user action" flag; allow-once lets that request through', async () => {
		await client.request('tab.userAction', { tabId });
		assert.equal(await code('https://example.org/'), '200');
		const [s] = prompted('example.org');
		assert.ok(s && !s.flags.includes('no-user-action-yet'), `flags ${s?.flags}`);
		assert.deepEqual([s.decision, s.resolvedBy], ['allow-once', 'controller']);
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
		const r = inTab(`curl -sS -o /dev/null -w '%{http_code}' --max-time 20 -x http://${proxyHost} --proxy-user seclab:wrong-password-xxxxxxxx https://${ALLOWED}/zen`);
		assert.match(r.stdout.trim() + r.stderr, /407/);
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
	if (spawnSync('docker', ['container', 'inspect', '--', `${ctr}-broker`]).status === 0) {
		failed = true;
		console.log('FAIL broker container left behind after remove');
	}
	client.dispose();
	other.kill();
}
console.log(failed ? 'e2e-broker: FAILED' : 'e2e-broker: all checks passed');
process.exitCode = failed ? 1 : 0;
