// The consented /copilot_internal/user field-name measurement (ADR broker-model-access,
// Amendment 1). Records the response's TOP-LEVEL FIELD NAMES only, never a value.
//
//   node test/agentic/ahp/user-fields.ts --dry-run   fixture with a canary value in every field
//   node test/agentic/ahp/user-fields.ts --real      the user's real GitHub sign-in (consented)
//
// How no value can be recorded:
// - A per-run broker image whose /copilot_internal/user exception allows no response field, so
//   the broker drops every field before the tab sees the response, and its
//   credential.backstop_exception_filtered audit lists the names (`fields`), never values.
// - The tab sends the sentinel with curl and writes the body to /dev/null; it gets `{}` anyway.
//   No agent host, no extension, no other code runs in the tab, and no model call is made.
// - The run directory keeps only the audit events' names. The dry run proves it: every value
//   it serves is a canary, and the canary must appear nowhere afterwards.
// The real sign-in uses the editor's own GitHub app (VS Code's GitHub client, device-code flow,
// scopes read:user user:email). The token lives only in this process and the broker: it goes
// to the broker in credential.import and is never printed or written.
// Teardown: tab, broker, fixture, network, image; then a token/canary scan and gitleaks.

import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../../../tabd/src/client.ts';
import { connectBroker, type BrokerControl } from '../../../tabd/src/broker-control.ts';
import { teardownGate, writeManifest, writeSnapshot } from '../../containment/teardown.ts';

const mode = process.argv[2];
if (mode !== '--dry-run' && mode !== '--real') {
	console.error('usage: node test/agentic/ahp/user-fields.ts --dry-run|--real');
	process.exit(2);
}
const REAL = mode === '--real';
const SBX = '/opt/homebrew/bin/sbx';
const NODE_IMG = 'node:24.22.1-trixie@sha256:f1e034976f948cf212ef1f659c12e5dd58ac7eab947831813e81a62401ca38be';
const BASE_BROKER = process.env.SECLAB_BROKER_IMAGE ?? 'seclab-broker:dev';
// VS Code's own GitHub authentication client (extensions/github-authentication/src/config.ts
// @ the pinned upstream SHA), which the product signs in with.
const GITHUB_CLIENT_ID = '01ab8ac9400c4e429b23';
const SCOPES = 'read:user user:email';
const HOST = REAL ? 'api.github.com' : 'api.ghe.example.test';
const ROUTE = '/copilot_internal/user';

const repo = path.resolve(import.meta.dirname, '../../..');
const here = import.meta.dirname;
const NONCE = randomBytes(8).toString('hex');
const run = path.join(repo, '.work', 'agentic', 'runs', `${new Date().toISOString().replace(/[-:]|\.\d+/g, '')}-${NONCE}-user-fields${REAL ? '' : '-dry'}`);
const state = path.join(run, 'state');
const tabs = path.join(run, 'tabs');
const ws = path.join(tabs, 'ws1');
const fixtureOut = path.join(run, 'fixture');
fs.mkdirSync(ws, { recursive: true });
fs.mkdirSync(fixtureOut, { recursive: true });
fs.mkdirSync(state, { recursive: true, mode: 0o700 });
const SENTINEL = `seclab_sentinel_github_${NONCE}${randomBytes(8).toString('hex')}`;
const CANARY = `seclabcanary_value_${NONCE}`;
const NET = `seclab-uf-${NONCE}`;
const FIXTURE = `seclab-uf-${NONCE}-fixture`;
const BROKER_IMG = `seclab-broker-uf-${NONCE}:local`;
const SUBNET = `11.251.${64 + (randomBytes(1)[0] % 180)}.0/24`;
fs.writeFileSync(path.join(run, 'run.json'), JSON.stringify({ nonce: NONCE, mode: REAL ? 'real' : 'dry-run', host: HOST, route: ROUTE, baseBroker: BASE_BROKER }, null, 1));
writeSnapshot(run);
writeManifest(run, { driver: 'sbx', stateDirs: [state], workspaces: [ws] });

const docker = (...a: string[]) => execFileSync('docker', a, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
const dockerQuiet = (...a: string[]) => spawnSync('docker', a, { encoding: 'utf8' });
const cleanups: (() => void)[] = [];
let failed = false;
const note = (s: string) => console.log(`[user-fields] ${s}`);

/** Device-code sign-in with the editor's GitHub app. Prints only the user code and URL. */
async function signIn(): Promise<string> {
	const post = async (url: string, body: Record<string, string>) => {
		const r = await fetch(url, { method: 'POST', headers: { accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(body) });
		return await r.json() as Record<string, unknown>;
	};
	const dc = await post('https://github.com/login/device/code', { client_id: GITHUB_CLIENT_ID, scope: SCOPES }); // fixture-lint: allow non-test-host -- consented real sign-in (--real only)
	if (typeof dc.device_code !== 'string' || typeof dc.user_code !== 'string') {
		throw new Error(`device code request failed: ${String(dc.error ?? 'no device code')}`);
	}
	note(`SIGN-IN: open ${String(dc.verification_uri)} and enter the code ${dc.user_code} (expires in ${String(dc.expires_in)}s)`);
	let interval = Number(dc.interval ?? 5);
	const deadline = Date.now() + Number(dc.expires_in ?? 900) * 1000;
	while (Date.now() < deadline) {
		await new Promise(r => setTimeout(r, interval * 1000));
		const t = await post('https://github.com/login/oauth/access_token', { client_id: GITHUB_CLIENT_ID, device_code: dc.device_code, grant_type: 'urn:ietf:params:oauth:grant-type:device_code' }); // fixture-lint: allow non-test-host -- consented real sign-in (--real only)
		if (typeof t.access_token === 'string') {
			note('signed in (token held in memory only)');
			return t.access_token;
		}
		if (t.error === 'slow_down') {
			interval += 5;
		} else if (t.error !== 'authorization_pending') {
			throw new Error(`sign-in failed: ${String(t.error)}`);
		}
	}
	throw new Error('sign-in timed out');
}

let client: TabdClient | undefined;
let tabId = '';
let ctl: BrokerControl | undefined;
let secret = '';
const measured: Record<string, unknown>[] = [];
try {
	// 1. Dry run only: an internal network and a fixture serving canary values.
	let caFile: string | undefined;
	if (!REAL) {
		docker('network', 'create', '--internal', '--subnet', SUBNET, '--label', `seclab.uf=${NONCE}`, '--', NET);
		cleanups.push(() => void dockerQuiet('network', 'rm', NET));
		docker('run', '-d', '--rm', '--name', FIXTURE, '--label', `seclab.uf=${NONCE}`, '--network', NET, '--network-alias', HOST,
			'-u', `${process.getuid!()}:${process.getgid!()}`, '--sysctl', 'net.ipv4.ip_unprivileged_port_start=0', '--cap-drop', 'ALL',
			'--security-opt', 'no-new-privileges', '--read-only',
			'--tmpfs', `/run/fixture-tls:rw,noexec,nosuid,size=4m,mode=0700,uid=${process.getuid!()},gid=${process.getgid!()}`, '-e', 'HOME=/run/fixture-tls',
			'-v', `${path.join(here, 'user-fields-fixture.mjs')}:/fx/fixture.mjs:ro`, '-v', `${fixtureOut}:/out`,
			'-e', `NONCE=${NONCE}`, '-e', 'OUT=/out', NODE_IMG, 'node', '/fx/fixture.mjs');
		cleanups.unshift(() => void dockerQuiet('rm', '-f', FIXTURE));
		caFile = path.join(fixtureOut, 'ca.pem');
		for (let i = 0; i < 100 && !fs.existsSync(caFile); i++) {
			await new Promise(r => setTimeout(r, 200));
		}
		if (!fs.existsSync(caFile)) {
			throw new Error('fixture never wrote its CA');
		}
	}

	// 2. A per-run broker image: the shipped broker, with the /user exception allowing no field
	// (every field is dropped and named in the audit), plus the fixture CA in the dry run.
	const ctx = path.join(run, 'broker-image');
	fs.mkdirSync(ctx);
	const gh = JSON.parse(fs.readFileSync(path.join(repo, 'broker/seclab_broker/data/providers/github.json'), 'utf8'));
	const userExc = gh.exceptions.find((e: { path: string }) => e.path === ROUTE);
	userExc.responseFields = [];
	userExc.strictFields = false;
	fs.writeFileSync(path.join(ctx, 'github.json'), JSON.stringify(gh, null, 1));
	const lines = [`FROM ${BASE_BROKER}`, 'COPY github.json /opt/seclab/seclab_broker/data/providers/github.json'];
	if (caFile) {
		fs.copyFileSync(caFile, path.join(ctx, 'ca.pem'));
		lines.push('COPY ca.pem /etc/seclab-uf-ca.pem',
			'ENTRYPOINT ["sh", "-c", "SECLAB_EXTRA_UPSTREAM_CA_PEM=\\"$(cat /etc/seclab-uf-ca.pem)\\" exec seclab-broker \\"$@\\"", "seclab-broker"]', 'CMD ["run"]');
	}
	fs.writeFileSync(path.join(ctx, 'Dockerfile'), lines.join('\n') + '\n');
	docker('build', '-q', '--label', `seclab.uf=${NONCE}`, '--label', 'io.seclab.broker.derived=measurement-only', '-t', BROKER_IMG, ctx);
	cleanups.push(() => void dockerQuiet('image', 'rm', '-f', BROKER_IMG));

	// 3. A fresh sbx tab behind that broker. Its policy allows exactly the one route.
	const policy = { version: 1, baseline: false, prompt: { enabled: false }, allow: [{ id: 'user', host: HOST, methods: ['GET'], path: ROUTE }] };
	fs.writeFileSync(path.join(state, 'broker-policy.json'), JSON.stringify(policy), { mode: 0o600 });
	client = new TabdClient({
		command: process.execPath,
		args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', state, '--driver', 'sbx', '--broker', 'required', '--broker-image', BROKER_IMG, '--allowed-root', tabs],
		env: { HOME: process.env.HOME, USER: process.env.USER, PATH: '/usr/bin:/bin' },
	});
	client.on('stderr', (s: string) => process.stderr.write(`[tabd] ${s}`));
	await client.initialize('user-fields-measurement', '0');
	const { tab } = await client.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
	tabId = tab.metadata.name;
	writeManifest(run, { tabs: [tabId] });
	await client.request('tab.ensureRunning', { tabId });
	const ctr = `seclab-${tabId}`;
	const broker = `${ctr}-broker`;
	if (!REAL) {
		docker('network', 'connect', NET, broker);
		const ip = docker('exec', broker, 'python3', '-c', `import socket,sys;print(' '.join(sorted({a[4][0] for a in socket.getaddrinfo(sys.argv[1], 443)})))`, HOST);
		if (!ip || ip.split(' ').some(a => !a.startsWith(SUBNET.replace(/0\/24$/, '')))) {
			throw new Error(`${HOST} resolved to ${ip || 'nothing'}, not inside ${SUBNET}`);
		}
	}
	note(`tab ${tabId} up behind ${broker}`);
	ctl = await connectBroker(() => spawn('docker', ['exec', '-i', broker, 'seclab-broker', 'control'], { stdio: ['pipe', 'pipe', 'pipe'] }), tabId);
	const audit: Record<string, unknown>[] = [];
	ctl.onNotification(n => {
		if (n.method === 'audit.event') {
			audit.push(n.params as Record<string, unknown>);
		}
	});

	// 4. The credential: the user's sign-in (real) or a canary (dry run), into the broker only.
	secret = REAL ? await signIn() : `${CANARY}_token`;
	await ctl.request('credential.import', {
		id: 'github', value: secret, sentinel: SENTINEL, provider: 'github', source: { kind: 'host' },
		inject: { header: 'Authorization', fmt: 'Bearer {value}' }, bind: [{ host: HOST, path: ROUTE, methods: ['GET'] }],
	});

	// 5. In the tab: the two request shapes the product sends (the agent host sets
	// X-GitHub-Api-Version, the runtime doesn't). Bodies go to /dev/null; only status codes print.
	const curl = (extra: string) => `curl -sS -o /dev/null -w '%{http_code}\\n' -H 'Authorization: Bearer ${SENTINEL}' -H 'Accept: application/json' ${extra} https://${HOST}${ROUTE}`;
	const r = spawnSync(SBX, ['exec', '-u', 'agent', ctr, '/opt/seclab/bin/seclab-tab-env', 'sh', '-c',
		`${curl('')}; ${curl("-H 'X-GitHub-Api-Version: 2025-04-01'")}`], { encoding: 'utf8', timeout: 120_000 });
	const codes = r.stdout.trim().split('\n');
	await new Promise(res => setTimeout(res, 1000));
	const relevant = audit.filter(e => String(e.type).startsWith('credential.backstop_exception') || e.type === 'request.denied' || e.type === 'sentinel.misplaced');
	['without X-GitHub-Api-Version', 'with X-GitHub-Api-Version: 2025-04-01'].forEach((label, i) => {
		const e = relevant.filter(x => String(x.type).startsWith('credential.backstop_exception'))[i];
		measured.push({ request: label, tabStatus: codes[i] ?? null, audit: e?.type ?? null, reason: e?.reason ?? null, fields: e?.fields ?? null });
	});
	const other = relevant.filter(x => !String(x.type).startsWith('credential.backstop_exception')).map(x => ({ type: x.type, reason: x.reason }));
	fs.writeFileSync(path.join(run, 'measured.json'), JSON.stringify({ nonce: NONCE, mode: REAL ? 'real' : 'dry-run', host: HOST, route: ROUTE, source: 'broker audit `fields` (names only)', requests: measured, otherEvents: other }, null, 1));
	note(`measured: ${JSON.stringify(measured)}`);
	if (measured.some(m => !Array.isArray(m.fields))) {
		failed = true;
		note('FAIL no field names captured for a request');
	}

	// 6. Leak check before the broker goes: the secret, and (dry run) every canary value, must
	// appear in no file of the run, in the broker's own log, or in its audit.
	const brokerLog = dockerQuiet('logs', broker);
	const haystacks: [string, string][] = [['broker log', brokerLog.stdout + brokerLog.stderr], ['audit', JSON.stringify(audit)]];
	const walk = (d: string) => {
		for (const ent of fs.readdirSync(d, { withFileTypes: true })) {
			const p = path.join(d, ent.name);
			if (ent.isDirectory()) {
				walk(p);
			} else if (ent.isFile() && fs.statSync(p).size < 8 << 20) {
				haystacks.push([path.relative(run, p), fs.readFileSync(p, 'latin1')]);
			}
		}
	};
	walk(run);
	const needles = REAL ? [secret] : [secret, CANARY];
	for (const [where, text] of haystacks) {
		for (const nd of needles) {
			if (text.includes(nd)) {
				failed = true;
				note(`FAIL ${nd === secret ? 'the credential' : 'a canary value'} found in ${where}`);
			}
		}
	}
	if (!failed) {
		note(`leak check: no ${REAL ? 'credential' : 'credential or canary value'} in ${haystacks.length} places (broker log, audit, run files)`);
	}
} catch (e) {
	failed = true;
	console.log(`FAIL ${String((e as Error).message ?? e).split(secret || '\0').join('[redacted]')}`);
} finally {
	secret = '';
	ctl?.close();
	if (client && tabId) {
		await client.request('tab.remove', { tabId }).catch(e => {
			failed = true;
			console.log(`remove: ${(e as Error).message}`);
		});
	}
	client?.dispose();
	for (const c of cleanups) {
		c();
	}
	const left = [dockerQuiet('ps', '-aq', '--filter', `label=seclab.uf=${NONCE}`).stdout.trim(), dockerQuiet('network', 'ls', '-q', '--filter', `label=seclab.uf=${NONCE}`).stdout.trim(),
		dockerQuiet('image', 'ls', '-q', '--filter', `label=seclab.uf=${NONCE}`).stdout.trim()].filter(Boolean);
	if (left.length) {
		failed = true;
		console.log(`FAIL resources left: ${left.join(' ')}`);
	}
	fs.rmSync(path.join(run, 'broker-image'), { recursive: true, force: true });
	if (!teardownGate(run)) {
		failed = true;
	}
	console.log(`run: ${run}`);
	process.exit(failed ? 1 : 0);
}
