// Agents-in-the-tab spike, step 3 (plan §11.1, EDR 20261105-agents-in-tab-spike): the shipped
// agent host in a REAL sbx tab, behind that tab's REAL broker, against a fake GitHub Enterprise
// + Copilot API. No real credential exists anywhere: the broker holds a fake seclabcanary_
// GitHub value, the tab holds only the sentinel, and the fixture mints a fake Copilot token
// that the broker re-sentinelises (D7 derive). Measures what the runtime actually sends.
//
//   node test/agentic/ahp/tab-spike.ts            (needs sbx, docker, seclab-tab:local, seclab-broker:dev)
//
// Two broker policies, one agent-host run each:
//   A  plain allows for the fixture hosts: the fixture records the raw request shapes;
//   B  capi.example.test declared as a provider with the broker's DRAFT copilot lists, so
//      the broker's own model.call / model.denied audit shows what the draft would refuse.
// Writes .work/agentic/runs/<ts>-<nonce>-tab/. Teardown: tab, broker, fixture, network, image.

import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../../../tabd/src/client.ts';
import { connectBroker, type BrokerControl } from '../../../tabd/src/broker-control.ts';
import { teardownGate, treeTexts, writeManifest, writeSnapshot } from '../../containment/teardown.ts';
import { avFindings } from '../../safety/av-shape.ts';

const SBX = '/opt/homebrew/bin/sbx';
const NODE_IMG = 'node:24.22.1-trixie@sha256:f1e034976f948cf212ef1f659c12e5dd58ac7eab947831813e81a62401ca38be';
const BASE_BROKER = process.env.SECLAB_BROKER_IMAGE ?? 'seclab-broker:dev';
const GHE = 'ghe.example.test';
const GHE_API = `api.${GHE}`;
const CAPI = 'capi.example.test';
// The broker's credential-name pattern for exception-route responses, read from its source so the
// fixture strips exactly what the broker would block (and records it).
const repo = path.resolve(import.meta.dirname, '../../..');
const here = import.meta.dirname;
const NONCE = randomBytes(8).toString('hex');
const run = path.join(repo, '.work', 'agentic', 'runs', `${new Date().toISOString().replace(/[-:]|\.\d+/g, '')}-${NONCE}-tab`);
const state = path.join(run, 'state');
const tabs = path.join(run, 'tabs');
const ws = path.join(tabs, 'ws1');
const fixtureOut = path.join(run, 'fixture');
for (const d of [ws, fixtureOut]) {
	fs.mkdirSync(d, { recursive: true });
}
fs.mkdirSync(state, { recursive: true, mode: 0o700 });

// Fake values only (fixture-safety EDR). GH_FAKE plays the user's real GitHub token: it lives in
// the broker and the fixture, never in the tab. The tab gets SENTINEL.
const GH_FAKE = `seclabcanary_github_${NONCE}`;
const CP_MINT = `seclabcanary_copilot_${NONCE}`;
const SENTINEL = `seclab_sentinel_github_${NONCE}${randomBytes(8).toString('hex')}`;
const AH_TOKEN = `ah-${randomBytes(16).toString('hex')}`;
const NET = `seclab-spike-${NONCE}`;
const FIXTURE = `seclab-spike-${NONCE}-capi`;
const BROKER_IMG = `seclab-broker-spike-${NONCE}:local`;
const SUBNET = `11.250.${64 + (randomBytes(1)[0] % 180)}.0/24`;

const upstream = Object.fromEntries(fs.readFileSync(path.join(repo, 'upstream.lock'), 'utf8').split('\n').filter(l => /^[A-Z_]+=/.test(l)).map(l => l.split('=', 2).map(s => s.replace(/^"|"$/g, ''))));
fs.writeFileSync(path.join(run, 'spike.json'), JSON.stringify({ nonce: NONCE, upstream: upstream.UPSTREAM_SHA, fixtureImage: NODE_IMG, baseBroker: BASE_BROKER, subnet: SUBNET, hosts: [GHE, GHE_API, CAPI] }, null, 1));
writeSnapshot(run);
// The tab writes into ws (hostile content on a host path): teardown owns and deletes it.
writeManifest(run, { driver: 'sbx', stateDirs: [state], workspaces: [ws] });

const docker = (...a: string[]) => execFileSync('docker', a, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
const dockerQuiet = (...a: string[]) => spawnSync('docker', a, { encoding: 'utf8' });
const cleanups: (() => void)[] = [];
let failed = false;
const note = (s: string) => console.log(`[spike] ${s}`);

function policy(phase: 'A' | 'B'): Record<string, unknown> {
	const p: Record<string, unknown> = {
		version: 1, baseline: false, prompt: { enabled: false },
		allow: [{ id: 'fixture-ghe', host: GHE, methods: ['GET', 'POST'] }, { id: 'fixture-ghe-api', host: GHE_API, methods: ['GET', 'POST'] }, { id: 'fixture-capi', host: CAPI, methods: ['GET', 'POST'] }],
	};
	if (phase === 'B') {
		const draft = (JSON.parse(fs.readFileSync(path.join(repo, 'broker/seclab_broker/data/model-providers.v1.json'), 'utf8')).providers as { id: string }[]).find(x => x.id === 'copilot')!;
		p.models = { providers: [{ ...draft, id: 'spike-copilot-draft', hosts: [CAPI] }] };
	}
	return p;
}

let client: TabdClient | undefined;
let tabId = '';
let ctl: BrokerControl | undefined;

/**
 * The measurement, from host-side sources only (fixture log, broker audit), never from the
 * tab-written report: per route, the fields, tool types and headers the runtime sent, and the
 * difference from the broker's draft copilot provider.
 */
function summarise(phases: Record<string, { audit: Record<string, unknown>[] }>) {
	type Req = { host: string; method: string; path: string; auth: string; status: number; queryKeys: string[]; headers: Record<string, string>; probeInBody: boolean; body?: { topLevel?: string[]; tools?: { type: string | null; name: string | null }[]; typeValues?: string[]; keyPaths?: string[] } };
	const reqs = fs.readFileSync(path.join(fixtureOut, 'requests.jsonl'), 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l) as Req);
	const routes: Record<string, Record<string, unknown>> = {};
	const add = (o: Record<string, unknown>, k: string, vs: Iterable<string>) => {
		o[k] = [...new Set([...(o[k] as string[] ?? []), ...vs])].sort();
	};
	const SHOW = ['user-agent', 'copilot-integration-id', 'copilot-harness-id', 'openai-intent', 'x-github-api-version', 'editor-version', 'x-interaction-type', 'x-initiator', 'accept', 'content-type'];
	for (const r of reqs) {
		const key = `${r.method} ${r.host}${r.path}`;
		const o = routes[key] ??= { count: 0, toolTypes: {} as Record<string, number> };
		o.count = (o.count as number) + 1;
		add(o, 'status', [String(r.status)]);
		add(o, 'credential', [r.auth.split(' ').slice(1).join(' ')]);
		add(o, 'queryKeys', r.queryKeys);
		add(o, 'headerNames', Object.keys(r.headers));
		add(o, 'headerValues', SHOW.filter(h => r.headers[h] && r.headers[h] !== '(present)').map(h => `${h}: ${r.headers[h]}`));
		if (r.probeInBody) {
			o.toolResultRoundTrips = ((o.toolResultRoundTrips as number) ?? 0) + 1;
		}
		if (r.body?.topLevel) {
			add(o, 'topLevelFields', r.body.topLevel);
			add(o, 'messageTypeValues', (r.body.typeValues ?? []).filter(t => !t.startsWith('tools[]')));
			add(o, 'messageKeyPaths', (r.body.keyPaths ?? []).filter(t => !t.startsWith('tools')));
			const tt = o.toolTypes as Record<string, number>;
			for (const t of r.body.tools ?? []) {
				tt[String(t.type)] = Math.max(tt[String(t.type)] ?? 0, (r.body.tools ?? []).filter(x => x.type === t.type).length);
			}
			add(o, 'toolNames', (r.body.tools ?? []).map(t => `${t.type}:${t.name ?? ''}`));
		}
	}
	const draft = (JSON.parse(fs.readFileSync(path.join(repo, 'broker/seclab_broker/data/model-providers.v1.json'), 'utf8')).providers as { id: string; endpoints: { path: string; methods: string[] }[]; fields: string[]; toolTypes?: string[] }[]).find(x => x.id === 'copilot')!;
	const capi = Object.entries(routes).filter(([k]) => k.includes(` ${CAPI}/`));
	const vsDraft = {
		endpointsNotInDraft: capi.map(([k]) => k.split(' ')).filter(([m, u]) => !draft.endpoints.some(e => e.path === u.slice(CAPI.length) && e.methods.includes(m))).map(x => x.join(' ')),
		fieldsNotInDraft: [...new Set(capi.flatMap(([, o]) => (o.topLevelFields as string[] ?? []).filter(f => !draft.fields.includes(f))))].sort(),
		toolTypesNotInDraft: [...new Set(capi.flatMap(([, o]) => Object.keys(o.toolTypes as object).filter(t => !(draft.toolTypes ?? []).includes(t))))].sort(),
		draftFieldsNeverSent: draft.fields.filter(f => !capi.some(([, o]) => (o.topLevelFields as string[] ?? []).includes(f))),
	};
	const brokerDecisions = Object.fromEntries(Object.entries(phases).map(([p, v]) => [p, [...new Set(v.audit
		.filter(e => /^(model\.|request\.denied|sentinel\.|response\.blocked|credential\.(derived|backstop))/.test(String(e.type)))
		.map(e => JSON.stringify(Object.fromEntries(['type', 'method', 'host', 'path', 'reason', 'detail', 'status', 'provider', 'tools'].filter(k => e[k] !== undefined).map(k => [k, e[k]])))))].map(s => JSON.parse(s))]));
	let userShape: unknown;
	try {
		userShape = JSON.parse(fs.readFileSync(path.join(fixtureOut, 'user-shape.json'), 'utf8'));
	} catch { /* never served */ }
	return { nonce: NONCE, upstream: upstream.UPSTREAM_SHA, source: 'fixture log + broker audit (host-side)', routes, vsDraft, brokerDecisions, userShape };
}
try {
	// 1. Fixture: internal network (no route out), *.test aliases resolved by Docker's embedded DNS.
	docker('network', 'create', '--internal', '--subnet', SUBNET, '--label', `seclab.spike=${NONCE}`, '--', NET);
	cleanups.push(() => void dockerQuiet('network', 'rm', NET));
	docker('run', '-d', '--rm', '--name', FIXTURE, '--label', `seclab.spike=${NONCE}`, '--network', NET,
		'--network-alias', GHE, '--network-alias', GHE_API, '--network-alias', CAPI, '-u', `${process.getuid!()}:${process.getgid!()}`,
		'--sysctl', 'net.ipv4.ip_unprivileged_port_start=0', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--read-only',
		'--tmpfs', `/run/fixture-tls:rw,noexec,nosuid,size=4m,mode=0700,uid=${process.getuid!()},gid=${process.getgid!()}`, '-e', 'HOME=/run/fixture-tls',
		'-v', `${path.join(here, 'fake-capi.mjs')}:/fx/fake-capi.mjs:ro`, '-v', `${fixtureOut}:/out`,
		'-e', `NONCE=${NONCE}`, '-e', `GH_FAKE=${GH_FAKE}`, '-e', `CP_MINT=${CP_MINT}`, '-e', 'OUT=/out',
		NODE_IMG, 'node', '/fx/fake-capi.mjs');
	cleanups.unshift(() => void dockerQuiet('rm', '-f', FIXTURE));
	const caFile = path.join(fixtureOut, 'ca.pem');
	for (let i = 0; i < 100 && !fs.existsSync(caFile); i++) {
		await new Promise(r => setTimeout(r, 200));
	}
	if (!fs.existsSync(caFile)) {
		throw new Error(`fixture never wrote its CA: ${dockerQuiet('logs', FIXTURE).stderr}`);
	}

	// 2. A per-run broker image that also trusts the fixture CA (SECLAB_EXTRA_UPSTREAM_CA_PEM is
	// read at start; it adds to certifi, never replaces it). No tabd change: --broker-image.
	const ctx = path.join(run, 'broker-image');
	fs.mkdirSync(ctx);
	fs.copyFileSync(caFile, path.join(ctx, 'ca.pem'));
	fs.writeFileSync(path.join(ctx, 'Dockerfile'), [
		`FROM ${BASE_BROKER}`,
		'COPY ca.pem /etc/seclab-spike-ca.pem',
		'ENTRYPOINT ["sh", "-c", "SECLAB_EXTRA_UPSTREAM_CA_PEM=\\"$(cat /etc/seclab-spike-ca.pem)\\" exec seclab-broker \\"$@\\"", "seclab-broker"]',
		'CMD ["run"]', '',
	].join('\n'));
	docker('build', '-q', '--label', `seclab.spike=${NONCE}`, '--label', 'io.seclab.broker.derived=spike-test-only', '-t', BROKER_IMG, ctx);
	cleanups.push(() => void dockerQuiet('image', 'rm', '-f', BROKER_IMG));

	// 3. A real sbx tab behind its real broker (B2), policy A from tabd's state dir.
	fs.writeFileSync(path.join(state, 'broker-policy.json'), JSON.stringify(policy('A')), { mode: 0o600 });
	fs.copyFileSync(path.join(here, 'tab-driver.mjs'), path.join(ws, 'tab-driver.mjs'));
	// What the agent's in-tab `view` tool reads; the fixture looks for this marker in the
	// follow-up model request (tool executed in the tab, result sent to the model).
	fs.writeFileSync(path.join(ws, 'probe.txt'), `SECLAB_PROBE_${NONCE}\n`);
	client = new TabdClient({
		command: process.execPath,
		args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', state, '--driver', 'sbx', '--broker', 'required', '--broker-image', BROKER_IMG, '--allowed-root', tabs],
		env: { HOME: process.env.HOME, USER: process.env.USER, PATH: '/usr/bin:/bin' },
	});
	client.on('stderr', (s: string) => process.stderr.write(`[tabd] ${s}`));
	await client.initialize('agentic-tab-spike', '0');
	const { tab } = await client.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
	tabId = tab.metadata.name;
	writeManifest(run, { tabs: [tabId] });
	await client.request('tab.ensureRunning', { tabId });
	const ctr = `seclab-${tabId}`;
	const broker = `${ctr}-broker`;
	docker('network', 'connect', NET, broker);
	note(`tab ${tabId} up; broker ${broker} joined ${NET}`);
	// Fail closed if a fixture name resolves anywhere but this run's internal subnet: the broker
	// trusts certifi as well as the fixture CA, so a real host with a public certificate would pass.
	const prefix = SUBNET.replace(/0\/24$/, '');
	for (const h of [GHE, GHE_API, CAPI]) {
		const ip = docker('exec', broker, 'python3', '-c', `import socket,sys;print(' '.join(sorted({a[4][0] for a in socket.getaddrinfo(sys.argv[1], 443)})))`, h);
		if (!ip || ip.split(' ').some(a => !a.startsWith(prefix))) {
			throw new Error(`${h} resolved to ${ip || 'nothing'} from the broker, not inside ${SUBNET}`);
		}
	}

	ctl = await connectBroker(() => spawn('docker', ['exec', '-i', broker, 'seclab-broker', 'control'], { stdio: ['pipe', 'pipe', 'pipe'] }), tabId);
	const audit: unknown[] = [];
	ctl.onNotification(n => {
		if (n.method === 'audit.event' || n.method === 'credential.derived') {
			audit.push(n.params);
		}
	});
	const imported = await ctl.request('credential.import', {
		id: 'github', value: GH_FAKE, sentinel: SENTINEL, provider: 'github', source: { kind: 'host' },
		inject: { header: 'Authorization', fmt: 'Bearer {value}' },
		// Measurement bindings, deliberately broad on the fixture hosts so phase A sees every route
		// the runtime uses with which credential; the shipped bindings are cut from the result.
		bind: [
			{ host: GHE, path: '/api/v3/copilot_internal/user', methods: ['GET'] }, { host: GHE, path: '/api/v3/copilot_internal/v2/token', methods: ['GET'] },
			{ host: GHE_API, path: '/copilot_internal/**', methods: ['GET'] }, { host: CAPI, path: '/**', methods: ['GET', 'POST'] },
		],
		derive: [GHE, GHE_API].map((h, i) => ({
			id: i === 0 ? 'copilot' : 'copilot-api', from: { host: h, path: `${h === GHE ? '/api/v3' : ''}/copilot_internal/v2/token`, method: 'GET' }, field: 'token',
			inject: { header: 'Authorization', fmt: 'Bearer {value}' }, bind: [{ host: CAPI, path: '/**', methods: ['GET', 'POST'] }],
		})),
	}) as { confirmed: boolean };
	note(`credential.import confirmed=${imported.confirmed}`);

	const inTab = (phase: string) => {
		const out = path.join(ws, `out-${phase}`);
		fs.mkdirSync(out, { recursive: true });
		const reh = '/opt/seclab-reh';
		const nls = JSON.stringify({ userLocale: 'en', osLocale: 'en', resolvedLanguage: 'en', defaultMessagesFile: `${reh}/out/nls.messages.json`, locale: 'en', availableLanguages: {} });
		const q = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
		const script = [
			'set -u', `OUT=${q(out)}`, 'mkdir -p "$OUT/logs" "$OUT/ud"', `cd ${reh}`,
			`VSCODE_NLS_CONFIG=${q(nls)} VSCODE_ESM_ENTRYPOINT=vs/platform/agentHost/node/agentHostMain VSCODE_PIPE_LOGGING=true VSCODE_VERBOSE_LOGGING=true`
			+ ` VSCODE_AGENT_HOST_PORT=8091 VSCODE_AGENT_HOST_HOST=127.0.0.1 VSCODE_AGENT_HOST_CONNECTION_TOKEN=${AH_TOKEN}`
			+ ' timeout 400 ./node out/bootstrap-fork.js --logsPath "$OUT/logs" --user-data-dir "$OUT/ud" > "$OUT/agent-host.stdout" 2>&1 &',
			'AH=$!',
			'i=0; while [ $i -lt 100 ] && ! grep -q listening "$OUT/agent-host.stdout" 2>/dev/null; do sleep 0.2; i=$((i+1)); done',
			`AH_PORT=8091 AH_TOKEN=${AH_TOKEN} SENTINEL=${SENTINEL} GHE_URI=https://${GHE} WORKDIR=${q(ws)} OUT="$OUT" NONCE=${NONCE} MODELS=gpt-5.3-codex,claude-sonnet-4.5,gpt-4o`
			+ ` ./node ${q(path.join(ws, 'tab-driver.mjs'))}; rc=$?`,
			'kill $AH 2>/dev/null; wait $AH 2>/dev/null',
			// The agent host's and runtime's own record of each egress failure (positive evidence).
			'grep -rhoE "error sending request for url \\([^)]*\\)|ECONNREFUSED|self[- ]signed|unable to verify[^\\"]*" "$OUT/logs" 2>/dev/null | sort | uniq -c > "$OUT/egress-errors.txt"',
			'exit $rc',
		].join('\n');
		const r = spawnSync(SBX, ['exec', '-u', 'agent', ctr, '/opt/seclab/bin/seclab-tab-env', 'sh', '-c', script], { encoding: 'utf8', timeout: 600_000 });
		fs.writeFileSync(path.join(run, `in-tab-${phase}.log`), `${r.stdout}\n--- stderr\n${r.stderr}`);
		note(`phase ${phase}: in-tab exit ${r.status}`);
		return r.status;
	};

	const phases: Record<string, unknown> = {};
	for (const phase of ['A', 'B'] as const) {
		if (phase === 'B') {
			await ctl.request('policy.load', { policy: { ...policy('B'), tabId } });
		}
		const before = audit.length;
		const rc = inTab(phase);
		await new Promise(r => setTimeout(r, 1000));
		phases[phase] = { rc, audit: audit.slice(before) };
	}
	const tail = await ctl.request('audit.tail', { limit: 2000 });
	fs.writeFileSync(path.join(run, 'broker-audit.json'), JSON.stringify({ phases, tail }, null, 1));
	fs.writeFileSync(path.join(run, 'measured.json'), JSON.stringify(summarise(phases), null, 1));
	await new Promise(r => setTimeout(r, 3000)); // sbx file sharing lags the VM's last writes
	// Measured facts must not depend on a file the tab could have written: the fixture log and
	// the broker audit are host-side. Of the tab's output only the driver report is kept, as a
	// regular file under 1 MiB that passes the AV-shape check (EDR fixture-safety); the rest
	// goes with the workspace at teardown.
	for (const phase of ['A', 'B']) {
		const src = path.join(ws, `out-${phase}`, 'driver-report.json');
		const st = fs.lstatSync(src, { throwIfNoEntry: false });
		if (!st?.isFile() || st.size >= 1 << 20) {
			continue;
		}
		const text = fs.readFileSync(src, 'utf8');
		const av = avFindings(new Map([['driver-report.json', text]]));
		if (av.length) {
			failed = true;
			console.log(`FAIL tab-written report ${phase} has an AV loader shape; not copied: ${av.join('; ')}`);
			continue;
		}
		fs.writeFileSync(path.join(run, `tab-written-${phase}.driver-report.json`), text);
	}
	// The fixture log carries tab-influenced strings (key names, tool names): same check.
	const fxAv = avFindings(treeTexts(fixtureOut));
	if (fxAv.length) {
		failed = true;
		fs.rmSync(fixtureOut, { recursive: true, force: true });
		console.log(`FAIL fixture log has an AV loader shape; removed: ${fxAv.join('; ')}`);
	}
} catch (e) {
	failed = true;
	console.log(`FAIL ${(e as Error).stack ?? e}`);
} finally {
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
	const left = [dockerQuiet('ps', '-aq', '--filter', `label=seclab.spike=${NONCE}`).stdout.trim(), dockerQuiet('network', 'ls', '-q', '--filter', `label=seclab.spike=${NONCE}`).stdout.trim(),
		dockerQuiet('image', 'ls', '-q', '--filter', `label=seclab.spike=${NONCE}`).stdout.trim()].filter(Boolean);
	if (left.length) {
		failed = true;
		console.log(`FAIL spike resources left: ${left.join(' ')}`);
	}
	fs.rmSync(path.join(run, 'broker-image'), { recursive: true, force: true });
	if (!teardownGate(run)) {
		failed = true;
	}
	console.log(`run: ${run}`);
	process.exit(failed ? 1 : 0);
}
