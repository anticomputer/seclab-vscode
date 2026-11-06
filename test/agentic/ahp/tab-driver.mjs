// Agents-in-the-tab spike, step 3: runs INSIDE the sbx tab, under seclab-tab-env, against the
// agent host from the tab's own REH (/opt/seclab-reh). Speaks AHP 1.1.0 over the loopback
// WebSocket with the shape upstream's e2e client uses (test/node/serverIntegrationTestHelpers.ts,
// e2e/harness/agentHostE2ETestHarness.ts @ the pinned SHA): initialize, root config
// (githubEnterpriseUri), authenticate every advertised resource with the broker SENTINEL, create
// a copilotcli session, and run one turn per model. Records protocol facts only.
//
// Env: AH_PORT, AH_TOKEN, SENTINEL, GHE_URI, WORKDIR, OUT, MODELS (comma list), NONCE.

import * as fs from 'node:fs';
import { randomUUID } from 'node:crypto';

const { AH_PORT, AH_TOKEN, SENTINEL, GHE_URI, WORKDIR, OUT, MODELS, NONCE } = process.env;
const ROOT = 'ahp-root://';
const report = { nonce: NONCE, steps: [], reverseRequests: [], actionTypes: {}, turns: [] };
const step = (name, data) => {
	report.steps.push({ name, t: Date.now(), ...data });
	console.log(`[driver] ${name}${data ? ' ' + JSON.stringify(data).slice(0, 300) : ''}`);
};

const ws = new WebSocket(`ws://127.0.0.1:${AH_PORT}/?tkn=${encodeURIComponent(AH_TOKEN)}`);
let nextId = 1;
const pending = new Map();
const notes = [];
const waiters = new Set();
ws.addEventListener('message', ev => {
	const msg = JSON.parse(String(ev.data));
	if ('id' in msg && msg.id !== null && ('result' in msg || 'error' in msg) && !('method' in msg)) {
		const p = pending.get(msg.id);
		pending.delete(msg.id);
		if (p) {
			msg.error ? p.reject(Object.assign(new Error(msg.error.message), { code: msg.error.code })) : p.resolve(msg.result);
		}
	} else if ('method' in msg && 'id' in msg) {
		// A reverse request (agent host -> client). The gate denies these in the shipped design;
		// the spike records the method and refuses it.
		report.reverseRequests.push({ method: msg.method, uriScheme: String(msg.params?.uri ?? msg.params?.source ?? '').split(':')[0] });
		ws.send(JSON.stringify({ jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'refused by the spike client' } }));
	} else if ('method' in msg) {
		if (msg.method === 'action') {
			const t = msg.params?.action?.type ?? '?';
			report.actionTypes[t] = (report.actionTypes[t] ?? 0) + 1;
		}
		notes.push(msg);
		for (const w of [...waiters]) {
			if (w.pred(msg)) {
				waiters.delete(w);
				clearTimeout(w.timer);
				w.resolve(msg);
			}
		}
	}
});
const call = (method, params, ms = 60_000) => new Promise((resolve, reject) => {
	const id = nextId++;
	const timer = setTimeout(() => {
		pending.delete(id);
		reject(new Error(`timeout: ${method}`));
	}, ms);
	pending.set(id, { resolve: v => { clearTimeout(timer); resolve(v); }, reject: e => { clearTimeout(timer); reject(e); } });
	ws.send(JSON.stringify({ jsonrpc: '2.0', id, method, params }));
});
const notify = (method, params) => ws.send(JSON.stringify({ jsonrpc: '2.0', method, params }));
const waitFor = (pred, ms) => new Promise((resolve, reject) => {
	const hit = notes.find(pred);
	if (hit) {
		return resolve(hit);
	}
	const w = { pred, resolve, timer: setTimeout(() => { waiters.delete(w); reject(new Error('timeout waiting for notification')); }, ms) };
	waiters.add(w);
});
const isAction = (n, type, channel) => n.method === 'action' && n.params?.action?.type === type && (!channel || n.params?.channel === channel);
const sleep = ms => new Promise(r => setTimeout(r, ms));

let exit = 0;
try {
	await new Promise((resolve, reject) => {
		ws.addEventListener('open', resolve, { once: true });
		ws.addEventListener('error', () => reject(new Error('websocket error')), { once: true });
	});
	const init = await call('initialize', { channel: ROOT, protocolVersions: ['1.1.0'], clientId: `seclab-spike-${NONCE}` });
	step('initialize', { protocolVersion: init?.protocolVersion, keys: Object.keys(init ?? {}).sort() });

	notify('dispatchAction', { channel: ROOT, clientSeq: 1, action: { type: 'root/configChanged', config: { githubEnterpriseUri: GHE_URI } } });
	await waitFor(n => isAction(n, 'root/configChanged'), 15_000).then(() => step('root/configChanged echoed'), e => step('root/configChanged not echoed', { error: e.message }));
	await sleep(1500);

	const root = await call('subscribe', { channel: ROOT });
	const agents = root?.snapshot?.state?.agents ?? [];
	report.agents = agents.map(a => ({ provider: a.provider, models: a.models?.length ?? 0, protectedResources: a.protectedResources ?? [] }));
	step('agents', { agents: report.agents.map(a => `${a.provider}:${a.protectedResources.map(r => r.resource).join('|')}`) });

	report.authenticate = [];
	for (const a of agents) {
		for (const r of a.protectedResources ?? []) {
			try {
				const res = await call('authenticate', { channel: ROOT, resource: r.resource, token: SENTINEL }, 60_000);
				report.authenticate.push({ provider: a.provider, resource: r.resource, scopes: r.scopes_supported, result: res });
			} catch (e) {
				report.authenticate.push({ provider: a.provider, resource: r.resource, error: e.message.slice(0, 200) });
			}
		}
	}
	step('authenticated', { n: report.authenticate.length });
	await sleep(5000);
	const root2 = await call('subscribe', { channel: ROOT });
	report.agentsAfterAuth = (root2?.snapshot?.state?.agents ?? []).map(a => ({ provider: a.provider, models: (a.models ?? []).map(m => m.id ?? m) }));
	step('agents after auth', { agents: report.agentsAfterAuth });

	let seq = 10;
	for (const model of (MODELS ?? '').split(',').filter(Boolean)) {
		// One session per model, so each turn's first request has no earlier tool result in it.
		const sessionUri = `copilotcli:/${randomUUID()}`;
		await call('createSession', { channel: sessionUri, provider: 'copilotcli', workingDirectories: [`file://${WORKDIR}`] }, 60_000);
		// As upstream's real-SDK suite does (e2e/suites/workspaceSuite.ts): subscribe to the session
		// URI at once; sessionAdded is not guaranteed before the first turn.
		const sub = await call('subscribe', { channel: sessionUri });
		const chat = sub?.snapshot?.state?.defaultChat;
		if (typeof chat !== 'string') {
			throw new Error(`no default chat advertised (state keys: ${Object.keys(sub?.snapshot?.state ?? {}).join(',')})`);
		}
		await call('subscribe', { channel: chat });
		const turnId = randomUUID();
		const turn = { model, turnId, approvals: 0, inputRequests: 0 };
		notify('dispatchAction', {
			channel: chat, clientSeq: seq++,
			action: { type: 'chat/turnStarted', turnId, startedAt: new Date().toISOString(), message: { text: `Use the view tool on the file, then reply. SECLAB_TOOLCALL path=${WORKDIR}/probe.txt (${NONCE})`, origin: { kind: 'user' }, model: { id: model } } },
		});
		const seen = new Set();
		const deadline = Date.now() + 150_000;
		turn.end = 'timeout';
		while (Date.now() < deadline) {
			let n;
			try {
				n = await waitFor(x => !seen.has(x) && x.method === 'action' && x.params?.channel === chat
					&& (x.params?.action?.turnId === turnId || x.params?.action?.type === 'chat/inputRequested'), Math.max(1, deadline - Date.now()));
			} catch {
				break;
			}
			seen.add(n);
			const a = n.params.action;
			if (a.type === 'chat/toolCallReady' && !a.confirmed) {
				// As upstream's e2e harness does (driveTurn): the user approves.
				turn.approvals++;
				notify('dispatchAction', { channel: chat, clientSeq: seq++, action: { type: 'chat/toolCallConfirmed', turnId, toolCallId: a.toolCallId, approved: true, confirmed: 'user-action' } });
			} else if (a.type === 'chat/inputRequested') {
				turn.inputRequests++;
				notify('dispatchAction', { channel: chat, clientSeq: seq++, action: { type: 'chat/inputCompleted', requestId: a.request?.id, response: 'cancel' } });
			} else if (a.type === 'chat/toolCallStart' || a.type === 'chat/toolCallComplete') {
				(turn.toolEvents ??= []).push({ type: a.type, tool: a.toolName ?? a.name ?? undefined });
			} else if (['chat/turnComplete', 'chat/error', 'chat/turnCancelled'].includes(a.type)) {
				turn.end = a.type;
				if (a.type === 'chat/error') {
					turn.error = JSON.stringify(a.part?.error ?? a).slice(0, 400);
				}
				break;
			}
		}
		const text = notes.filter(n => n.method === 'action' && n.params?.channel === chat && n.params?.action?.turnId === turnId)
			.map(n => n.params.action).filter(a => a.type === 'chat/delta' || a.type === 'chat/responsePart')
			.map(a => a.content ?? a.part?.content ?? '').join('');
		turn.replyHasNonce = text.includes(`SECLAB_SPIKE_OK_${NONCE}`);
		report.turns.push(turn);
		step('turn', turn);
	}
} catch (e) {
	report.error = String(e?.message ?? e).slice(0, 400);
	step('error', { error: report.error });
	exit = 1;
}
fs.writeFileSync(`${OUT}/driver-report.json`, JSON.stringify(report, null, 1));
ws.close();
process.exit(exit);
