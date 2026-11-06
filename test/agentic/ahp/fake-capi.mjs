// Agents-in-the-tab spike, step 3: a fake GitHub Enterprise + Copilot API, reachable only
// from the tab's broker on an --internal network under *.test names. Modelled on upstream's
// e2e stubs (test/node/e2e/harness/capiStubs.ts, capiWireCodec.ts @ the pinned SHA).
// It logs the SHAPE of every request (header names, auth class, body key paths, tool types)
// and never a credential value: the only credentials it can see are this run's fake
// seclabcanary_ values, which it classifies by equality.
//
// Env: NONCE, GH_FAKE (the "real" GitHub value the broker injects), CP_MINT (the Copilot token
// this fixture mints), OUT (log dir). Writes OUT/ca.pem and OUT/requests.jsonl.

import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as https from 'node:https';

const { NONCE, GH_FAKE, CP_MINT, OUT, STRIP_KEYS_RE } = process.env;
if (!/^[0-9a-f]{16}$/.test(NONCE ?? '') || !GH_FAKE?.startsWith('seclabcanary_') || !CP_MINT?.startsWith('seclabcanary_') || !OUT) {
	console.error('fake-capi: NONCE, GH_FAKE, CP_MINT (seclabcanary_ values) and OUT are required');
	process.exit(2);
}
const GHE = 'ghe.example.test';
// The Copilot runtime derives a ghe.com-style API host (api.<host>, no /api/v3) from
// COPILOT_GH_HOST, while the agent host uses <host>/api/v3: serve both.
const GHE_API = `api.${GHE}`;
const CAPI_HOST = 'capi.example.test';
const CAPI = `https://${CAPI_HOST}`;
const REPLY = `SECLAB_SPIKE_OK_${NONCE}`;

// Per-run CA and leaf, generated in this container; the CA key never leaves it.
const tls = '/run/fixture-tls';
fs.mkdirSync(tls, { recursive: true, mode: 0o700 });
const ossl = (...a) => execFileSync('openssl', a, { cwd: tls, stdio: ['ignore', 'ignore', 'pipe'] });
ossl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '1', '-subj', `/CN=seclab spike fixture CA ${NONCE}`,
	'-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign');
ossl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'leaf.key', '-out', 'leaf.csr', '-subj', '/CN=seclab-spike-fixture');
fs.writeFileSync(`${tls}/leaf.ext`, `subjectAltName=DNS:${GHE},DNS:${GHE_API},DNS:${CAPI_HOST}\nextendedKeyUsage=serverAuth\n`);
ossl('x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'leaf.pem', '-days', '1', '-extfile', 'leaf.ext');
fs.rmSync(`${tls}/ca.key`);
fs.copyFileSync(`${tls}/ca.pem`, `${OUT}/ca.pem.tmp`);
fs.renameSync(`${OUT}/ca.pem.tmp`, `${OUT}/ca.pem`);

const log = fs.openSync(`${OUT}/requests.jsonl`, 'a');
const record = o => fs.writeSync(log, JSON.stringify(o) + '\n');

// --- shape extraction (no values) -------------------------------------------------------
const SAFE_HEADER = /^(user-agent|editor-|copilot-|openai-|x-github-|x-interaction|x-initiator|x-onbehalf|x-agent|x-vscode|anthropic-|content-type|accept$|x-request-id|vscode-)/;
function authClass(v) {
	if (v === undefined) {
		return 'none';
	}
	const [scheme, ...rest] = String(v).split(' ');
	const tok = rest.join(' ');
	const cls = tok === GH_FAKE ? 'github-fake-real' : tok === CP_MINT ? 'copilot-minted' : tok.startsWith('seclab') ? 'seclab-other' : tok ? `unknown(len=${tok.length})` : 'empty';
	return `${scheme} ${cls}`;
}
function keyPaths(v, prefix, out, depth) {
	if (depth > 8 || out.size > 600) {
		return;
	}
	if (Array.isArray(v)) {
		for (const e of v) {
			keyPaths(e, `${prefix}[]`, out, depth + 1);
		}
	} else if (v && typeof v === 'object') {
		for (const [k, e] of Object.entries(v)) {
			const p = prefix ? `${prefix}.${k}` : k;
			out.add(p);
			keyPaths(e, p, out, depth + 1);
		}
	}
}
function typeValues(v, prefix, out, depth) {
	if (depth > 8) {
		return;
	}
	if (Array.isArray(v)) {
		v.forEach(e => typeValues(e, `${prefix}[]`, out, depth + 1));
	} else if (v && typeof v === 'object') {
		for (const [k, e] of Object.entries(v)) {
			const p = prefix ? `${prefix}.${k}` : k;
			if (k === 'type' && typeof e === 'string') {
				out.add(`${p}=${e}`);
			}
			typeValues(e, p, out, depth + 1);
		}
	}
}
function shape(body) {
	let j;
	try {
		j = JSON.parse(body);
	} catch {
		return { json: false };
	}
	if (!j || typeof j !== 'object' || Array.isArray(j)) {
		return { json: true, topLevel: typeof j };
	}
	const paths = new Set();
	keyPaths(j, '', paths, 0);
	const types = new Set();
	typeValues(j, '', types, 0);
	const tools = Array.isArray(j.tools) ? j.tools.map(t => ({ type: t?.type ?? null, name: t?.name ?? t?.function?.name ?? null })) : undefined;
	return {
		json: true, topLevel: Object.keys(j).sort(), model: typeof j.model === 'string' ? j.model : undefined, stream: j.stream,
		tools, keyPaths: [...paths].sort(), typeValues: [...types].sort(),
	};
}

// --- responses ----------------------------------------------------------------------------
const JSON_H = { 'content-type': 'application/json' };
const SSE_H = { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' };
const sse = (name, data) => `event: ${name}\ndata: ${JSON.stringify(data)}\n\n`;
const models = [
	['gpt-5.3-codex', 'OpenAI', ['/responses'], true, 128000],
	['claude-sonnet-4.5', 'Anthropic', ['/v1/messages', '/chat/completions'], false, 32000],
	['gpt-4o', 'Azure OpenAI', ['/chat/completions'], false, 4096],
].map(([id, vendor, eps, def, maxOut]) => ({
	id, name: id, object: 'model', vendor, version: id, preview: false, model_picker_enabled: true,
	is_chat_default: def, is_chat_fallback: def, supported_endpoints: eps,
	capabilities: {
		type: 'chat', family: id, tokenizer: 'o200k_base', object: 'model_capabilities',
		limits: { max_context_window_tokens: 200000, max_output_tokens: maxOut, max_prompt_tokens: 128000 },
		supports: { streaming: true, tool_calls: true, parallel_tool_calls: true, vision: false, structured_outputs: true },
	},
}));
const quota = { unlimited: true, percent_remaining: 100.0, remaining: 0, entitlement: 0, overage_count: 0, overage_permitted: true, has_quota: true, quota_remaining: 0.0, token_based_billing: true };
const userBody = () => ({
	login: 'seclab-spike', access_type_sku: 'copilot_for_business_seat', copilot_plan: 'enterprise', chat_enabled: true, cli_enabled: true,
	copilotignore_enabled: true, editor_preview_features_enabled: true, is_mcp_enabled: true, organization_login_list: [], organization_list: [],
	codex_agent_enabled: true, cloud_session_storage_enabled: true, token_based_billing: true,
	endpoints: { api: CAPI, proxy: CAPI, telemetry: CAPI, 'origin-tracker': CAPI },
	quota_snapshots: { chat: { ...quota, quota_id: 'chat' }, completions: { ...quota, quota_id: 'completions' }, premium_interactions: { ...quota, quota_id: 'premium_interactions' } },
});
// The broker blocks a /copilot_internal/user response with any key matching its credential-name
// pattern (engine_mitmproxy.py CREDENTIAL_KEY, passed in by tab-spike.ts). Upstream's own stub
// shape trips it; strip those keys so the run can proceed, and record which were stripped.
const stripRe = STRIP_KEYS_RE ? new RegExp(STRIP_KEYS_RE, 'i') : undefined;
const stripped = new Set();
function strip(v, p) {
	if (!stripRe || !v || typeof v !== 'object') {
		return v;
	}
	if (Array.isArray(v)) {
		return v.map(e => strip(e, `${p}[]`));
	}
	return Object.fromEntries(Object.entries(v).filter(([k]) => !(stripRe.test(k) && stripped.add(`${p}.${k}`))).map(([k, e]) => [k, strip(e, `${p}.${k}`)]));
}
const servedUserBody = () => {
	const full = userBody();
	const out = strip(full, '$');
	fs.writeFileSync(`${OUT}/user-shape.json`, JSON.stringify({ upstreamStubKeys: Object.keys(full).sort(), servedKeys: Object.keys(out).sort(), strippedForBroker: [...stripped].sort() }, null, 1));
	return out;
};
const tokenBody = () => ({ token: CP_MINT, expires_at: Math.floor(Date.now() / 1000) + 3600, refresh_in: 1800, endpoints: { api: CAPI, proxy: CAPI, telemetry: CAPI } });

function responsesSse(toolPath) {
	const id = `resp_spike_${NONCE}`;
	let seq = 0;
	const env = (status, output, text, usage) => ({ id, object: 'response', created_at: 0, status, error: null, incomplete_details: null, instructions: null, model: 'spike', output, output_text: text, parallel_tool_calls: true, temperature: 1, tool_choice: 'auto', tools: [], top_p: 1, usage });
	const sk = env('in_progress', [], '', undefined);
	if (toolPath) {
		const args = JSON.stringify({ path: toolPath });
		const call = { id: 'item_0', type: 'function_call', name: 'view', call_id: `call_spike_${NONCE}`, arguments: args, status: 'completed' };
		return [
			sse('response.created', { type: 'response.created', sequence_number: seq++, response: sk }),
			sse('response.output_item.added', { type: 'response.output_item.added', sequence_number: seq++, output_index: 0, item: { ...call, status: 'in_progress', arguments: '' } }),
			sse('response.function_call_arguments.delta', { type: 'response.function_call_arguments.delta', sequence_number: seq++, item_id: 'item_0', output_index: 0, delta: args }),
			sse('response.function_call_arguments.done', { type: 'response.function_call_arguments.done', sequence_number: seq++, item_id: 'item_0', output_index: 0, arguments: args }),
			sse('response.output_item.done', { type: 'response.output_item.done', sequence_number: seq++, output_index: 0, item: call }),
			sse('response.completed', { type: 'response.completed', sequence_number: seq++, response: env('completed', [call], '', { input_tokens: 1, output_tokens: 1, total_tokens: 2 }) }),
		].join('');
	}
	const item = { id: 'item_0', type: 'message', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: REPLY, annotations: [], logprobs: [] }] };
	return [
		sse('response.created', { type: 'response.created', sequence_number: seq++, response: sk }),
		sse('response.in_progress', { type: 'response.in_progress', sequence_number: seq++, response: sk }),
		sse('response.output_item.added', { type: 'response.output_item.added', sequence_number: seq++, output_index: 0, item: { ...item, status: 'in_progress', content: [] } }),
		sse('response.content_part.added', { type: 'response.content_part.added', sequence_number: seq++, item_id: 'item_0', output_index: 0, content_index: 0, part: { type: 'output_text', text: '', annotations: [], logprobs: [] } }),
		sse('response.output_text.delta', { type: 'response.output_text.delta', sequence_number: seq++, item_id: 'item_0', output_index: 0, content_index: 0, delta: REPLY, logprobs: [] }),
		sse('response.output_text.done', { type: 'response.output_text.done', sequence_number: seq++, item_id: 'item_0', output_index: 0, content_index: 0, text: REPLY, logprobs: [] }),
		sse('response.content_part.done', { type: 'response.content_part.done', sequence_number: seq++, item_id: 'item_0', output_index: 0, content_index: 0, part: item.content[0] }),
		sse('response.output_item.done', { type: 'response.output_item.done', sequence_number: seq++, output_index: 0, item }),
		sse('response.completed', { type: 'response.completed', sequence_number: seq++, response: env('completed', [item], REPLY, { input_tokens: 1, output_tokens: 1, total_tokens: 2 }) }),
	].join('');
}
function anthropicSse(toolPath) {
	const block = toolPath
		? [sse('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'tool_use', id: `toolu_spike_${NONCE}`, name: 'view', input: {} } }),
			sse('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: JSON.stringify({ path: toolPath }) } })]
		: [sse('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } }),
			sse('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: REPLY } })];
	return [
		sse('message_start', { type: 'message_start', message: { id: `msg_spike_${NONCE}`, type: 'message', role: 'assistant', content: [], model: 'spike', stop_reason: null, stop_sequence: null, usage: { input_tokens: 1, output_tokens: 1 } } }),
		...block,
		sse('content_block_stop', { type: 'content_block_stop', index: 0 }),
		sse('message_delta', { type: 'message_delta', delta: { stop_reason: toolPath ? 'tool_use' : 'end_turn', stop_sequence: null }, usage: { output_tokens: 1 } }),
		sse('message_stop', { type: 'message_stop' }),
	].join('');
}
function chatSse(model, toolPath) {
	const base = { id: `chatcmpl-spike-${NONCE}`, object: 'chat.completion.chunk', created: 0, model };
	const first = toolPath
		? { role: 'assistant', content: null, tool_calls: [{ index: 0, id: `call_spike_${NONCE}`, type: 'function', function: { name: 'view', arguments: JSON.stringify({ path: toolPath }) } }] }
		: { role: 'assistant', content: REPLY };
	return [
		`data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta: first, finish_reason: null }] })}\n\n`,
		`data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta: {}, finish_reason: toolPath ? 'tool_calls' : 'stop' }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } })}\n\n`,
		'data: [DONE]\n\n',
	].join('');
}

function route(host, method, path, body, j) {
	// Tool round trip: a prompt carrying "SECLAB_TOOLCALL path=<abs>" gets one `view` call for
	// that path; the follow-up request (carrying the tool result) gets the text reply.
	const toolPath = /SECLAB_TOOLCALL path=([A-Za-z0-9._/-]+)/.exec(body ?? '')?.[1];
	const hasResult = /"(function_call_output|custom_tool_call_output|tool_result)"|"role":"tool"/.test(body ?? '');
	const wantTool = toolPath && !hasResult;
	if (host === GHE || host === GHE_API) {
		const p = host === GHE ? path.replace(/^\/api\/v3(?=\/)/, '') : path;
		if (host === GHE && p === path) {
			return [404, JSON_H, '{"message":"Not Found"}'];
		}
		if (method === 'GET' && p === '/copilot_internal/user') {
			return [200, JSON_H, JSON.stringify(servedUserBody())];
		}
		if (method === 'GET' && p === '/copilot_internal/v2/token') {
			return [200, JSON_H, JSON.stringify(tokenBody())];
		}
		if (p.startsWith('/copilot_internal/')) {
			return [200, JSON_H, '{}'];
		}
		return [404, JSON_H, '{"message":"Not Found"}'];
	}
	if (host !== CAPI_HOST) {
		return [421, JSON_H, '{}'];
	}
	if (path === '/models' && method === 'GET') {
		return [200, JSON_H, JSON.stringify({ data: models, object: 'list' })];
	}
	if (path === '/responses' && method === 'GET') {
		return [400, { 'content-type': 'text/plain' }, 'Bad Request'];
	}
	if ((path === '/models/session' || path === '/models/session/intent') && method === 'POST') {
		return [500, { 'content-type': 'text/plain', 'x-should-retry': 'false' }, 'auto-mode not available in the spike'];
	}
	if (path === '/copilot/mcp_registry' && method === 'GET') {
		return [200, JSON_H, '{"mcp_registries":[]}'];
	}
	if (path === '/mcp' || path === '/mcp/readonly' || path.includes('/.well-known/')) {
		return [404, { 'content-type': 'text/plain', 'x-should-retry': 'false' }, 'not available in the spike'];
	}
	if (path === '/telemetry' || path.startsWith('/agents')) {
		return [200, JSON_H, '{}'];
	}
	if (method === 'POST' && path === '/responses') {
		return [200, SSE_H, responsesSse(wantTool ? toolPath : undefined)];
	}
	if (method === 'POST' && path === '/v1/messages') {
		return [200, SSE_H, anthropicSse(wantTool ? toolPath : undefined)];
	}
	if (method === 'POST' && path === '/chat/completions') {
		if (j?.stream === false) {
			return [200, JSON_H, JSON.stringify({ id: `chatcmpl-spike-${NONCE}`, object: 'chat.completion', choices: [{ index: 0, message: { role: 'assistant', content: REPLY }, finish_reason: 'stop' }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } })];
		}
		return [200, SSE_H, chatSse(j?.model ?? 'spike', wantTool ? toolPath : undefined)];
	}
	return [404, JSON_H, '{}'];
}

const server = https.createServer({ key: fs.readFileSync(`${tls}/leaf.key`), cert: fs.readFileSync(`${tls}/leaf.pem`) }, (req, res) => {
	const chunks = [];
	let size = 0;
	req.on('data', c => {
		size += c.length;
		if (size <= 8 * 1024 * 1024) {
			chunks.push(c);
		}
	});
	req.on('end', () => {
		const host = String(req.headers.host ?? '').replace(/:443$/, '').toLowerCase();
		const u = new URL(req.url ?? '/', `https://${host || 'fixture.invalid'}`);
		const body = Buffer.concat(chunks).toString('utf8');
		const headers = {};
		for (const [k, v] of Object.entries(req.headers)) {
			headers[k] = SAFE_HEADER.test(k) ? String(v).slice(0, 160) : '(present)';
		}
		const sh = body ? shape(body) : undefined;
		let j;
		try {
			j = body ? JSON.parse(body) : undefined;
		} catch { /* shape() recorded it */ }
		// A real server rejects the wrong credential: a failed broker swap must show, not pass.
		const auth = authClass(req.headers.authorization);
		// CAPI takes the minted Copilot token (D7) or, as measured, the GitHub token itself.
		const ok = host === GHE || host === GHE_API ? auth.endsWith('github-fake-real')
			: host === CAPI_HOST ? auth.endsWith('copilot-minted') || auth.endsWith('github-fake-real') || /^\/(telemetry|agents)/.test(u.pathname) : false;
		let [status, h, out] = ok ? route(host, req.method, u.pathname, body, j) : [401, JSON_H, '{"message":"Bad credentials"}'];
		record({ t: Date.now(), host, method: req.method, path: u.pathname, queryKeys: [...u.searchParams.keys()], headers, auth, bodyBytes: size, body: sh, probeInBody: body.includes(`SECLAB_PROBE_${NONCE}`), status });
		res.writeHead(status, h);
		res.end(out);
	});
});
server.listen(443, () => console.log('fake-capi listening'));
