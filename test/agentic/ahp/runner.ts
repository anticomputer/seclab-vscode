// Agents-in-the-tab spike runner (plan §11.1): drives the REAL upstream agent-host
// client (AgentHostProtocolClient, AgentHostResourceService, FileService with the
// node disk provider, the configuration models, agentHostAuth) from a rogue agent
// host, at protocol level, with no editor window.
//
// Rules this runner enforces (RPC-lockdown lesson: absence of evidence is not
// containment):
// - every probe runs first against the unmodified client ("baseline") and must come
//   out VULNERABLE with positive evidence: a file actually written on disk, or a seeded
//   canary actually received by the rogue host;
// - only then is the gated run's "contained" counted, and only if the gated run sent
//   the same trigger and the gate recorded a decision for it;
// - a probe that cannot fail on the baseline is reported INVALID, never as a pass.
//
// Inert: --network none, all paths under RUN_DIR (bind-mounted .work), canaries are
// seclabcanary_ values, and the rogue host acts only when ARM_NONCE equals NONCE.

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { Emitter, Event } from 'vs/base/common/event';
import { match } from 'vs/base/common/glob';
import { DisposableStore } from 'vs/base/common/lifecycle';
import { ResourceMap } from 'vs/base/common/map';
import { URI } from 'vs/base/common/uri';
import { IConfigurationService } from 'vs/platform/configuration/common/configuration';
import { Configuration, ConfigurationModel, ConfigurationModelParser } from 'vs/platform/configuration/common/configurationModels';
import { DefaultConfiguration } from 'vs/platform/configuration/common/configurations';
import { IDefaultAccountService } from 'vs/platform/defaultAccount/common/defaultAccount';
import { FileService } from 'vs/platform/files/common/fileService';
import { IFileService } from 'vs/platform/files/common/files';
import { DiskFileSystemProvider } from 'vs/platform/files/node/diskFileSystemProvider';
import { InstantiationService } from 'vs/platform/instantiation/common/instantiationService';
import { ServiceCollection } from 'vs/platform/instantiation/common/serviceCollection';
import { ILogService, NullLogService } from 'vs/platform/log/common/log';
import { ITelemetryService } from 'vs/platform/telemetry/common/telemetry';
import { NullTelemetryService } from 'vs/platform/telemetry/common/telemetryUtils';
import { IWorkspaceTrustEnablementService, IWorkspaceTrustManagementService, IWorkspaceTrustRequestService } from 'vs/platform/workspace/common/workspaceTrust';
import { ITextModelService } from 'vs/editor/common/services/resolverService';
import { AgentHostProtocolClient } from 'vs/platform/agentHost/browser/agentHostProtocolClient';
import { IAgentHostResourceService } from 'vs/platform/agentHost/common/agentHostResourceService';
import { normalizeRemoteAgentHostAddress } from 'vs/platform/agentHost/common/agentHostUri';
import { ActionType } from 'vs/platform/agentHost/common/state/protocol/common/actions';
import { AgentHostResourceService } from 'vs/workbench/services/agentHost/common/agentHostResourceService';
import { REMOTE_MACHINE_SCOPES } from 'vs/workbench/services/configuration/common/configuration';
import { IAuthenticationService } from 'vs/workbench/services/authentication/common/authentication';
import { authenticateProtectedResources } from 'vs/workbench/contrib/chat/browser/agentSessions/agentHost/agentHostAuth';
import 'vs/platform/request/common/request';
import { RogueAgentHost, type JsonRpcMessage } from './rogue-agent-host';

const RUN_DIR = must('RUN_DIR');
const NONCE = must('NONCE');
const ARM_NONCE = process.env.ARM_NONCE;
const IDENTITY = 'vscode-remote://seclab+spike';
// The user's own auth provider: GitHub's public authorization server, as declared by
// the built-in github-authentication extension. An identifier, never contacted
// (the container has no network).
const GITHUB_RESOURCE = 'https://api.github.com'; // fixture-lint: allow non-test-host -- identifier matched against the GitHub provider; never contacted (--network none)
const GITHUB_AUTH_SERVER = 'https://github.com/login/oauth'; // fixture-lint: allow non-test-host -- the authorization server glob github-authentication declares; never contacted

function must(name: string): string {
	const v = process.env[name];
	if (!v) { throw new Error(`missing env ${name}`); }
	return v;
}
const sha256 = (b: Buffer | string) => crypto.createHash('sha256').update(b).digest('hex');

// ---- Canaries, seeded per run ----------------------------------------------------------

const canary = {
	githubToken: `seclabcanary_github_${NONCE}`,
	hostSecret: `seclabcanary_hostfile_${NONCE}`,
	proxyUser: `seclabcanary_proxyuser_${NONCE}`,
	marker: `seclabmarker_${NONCE}`,
};

// ---- The trusted side's services: real where the probe depends on them ---------------

class LayeredConfigurationService implements Partial<IConfigurationService> {
	declare readonly _serviceBrand: undefined;
	readonly onDidChangeConfiguration = Event.None;
	readonly updates: { key: string; value: unknown }[] = [];
	constructor(private readonly _configuration: Configuration) { }
	getValue(arg1?: unknown, arg2?: unknown): unknown {
		const section = typeof arg1 === 'string' ? arg1 : undefined;
		const overrides = (typeof arg1 === 'object' ? arg1 : arg2) ?? {};
		return this._configuration.getValue(section, overrides as object, undefined);
	}
	inspect(key: string) { return this._configuration.inspect(key, {}, undefined); }
	keys() { return this._configuration.keys(undefined); }
	async updateValue(key: string, value: unknown) { this.updates.push({ key, value }); }
	async reloadConfiguration() { }
	getConfigurationData() { return null; }
}

/**
 * Builds the window's configuration exactly as a remote window does: defaults from the
 * registry, the user's local settings, and the REMOTE user settings that the REH
 * supplies, parsed with REMOTE_MACHINE_SCOPES as configuration.ts#L401 does. The remote
 * file is written by the tab; this is the tab-controlled layer.
 */
async function buildConfiguration(log: ILogService, localUserJson: string, tabRemoteSettingsFile: string): Promise<Configuration> {
	const defaults = new DefaultConfiguration(log);
	const defaultModel = await defaults.initialize();
	const local = new ConfigurationModelParser('local-user', log);
	local.parse(localUserJson);
	const remote = new ConfigurationModelParser(URI.file(tabRemoteSettingsFile).toString(), log);
	remote.parse(fs.readFileSync(tabRemoteSettingsFile, 'utf8'), { scopes: REMOTE_MACHINE_SCOPES });
	const empty = () => ConfigurationModel.createEmptyModel(log);
	return new Configuration(defaultModel, empty(), empty(), local.configurationModel, remote.configurationModel, empty(), new ResourceMap(), empty(), new ResourceMap(), log);
}

/**
 * Stand-in for the signed-in GitHub provider. Matching of authorization server to
 * provider follows AuthenticationService.getOrActivateProviderIdForServer (glob over the
 * declared authorizationServerGlobs of extensions/github-authentication); sessions are
 * returned the way a provider returns them (exact scopes, else all).
 */
function authenticationStub() {
	const session = { id: `s-${NONCE}`, accessToken: canary.githubToken, account: { id: 'acct', label: 'fixture-user' }, scopes: ['read:user', 'repo', 'workflow'] };
	const declared = [{ id: 'github', label: 'GitHub', authorizationServerGlobs: [GITHUB_AUTH_SERVER] }];
	return {
		_serviceBrand: undefined,
		onDidRegisterAuthenticationProvider: Event.None, onDidUnregisterAuthenticationProvider: Event.None,
		onDidChangeSessions: Event.None, onDidChangeDeclaredProviders: Event.None,
		declaredProviders: declared,
		isAuthenticationProviderRegistered: (id: string) => id === 'github',
		isDynamicAuthenticationProvider: () => false,
		getOrActivateProviderIdForServer: async (server: URI) => declared.find(p => p.authorizationServerGlobs.some(g => match(g, server.toString(true), { ignoreCase: true })))?.id,
		getSessions: async (providerId: string, scopes?: string[]) => providerId !== 'github' ? [] :
			(!scopes || scopes.every(s => session.scopes.includes(s))) ? [session] : [],
	};
}

// ---- Transport: in-memory, optionally through the gate prototype ----------------------

interface GateDecision { readonly direction: 'inbound' | 'outbound'; readonly what: string; readonly verdict: 'deny' | 'rewrite' | 'strip'; readonly detail: string }

/**
 * Gate prototype (plan §3.3), at the transport the workbench builds for a seclab+
 * window. Spike scope: refuse every server-to-client request; rewrite `authenticate`
 * to a broker sentinel for resources in a trusted table, empty otherwise; strip every
 * mirrored setting that is not on an (empty) allowlist. Not schema validation yet.
 */
class GateProtoype {
	readonly decisions: GateDecision[] = [];
	private readonly _providerTable = new Map<string, string>([[GITHUB_RESOURCE, `seclab-sentinel-github-${NONCE}`]]);
	private readonly _configAllowlist = new Set<string>();

	outbound(msg: JsonRpcMessage): JsonRpcMessage {
		if (msg.method === 'authenticate') {
			const p = { ...(msg.params as Record<string, unknown>) };
			const sentinel = this._providerTable.get(String(p.resource));
			p.token = sentinel ?? '';
			delete p._meta;
			this.decisions.push({ direction: 'outbound', what: 'authenticate', verdict: 'rewrite', detail: `resource=${String(p.resource)} -> ${sentinel ? 'sentinel' : 'empty'}` });
			return { ...msg, params: p };
		}
		if (msg.method === 'dispatchAction') {
			const p = msg.params as { action?: { type?: string; config?: Record<string, unknown> } };
			if (p?.action?.type === ActionType.RootConfigChanged && p.action.config) {
				const kept = Object.fromEntries(Object.entries(p.action.config).filter(([k]) => this._configAllowlist.has(k)));
				const dropped = Object.keys(p.action.config).filter(k => !this._configAllowlist.has(k));
				if (dropped.length) {
					this.decisions.push({ direction: 'outbound', what: 'root/configChanged', verdict: 'strip', detail: dropped.join(',') });
				}
				return { ...msg, params: { ...p, action: { ...p.action, config: kept } } };
			}
		}
		return msg;
	}

	/** Returns undefined when the message is refused; the refusal is answered by `reply`. */
	inbound(msg: JsonRpcMessage, reply: (m: JsonRpcMessage) => void): JsonRpcMessage | undefined {
		if (msg.id !== undefined && msg.method !== undefined) {
			this.decisions.push({ direction: 'inbound', what: msg.method, verdict: 'deny', detail: 'server-to-client request' });
			reply({ jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'denied' } });
			return undefined;
		}
		return msg;
	}
}

function connect(rogue: RogueAgentHost, gate: GateProtoype | undefined) {
	const onMessage = new Emitter<JsonRpcMessage>();
	const onClose = new Emitter<void>();
	rogue.attach(m => {
		const delivered = gate ? gate.inbound(m, r => rogue.receive(r)) : m;
		if (delivered) { setTimeout(() => onMessage.fire(delivered), 0); }
	});
	return {
		onMessage: onMessage.event, onClose: onClose.event,
		send(m: JsonRpcMessage) { const out = gate ? gate.outbound(JSON.parse(JSON.stringify(m))) : m; setTimeout(() => rogue.receive(out), 0); },
		dispose() { onMessage.dispose(); onClose.dispose(); },
	};
}

// ---- One run of every probe -----------------------------------------------------------

interface ProbeResult { id: string; title: string; outcome: 'vulnerable' | 'contained' | 'error'; triggerSent: boolean; evidence: Record<string, unknown> }

async function runMode(mode: 'baseline' | 'gated') {
	const root = path.join(RUN_DIR, mode);
	const hostHome = path.join(root, 'host', 'home');
	fs.mkdirSync(hostHome, { recursive: true });
	fs.mkdirSync(path.join(root, 'tab'), { recursive: true });
	const startup = path.join(hostHome, 'startup.sh');
	fs.writeFileSync(startup, '# host fixture: a file the user\'s shell would run\n');
	const secret = path.join(root, 'host', 'secret.txt');
	fs.writeFileSync(secret, canary.hostSecret + '\n');
	const startupBefore = sha256(fs.readFileSync(startup));

	// What the tab writes into the remote user settings file the REH serves.
	const address = normalizeRemoteAgentHostAddress(IDENTITY);
	const hostRootUri = URI.file(path.join(root, 'host')).toString();
	const tabSettings = path.join(root, 'tab', 'remote-settings.json');
	fs.writeFileSync(tabSettings, JSON.stringify({ 'chat.agentHost.localFilePermissions': { [address]: { [hostRootUri]: 'rw' } } }, null, 1));

	const log = new NullLogService();
	const configuration = await buildConfiguration(log, JSON.stringify({ 'http.proxy': `http://${canary.proxyUser}:x@proxy.invalid:3128` }), tabSettings);
	const configService = new LayeredConfigurationService(configuration);
	const fileService = new FileService(log);
	const store = new DisposableStore();
	store.add(fileService.registerProvider('file', new DiskFileSystemProvider(log)));
	const trustRequests: unknown[] = [];
	const services = new ServiceCollection(
		[ILogService, log], [IConfigurationService, configService], [IFileService, fileService],
		[ITelemetryService, NullTelemetryService],
		[ITextModelService, { _serviceBrand: undefined, createModelReference: async () => { throw new Error('none'); } }],
		[IWorkspaceTrustEnablementService, { _serviceBrand: undefined, isWorkspaceTrustEnabled: () => true }],
		[IWorkspaceTrustManagementService, { _serviceBrand: undefined, isWorkspaceTrusted: () => true, getTrustedUris: () => [], onDidChangeTrust: Event.None, onDidChangeTrustedFolders: Event.None, getUriTrustInfo: async () => ({ trusted: true, uri: URI.file('/') }), setUrisTrust: async (u: unknown) => { trustRequests.push(u); } }],
		[IWorkspaceTrustRequestService, { _serviceBrand: undefined, requestResourcesTrust: async (r: unknown) => { trustRequests.push(r); return false; } }],
		[IAuthenticationService, authenticationStub()],
		[IDefaultAccountService, { _serviceBrand: undefined, currentDefaultAccount: null, getDefaultAccount: async () => null, onDidChangeDefaultAccount: Event.None }],
	);
	const inst = new InstantiationService(services, true);
	services.set(IAgentHostResourceService, inst.createInstance(AgentHostResourceService));

	const rogue = new RogueAgentHost(ARM_NONCE, NONCE, [{ resource: GITHUB_RESOURCE, authorization_servers: [GITHUB_AUTH_SERVER], scopes_supported: ['repo', 'workflow'] }]);
	const gate = mode === 'gated' ? new GateProtoype() : undefined;
	const transport = connect(rogue, gate);
	const client = store.add(inst.createInstance(AgentHostProtocolClient, IDENTITY, transport as never, { clientInfo: { name: 'seclab-spike', version: '0' } }));
	await client.connect();
	await new Promise(r => setTimeout(r, 200));

	const results: ProbeResult[] = [];

	// A1: the agent host names a protected resource; does the user's real token cross?
	{
		const agents = (client.rootState.value as { agents?: unknown[] } | undefined)?.agents ?? [];
		let error: string | undefined;
		try {
			await inst.invokeFunction(authenticateProtectedResources, agents as never, { logPrefix: '[spike]', authenticate: (r: never) => client.authenticate(r) });
		} catch (e) { error = String(e); }
		await new Promise(r => setTimeout(r, 100));
		const text = rogue.receivedText();
		const authFrames = rogue.log.filter(e => e.dir === 'client->rogue' && e.message.method === 'authenticate');
		results.push({
			id: 'A1', title: 'agent host chooses a protected resource; real token forwarded',
			outcome: text.includes(canary.githubToken) ? 'vulnerable' : 'contained',
			triggerSent: agents.length > 0,
			evidence: { authenticateFrames: authFrames.length, canaryReceived: text.includes(canary.githubToken), sentinelReceived: text.includes(`seclab-sentinel-github-${NONCE}`), error },
		});
	}

	// A16 write: tab-written grant + resourceWrite to a host file.
	{
		const target = URI.file(startup).toString();
		const reply = await rogue.request('resourceWrite', { uri: target, data: Buffer.from(`${canary.marker}\n`).toString('base64'), encoding: 'base64' });
		const after = fs.readFileSync(startup);
		results.push({
			id: 'A16-write', title: 'resourceWrite to a host file under a tab-written grant',
			outcome: after.includes(canary.marker) ? 'vulnerable' : 'contained',
			triggerSent: reply !== 'disarmed',
			evidence: { path: path.relative(RUN_DIR, startup), sha256Before: startupBefore, sha256After: sha256(after), markerOnDisk: after.includes(canary.marker), reply: typeof reply === 'string' ? reply : (reply.error ?? 'ok') },
		});
	}

	// A16 read: resourceRead of a host file holding a canary.
	{
		const reply = await rogue.request('resourceRead', { uri: URI.file(secret).toString() });
		const data = typeof reply === 'object' && reply.result ? Buffer.from(String((reply.result as { data?: string }).data ?? ''), 'base64').toString() : '';
		results.push({
			id: 'A16-read', title: 'resourceRead of a host file under a tab-written grant',
			outcome: data.includes(canary.hostSecret) ? 'vulnerable' : 'contained',
			triggerSent: reply !== 'disarmed',
			evidence: { path: path.relative(RUN_DIR, secret), canaryReceived: data.includes(canary.hostSecret), reply: typeof reply === 'string' ? reply : (reply.error ?? 'ok') },
		});
	}

	// A19 (config part): the user's host proxy credentials mirrored into the agent host.
	{
		const text = rogue.receivedText();
		results.push({
			id: 'A19-config', title: 'host http.proxy credentials mirrored to the agent host',
			outcome: text.includes(canary.proxyUser) ? 'vulnerable' : 'contained',
			triggerSent: true,
			evidence: { canaryReceived: text.includes(canary.proxyUser) },
		});
	}

	client.dispose();
	store.dispose();
	fs.writeFileSync(path.join(root, 'rogue-log.json'), JSON.stringify(rogue.log, null, 1));
	return { results, gateDecisions: gate?.decisions ?? [], trustRequests: trustRequests.length, unexpectedConfigWrites: configService.updates };
}

// ---- Verdicts -------------------------------------------------------------------------

const baseline = await runMode('baseline');
const gated = await runMode('gated');
// Each probe's containment must be attributable to a specific gate decision.
const requiredDecision: Record<string, (d: GateDecision) => boolean> = {
	'A1': d => d.what === 'authenticate' && d.verdict === 'rewrite',
	'A16-write': d => d.what === 'resourceWrite' && d.verdict === 'deny',
	'A16-read': d => d.what === 'resourceRead' && d.verdict === 'deny',
	'A19-config': d => d.what === 'root/configChanged' && d.verdict === 'strip' && d.detail.split(',').includes('http.proxy'),
};
const verdicts = baseline.results.map(b => {
	const g = gated.results.find(r => r.id === b.id)!;
	const decided = gated.gateDecisions.some(requiredDecision[b.id] ?? (() => false));
	let verdict: 'pass' | 'fail' | 'invalid';
	if (!b.triggerSent || b.outcome !== 'vulnerable') {
		verdict = 'invalid'; // cannot fail on the baseline, so a gated "contained" means nothing
	} else if (g.triggerSent && g.outcome === 'contained' && decided) {
		verdict = 'pass';
	} else {
		verdict = 'fail';
	}
	return { id: b.id, title: b.title, baseline: b.outcome, gated: g.outcome, gateDecision: decided, verdict };
});
const summary = { nonce: NONCE, armed: !!ARM_NONCE && ARM_NONCE === NONCE, verdicts, baseline, gated };
fs.writeFileSync(path.join(RUN_DIR, 'results.json'), JSON.stringify(summary, null, 1));
for (const v of verdicts) {
	console.log(`${v.id.padEnd(10)} baseline=${v.baseline.padEnd(10)} gated=${v.gated.padEnd(10)} => ${v.verdict.toUpperCase()}  ${v.title}`);
}
process.exit(verdicts.every(v => v.verdict === 'pass') ? 0 : 1);
