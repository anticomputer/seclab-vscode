// Validates the probe runner's probes at protocol level, against the REAL upstream
// agent-host client, before any editor run.
//
// Why this exists: the first probe-runner runs injected twelve probes into the shipped
// build and produced no host effect at all. Reading upstream showed that most of them
// could not have produced one for reasons that have nothing to do with our gate: an
// action channel no subscription matches, a malformed `resourceWrite`, a command sent in
// the wrong direction. A run that reports "no host effect" for those reasons looks exactly
// like containment, which is the false-negative class every 0015 review round has found.
//
// So each probe states what it must reach in the client, and this driver checks it:
//
//   lands       the probe reaches the behaviour that makes it a threat, and on an
//               ungated client that behaviour happens. Only these probes can decide
//               "vulnerable" in a real run.
//   surface     the probe is well formed and reaches the client's dispatch, but upstream
//               itself refuses it (its own resource permission gate, or a direction that
//               cannot exist). It exercises the gate's surface and can never show a host
//               effect, so a real run must not count its absence as containment.
//
// A probe that reaches neither is INVALID and fails this check, which is the whole point:
// it fails here, in a container with no network and no window, instead of silently
// passing in a run.
//
// The probe table is imported from the runner, never copied: a validator with its own
// copy of the probes proves nothing about the probes a run sends.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { Emitter, Event } from 'vs/base/common/event';
import { DisposableStore } from 'vs/base/common/lifecycle';
import { ResourceMap } from 'vs/base/common/map';
import { URI } from 'vs/base/common/uri';
import { CancellationToken } from 'vs/base/common/cancellation';
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
import { ITextModelService } from 'vs/editor/common/services/resolverService';
import { IWorkspaceTrustEnablementService, IWorkspaceTrustManagementService, IWorkspaceTrustRequestService } from 'vs/platform/workspace/common/workspaceTrust';
import { ILabelService } from 'vs/platform/label/common/label';
import { IRequestService } from 'vs/platform/request/common/request';
import { AgentHostProtocolClient } from 'vs/platform/agentHost/browser/agentHostProtocolClient';
import { IAgentHostResourceService } from 'vs/platform/agentHost/common/agentHostResourceService';
import { IAgentHostMcpOAuthMetadataService } from 'vs/platform/agentHost/common/agentHostMcpOAuthMetadataService';
import { AgentHostMcpOAuthMetadataService } from 'vs/platform/agentHost/common/agentHostMcpOAuthMetadataService';
import { AgentHostResourceService } from 'vs/workbench/services/agentHost/common/agentHostResourceService';
import { IAuthenticationService } from 'vs/workbench/services/authentication/common/authentication';
import { autoAuthenticateMcpServer } from 'vs/workbench/contrib/chat/browser/agentSessions/agentHost/agentHostAuth';
import { AGENT_HOST_SCHEME } from 'vs/platform/agentHost/common/agentHostUri';
import { IAuthenticationMcpAccessService } from 'vs/workbench/services/authentication/browser/authenticationMcpAccessService';
import { IAuthenticationMcpService } from 'vs/workbench/services/authentication/browser/authenticationMcpService';
import { IAuthenticationMcpUsageService } from 'vs/workbench/services/authentication/browser/authenticationMcpUsageService';
import { IDynamicAuthenticationProviderStorageService } from 'vs/workbench/services/authentication/common/dynamicAuthenticationProviderStorage';
import { RogueAgentHost, type JsonRpcMessage } from './rogue-agent-host';
import { probes } from '/probes/probes.js';

const RUN_DIR = must('RUN_DIR');
const NONCE = must('NONCE');
const IDENTITY = 'vscode-remote://seclab+spike';

function must(name: string): string {
	const v = process.env[name];
	if (!v) { throw new Error(`missing env ${name}`); }
	return v;
}

// ---- What each probe must reach -------------------------------------------------------

// `host-effect` is the only kind the probe runner's verdict can read: its evidence rule is
// a host marker, a host beacon hit or the host canary. `renderer` reaches an
// attacker-controlled effect inside the trusted renderer, which is real but invisible to
// that rule, and `surface` exercises the gate's surface and can never show a host effect.
// The distinction is the point: a run must not read a `surface` or `renderer` probe's
// silence as containment, and at least one named `host-effect` probe must be present and
// landing or the whole suite proves nothing.
type Kind = 'host-effect' | 'renderer' | 'surface';

/**
 * The probes whose evidence the runner's verdict actually reads. Named, not counted: a
 * count is satisfied by any probe that happens to be typed `host-effect`, and the suite has
 * to fail if the one probe that can produce a beacon hit is removed or retyped.
 */
const REQUIRED_HOST_EFFECT = ['A20-mcp-auth'];

interface Expectation {
	readonly kind: Kind;
	/** Why, in one line, for the record this writes. */
	readonly reaches: string;
}

const EXPECTED: Record<string, Expectation> = {
	// The only probe that turns a hostile agent host into a host-side effect with no user
	// action: the client fetches the agent-host-chosen URL through IRequestService, which in
	// the real app runs in the shared process, outside the tab's broker.
	'A20-mcp-auth': { kind: 'host-effect', reaches: 'IRequestService fetches the agent-host-chosen resource URL' },
	// Reaches the root reducer, so the agent list the window trusts is attacker-controlled.
	// It cannot push a token here because the run profile is signed out, which is why it is
	// checked at the reducer rather than at the wire.
	'A1-protected': { kind: 'renderer', reaches: 'the root reducer applies the envelope and rootState carries the agent' },
	// Well formed, reaches the client's reverse-request dispatch, and is then refused by
	// upstream's own resource permission gate because a seclab+ identity holds no grant.
	'A16-read': { kind: 'surface', reaches: "the resource service's permission gate" },
	'A16-write': { kind: 'surface', reaches: "the resource service's permission gate" },
	'A5-outside': { kind: 'surface', reaches: "the resource service's permission gate" },
	'A26-scheme': { kind: 'surface', reaches: "the resource service's permission gate" },
	// Unknown by design, in each direction.
	'A14-method': { kind: 'surface', reaches: "the client's unknown-method arm" },
	'A14-action': { kind: 'surface', reaches: 'the root subscription, which has no reducer for it' },
	// A client-to-server command: inbound it can only reach the unknown-method arm.
	'A7-tcp': { kind: 'surface', reaches: "the client's unknown-method arm (it is a client-to-server command)" },
	// Session and chat channels: no subscription exists in a window with no open session.
	'A21-ui': { kind: 'surface', reaches: 'the action dispatch with no matching subscription' },
	'A1-mcp-state': { kind: 'surface', reaches: 'the action dispatch with no matching subscription' },
	'A1-customizations': { kind: 'surface', reaches: 'the action dispatch with no matching subscription' },
	'A1-toolcall-auth': { kind: 'surface', reaches: 'the action dispatch with no matching subscription' },
};

/** Captures the warnings upstream emits when it gives up on a probe, which is the only
 *  place the reason surfaces (`Failed to discover MCP authentication for …`). */
class RecordingLogService extends NullLogService {
	readonly warnings: string[] = [];
	override warn(message: string | Error, ...rest: unknown[]): void {
		this.warnings.push([message instanceof Error ? `${message.name}: ${message.message}` : String(message), ...rest.map(r => r instanceof Error ? `${r.name}: ${r.message}` : String(r))].join(' '));
	}
	override error(message: string | Error, ...rest: unknown[]): void {
		this.warnings.push(`ERROR ${message instanceof Error ? `${message.name}: ${message.message}` : String(message)} ${rest.map(r => r instanceof Error ? `${r.name}: ${r.message}` : String(r)).join(' ')}`);
	}
}

// ---- Services -------------------------------------------------------------------------

class RecordingRequestService implements Partial<IRequestService> {
	declare readonly _serviceBrand: undefined;
	readonly urls: string[] = [];
	async request(options: { url?: string }) {
		this.urls.push(String(options.url ?? ''));
		// 404 with an empty body: the client then falls back to treating the resource origin
		// as the issuer, which is upstream's own behaviour and keeps the probe realistic.
		return { res: { statusCode: 404, headers: {} }, stream: emptyStream() } as never;
	}
	async resolveProxy() { return undefined; }
	async lookupAuthorization() { return undefined; }
	async lookupKerberosAuthorization() { return undefined; }
	async loadCertificates() { return []; }
}

function emptyStream() {
	return {
		on(event: string, cb: (...a: unknown[]) => void) { if (event === 'end') { setTimeout(() => cb(), 0); } return this; },
		removeListener() { return this; },
		destroy() { },
	};
}

async function buildConfiguration(log: ILogService): Promise<Configuration> {
	const defaults = new DefaultConfiguration(log);
	const defaultModel = await defaults.initialize();
	const empty = () => ConfigurationModel.createEmptyModel(log);
	const user = new ConfigurationModelParser('local-user', log);
	user.parse('{}');
	return new Configuration(defaultModel, empty(), empty(), user.configurationModel, empty(), empty(), new ResourceMap(), empty(), new ResourceMap(), log);
}

class ConfigService implements Partial<IConfigurationService> {
	declare readonly _serviceBrand: undefined;
	readonly onDidChangeConfiguration = Event.None;
	constructor(private readonly _c: Configuration) { }
	getValue(a?: unknown, b?: unknown): unknown {
		const section = typeof a === 'string' ? a : undefined;
		return this._c.getValue(section, (typeof a === 'object' ? a : b) ?? {} as object, undefined);
	}
	inspect(key: string) { return this._c.inspect(key, {}, undefined); }
	keys() { return this._c.keys(undefined); }
	async updateValue() { }
	async reloadConfiguration() { }
	getConfigurationData() { return null; }
}

/** Signed out: no provider, no session. The probe must still reach the metadata fetch. */
function signedOutAuthentication() {
	return {
		_serviceBrand: undefined,
		onDidChangeSessions: Event.None, onDidRegisterAuthenticationProvider: Event.None,
		onDidUnregisterAuthenticationProvider: Event.None, onDidChangeDeclaredProviders: Event.None,
		declaredProviders: [], getProviderIds: () => [], isAuthenticationProviderRegistered: () => false,
		isDynamicAuthenticationProvider: () => false,
		getOrActivateProviderIdForServer: async () => undefined,
		createDynamicAuthenticationProvider: async () => undefined,
		unregisterAuthenticationProvider: () => { },
		getSessions: async () => [], getProvider: () => { throw new Error('no provider'); },
		getAccounts: async () => [], createSession: async () => { throw new Error('signed out'); },
	};
}

function inertStorage() {
	return {
		_serviceBrand: undefined,
		getClientRegistration: async () => undefined,
		storeClientRegistration: async () => { },
		removeDynamicProvider: async () => { },
		getInteractedProviders: () => [],
	};
}

// ---- The transport, as in the spike ----------------------------------------------------

function connect(rogue: RogueAgentHost) {
	const onMessage = new Emitter<JsonRpcMessage>();
	const onClose = new Emitter<void>();
	rogue.attach(m => setTimeout(() => onMessage.fire(m), 0));
	return {
		onMessage: onMessage.event, onClose: onClose.event,
		send(m: JsonRpcMessage) { setTimeout(() => rogue.receive(m), 0); },
		dispose() { onMessage.dispose(); onClose.dispose(); },
	};
}

const settle = () => new Promise(r => setTimeout(r, 150));

// ---- The run ---------------------------------------------------------------------------

interface Check { probe: string; kind: Kind; reaches: string; ok: boolean; evidence: Record<string, unknown> }

async function main(): Promise<number> {
	fs.mkdirSync(RUN_DIR, { recursive: true });
	const beaconPort = 59999;
	// Fake paths only: nothing here is read or written, the probes just have to name
	// something that looks like a host path to the client.
	const cfg = {
		arm: NONCE, beaconPort,
		canary: path.join(RUN_DIR, 'canary', 'host-secret.txt'),
		marker: path.join(RUN_DIR, 'PWNED-AHP'),
		outside: path.join(RUN_DIR, 'outside.txt'),
	};
	fs.mkdirSync(path.join(RUN_DIR, 'canary'), { recursive: true });
	fs.writeFileSync(cfg.canary, `seclabcanary_hostfile_${NONCE}\n`);
	fs.writeFileSync(cfg.outside, `seclabcanary_outside_${NONCE}\n`);

	const log = new RecordingLogService();
	const configService = new ConfigService(await buildConfiguration(log));
	const fileService = new FileService(log);
	const store = new DisposableStore();
	store.add(fileService.registerProvider('file', new DiskFileSystemProvider(log)));
	const requests = new RecordingRequestService();
	const services = new ServiceCollection(
		[ILogService, log], [IConfigurationService, configService], [IFileService, fileService],
		[ITelemetryService, NullTelemetryService], [IRequestService, requests],
		[ITextModelService, { _serviceBrand: undefined, createModelReference: async () => { throw new Error('none'); } }],
		[IWorkspaceTrustEnablementService, { _serviceBrand: undefined, isWorkspaceTrustEnabled: () => true }],
		[IWorkspaceTrustManagementService, { _serviceBrand: undefined, isWorkspaceTrusted: () => true, getTrustedUris: () => [], onDidChangeTrust: Event.None, onDidChangeTrustedFolders: Event.None, getUriTrustInfo: async () => ({ trusted: true, uri: URI.file('/') }), setUrisTrust: async () => { } }],
		[IWorkspaceTrustRequestService, { _serviceBrand: undefined, requestResourcesTrust: async () => false }],
		[ILabelService, { _serviceBrand: undefined, getHostLabel: () => 'seclab+spike', onDidChangeFormatters: Event.None }],
		[IAuthenticationService, signedOutAuthentication()],
		[IDefaultAccountService, { _serviceBrand: undefined, currentDefaultAccount: null, getDefaultAccount: async () => null, onDidChangeDefaultAccount: Event.None }],
		// The MCP authentication bookkeeping the resolver consults before it discovers
		// anything. All inert: the probe must reach the discovery fetch, not sign anything in.
		[IAuthenticationMcpAccessService, { _serviceBrand: undefined, onDidChangeMcpSessionAccess: Event.None, isAccessAllowed: () => undefined, readAllowedMcpServers: () => [], updateAllowedMcpServers: () => { }, removeAllowedMcpServers: () => { } }],
		[IAuthenticationMcpService, { _serviceBrand: undefined, onDidChangeMcpSessionAccess: Event.None, updatedAllowedMcpServer: () => { }, showGetSessionPrompt: async () => false, selectSession: async () => { throw new Error('no interaction'); }, requestSessionAccess: () => { }, requestNewSession: async () => { } }],
		[IAuthenticationMcpUsageService, { _serviceBrand: undefined, initializeExtensionUsageCache: async () => { }, extensionUsesAuth: async () => false, readAccountUsages: () => [], removeAccountUsage: () => { }, addAccountUsage: () => { } }],
		[IDynamicAuthenticationProviderStorageService, inertStorage()],
	);
	const inst = new InstantiationService(services, true);
	services.set(IAgentHostResourceService, inst.createInstance(AgentHostResourceService));
	services.set(IAgentHostMcpOAuthMetadataService, inst.createInstance(AgentHostMcpOAuthMetadataService));

	const rogue = new RogueAgentHost(NONCE, NONCE, []);
	const transport = connect(rogue);
	const client = store.add(inst.createInstance(AgentHostProtocolClient, IDENTITY, transport as never, { clientInfo: { name: 'seclab-probe-validate', version: '0' } }));
	await client.connect();
	await settle();

	// As close to what remoteAgentHostChatContribution registers as a harness can be: the
	// same `{ authenticate }` shape and the same agent-host identity it passes
	// (`{ scheme: AGENT_HOST_SCHEME, authority: '' }`), so the stub differs from the
	// workbench in as few places as possible.
	//
	// PRECONDITION, and the limit of what this file proves: the real contribution registers
	// this handler only for a connection it has adopted, after root state. So this proves
	// the CLIENT-SIDE half -- given a registered handler, the probe reaches the host-side
	// discovery fetch. Whether a `seclab+` window registers one at all is the window-side
	// half, and only the pending U run can show that. `mitm.js` re-sends the probe on a
	// timer for exactly this reason.
	// Counted, because a handler that is never invoked and one that runs and declines both
	// answer the agent host `{ authenticated: false }`, and only the count tells them apart.
	const handlerCalls: { serverName: string; error?: string }[] = [];
	store.add(client.registerMcpAuthenticationHandler(async (request: never) => {
		const entry: { serverName: string; error?: string } = { serverName: (request as { serverName: string }).serverName };
		handlerCalls.push(entry);
		try {
			return await inst.invokeFunction(
				autoAuthenticateMcpServer as never,
				{ authenticate: (r: unknown) => (client as unknown as { authenticate(r: unknown): Promise<unknown> }).authenticate(r) } as never,
		{ scheme: AGENT_HOST_SCHEME, authority: '' } as never,
				(request as { serverName: string }).serverName as never,
				(request as { auth: unknown }).auth as never, undefined as never,
			) as never;
		} catch (err) {
			entry.error = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
			throw err;
		}
	}) as never);

	// The positive observable for every notification probe: the client parsed the envelope
	// and dispatched it. Without this, "nothing was fetched" was the only assertion, and a
	// probe that the client dropped on the floor passed exactly like one it dispatched.
	const dispatched: { channel?: string; type?: string }[] = [];
	store.add((client as unknown as { onDidAction: (cb: (e: { channel?: string; action?: { type?: string } }) => void) => { dispose(): void } })
		.onDidAction(e => dispatched.push({ channel: e.channel, type: e.action?.type })));

	const checks: Check[] = [];
	for (const probe of probes(cfg) as { id: string; msg: JsonRpcMessage }[]) {
		const expect = EXPECTED[probe.id];
		if (!expect) {
			checks.push({ probe: probe.id, kind: 'surface', reaches: 'UNDECLARED', ok: false, evidence: { error: 'probe has no declared expectation' } });
			continue;
		}
		checks.push(await drive(probe, expect, rogue, client, requests, log, handlerCalls, beaconPort, dispatched));
	}

	// Every declared expectation must have a probe: a probe removed from the table without
	// its expectation would otherwise pass silently.
	for (const id of Object.keys(EXPECTED)) {
		if (!checks.some(c => c.probe === id)) {
			checks.push({ probe: id, kind: EXPECTED[id].kind, reaches: EXPECTED[id].reaches, ok: false, evidence: { error: 'declared expectation has no probe in the table' } });
		}
	}

	client.dispose();
	store.dispose();

	const landed = checks.filter(c => c.kind === 'host-effect');
	// Every required host-effect probe must be present AND passing. Without this the suite
	// goes green when the only probe whose evidence a run can read has been removed.
	const missingRequired = REQUIRED_HOST_EFFECT.filter(id => !checks.some(c => c.probe === id && c.kind === 'host-effect' && c.ok));
	for (const id of missingRequired) {
		checks.push({ probe: id, kind: 'host-effect', reaches: 'REQUIRED', ok: false, evidence: { error: 'a required host-effect probe is missing, retyped or failing' } });
	}
	const ok = checks.every(c => c.ok) && missingRequired.length === 0;
	fs.writeFileSync(path.join(RUN_DIR, 'probe-validate.json'), JSON.stringify({ nonce: NONCE, ok, checks }, null, 1));
	for (const c of checks) {
		console.log(`${c.ok ? 'OK  ' : 'FAIL'}  ${c.kind.padEnd(7)} ${c.probe.padEnd(19)} ${c.reaches}${c.ok ? '' : `  -> ${JSON.stringify(c.evidence)}`}`);
	}
	console.log(ok
		? `probe-validate: ${checks.length} probe(s) reach what they claim (${landed.length} produce host-observable evidence a run can read)`
		: 'probe-validate: a probe does not reach what it claims');
	return ok ? 0 : 1;
}

async function drive(
	probe: { id: string; msg: JsonRpcMessage },
	expect: Expectation,
	rogue: RogueAgentHost,
	client: { rootState: { value: unknown } },
	requests: RecordingRequestService,
	log: RecordingLogService,
	handlerCalls: { serverName: string; error?: string }[],
	beaconPort: number,
	dispatched: { channel?: string; type?: string }[],
): Promise<Check> {
	const before = requests.urls.length;
	const warnBefore = log.warnings.length;
	const callsBefore = handlerCalls.length;
	const dispatchedBefore = dispatched.length;
	const isRequest = probe.msg.id !== undefined;
	let reply: unknown;
	if (isRequest) {
		reply = await rogue.request(String(probe.msg.method), probe.msg.params);
	} else {
		rogue.notify(String(probe.msg.method), probe.msg.params);
	}
	await settle();
	const newUrls = requests.urls.slice(before);
	const errorMessage = typeof reply === 'object' && reply !== null
		? String(((reply as { error?: { message?: string } }).error?.message) ?? '')
		: String(reply ?? '');

	const seen = dispatched.slice(dispatchedBefore);
	const evidence: Record<string, unknown> = { dispatched: seen, rawReply: clip(JSON.stringify(reply ?? null)), reply: clip(errorMessage), fetched: newUrls, warnings: log.warnings.slice(warnBefore).map(clip), mcpHandlerCalls: handlerCalls.slice(callsBefore) };
	let ok: boolean;
	switch (probe.id) {
		case 'A20-mcp-auth':
			// It landed only if the client actually fetched the attacker's URL.
			ok = newUrls.some(u => u.includes(`127.0.0.1:${beaconPort}`));
			break;
		case 'A1-protected': {
			const agents = (client.rootState.value as { agents?: { provider?: string }[] } | undefined)?.agents ?? [];
			evidence.rootAgents = agents.map(a => a.provider);
			ok = agents.some(a => a.provider === 'p');
			break;
		}
		case 'A16-read': case 'A16-write': case 'A5-outside': case 'A26-scheme':
			// Reached the permission gate, not a shape check in front of it. A "Missing uri
			// or data" here is the malformed-probe bug this file exists to catch.
			ok = /permission|denied|not granted|not allowed|cancelled/i.test(errorMessage) && !/missing uri|unknown method/i.test(errorMessage);
			break;
		case 'A14-method': case 'A7-tcp':
			ok = /unknown method/i.test(errorMessage);
			break;
		// Notification-form probes. The positive observable is that the client parsed the
		// envelope and dispatched it, which `onDidAction` reports; "nothing was fetched"
		// alone is satisfied by a frame the client silently dropped, and that is how a
		// reverted channel fix would have passed.
		case 'A14-action': case 'A21-ui': case 'A1-mcp-state':
		case 'A1-customizations': case 'A1-toolcall-auth': {
			const wanted = (probe.msg.params as { channel?: string; action?: { type?: string } } | undefined);
			ok = seen.some(d => d.channel === wanted?.channel && d.type === wanted?.action?.type) && newUrls.length === 0;
			break;
		}
		default:
			// No silent catch-all: a probe added to the table without a check here would
			// otherwise pass on an assertion about nothing, and count toward the "probes
			// land" guarantee.
			evidence.error = 'probe has no check in the validator';
			ok = false;
			break;
	}
	return { probe: probe.id, kind: expect.kind, reaches: expect.reaches, ok, evidence };
}

const clip = (s: string) => s.length > 200 ? `${s.slice(0, 200)}…` : s;

const code = await main();
// The client leaves liveness timers behind; the checks are complete at this point.
process.exit(code);
