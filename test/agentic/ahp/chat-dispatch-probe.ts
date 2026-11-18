// Chat dispatch in a tab window, through the REAL ChatService: which entry points can make an
// agent run, and which patch stops each one.
//
// What this settles. Patch 0009 throws at the top of `ChatService.sendRequest` in every `seclab+`
// window, and that refusal is kept (project owner decision, 2026-11-17). Three public entry points
// reach dispatch without passing through `sendRequest`: `resendRequest`, the queue drain behind
// `processPendingRequests`, and `migrateRequests`, whose first send to an untitled session hands
// the request text to that session type's item controller (review round 14). Patch 0018 is a
// second layer on exactly those paths: in a tab window it refuses to dispatch any session but the
// window's own agent-host session. This probe issues real requests down all four paths and
// counts the agent invocations and controller prompts that result, rather than reading the code
// and inferring them.
//
// The ChatService, the chat model, the request parser, the agent service and the queue are all
// upstream's, bundled from the tree under test. Around them sit upstream's own test services
// (the set its `chatService.test.ts` uses), so nothing about the dispatch path is a copy. A
// "tab window" is what the patches read: `IWorkbenchEnvironmentService.remoteAuthority` starting
// `seclab+`, as the agent-registration probe does. Agents are switched ON in the tab window, so a
// refusal on the bypass paths is the foreign-session rule and not the agents-off rule.
//
// THE CONTROLS MUST FAIL. Run against a tree without 0009 (pristine upstream), `sendRequest` in a
// tab window dispatches. Run against the patch series without 0018, `sendRequest` is refused but
// resend and the drain dispatch. Each tree must show its own failure BY NAME, or the run fails,
// and every tree must dispatch in an ordinary window, or a refusal could be a harness that never
// dispatches anything.
//
//   PROBE_TREE=gated|upstream|no-0018   (set by chat-dispatch.sh, one container per tree)

import { CancellationToken } from 'vs/base/common/cancellation.js';
import { DisposableStore } from 'vs/base/common/lifecycle.js';
import { Event } from 'vs/base/common/event.js';
import { observableValue } from 'vs/base/common/observable.js';
import { URI } from 'vs/base/common/uri.js';
import { mock } from 'vs/base/test/common/mock.js';
import { IAgentHostConnectionsService } from 'vs/platform/agentHost/common/agentHostConnectionsService.js';
import { ICommandService } from 'vs/platform/commands/common/commands.js';
import { IConfigurationService } from 'vs/platform/configuration/common/configuration.js';
import { TestConfigurationService } from 'vs/platform/configuration/test/common/testConfigurationService.js';
import { IContextKeyService } from 'vs/platform/contextkey/common/contextkey.js';
import { IFileService } from 'vs/platform/files/common/files.js';
import { ServiceCollection } from 'vs/platform/instantiation/common/serviceCollection.js';
import { TestInstantiationService } from 'vs/platform/instantiation/test/common/instantiationServiceMock.js';
import { MockContextKeyService } from 'vs/platform/keybinding/test/common/mockKeybindingService.js';
import { ILogService, NullLogService } from 'vs/platform/log/common/log.js';
import { IManagedSettingsService, NullManagedSettingsService } from 'vs/platform/policy/common/copilotManagedSettings.js';
import { IStorageService } from 'vs/platform/storage/common/storage.js';
import { ITelemetryService } from 'vs/platform/telemetry/common/telemetry.js';
import { NullTelemetryService } from 'vs/platform/telemetry/common/telemetryUtils.js';
import { IUserDataProfilesService, toUserDataProfile } from 'vs/platform/userDataProfile/common/userDataProfile.js';
import { IWorkspaceContextService } from 'vs/platform/workspace/common/workspace.js';
import { IWorkbenchAssignmentService } from 'vs/workbench/services/assignment/common/assignmentService.js';
import { NullWorkbenchAssignmentService } from 'vs/workbench/services/assignment/test/common/nullAssignmentService.js';
import { IChatEntitlementService } from 'vs/workbench/services/chat/common/chatEntitlementService.js';
import { IWorkbenchEnvironmentService } from 'vs/workbench/services/environment/common/environmentService.js';
import { IExtensionService, nullExtensionDescription } from 'vs/workbench/services/extensions/common/extensions.js';
import { ILifecycleService } from 'vs/workbench/services/lifecycle/common/lifecycle.js';
import { AccountPolicyGateState, IAccountPolicyGateService } from 'vs/workbench/services/policies/common/accountPolicyService.js';
import { IViewsService } from 'vs/workbench/services/views/common/viewsService.js';
import { IWorkspaceEditingService } from 'vs/workbench/services/workspaces/common/workspaceEditing.js';
import { InMemoryTestFileService, TestChatEntitlementService, TestContextService, TestExtensionService, TestStorageService } from 'vs/workbench/test/common/workbenchTestServices.js';
import { IMcpService } from 'vs/workbench/contrib/mcp/common/mcpTypes.js';
import { TestMcpService } from 'vs/workbench/contrib/mcp/test/common/testMcpService.js';
import { IChatVariablesService } from 'vs/workbench/contrib/chat/common/attachments/chatVariables.js';
import { IChatDebugService } from 'vs/workbench/contrib/chat/common/chatDebugService.js';
import { ChatDebugServiceImpl } from 'vs/workbench/contrib/chat/common/chatDebugServiceImpl.js';
import { ChatOpenDiagnosticsService, IChatOpenDiagnosticsService } from 'vs/workbench/contrib/chat/common/chatOpenDiagnosticsService.js';
import { ChatRequestQueueKind, IChatService } from 'vs/workbench/contrib/chat/common/chatService/chatService.js';
import { ChatService } from 'vs/workbench/contrib/chat/common/chatService/chatServiceImpl.js';
import { IChatSessionsService } from 'vs/workbench/contrib/chat/common/chatSessionsService.js';
import { ChatAgentLocation, ChatModeKind } from 'vs/workbench/contrib/chat/common/constants.js';
import { ChatEditingSessionState, IChatEditingService, IChatEditingSession } from 'vs/workbench/contrib/chat/common/editing/chatEditingService.js';
import { ILanguageModelsService } from 'vs/workbench/contrib/chat/common/languageModels.js';
import type { ISerializableChatData } from 'vs/workbench/contrib/chat/common/model/chatModel.js';
import { ChatSessionOperationLog } from 'vs/workbench/contrib/chat/common/model/chatSessionOperationLog.js';
import { revive } from 'vs/base/common/marshalling.js';
import { ChatAgentService, IChatAgentService } from 'vs/workbench/contrib/chat/common/participants/chatAgents.js';
import { ChatSlashCommandService, IChatSlashCommandService } from 'vs/workbench/contrib/chat/common/participants/chatSlashCommands.js';
import { IPromptsService } from 'vs/workbench/contrib/chat/common/promptSyntax/service/promptsService.js';
import { ILanguageModelToolsService } from 'vs/workbench/contrib/chat/common/tools/languageModelToolsService.js';
import { NullLanguageModelsService } from 'vs/workbench/contrib/chat/test/common/languageModels.js';
import { MockChatVariablesService } from 'vs/workbench/contrib/chat/test/common/mockChatVariables.js';
import { MockChatSessionsService } from 'vs/workbench/contrib/chat/test/common/mockChatSessionsService.js';
import { MockPromptsService } from 'vs/workbench/contrib/chat/test/common/promptSyntax/service/mockPromptsService.js';
import { MockLanguageModelToolsService } from 'vs/workbench/contrib/chat/test/common/tools/mockLanguageModelToolsService.js';
import { MockChatService } from 'vs/workbench/contrib/chat/test/common/chatService/mockChatService.js';
// The tree's own gate-log module, or `{ absent: true }` in pristine upstream (see bundle.mjs).
import * as gateCheck from 'seclab-probe:gatecheck';

type Tree = 'gated' | 'upstream' | 'no-0018';
const TREE = process.env.PROBE_TREE as Tree;
if (TREE !== 'gated' && TREE !== 'upstream' && TREE !== 'no-0018') {
	console.error('chat-dispatch probe: PROBE_TREE must be gated, upstream or no-0018');
	process.exit(2);
}

const TAB_AUTHORITY = 'seclab+t-chat-dispatch-probe';
const AGENT = 'seclabProbeAgent';

/** The gate log, as the window's sink would receive it. Empty, and marked absent, in upstream. */
const gateLog: { detail?: { gateRule?: string; reason?: string } }[] = [];
const gate = gateCheck as { absent?: true; seclabAhpInstallWindow?: (sink: (e: unknown) => void) => void };
gate.seclabAhpInstallWindow?.(e => gateLog.push(e as typeof gateLog[number]));

/** Every time the agent actually runs. This, not a return value, is what "dispatched" means. */
let invocations = 0;

/**
 * Every time a session type's item controller receives request text. Materialising an untitled
 * session hands the prompt to the controller before any agent runs, so on the `migrateRequests`
 * path this, as well as an invocation, counts as the request leaving the service (review round
 * 14).
 */
let controllerPrompts = 0;
const PROBE_SCHEME = 'seclabProbeRemote';

/**
 * `migrateRequests` fires its sends without awaiting them, so a refusal surfaces as an unhandled
 * rejection. A listener is installed only while an arm runs (Node's default, which fails the
 * process, applies outside them), and a rejection other than a tab window's refusal fails the
 * run rather than being swallowed (review round 15).
 */
const unexpectedRejections: string[] = [];

/** Two distinct connection objects: the window's own agent host, and some other one. */
const OWN_CONNECTION = { name: 'own' };
const OTHER_CONNECTION = { name: 'other' };

/** Which session the connections service says a resource is. Only patch 0018 reads it. */
type Foreign = 'local' | 'other-connection';
function connections(foreign: Foreign) {
	return {
		ambientConnection: OWN_CONNECTION,
		// Upstream's telemetry reads this; the same stub upstream's own tests use.
		resolveSessionResourceIdentity: () => undefined,
		// `local`: a built-in chat session, which no agent host advertised. `other-connection`: a
		// session another connection advertised, which is the case 0019 exists to keep out.
		resolveSessionResource: () => foreign === 'local' ? undefined : { connection: OTHER_CONNECTION, backendSessionIsAdvertised: true as const },
	};
}

/** A ChatService wired with upstream's own test services, in the window kind given. */
function chatService(store: DisposableStore, authority: string | undefined, foreign: Foreign): ChatService {
	const inst = store.add(new TestInstantiationService(new ServiceCollection(
		[IChatVariablesService, new MockChatVariablesService()],
		[IWorkbenchAssignmentService, new NullWorkbenchAssignmentService()],
		[IMcpService, new TestMcpService()],
		[IPromptsService, new MockPromptsService()],
		[ILanguageModelToolsService, store.add(new MockLanguageModelToolsService())],
	)));
	inst.stub(IStorageService, store.add(new TestStorageService()));
	inst.stub(IChatEntitlementService, new TestChatEntitlementService());
	inst.stub(IManagedSettingsService, new NullManagedSettingsService());
	inst.stub(IAccountPolicyGateService, { _serviceBrand: undefined, gateInfo: { state: AccountPolicyGateState.Inactive }, onDidChangeGateInfo: Event.None, whenInitialized: async () => { } });
	inst.stub(ILogService, new NullLogService());
	inst.stub(IUserDataProfilesService, { defaultProfile: toUserDataProfile('default', 'Default', URI.file('/probe/userdata'), URI.file('/probe/cache')) });
	inst.stub(ITelemetryService, NullTelemetryService);
	inst.stub(IExtensionService, new TestExtensionService());
	const contextKeyService = store.add(new MockContextKeyService());
	inst.stub(IContextKeyService, contextKeyService);
	inst.stub(IViewsService, new TestExtensionService());
	inst.stub(IWorkspaceContextService, new TestContextService());
	inst.stub(IChatSlashCommandService, store.add(inst.createInstance(ChatSlashCommandService)));
	inst.stub(IConfigurationService, new TestConfigurationService());
	inst.stub(ICommandService, { executeCommand: async () => undefined });
	inst.stub(IChatService, new MockChatService());
	// A contributed session type whose item controller records the prompts it is handed, and
	// whose content provider lets an untitled session of that type be opened.
	const sessions = new MockChatSessionsService();
	sessions.createNewChatSessionItem = async (_type, request) => { if (request.prompt) { controllerPrompts++; } return undefined; };
	store.add(sessions.registerChatSessionContentProvider(PROBE_SCHEME, {
		provideChatSessionContent: (resource: URI) => Promise.resolve({ sessionResource: resource, history: [], onWillDispose: Event.None, dispose: () => { } }),
	}));
	inst.stub(IChatSessionsService, sessions);
	inst.stub(IAgentHostConnectionsService, connections(foreign));
	inst.stub(ILanguageModelsService, new NullLanguageModelsService());
	// The window kind, as patches 0009 and 0018 read it. `IWorkbenchEnvironmentService` refines
	// `IEnvironmentService` (one service id), so one object carries both. `seclabAgentsEnabled` is
	// what SECLAB_AGENTS_ENABLED=1 stamps on the window configuration: agents ON, so the bypass
	// paths are refused for the session, not because agents are off.
	inst.stub(IWorkbenchEnvironmentService, {
		workspaceStorageHome: URI.file('/probe/workspaceStorage'),
		remoteAuthority: authority,
		configuration: { seclabAgentsEnabled: true },
	});
	inst.stub(ILifecycleService, { onWillShutdown: Event.None });
	inst.stub(IWorkspaceEditingService, { onDidEnterWorkspace: Event.None });
	inst.stub(IChatDebugService, store.add(new ChatDebugServiceImpl(new TestConfigurationService(), contextKeyService)));
	inst.stub(IChatOpenDiagnosticsService, store.add(new ChatOpenDiagnosticsService(new NullLogService())));
	inst.stub(IChatEditingService, new class extends mock<IChatEditingService>() {
		override startOrContinueGlobalEditingSession(): IChatEditingSession {
			return {
				state: observableValue('state', ChatEditingSessionState.Idle),
				requestDisablement: observableValue('requestDisablement', []),
				entries: observableValue('entries', []),
				dispose: () => { },
			} as unknown as IChatEditingSession;
		}
	});
	inst.stub(IFileService, store.add(new InMemoryTestFileService()));
	const agents = store.add(inst.createInstance(ChatAgentService));
	inst.stub(IChatAgentService, agents);
	store.add(agents.registerAgent(AGENT, {
		id: AGENT, name: AGENT, isDefault: true,
		extensionId: nullExtensionDescription.identifier, extensionVersion: undefined, extensionPublisherId: '',
		publisherDisplayName: '', extensionDisplayName: '', locations: [ChatAgentLocation.Chat], modes: [ChatModeKind.Ask],
		metadata: {}, slashCommands: [], disambiguation: [],
	}));
	store.add(agents.registerAgentImplementation(AGENT, { async invoke() { invocations++; return {}; } }));
	agents.updateAgent(AGENT, {});
	return store.add(inst.createInstance(ChatService));
}

const settle = () => new Promise(r => setTimeout(r, 300));

/**
 * A chat history with one answered request and one queued, recorded in an ORDINARY window. In a
 * tab window `sendRequest` is refused, so the history a tab window holds arrives the way history
 * really does: restored from storage. That is the case the bypass paths are about.
 */
async function recordHistory(): Promise<ISerializableChatData> {
	const store = new DisposableStore();
	try {
		const svc = chatService(store, undefined, 'local');
		const model = store.add(svc.startNewLocalSession(ChatAgentLocation.Chat)).object;
		const sent = await svc.sendRequest(model.sessionResource, 'probe: answered request');
		if (sent.kind !== 'sent') { throw new Error(`recording: the first request was ${sent.kind}`); }
		await sent.data.responseCompletePromise;
		const queued = await svc.sendRequest(model.sessionResource, 'probe: queued request', { queue: ChatRequestQueueKind.Queued, pauseQueue: true });
		if (queued.kind !== 'queued') { throw new Error(`recording: the queued request was ${queued.kind}`); }
		// Through the operation log, which is the format the session store really writes to disk,
		// and which (unlike `toJSON`) carries the queue.
		const data = revive(new ChatSessionOperationLog().read(new ChatSessionOperationLog().createInitial(model))) as ISerializableChatData;
		if (data.requests.length !== 1 || (data.pendingRequests?.length ?? 0) !== 1) {
			throw new Error(`recording: expected 1 request and 1 pending, got ${data.requests.length} and ${data.pendingRequests?.length ?? 0}`);
		}
		await svc.waitForModelDisposals?.();
		return data;
	} finally {
		store.dispose();
	}
}

type Path = 'sendRequest' | 'resendRequest' | 'queue-drain' | 'send-now' | 'migrateRequests';
interface Observation {
	readonly path: Path; readonly window: 'tab' | 'ordinary'; readonly session: Foreign;
	readonly invocations: number; readonly controllerPrompts: number; readonly threw: string | undefined; readonly gateReasons: string[];
	/** The restored session's transcript (request ids, each answered) and queue, unchanged afterwards. */
	readonly kept: boolean;
}

/** One request down one path, in a fresh service with the history restored into it. */
async function issue(path: Path, window: 'tab' | 'ordinary', session: Foreign, history: ISerializableChatData): Promise<Observation> {
	const store = new DisposableStore();
	const before = invocations;
	const promptsBefore = controllerPrompts;
	const logged = gateLog.length;
	const rejections: string[] = [];
	const onRejection = (err: unknown) => {
		const message = (err as Error)?.message ?? String(err);
		rejections.push(message);
		if (!(window === 'tab' && message === 'Unsupported operation')) {
			unexpectedRejections.push(`${path} (${window}, ${session}): ${message}`);
		}
	};
	process.on('unhandledRejection', onRejection);
	let threw: string | undefined;
	let kept = false;
	try {
		const svc = chatService(store, window === 'tab' ? TAB_AUTHORITY : undefined, session);
		const model = store.add(svc.loadSessionFromData(history)).object;
		const snapshot = () => JSON.stringify({
			requests: model.getRequests().map(r => [r.id, !!r.response]),
			pending: model.getPendingRequests().map(p => p.request.id),
		});
		const atStart = snapshot();
		try {
			if (path === 'sendRequest') {
				const r = await svc.sendRequest(model.sessionResource, 'probe: new request');
				if (r.kind === 'sent') { await r.data.responseCompletePromise; }
			} else if (path === 'resendRequest') {
				await svc.resendRequest(model.getRequests()[0]);
			} else if (path === 'queue-drain') {
				svc.processPendingRequests(model.sessionResource);
			} else if (path === 'send-now') {
				// "Run this queued message now": reorders the queue, cancels, then drains.
				await svc.sendPendingRequestImmediately(model.sessionResource, model.getPendingRequests()[0].request.id);
			} else {
				// The restored queue moves to an untitled session of a contributed type, as when a
				// session is committed; the first send there materialises it.
				const untitled = URI.from({ scheme: PROBE_SCHEME, path: '/untitled-probe' });
				const target = await svc.acquireOrLoadSession(untitled, ChatAgentLocation.Chat, CancellationToken.None);
				if (!target) { throw new Error('probe: the untitled target session did not open'); }
				store.add(target);
				svc.migrateRequests(model.sessionResource, untitled);
			}
		} catch (err) {
			threw = (err as Error).message;
		}
		await settle();
		threw ??= rejections[0];
		kept = snapshot() === atStart;
		await svc.waitForModelDisposals?.();
	} finally {
		store.dispose();
		process.off('unhandledRejection', onRejection);
	}
	const gateReasons = gateLog.slice(logged).filter(e => e.detail?.gateRule === 'ahp-sessions.chat').map(e => String(e.detail?.reason));
	return { path, window, session, invocations: invocations - before, controllerPrompts: controllerPrompts - promptsBefore, threw, gateReasons, kept };
}

const PATHS = ['sendRequest', 'resendRequest', 'queue-drain', 'send-now', 'migrateRequests'] as const;
const history = await recordHistory();
const observations: Observation[] = [];
for (const path of PATHS) {
	observations.push(await issue(path, 'ordinary', 'local', history));
	observations.push(await issue(path, 'tab', 'local', history));
	if (path !== 'sendRequest') {
		observations.push(await issue(path, 'tab', 'other-connection', history));
	}
}
const find = (path: Path, window: 'tab' | 'ordinary', session: Foreign = 'local') =>
	observations.find(o => o.path === path && o.window === window && o.session === session)!;
/** The request left the service: an agent ran, or an item controller was handed the prompt. */
const dispatched = (o: Observation) => o.invocations > 0 || o.controllerPrompts > 0;

const problems: string[] = [];
const expect = (ok: boolean, what: string) => { if (!ok) { problems.push(what); } };

// A rejection no arm expects is a broken measurement, in every tree and every expectation.
expect(unexpectedRejections.length === 0, `unexpected rejections: ${unexpectedRejections.join('; ')}`);

// Every tree: the harness really dispatches. Without this a refusal below could be a harness
// that never ran an agent at all, which is the absence this project keeps mistaking for a result.
for (const path of PATHS) {
	expect(dispatched(find(path, 'ordinary')), `${path} in an ordinary window did not dispatch, so a refusal in a tab window would mean nothing`);
}

/** The gated tree's assertions, named, so the same ones can be shown failing on a baseline. */
const CONTAINED_SEND = 'CONTAINED: sendRequest in a tab window is refused by patch 0009 before any session check';
const BYPASS = [['resendRequest', 'local', 'deny:unresolved'], ['resendRequest', 'other-connection', 'deny:other-connection'],
	['queue-drain', 'local', 'deny:unresolved'], ['queue-drain', 'other-connection', 'deny:other-connection'],
	['send-now', 'local', 'deny:unresolved'], ['send-now', 'other-connection', 'deny:other-connection'],
	['migrateRequests', 'local', 'deny:unresolved'], ['migrateRequests', 'other-connection', 'deny:other-connection']] as const;
const containedBypass = ([path, session, reason]: typeof BYPASS[number]) =>
	`CONTAINED: ${path} in a tab window does not dispatch the ${session} session, and the gate log records ${reason}`;
const GATE_MODULE = 'the tree has no gate-log module';
/** A refusal must not cost the user the history it refused to resend or the queue it refused to drain (PR #43 review). */
const keptBypass = ([path, session]: typeof BYPASS[number]) =>
	`KEPT: ${path} refused in a tab window leaves the ${session} session's transcript and queue as they were`;

// PROBE_EXPECT=gated on a baseline tree applies the gated assertions there, and the run passes only
// if they fail exactly where the missing patch predicts: every one in pristine upstream, and only
// the bypass ones without 0018. This is the literal "the test fails without the patch".
const EXPECT = (process.env.PROBE_EXPECT ?? TREE) as Tree;
const PREDICTED_FAILURES: Record<Exclude<Tree, 'gated'>, string[]> = {
	'upstream': [CONTAINED_SEND, ...BYPASS.map(containedBypass), ...BYPASS.map(keptBypass), GATE_MODULE],
	'no-0018': [...BYPASS.map(containedBypass), ...BYPASS.map(keptBypass)],
};

if (EXPECT === 'gated') {
	// 0009: sendRequest refuses before anything else, so 0018's check never sees it.
	const send = find('sendRequest', 'tab');
	expect(!dispatched(send) && send.threw === 'Unsupported operation' && send.gateReasons.length === 0, CONTAINED_SEND);
	// 0018: the bypass paths refuse every foreign session, and say why in the gate log.
	for (const b of BYPASS) {
		const o = find(b[0], 'tab', b[1]);
		expect(!dispatched(o) && o.gateReasons.includes(b[2]), containedBypass(b));
		expect(o.kept, keptBypass(b));
	}
	expect(!gate.absent, GATE_MODULE);
} else if (EXPECT === 'upstream') {
	// The control for 0009: without it, sendRequest in a tab window runs the agent.
	expect(dispatched(find('sendRequest', 'tab')), 'CONTROL (no 0009): sendRequest in a tab window dispatches');
} else {
	// The control for 0018: 0009 still refuses sendRequest, and the bypass paths dispatch.
	expect(!dispatched(find('sendRequest', 'tab')), 'CONTROL (no 0018): sendRequest is still refused, by 0009');
	for (const path of ['resendRequest', 'queue-drain', 'send-now', 'migrateRequests'] as const) {
		for (const session of ['local', 'other-connection'] as const) {
			expect(dispatched(find(path, 'tab', session)), `CONTROL (no 0018): ${path} in a tab window dispatches a ${session} session`);
		}
	}
}

const crossCheck = EXPECT === 'gated' && TREE !== 'gated';
let ok = problems.length === 0;
if (crossCheck) {
	const predicted = PREDICTED_FAILURES[TREE as Exclude<Tree, 'gated'>];
	ok = problems.length === predicted.length && predicted.every(p => problems.includes(p));
}

console.log(JSON.stringify({ tree: TREE, expect: EXPECT, gateLog: !gate.absent, observations, problems, ok }, undefined, '\t'));
if (!ok) {
	console.error(crossCheck
		? `chat-dispatch probe: the gated assertions on ${TREE} did not fail exactly as predicted; failed:\n  ${problems.join('\n  ') || '(nothing)'}`
		: `chat-dispatch probe (${TREE}): ${problems.length} expectation(s) not met:\n  ${problems.join('\n  ')}`);
	process.exit(1);
}
console.log(crossCheck
	? `chat-dispatch probe: the gated assertions fail on ${TREE}, exactly the ${problems.length} the missing patch predicts`
	: `chat-dispatch probe (${TREE}): ok`);
// Upstream's services hold timers; nothing more is measured after this point.
process.exit(0);
