/*---------------------------------------------------------------------------------------------
 *  seclab-vscode: the agent-host protocol gate (patch 0015).
 *  In a seclab tab window (`seclab+<tab>` authority) the workbench's only agent-host transport is
 *  built over a filtered channel: every frame in either direction passes `SeclabAhpFilter`
 *  with the verdict tables in `seclabAhpPolicyData.ts`. With `seclab.agents.enabled` off, no
 *  connection is made at all. Decisions go to a per-window log, `seclabAhpGate.log`, one JSON
 *  object per line in the shape `tab.events.report` accepts. Other windows are unchanged.
 *--------------------------------------------------------------------------------------------*/

import type { CancellationToken } from '../../../../base/common/cancellation.js';
import { Emitter, Event } from '../../../../base/common/event.js';
import { Disposable, IDisposable } from '../../../../base/common/lifecycle.js';
import { joinPath } from '../../../../base/common/resources.js';
import type { IChannel } from '../../../../base/parts/ipc/common/ipc.js';
import { localize } from '../../../../nls.js';
import { isSeclabAuthority, seclabAhpBrandTransport, seclabAhpInstallWindow, seclabAhpNextConnection } from '../../../../platform/agentHost/common/seclabAhpGateCheck.js';
import { SeclabAhpEvent, SeclabAhpFilter, SeclabAhpOutput } from '../../../../platform/agentHost/common/seclabAhpPolicy.js';
import { SECLAB_AHP_TABLES } from '../../../../platform/agentHost/common/seclabAhpPolicyData.js';
import { IConfigurationService } from '../../../../platform/configuration/common/configuration.js';
import { ConfigurationScope, Extensions as ConfigurationExtensions, IConfigurationRegistry } from '../../../../platform/configuration/common/configurationRegistry.js';
import { IInstantiationService, ServicesAccessor } from '../../../../platform/instantiation/common/instantiation.js';
import { ILoggerService } from '../../../../platform/log/common/log.js';
import { Registry } from '../../../../platform/registry/common/platform.js';
import { IWorkbenchContribution, registerWorkbenchContribution2, WorkbenchPhase } from '../../../common/contributions.js';
import { IWorkbenchEnvironmentService } from '../../environment/common/environmentService.js';

export const SECLAB_AGENTS_ENABLED_SETTING = 'seclab.agents.enabled';

// APPLICATION scope: the remote (tab-supplied) user settings layer can't set it.
Registry.as<IConfigurationRegistry>(ConfigurationExtensions.Configuration).registerConfiguration({
	id: 'seclab.agents',
	title: localize('seclab.agents.title', "Sandboxed tab agents"),
	type: 'object',
	properties: {
		[SECLAB_AGENTS_ENABLED_SETTING]: {
			type: 'boolean',
			default: false,
			scope: ConfigurationScope.APPLICATION,
			description: localize('seclab.agents.enabled', "Connect tab windows to the agent host running inside their tab, through the agent-host gate. When off, tab windows make no agent-host connection."),
		},
	},
});

const DECISIONS_PER_CONNECTION = 2000;
let emitWindow: ((e: SeclabAhpEvent) => void) | undefined;

/** Creates this window's gate log and installs it as the invariant's sink. Idempotent. */
function installWindowSink(accessor: ServicesAccessor): (e: SeclabAhpEvent) => void {
	if (!emitWindow) {
		const environmentService = accessor.get(IWorkbenchEnvironmentService);
		const logger = accessor.get(ILoggerService).createLogger(joinPath(environmentService.windowLogsPath, 'seclabAhpGate.log'), { id: 'seclabAhpGate', name: 'seclab agent-host gate', logLevel: 'always', hidden: true });
		const counts = new Map<number, number>();
		const sink = (e: SeclabAhpEvent) => {
			const connection = typeof e.detail.connection === 'number' ? e.detail.connection : 0;
			const rule = e.detail.gateRule;
			if (rule !== 'ahp-gate.opened' && rule !== 'ahp-gate.verified' && rule !== 'ahp-gate.refused') {
				const n = (counts.get(connection) ?? 0) + 1;
				counts.set(connection, n);
				if (n > DECISIONS_PER_CONNECTION) {
					if (n === DECISIONS_PER_CONNECTION + 1) {
						logger.info(JSON.stringify({ source: 'ahp-gate', class: 'ahp.decision', priority: 'warning', summary: 'ahp-gate.log-capped', detail: { gateRule: 'ahp-gate.log-capped', connection, verdict: 'deny' } } satisfies SeclabAhpEvent));
					}
					return;
				}
			}
			logger.info(JSON.stringify(e));
		};
		emitWindow = sink;
		seclabAhpInstallWindow(sink);
	}
	return emitWindow;
}

/**
 * Whether this window may connect to an agent host. Any window that isn't a seclab tab window
 * may; a tab window may only with `seclab.agents.enabled` on. Read at each connection.
 * This is the predicate patches 0009/0010 call (`seclabAgentHostAllowed`).
 */
export function seclabAgentHostAllowed(accessor: ServicesAccessor, authority: string | undefined): boolean {
	if (!isSeclabAuthority(authority)) {
		return true;
	}
	const emit = installWindowSink(accessor);
	if (accessor.get(IConfigurationService).getValue<boolean>(SECLAB_AGENTS_ENABLED_SETTING) === true) {
		return true;
	}
	emit({ source: 'ahp-gate', class: 'ahp.decision', priority: 'notice', summary: 'ahp-gate.disabled deny', detail: { gateRule: 'ahp-gate.disabled', connection: 0, verdict: 'deny' } });
	return false;
}

/** Builds the agent-host transport for one remote authority: through the gate for a seclab tab
 *  window, unchanged otherwise. */
export class SeclabAhpGate extends Disposable {
	constructor(
		private readonly _authority: string,
		@IInstantiationService private readonly _instantiationService: IInstantiationService,
	) {
		super();
	}

	transport<T extends object>(channel: IChannel, make: (channel: IChannel) => T): T {
		if (!isSeclabAuthority(this._authority)) {
			return make(channel);
		}
		if (!this._instantiationService.invokeFunction(seclabAgentHostAllowed, this._authority)) {
			throw new Error(`seclab: agents are off in tab windows (${SECLAB_AGENTS_ENABLED_SETTING})`);
		}
		const emit = this._instantiationService.invokeFunction(installWindowSink);
		const connection = seclabAhpNextConnection();
		const transport = make(new SeclabAhpGatedChannel(channel, new SeclabAhpFilter(SECLAB_AHP_TABLES, connection, emit)));
		seclabAhpBrandTransport(transport, connection);
		return transport;
	}
}

/** The `agentHostProxy` channel with every frame filtered. Only `connect`, `send` and `close`
 *  calls and the `frame` and `close` events exist on it. */
class SeclabAhpGatedChannel implements IChannel {
	private readonly _frames: Emitter<string>;
	private _upstream: IDisposable | undefined;

	constructor(
		private readonly _channel: IChannel,
		private readonly _filter: SeclabAhpFilter,
	) {
		this._frames = new Emitter<string>({
			onWillAddFirstListener: () => { this._upstream = this._channel.listen<string>('frame')(text => this._deliver(this._filter.fromUpstream(text), false)); },
			onDidRemoveLastListener: () => { this._upstream?.dispose(); this._upstream = undefined; },
		});
	}

	call<T>(command: string, arg?: unknown, cancellationToken?: CancellationToken): Promise<T> {
		if (command === 'send') {
			return this._deliver(this._filter.fromClient(typeof arg === 'string' ? arg : ''), true) as Promise<T>;
		}
		if (command === 'connect' || command === 'close') {
			return this._channel.call<T>(command, arg, cancellationToken);
		}
		return Promise.reject(new Error(`seclab: agent-host channel call '${command}' refused`));
	}

	listen<T>(event: string, arg?: unknown): Event<T> {
		if (event === 'frame') {
			return this._frames.event as unknown as Event<T>;
		}
		if (event === 'close') {
			return this._channel.listen<T>('close', arg);
		}
		return Event.None;
	}

	private _deliver(out: SeclabAhpOutput, fromClient: boolean): Promise<undefined> {
		const sends = out.toUpstream.map(frame => this._channel.call<void>('send', frame));
		if (out.toClient.length) {
			// A refusal answers the client's own send: deliver it after that send returns.
			const deliver = () => out.toClient.forEach(frame => this._frames.fire(frame));
			if (fromClient) {
				queueMicrotask(deliver);
			} else {
				deliver();
			}
		}
		const all = Promise.all(sends).then(() => undefined);
		if (!fromClient) {
			all.catch(() => undefined);
		}
		return all;
	}
}

class SeclabAhpWindowContribution implements IWorkbenchContribution {
	static readonly ID = 'workbench.contrib.seclabAhpGate';

	constructor(
		@IWorkbenchEnvironmentService environmentService: IWorkbenchEnvironmentService,
		@IInstantiationService instantiationService: IInstantiationService,
	) {
		// Before any agent-host client exists: from here on, every transport in this window must be gated.
		if (isSeclabAuthority(environmentService.remoteAuthority)) {
			instantiationService.invokeFunction(installWindowSink);
		}
	}
}

registerWorkbenchContribution2(SeclabAhpWindowContribution.ID, SeclabAhpWindowContribution, WorkbenchPhase.BlockStartup);
