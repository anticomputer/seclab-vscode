// Agents-in-the-tab spike, step 2: the REAL agent host from our shipped REH build, started
// offline in a network-less container that stands in for the fenced tab, observed by the
// REAL upstream client over its WebSocket. Records what the agent host advertises
// (providers, protected resources and scopes: the input the broker's provider table
// needs) and what it does when it is handed only a sentinel. No real credential exists.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { Event } from 'vs/base/common/event';
import { URI } from 'vs/base/common/uri';
import { IConfigurationService } from 'vs/platform/configuration/common/configuration';
import { ConfigurationModel } from 'vs/platform/configuration/common/configurationModels';
import { Configuration } from 'vs/platform/configuration/common/configurationModels';
import { DefaultConfiguration } from 'vs/platform/configuration/common/configurations';
import { ResourceMap } from 'vs/base/common/map';
import { InstantiationService } from 'vs/platform/instantiation/common/instantiationService';
import { ServiceCollection } from 'vs/platform/instantiation/common/serviceCollection';
import { ILogService, NullLogService } from 'vs/platform/log/common/log';
import { ITelemetryService } from 'vs/platform/telemetry/common/telemetry';
import { NullTelemetryService } from 'vs/platform/telemetry/common/telemetryUtils';
import { IWorkspaceTrustEnablementService, IWorkspaceTrustManagementService, IWorkspaceTrustRequestService } from 'vs/platform/workspace/common/workspaceTrust';
import { IAgentHostResourceService } from 'vs/platform/agentHost/common/agentHostResourceService';
import { AgentHostProtocolClient } from 'vs/platform/agentHost/browser/agentHostProtocolClient';
import { WebSocketClientTransport } from 'vs/platform/agentHost/browser/webSocketClientTransport';

const OUT = process.env.RUN_DIR!;
const ADDRESS = process.env.AH_ADDRESS!;
const TOKEN = process.env.AH_TOKEN!;
const SENTINEL = process.env.SENTINEL!;

const log = new NullLogService();
const defaults = new DefaultConfiguration(log);
const empty = () => ConfigurationModel.createEmptyModel(log);
const configuration = new Configuration(await defaults.initialize(), empty(), empty(), empty(), empty(), empty(), new ResourceMap(), empty(), new ResourceMap(), log);
const configService = {
	_serviceBrand: undefined, onDidChangeConfiguration: Event.None,
	getValue: (s?: unknown) => configuration.getValue(typeof s === 'string' ? s : undefined, {}, undefined),
	inspect: (k: string) => configuration.inspect(k, {}, undefined), keys: () => configuration.keys(undefined),
	updateValue: async () => { }, reloadConfiguration: async () => { },
};
const services = new ServiceCollection(
	[ILogService, log], [IConfigurationService, configService], [ITelemetryService, NullTelemetryService],
	[IAgentHostResourceService, { _serviceBrand: undefined }],
	[IWorkspaceTrustEnablementService, { _serviceBrand: undefined, isWorkspaceTrustEnabled: () => true }],
	[IWorkspaceTrustManagementService, { _serviceBrand: undefined, isWorkspaceTrusted: () => true, getTrustedUris: () => [], onDidChangeTrust: Event.None, onDidChangeTrustedFolders: Event.None }],
	[IWorkspaceTrustRequestService, { _serviceBrand: undefined, requestResourcesTrust: async () => false }],
);
const inst = new InstantiationService(services, true);
const transport = inst.createInstance(WebSocketClientTransport, `ws://${ADDRESS}`, TOKEN, undefined);
const client = inst.createInstance(AgentHostProtocolClient, ADDRESS, transport, { clientInfo: { name: 'seclab-spike', version: '0' } });

const report: Record<string, unknown> = { address: ADDRESS };
try {
	await client.connect();
	await new Promise(r => setTimeout(r, 1500));
	const root = client.rootState.value as { agents?: { provider: string; displayName: string; protectedResources?: unknown[]; models?: unknown[] }[] } | undefined;
	report.agents = (root?.agents ?? []).map(a => ({ provider: a.provider, displayName: a.displayName, models: a.models?.length ?? 0, protectedResources: a.protectedResources ?? [] }));
	// Hand every advertised resource a sentinel, never a real token, as the gate would.
	const auth: unknown[] = [];
	for (const a of root?.agents ?? []) {
		for (const r of (a.protectedResources ?? []) as { resource: string; scopes_supported?: string[] }[]) {
			try {
				const res = await client.authenticate({ resource: r.resource, scopes: r.scopes_supported, token: SENTINEL } as never);
				auth.push({ provider: a.provider, resource: r.resource, result: res });
			} catch (e) { auth.push({ provider: a.provider, resource: r.resource, error: String(e).slice(0, 200) }); }
		}
	}
	report.authenticateWithSentinel = auth;
	await new Promise(r => setTimeout(r, 3000));
	const after = client.rootState.value as { agents?: { provider: string; models?: unknown[] }[] } | undefined;
	report.agentsAfterSentinel = (after?.agents ?? []).map(a => ({ provider: a.provider, models: a.models?.length ?? 0 }));
} catch (e) {
	report.error = String(e).slice(0, 400);
}
fs.writeFileSync(path.join(OUT, 'in-tab-report.json'), JSON.stringify(report, null, 1));
console.log(JSON.stringify(report, null, 1).slice(0, 4000));
void URI;
const agents = (report.agents as unknown[] | undefined) ?? [];
process.exit(report.error || agents.length === 0 ? 1 : 0);
