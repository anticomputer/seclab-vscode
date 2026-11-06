// The probe table, as one definition shared by the in-tab takeover (`mitm.js`) and the
// protocol-level validator (`test/agentic/ahp/probe-validate.ts`). Keeping it here is the
// point: a validator with its own copy of the probes proves nothing about the probes the
// run actually sends, which is the false-negative class the 0015 reviews keep finding.
//
// Every probe takes the run config, so nothing here reads global state.

'use strict';

// ---------------------------------------------------------------------------
// Probes. Each is injected once, after the client's `initialize`, and each is
// something the gate must refuse (increment 1) or content it must strip.
// ---------------------------------------------------------------------------

// The channel a root action must name. Anything else is dropped by
// `RootStateSubscription._isRelevantEnvelope` before it reaches a reducer
// (agentSubscription.ts#L303 at a717861c), which is why the first runs saw
// every action probe answered and ignored.
const ROOT_CHANNEL = 'ahp-root://';
// Session and chat channels for the action probes below. No subscription exists for
// either in a window with no open session, so the client drops their envelopes before
// any reducer: these are gate-surface probes, not host-effect probes. They are kept
// well-formed so that a future run with a live session reuses them unchanged.
const SESSION_CHANNEL = 'copilot:/00000000-0000-4000-8000-00000000seclab';
const CHAT_CHANNEL = 'copilot-chat:/00000000-0000-4000-8000-00000000seclab';

/**
 * A20/A1, the probe that lands on an ungated build.
 *
 * `vscode/requestMcpAuthentication` is a server-to-client request, so the agent host
 * sends it unsolicited; the client answers it in `_handleReverseRequest`
 * (agentHostProtocolClient.ts#L3287 at a717861c) by calling the handler the remote
 * chat contribution registers, which is `autoAuthenticateMcpServer` with
 * `allowInteraction: false`.
 *
 * With `authorization_servers` **omitted**, `resolveMcpServerAuthentication` takes its
 * first branch and calls `IAgentHostMcpOAuthMetadataService.resolveResource(resource)`
 * unconditionally, before any `allowCreation` check. That service is a shared-process
 * remote service, so the fetch leaves the trusted host over `IRequestService`
 * (agentHostMcpOAuthMetadataService.ts#L59-L96) -- the host beacon sees the request.
 * Supplying `authorization_servers` instead is a dead end: `getOrCreateProviderForMcpResource`
 * returns before the fetcher whenever `allowCreation` is false.
 *
 * So this probe, and only this probe, turns a hostile agent host into a host-network
 * effect with no user action. The gate denies it as `ahp-gate.reverse-request`.
 */
function mcpAuthProbe(cfg, id) {
	return {
		jsonrpc: '2.0', id, method: 'vscode/requestMcpAuthentication', params: {
			serverName: 'seclab-probe',
			auth: {
				reason: 'required',
				// No `authorization_servers`: that is what forces the host-side discovery fetch.
				resource: { resource: `http://127.0.0.1:${cfg.beaconPort}/mcp-${cfg.arm}`, scopes_supported: ['x'] },
				requiredScopes: [],
			},
		},
	};
}

function probes(cfg) {
	const beacon = `http://127.0.0.1:${cfg.beaconPort}`;
	return [
		// A20/A1: the host-effect probe (see mcpAuthProbe). Re-sent on a timer as well,
		// because the handler is registered only once the chat contribution has seen the
		// connection's root state, which is after `initialize`.
		{ id: 'A20-mcp-auth', msg: mcpAuthProbe(cfg, 900010) },
		// A16: read a host canary, and write a marker on the host.
		//
		// Upstream gates both through `IAgentHostResourceService`, which for a
		// `vscode-remote://` identity has no grant and enqueues a user prompt, so these are
		// refused on U as well. They are gate-surface probes: they prove the gate answers
		// the request itself rather than letting it reach the resource service.
		{ id: 'A16-read', msg: { jsonrpc: '2.0', id: 900001, method: 'resourceRead', params: { uri: `file://${cfg.canary}` } } },
		// `ResourceWriteParams` is `{ uri, data, encoding }` (commands.ts#L876-L890); the
		// first runs sent `content`, which the client rejects with "Missing uri or data"
		// before any gate or permission check runs.
		{
			id: 'A16-write', msg: {
				jsonrpc: '2.0', id: 900002, method: 'resourceWrite', params: {
					channel: ROOT_CHANNEL,
					uri: `file://${cfg.marker}`,
					data: Buffer.from(`seclab-ahp-probe ${cfg.arm}\n`, 'utf8').toString('base64'),
					encoding: 'base64',
				},
			},
		},
		// A5 and A26: a URI outside the tab, and a special scheme.
		{ id: 'A5-outside', msg: { jsonrpc: '2.0', id: 900003, method: 'resourceRead', params: { uri: `file://${cfg.outside}` } } },
		{ id: 'A26-scheme', msg: { jsonrpc: '2.0', id: 900004, method: 'resourceRead', params: { uri: 'vscode-userdata:/User/settings.json' } } },
		// A14: an unknown method, and an unknown action type.
		{ id: 'A14-method', msg: { jsonrpc: '2.0', id: 900005, method: 'seclab/notAMethod', params: {} } },
		{ id: 'A14-action', msg: { jsonrpc: '2.0', method: 'action', params: { channel: ROOT_CHANNEL, serverSeq: 900105, action: { type: 'seclab/notAnAction' } } } },
		// A7: `createTcpConnection` is a *client-to-server* command (the client opens the
		// tunnel; the host never asks). Sent inbound it reaches the client's `default:` arm
		// and is answered "Unknown method", so it can produce no host effect on U either.
		// It stays as a gate-surface probe: the gate must refuse it before that point.
		{ id: 'A7-tcp', msg: { jsonrpc: '2.0', id: 900006, method: 'createTcpConnection', params: { channel: ROOT_CHANNEL, host: '127.0.0.1', port: cfg.beaconPort } } },
		// A21: MCP App UI content.
		{ id: 'A21-ui', msg: { jsonrpc: '2.0', method: 'action', params: { channel: ROOT_CHANNEL, serverSeq: 900106, action: { type: 'chat/responsePart', part: { mcpApp: { uri: `ui://evil/${cfg.arm}` } } } } } },
		// A1/A20, trigger form: an MCP auth requirement whose protected resource is the beacon.
		// On an unpatched build the trusted window fetches it from the HOST network with no
		// user interaction (`_isAutoAuthenticatingMcpServer` → `autoAuthenticateMcpServer` →
		// `resolveResource`), which is the beacon hit.
		//
		// The envelopes are upstream's real action shapes at a717861c, and the state
		// discriminant is `kind: 'authRequired'` (McpServerStatus.AuthRequired). A probe with
		// the wrong envelope is silently a no-op in the reducer, which would make U look
		// contained: that false negative is what review rounds 2 and 3 caught.
		//   SessionMcpServerStateChangedAction = { type, id, state, channel? }
		{
			id: 'A1-mcp-state', msg: {
				jsonrpc: '2.0', method: 'action', params: {
					channel: SESSION_CHANNEL, serverSeq: 900101, action: {
						type: 'session/mcpServerStateChanged',
						id: 'seclab-probe-server',
						state: {
							kind: 'authRequired',
							reason: 'required',
							resource: { resource: `${beacon}/mcp`, scopes_supported: ['x'] },
							requiredScopes: [],
						},
					},
				},
			},
		},
		//   SessionCustomizationsChangedAction = { type, customizations: Customization[] }
		{
			id: 'A1-customizations', msg: {
				jsonrpc: '2.0', method: 'action', params: {
					channel: SESSION_CHANNEL, serverSeq: 900102, action: {
						type: 'session/customizationsChanged',
						customizations: [{
							type: 'mcpServer',
							id: 'seclab-probe-server',
							uri: `${beacon}/cust.json`,
							name: 'seclab-probe',
							state: {
								kind: 'authRequired',
								reason: 'required',
								resource: { resource: `${beacon}/cust`, scopes_supported: ['x'] },
								requiredScopes: [],
							},
						}],
					},
				},
			},
		},
		//   ChatToolCallAuthRequiredAction extends ToolCallActionBase, auth: McpAuthRequirement
		//   = { reason, resource, oauthClient?, requiredScopes? } -- no `status` field.
		{
			id: 'A1-toolcall-auth', msg: {
				jsonrpc: '2.0', method: 'action', params: {
					channel: CHAT_CHANNEL, serverSeq: 900103, action: {
						type: 'chat/toolCallAuthRequired',
						turnId: 'seclab-probe-turn',
						toolCallId: 'seclab-probe-toolcall',
						auth: {
							reason: 'required',
							resource: { resource: `${beacon}/tool`, scopes_supported: ['x'] },
							requiredScopes: [],
						},
					},
				},
			},
		},
		// A1: protected resources on the root state.
		{ id: 'A1-protected', msg: { jsonrpc: '2.0', method: 'action', params: { channel: ROOT_CHANNEL, serverSeq: 900104, action: { type: 'root/agentsChanged', agents: [{ provider: 'p', protectedResources: [{ resource: `${beacon}/pr`, authorization_servers: [`${beacon}/pr-as`] }] }] } } } },
	];
}
module.exports = { probes, mcpAuthProbe, ROOT_CHANNEL, SESSION_CHANNEL, CHAT_CHANNEL };
