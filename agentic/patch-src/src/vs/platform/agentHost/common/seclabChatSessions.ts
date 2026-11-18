/*---------------------------------------------------------------------------------------------
 *  seclab-vscode patch 0018: in a `seclab+` window, no chat request is dispatched for a session
 *  other than this window's own agent-host session. A SECOND LAYER behind patch 0009.
 *
 *  Patch 0009 throws at the top of `chatService.sendRequest` in every tab window, and that
 *  refusal stays as it is (project owner decision, 2026-11-17): chat is not open in tab windows.
 *  But `sendRequest` is not the only way in. `resendRequest` and the queue drain
 *  (`processPendingRequests`, also reached from `sendPendingRequestImmediately`) call the
 *  dispatch function directly, and `migrateRequests` re-enters below `sendRequest`. On those
 *  paths this check refuses every session that is not this window's own. `./seclab test
 *  chat-dispatch` issues requests down each path in the real ChatService.
 *
 *  WHAT THIS DOES NOT CLAIM. That a tab window's own agent-host session can be used for chat.
 *  The allow verdict below exists so the rule is stated whole, but 0009 refuses the public entry
 *  point before it is consulted. Opening chat in tab windows is separate future work, with its
 *  own design and review.
 *
 *  WHAT IS REFUSED on the bypass paths: built-in agents and extension participants, which have no
 *  agent-host session; a session belonging to any other connection; and every session in a tab
 *  window where agents are off.
 *
 *  WHY REGISTRATION, NOT JUST IDENTITY (security review round 1, alert 1). Comparing the
 *  resolved connection object with the ambient connection is NOT by itself a test that this
 *  window owns the session. Upstream's `resolveSessionResourceIdentity` first looks the
 *  resource up in its registry and, when that misses, SYNTHESISES an ambient identity from the
 *  scheme alone: any resource whose scheme starts with `agent-host-` resolves to the ambient
 *  connection, registered or not. So an identity-only check would have been a scheme-prefix
 *  string test performed one layer down, which is exactly the dependency this patch exists to
 *  avoid. `backendSessionIsAdvertised` is set only on the registry hit, so requiring it is what
 *  makes this "a session this connection actually advertised".
 *
 *  The identity half still matters, and both are required: registration proves the resource is
 *  real, identity proves the connection serving it is ours and not some other agent host.
 *  `patches/sole-consumer.json` pins both the object equality and the synthesis branch, so an
 *  upstream change to either fails the patch build rather than silently widening this.
 *
 *  This module is in the `common` layer on purpose: its caller, `chatServiceImpl.ts`, is in
 *  `chat/common/`, and upstream's layering forbids a `common` file importing from `browser`.
 *--------------------------------------------------------------------------------------------*/

import type { URI } from '../../../base/common/uri.js';
import type { SeclabAhpEvent } from './seclabAhpPolicy.js';

/**
 * The seclab tab authority prefix, duplicated from `seclabAhpGateCheck.ts` rather than
 * imported. A VALUE import across these modules does not resolve under `node --test`'s type
 * stripping, which would make this module untestable, and an untested access-control predicate
 * is worse than a duplicated four-character string. A unit test asserts every copy in the tree
 * is equal, which is a stronger guarantee than the import it replaces (the same reasoning as
 * patch 0017). Type-only imports are erased, so `SeclabAhpEvent` above is fine.
 */
export const SECLAB_CHAT_AUTHORITY_PREFIX = 'seclab+';

function isSeclabAuthority(authority: string | undefined): boolean {
	return typeof authority === 'string' && authority.startsWith(SECLAB_CHAT_AUTHORITY_PREFIX);
}

/** Just the part of `IAgentHostConnectionsService` this predicate needs, so it can be tested. */
export interface SeclabSessionConnections {
	readonly ambientConnection: unknown;
	resolveSessionResource(sessionResource: URI): {
		readonly connection: unknown;
		/** Set by upstream only when the resource was in its registry, not synthesised. */
		readonly backendSessionIsAdvertised?: true;
	} | undefined;
}

/** Why a request was refused, for the decision log. Never includes the session resource. */
export type SeclabChatSessionVerdict = 'allow' | 'deny:agents-off' | 'deny:unresolved' | 'deny:not-advertised' | 'deny:other-connection';

/**
 * The decision, as a verdict rather than a boolean, so the caller can log WHICH rule refused.
 * A refusal that cannot be told apart from "nothing happened" is not provable from the log.
 *
 * `agentsEnabled` is passed in rather than computed here: it comes from 0015's gate, which
 * reads only sources a tab cannot write.
 */
export function seclabChatSessionVerdict(
	authority: string | undefined,
	agentsEnabled: boolean,
	connections: SeclabSessionConnections,
	sessionResource: URI,
): SeclabChatSessionVerdict {
	if (!isSeclabAuthority(authority)) {
		return 'allow';
	}
	if (!agentsEnabled) {
		return 'deny:agents-off';
	}
	const resolved = connections.resolveSessionResource(sessionResource);
	if (!resolved) {
		// A built-in agent or an extension participant: no agent-host session to resolve.
		return 'deny:unresolved';
	}
	if (resolved.backendSessionIsAdvertised !== true) {
		// Synthesised from the scheme, not advertised by a connection. See the header.
		return 'deny:not-advertised';
	}
	const ambient = connections.ambientConnection;
	// Both sides must be a real connection before they are compared: `undefined === undefined`
	// is true, so without this a window with no ambient connection would allow a session that
	// resolved to nothing. Found by the unit tests, not by reading the code.
	if (!resolved.connection || !ambient || resolved.connection !== ambient) {
		return 'deny:other-connection';
	}
	return 'allow';
}

/** Whether this window's chat gate would dispatch `sessionResource` (behind 0009; see the header). */
export function seclabChatSessionAllowed(
	authority: string | undefined,
	agentsEnabled: boolean,
	connections: SeclabSessionConnections,
	sessionResource: URI,
): boolean {
	return seclabChatSessionVerdict(authority, agentsEnabled, connections, sessionResource) === 'allow';
}

/** The decision event, so a refusal is visible in the window's own gate log. */
export function seclabChatSessionEvent(verdict: SeclabChatSessionVerdict): SeclabAhpEvent {
	const deny = verdict !== 'allow';
	return {
		source: 'ahp-gate',
		class: 'ahp.decision',
		priority: deny ? 'notice' : 'informational',
		summary: `ahp-sessions.chat ${deny ? 'deny' : 'allow'}`,
		detail: { gateRule: 'ahp-sessions.chat', connection: 0, verdict: deny ? 'deny' : 'allow', reason: verdict },
	} as SeclabAhpEvent;
}
