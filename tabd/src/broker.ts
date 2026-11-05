// The broker contract tabd relies on (docs/broker-protocol.md). `connectBroker`
// (broker-control.ts) calls this gate before anything else, so a broker enforcing a different
// policy schema is refused rather than assumed (fail closed).
//
// Policy schema revision 2 (broker 0.2.0): credentials enter a WebSocket upgrade only when the
// binding sets `websocket: true`. tabd's vault bindings ({host, path}) are HTTP-only; none
// relies on a credentialed WebSocket, so none sets the flag.
// Revision 3 (broker 0.3.0) only restricts: a fail-closed model-host body policy and budget,
// sentinel-only model credentials, and trusted derivation, which tabd does not use yet.

export const BROKER_PROTOCOL = 'seclab-broker/1';
export const BROKER_POLICY_SCHEMA = { version: 1, revision: 3 } as const;

export class BrokerContractError extends Error { }

/** Validate a `broker.hello` result; throws (refuse the tab's credentials) on any mismatch. */
export function checkBrokerHello(hello: unknown, tabId: string): void {
	const h = hello as { protocol?: unknown; tabId?: unknown; policySchema?: { version?: unknown; revision?: unknown } } | null;
	if (!h || typeof h !== 'object') {
		throw new BrokerContractError('broker.hello: no result');
	}
	if (h.protocol !== BROKER_PROTOCOL) {
		throw new BrokerContractError(`broker.hello: protocol ${JSON.stringify(h.protocol)}, expected ${BROKER_PROTOCOL}`);
	}
	if (h.tabId !== tabId) {
		throw new BrokerContractError(`broker.hello: broker is for tab ${JSON.stringify(h.tabId)}, not ${tabId}`);
	}
	const s = h.policySchema;
	if (!s || s.version !== BROKER_POLICY_SCHEMA.version || s.revision !== BROKER_POLICY_SCHEMA.revision) {
		throw new BrokerContractError(`broker.hello: policy schema ${JSON.stringify(s)}, expected ${JSON.stringify(BROKER_POLICY_SCHEMA)}`);
	}
}
