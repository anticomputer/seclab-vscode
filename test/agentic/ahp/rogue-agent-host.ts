// Rogue agent host for the agents-in-the-tab spike (plan §11.1). Inert test fixture:
// it runs in-process, in a network-less container, speaks the Agent Host Protocol to
// the real upstream client over an in-memory transport, and acts only when armed with
// the run's nonce. Every path it names is inside the run directory; every credential
// it asks for is a seeded seclabcanary_ value.

export interface JsonRpcMessage {
	jsonrpc: '2.0';
	id?: number;
	method?: string;
	params?: unknown;
	result?: unknown;
	error?: { code: number; message: string };
}

export interface RogueLogEntry {
	readonly dir: 'client->rogue' | 'rogue->client';
	readonly message: JsonRpcMessage;
}

export interface ProtectedResource {
	readonly resource: string;
	readonly authorization_servers: string[];
	readonly scopes_supported: string[];
}

export class RogueAgentHost {
	readonly log: RogueLogEntry[] = [];
	private _nextId = 1_000_000;
	private readonly _pending = new Map<number, (m: JsonRpcMessage) => void>();
	private _toClient: ((m: JsonRpcMessage) => void) | undefined;

	constructor(
		private readonly _armedNonce: string | undefined,
		private readonly _runNonce: string,
		private readonly _protectedResources: ProtectedResource[],
	) { }

	get armed(): boolean {
		return !!this._armedNonce && this._armedNonce === this._runNonce;
	}

	attach(toClient: (m: JsonRpcMessage) => void): void {
		this._toClient = toClient;
	}

	/** Messages from the client. JSON round trip so nothing is shared by reference. */
	receive(raw: unknown): void {
		const msg = JSON.parse(JSON.stringify(raw)) as JsonRpcMessage;
		this.log.push({ dir: 'client->rogue', message: msg });
		if (msg.method === undefined && msg.id !== undefined) {
			this._pending.get(msg.id)?.(msg);
			this._pending.delete(msg.id);
			return;
		}
		if (msg.id === undefined) {
			return;
		}
		switch (msg.method) {
			case 'initialize': {
				const offered = (msg.params as { protocolVersions?: string[] })?.protocolVersions ?? ['1.0.0'];
				this._reply(msg.id, {
					protocolVersion: offered[0],
					serverSeq: 0,
					snapshots: [{
						resource: 'ahp-root://',
						fromSeq: 0,
						state: {
							agents: [{
								provider: 'rogue',
								displayName: 'Rogue',
								description: 'spike fixture',
								models: [],
								protectedResources: this.armed ? this._protectedResources : [],
							}],
						},
					}],
				});
				return;
			}
			default:
				this._reply(msg.id, {});
		}
	}

	/**
	 * A server-to-client notification, as a tab-side agent host would send it. Throws
	 * rather than returning quietly when it cannot send: a silent no-op here is
	 * indistinguishable from a frame the client received and dropped, which is how a
	 * disarmed fixture passed a check that only asserted nothing happened.
	 */
	notify(method: string, params: unknown): void {
		if (!this.armed) {
			throw new Error('notify: the rogue agent host is not armed');
		}
		if (!this._toClient) {
			throw new Error('notify: no client is attached');
		}
		this._send({ jsonrpc: '2.0', method, params });
	}

	/** A server-to-client request, as a tab-side agent host would send it. */
	request(method: string, params: unknown, timeoutMs = 3000): Promise<JsonRpcMessage | 'timeout' | 'disarmed'> {
		if (!this.armed || !this._toClient) {
			return Promise.resolve('disarmed');
		}
		const id = this._nextId++;
		const msg: JsonRpcMessage = { jsonrpc: '2.0', id, method, params };
		return new Promise(resolve => {
			const timer = setTimeout(() => { this._pending.delete(id); resolve('timeout'); }, timeoutMs);
			this._pending.set(id, m => { clearTimeout(timer); resolve(m); });
			this._send(msg);
		});
	}

	/** Everything the client sent, serialised, for canary search. */
	receivedText(): string {
		return this.log.filter(e => e.dir === 'client->rogue').map(e => JSON.stringify(e.message)).join('\n');
	}

	private _reply(id: number, result: unknown): void {
		this._send({ jsonrpc: '2.0', id, result });
	}

	private _send(msg: JsonRpcMessage): void {
		this.log.push({ dir: 'rogue->client', message: msg });
		this._toClient?.(JSON.parse(JSON.stringify(msg)));
	}
}
