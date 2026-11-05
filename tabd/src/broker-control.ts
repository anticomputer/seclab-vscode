// Broker control client (docs/broker-protocol.md §1): newline-delimited JSON-RPC 2.0 over the
// stdio of `docker exec -i <broker> seclab-broker control`. Nothing listens on the host.
// tabd sends requests; the broker sends only responses and notifications.
//
// Secrets: params of `proxy.auth.set`, `credential.*` carry real values. This module never logs
// or echoes a request; errors carry the broker's message (safe by protocol) and the method only.

import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import { checkBrokerHello } from './broker.ts';

export const MAX_LINE = 1024 * 1024;

export class BrokerControlError extends Error {
	readonly code: number;
	constructor(code: number, message: string) {
		super(message);
		this.code = code;
	}
}

/** `seclab-broker control` printed -32002 and exited: the socket isn't up yet. Retry. */
export const CONTROL_UNAVAILABLE = -32002;

export interface BrokerNotification {
	readonly method: string;
	readonly params: unknown;
}

interface Pending {
	readonly method: string;
	readonly resolve: (v: unknown) => void;
	readonly reject: (e: Error) => void;
	readonly timer: NodeJS.Timeout;
}

export class BrokerControl {
	private nextId = 1;
	private buf = '';
	private closed: BrokerControlError | undefined;
	private readonly pending = new Map<number, Pending>();
	private readonly listeners = new Set<(n: BrokerNotification) => void>();
	private readonly closeListeners = new Set<(e: BrokerControlError) => void>();
	private readonly proc: ChildProcessWithoutNullStreams;
	private readonly timeoutMs: number;

	constructor(proc: ChildProcessWithoutNullStreams, timeoutMs = 15_000) {
		this.proc = proc;
		this.timeoutMs = timeoutMs;
		proc.stdout.setEncoding('utf8');
		proc.stdout.on('data', (chunk: string) => this.onData(chunk));
		proc.stderr.resume();
		proc.on('exit', code => this.close(new BrokerControlError(-32603, `control channel exited (${code})`)));
		proc.on('error', e => this.close(new BrokerControlError(-32603, `control channel failed: ${e.message}`)));
		proc.stdin.on('error', () => { /* reported through exit */ });
	}

	onNotification(cb: (n: BrokerNotification) => void): () => void {
		this.listeners.add(cb);
		return () => this.listeners.delete(cb);
	}

	onClose(cb: (e: BrokerControlError) => void): void {
		this.closeListeners.add(cb);
	}

	get isClosed(): boolean {
		return this.closed !== undefined;
	}

	request(method: string, params?: Record<string, unknown>, timeoutMs = this.timeoutMs): Promise<unknown> {
		if (this.closed) {
			return Promise.reject(this.closed);
		}
		const id = this.nextId++;
		const line = JSON.stringify(params === undefined ? { jsonrpc: '2.0', id, method } : { jsonrpc: '2.0', id, method, params });
		if (line.length > MAX_LINE) {
			return Promise.reject(new BrokerControlError(-32600, `${method}: request too large`));
		}
		return new Promise((resolve, reject) => {
			const timer = setTimeout(() => {
				this.pending.delete(id);
				reject(new BrokerControlError(-32603, `${method}: no reply within ${timeoutMs} ms`));
			}, timeoutMs);
			this.pending.set(id, { method, resolve, reject, timer });
			this.proc.stdin.write(line + '\n');
		});
	}

	close(reason = new BrokerControlError(-32603, 'control channel closed')): void {
		if (this.closed) {
			return;
		}
		this.closed = reason;
		for (const [id, p] of this.pending) {
			clearTimeout(p.timer);
			p.reject(reason);
			this.pending.delete(id);
		}
		try {
			this.proc.stdin.end();
			this.proc.kill();
		} catch { /* already gone */ }
		for (const cb of this.closeListeners) {
			cb(reason);
		}
	}

	private onData(chunk: string): void {
		this.buf += chunk;
		let nl: number;
		while ((nl = this.buf.indexOf('\n')) >= 0) {
			const line = this.buf.slice(0, nl);
			this.buf = this.buf.slice(nl + 1);
			if (line.trim()) {
				this.onLine(line);
			}
		}
		if (this.buf.length > MAX_LINE) {
			this.close(new BrokerControlError(-32700, 'control line over 1 MiB'));
		}
	}

	private onLine(line: string): void {
		let msg: { jsonrpc?: unknown; id?: unknown; method?: unknown; params?: unknown; result?: unknown; error?: { code?: unknown; message?: unknown } };
		try {
			msg = JSON.parse(line);
		} catch {
			this.close(new BrokerControlError(-32700, 'control channel sent a line that is not JSON'));
			return;
		}
		if (!msg || typeof msg !== 'object' || msg.jsonrpc !== '2.0') {
			this.close(new BrokerControlError(-32600, 'control channel sent a non JSON-RPC 2.0 message'));
			return;
		}
		if (msg.id === null && msg.error) {
			const code = typeof msg.error.code === 'number' ? msg.error.code : -32603;
			this.close(new BrokerControlError(code, String(msg.error.message ?? 'control error').slice(0, 300)));
			return;
		}
		if (typeof msg.id === 'number') {
			const p = this.pending.get(msg.id);
			if (!p) {
				return;
			}
			this.pending.delete(msg.id);
			clearTimeout(p.timer);
			if (msg.error) {
				const code = typeof msg.error.code === 'number' ? msg.error.code : -32603;
				p.reject(new BrokerControlError(code, `${p.method}: ${String(msg.error.message ?? 'error').slice(0, 300)}`));
			} else {
				p.resolve(msg.result);
			}
			return;
		}
		if (msg.id === undefined && typeof msg.method === 'string') {
			for (const cb of this.listeners) {
				cb({ method: msg.method, params: msg.params });
			}
		}
	}
}

/**
 * Open the control channel and check `broker.hello` before anything else (fail closed on a
 * protocol, tab or policy-schema mismatch). Retries while the bridge reports the socket isn't up.
 */
export async function connectBroker(openChannel: () => ChildProcessWithoutNullStreams, tabId: string, opts: { attempts?: number; delayMs?: number } = {}): Promise<BrokerControl> {
	const attempts = opts.attempts ?? 60;
	let last: Error | undefined;
	for (let i = 0; i < attempts; i++) {
		const c = new BrokerControl(openChannel());
		try {
			checkBrokerHello(await c.request('broker.hello'), tabId);
			return c;
		} catch (e) {
			c.close();
			last = e as Error;
			if (!(e instanceof BrokerControlError) || (e.code !== CONTROL_UNAVAILABLE && !/exited/.test(e.message))) {
				throw e;
			}
			await new Promise(r => setTimeout(r, opts.delayMs ?? 500));
		}
	}
	throw last ?? new BrokerControlError(CONTROL_UNAVAILABLE, 'broker control unavailable');
}
