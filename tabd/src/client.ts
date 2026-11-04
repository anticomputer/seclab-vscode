// Minimal seclab-tabd client: spawns the supervisor and exposes requests, notifications
// and byte channels. Used by the Tab Manager, the containment harness and the CLI.

import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { encodeData, encodeJson, FrameDecoder } from './frames.ts';

export const CLIENT_PROTOCOL_VERSION = 'seclab-tabd/0.1';

export interface TabdChannel {
	readonly id: number;
	write(data: Uint8Array): void;
	end(): void;
	close(): void;
	onData(cb: (d: Buffer) => void): void;
	onEnd(cb: () => void): void;
	onClose(cb: (error?: string) => void): void;
}

export interface SpawnOptions {
	readonly command: string;
	readonly args: readonly string[];
	/** Environment for the supervisor; keep it minimal (the supervisor wipes it anyway). */
	readonly env: NodeJS.ProcessEnv;
}

export class TabdClient extends EventEmitter {
	private readonly proc: ChildProcessWithoutNullStreams;
	private readonly decoder = new FrameDecoder();
	private nextId = 1;
	private readonly pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
	private readonly channels = new Map<number, EventEmitter>();
	private exited = false;

	constructor(opts: SpawnOptions) {
		super();
		this.proc = spawn(opts.command, [...opts.args], { env: opts.env, stdio: ['pipe', 'pipe', 'pipe'], shell: false });
		this.proc.stdout.on('data', (d: Buffer) => this.onBytes(d));
		this.proc.stderr.on('data', (d: Buffer) => this.emit('stderr', d.toString('utf8')));
		this.proc.on('exit', (code, signal) => {
			this.exited = true;
			const err = new Error(`seclab-tabd exited (${code ?? signal})`);
			for (const p of this.pending.values()) {
				p.reject(err);
			}
			this.pending.clear();
			for (const ch of this.channels.values()) {
				ch.emit('close', 'supervisor exited');
			}
			this.channels.clear();
			this.emit('exit', code, signal);
		});
		this.proc.stdin.on('error', () => { /* exit handler reports */ });
	}

	private onBytes(d: Buffer): void {
		let frames;
		try {
			frames = this.decoder.push(d);
		} catch (e) {
			this.emit('protocolError', (e as Error).message);
			this.proc.kill('SIGKILL');
			return;
		}
		for (const f of frames) {
			if (f.channel !== 0) {
				this.channels.get(f.channel)?.emit('data', f.payload);
				continue;
			}
			const msg = JSON.parse(f.payload.toString('utf8')) as { id?: number; result?: unknown; error?: { code: number; message: string; data?: unknown }; method?: string; params?: Record<string, unknown> };
			if (msg.id !== undefined && (msg.result !== undefined || msg.error !== undefined)) {
				const p = this.pending.get(msg.id);
				this.pending.delete(msg.id);
				if (msg.error) {
					const e = new Error(msg.error.message) as Error & { code?: number; data?: unknown };
					e.code = msg.error.code;
					e.data = msg.error.data;
					p?.reject(e);
				} else {
					p?.resolve(msg.result);
				}
			} else if (msg.method === 'stream.end') {
				this.channels.get(Number(msg.params?.channel))?.emit('end');
			} else if (msg.method === 'stream.close') {
				const id = Number(msg.params?.channel);
				this.channels.get(id)?.emit('close', typeof msg.params?.error === 'string' ? msg.params.error : undefined);
				this.channels.delete(id);
			} else if (msg.method) {
				this.emit('notification', msg.method, msg.params);
			}
		}
	}

	private send(buf: Buffer | Buffer[]): void {
		if (this.exited) {
			throw new Error('seclab-tabd is not running');
		}
		for (const b of Array.isArray(buf) ? buf : [buf]) {
			this.proc.stdin.write(b);
		}
	}

	request<T = unknown>(method: string, params: unknown = {}): Promise<T> {
		const id = this.nextId++;
		return new Promise<T>((resolve, reject) => {
			this.pending.set(id, { resolve: resolve as (v: unknown) => void, reject });
			try {
				this.send(encodeJson({ jsonrpc: '2.0', id, method, params }));
			} catch (e) {
				this.pending.delete(id);
				reject(e as Error);
			}
		});
	}

	notify(method: string, params: unknown): void {
		this.send(encodeJson({ jsonrpc: '2.0', method, params }));
	}

	initialize(name: string, version: string) {
		return this.request<{ protocolVersion: string; drivers: unknown[] }>('initialize', { protocolVersion: CLIENT_PROTOCOL_VERSION, client: { name, version } });
	}

	/** Connect to a tab's REH. Register listeners synchronously on the returned channel. */
	async connect(tabId: string): Promise<{ channel: TabdChannel; connectionToken: string }> {
		const r = await this.request<{ channel: number; connectionToken: string }>('tab.connect', { tabId });
		const em = new EventEmitter();
		this.channels.set(r.channel, em);
		const id = r.channel;
		const channel: TabdChannel = {
			id,
			write: data => this.send(encodeData(id, data)),
			end: () => this.notify('stream.end', { channel: id }),
			close: () => { this.notify('stream.close', { channel: id }); this.channels.delete(id); },
			onData: cb => em.on('data', cb),
			onEnd: cb => em.on('end', cb),
			onClose: cb => em.on('close', cb),
		};
		return { channel, connectionToken: r.connectionToken };
	}

	dispose(): void {
		if (!this.exited) {
			this.proc.stdin.end();
		}
	}
}
