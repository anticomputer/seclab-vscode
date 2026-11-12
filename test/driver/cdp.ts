// Chrome DevTools Protocol over Electron's --remote-debugging-pipe (EDR headless-driver).
// The editor reads CDP on fd 3 and writes on fd 4, NUL-delimited JSON. There is no port, so no
// other process (or a tab) can open a connection. The fds are inheritable, though, so the launcher
// keeps the editor from starting a login shell (VSCODE_CLI=1, --force-disable-user-env) and the
// driver checks that no other process holds them (DrivenEditor.cdpFdHolders). Closing the pipe
// quits the editor.

import type { Readable, Writable } from 'node:stream';

type Pending = { resolve: (v: any) => void; reject: (e: Error) => void; method: string };

export class CdpPipe {
	private nextId = 1;
	private readonly pending = new Map<number, Pending>();
	private readonly listeners = new Set<(method: string, params: any, sessionId?: string) => void>();
	private buf = Buffer.alloc(0);
	private closedError: Error | undefined;
	private readonly out: Writable;

	constructor(out: Writable, inp: Readable) {
		this.out = out;
		inp.on('data', (chunk: Buffer) => this.onData(chunk));
		const close = (why: string) => {
			this.closedError ??= new Error(`cdp: pipe closed (${why})`);
			for (const p of this.pending.values()) {
				p.reject(this.closedError);
			}
			this.pending.clear();
		};
		inp.on('end', () => close('end'));
		inp.on('error', e => close(e.message));
		out.on('error', e => close(e.message));
	}

	private onData(chunk: Buffer): void {
		this.buf = Buffer.concat([this.buf, chunk]);
		for (let i = this.buf.indexOf(0); i >= 0; i = this.buf.indexOf(0)) {
			const msg = JSON.parse(this.buf.subarray(0, i).toString('utf8'));
			this.buf = this.buf.subarray(i + 1);
			if (typeof msg.id === 'number') {
				const p = this.pending.get(msg.id);
				this.pending.delete(msg.id);
				if (msg.error) {
					p?.reject(new Error(`cdp ${p.method}: ${msg.error.message}`));
				} else {
					p?.resolve(msg.result);
				}
			} else if (typeof msg.method === 'string') {
				for (const l of this.listeners) {
					l(msg.method, msg.params, msg.sessionId);
				}
			}
		}
	}

	send<T = any>(method: string, params: object = {}, sessionId?: string, timeoutMs = 60_000): Promise<T> {
		if (this.closedError) {
			return Promise.reject(this.closedError);
		}
		const id = this.nextId++;
		return new Promise<T>((resolve, reject) => {
			const timer = setTimeout(() => {
				this.pending.delete(id);
				reject(new Error(`cdp ${method}: no answer in ${timeoutMs} ms`));
			}, timeoutMs);
			this.pending.set(id, {
				resolve: v => { clearTimeout(timer); resolve(v); },
				reject: e => { clearTimeout(timer); reject(e); },
				method,
			});
			this.out.write(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }) + '\0');
		});
	}

	on(listener: (method: string, params: any, sessionId?: string) => void): () => void {
		this.listeners.add(listener);
		return () => this.listeners.delete(listener);
	}
}
