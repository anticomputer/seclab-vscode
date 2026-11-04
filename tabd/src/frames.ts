// Frame codec for the seclab-tabd stdio protocol (docs/tabd/PROTOCOL.md §1).
// [u32be length][u32be channel][payload]; channel 0 = one JSON-RPC message.

export const MAX_FRAME = 1 << 20;
const HEADER = 8;

export interface Frame {
	readonly channel: number;
	readonly payload: Buffer;
}

export class FrameError extends Error { }

export function encodeFrame(channel: number, payload: Uint8Array): Buffer {
	if (!Number.isInteger(channel) || channel < 0 || channel > 0xffffffff) {
		throw new FrameError(`invalid channel ${channel}`);
	}
	if (payload.length > MAX_FRAME) {
		throw new FrameError(`frame too large: ${payload.length}`);
	}
	const header = Buffer.allocUnsafe(HEADER);
	header.writeUInt32BE(payload.length, 0);
	header.writeUInt32BE(channel, 4);
	return Buffer.concat([header, payload]);
}

/** Split arbitrary-size stream data into frames no larger than MAX_FRAME. */
export function encodeData(channel: number, data: Uint8Array): Buffer[] {
	const out: Buffer[] = [];
	for (let off = 0; off < data.length; off += MAX_FRAME) {
		out.push(encodeFrame(channel, data.subarray(off, Math.min(off + MAX_FRAME, data.length))));
	}
	return out;
}

export function encodeJson(message: unknown): Buffer {
	return encodeFrame(0, Buffer.from(JSON.stringify(message), 'utf8'));
}

/** Incremental decoder. Throws FrameError on an oversize header (fatal per spec). */
export class FrameDecoder {
	private buf: Buffer = Buffer.alloc(0);

	push(chunk: Buffer): Frame[] {
		this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
		const frames: Frame[] = [];
		while (this.buf.length >= HEADER) {
			const length = this.buf.readUInt32BE(0);
			if (length > MAX_FRAME) {
				throw new FrameError(`frame too large: ${length}`);
			}
			if (this.buf.length < HEADER + length) {
				break;
			}
			const channel = this.buf.readUInt32BE(4);
			// Copy so the payload does not pin the whole accumulation buffer.
			const payload = Buffer.from(this.buf.subarray(HEADER, HEADER + length));
			this.buf = this.buf.subarray(HEADER + length);
			frames.push({ channel, payload });
		}
		return frames;
	}
}
