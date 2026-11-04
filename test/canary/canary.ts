// Shared canary harness library (ADR 20261104-no-real-secret-in-a-tab).
// A canary is a unique, secret-shaped value seeded into one host-side store. The
// acceptance test: no canary ever appears, in any encoding, in anything a tab can
// observe, nor in supervisor/broker logs. Other sessions plug in by adding stores
// (seed) and observation sources (scan inputs).

import { randomBytes } from 'node:crypto';

export interface Canary {
	/** Which host-side store this canary was seeded into. */
	readonly store: string;
	readonly value: string;
}

export function mintCanary(store: string): Canary {
	const tag = store.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 16);
	// Token-shaped so tools treat it like a credential (ghp_-like prefix + hex body).
	return { store, value: `seclabcanary_${tag}_${randomBytes(16).toString('hex')}` };
}

/** Every form we search for: raw, base64 (and base64url), URL-encoded, hex (both cases). */
export function encodings(value: string): Record<string, string> {
	const b = Buffer.from(value, 'utf8');
	return {
		raw: value,
		base64: b.toString('base64').replace(/=+$/, ''),
		base64url: b.toString('base64url'),
		url: encodeURIComponent(value),
		hex: b.toString('hex'),
		HEX: b.toString('hex').toUpperCase(),
	};
}

export interface Hit {
	readonly store: string;
	readonly encoding: string;
	readonly source: string;
}

/**
 * Scan observed data for any canary in any encoding. Base64 is also checked at the
 * three byte alignments, since an embedded secret need not start on a 3-byte boundary.
 */
export function scan(canaries: readonly Canary[], source: string, data: string | Buffer): Hit[] {
	const s = new StreamScanner(canaries, source);
	s.push(Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8'));
	return [...s.hits.values()];
}

export function serialize(canaries: readonly Canary[]): string {
	return JSON.stringify(canaries, null, 2);
}

/** Incremental scanner for large streams (e.g. a whole filesystem dump). */
export class StreamScanner {
	private readonly forms: Array<{ store: string; encoding: string; bytes: Buffer }> = [];
	private tail = Buffer.alloc(0);
	private readonly maxLen: number;
	private readonly source: string;
	readonly hits = new Map<string, Hit>();
	bytes = 0;

	constructor(canaries: readonly Canary[], source: string) {
		this.source = source;
		for (const c of canaries) {
			const probe = scanForms(c.value);
			for (const [encoding, form] of Object.entries(probe)) {
				if (form.length >= 16) {
					this.forms.push({ store: c.store, encoding, bytes: Buffer.from(form, 'latin1') });
				}
			}
		}
		this.maxLen = Math.max(...this.forms.map(f => f.bytes.length));
	}

	push(chunk: Buffer): void {
		this.bytes += chunk.length;
		const buf = Buffer.concat([this.tail, chunk]);
		for (const f of this.forms) {
			if (buf.indexOf(f.bytes) !== -1) {
				this.hits.set(`${f.store}/${f.encoding}`, { store: f.store, encoding: f.encoding, source: this.source });
			}
		}
		this.tail = buf.subarray(Math.max(0, buf.length - this.maxLen));
	}
}

function scanForms(value: string): Record<string, string> {
	const forms: Record<string, string> = { ...encodings(value) };
	delete forms.base64;
	delete forms.base64url;
	// Base64 of an embedded value depends on its byte alignment and on the bytes around it,
	// so match only the stable inner part at each of the three alignments (both alphabets).
	for (const shift of [0, 1, 2]) {
		const b = Buffer.concat([Buffer.alloc(shift), Buffer.from(value)]);
		const lead = shift === 0 ? 0 : 4; // first quad mixes in the unknown preceding bytes
		const usable = Math.floor(b.length / 3) * 4; // drop the trailing partial group
		forms[`base64+${shift}`] = b.toString('base64').slice(lead, usable);
		forms[`base64url+${shift}`] = b.toString('base64url').slice(lead, usable);
	}
	return forms;
}

export function deserialize(json: string): Canary[] {
	return JSON.parse(json) as Canary[];
}
