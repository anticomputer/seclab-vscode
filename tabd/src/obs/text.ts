// Display-safety and redaction for observability text. Everything a tab (or a sensor inside
// a tab) can influence goes through here before it is stored, sent to a client or shown.
// Rules: never interpret, always escape, always cap. See docs/adr/20261104-tab-observability.md §3, §6.

// C0/C1 controls, DEL, bidi controls, zero-width and line/paragraph separators, BOM, lone surrogates.
// eslint-disable-next-line no-control-regex
const UNSAFE = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff\ufff9-\ufffb]|[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g;

/** Escape everything that could spoof or restyle a display, then cap to `max` code points. */
export function safeText(input: string, max: number): string {
	const escaped = input.replace(/\\/g, '\\\\').replace(UNSAFE, c => {
		const cp = c.codePointAt(0)!;
		if (cp >= 0xd800 && cp <= 0xdfff) {
			return '\\ufffd';
		}
		return cp < 0x100 ? `\\x${cp.toString(16).padStart(2, '0')}` : `\\u${cp.toString(16).padStart(4, '0')}`;
	});
	const cps = Array.from(escaped);
	return cps.length <= max ? escaped : cps.slice(0, Math.max(0, max - 1)).join('') + '…';
}

interface Redaction { readonly re: RegExp; readonly to: string | ((m: string, ...g: string[]) => string) }

/** A long base64-ish run that mixes cases and digits and isn't path-shaped. */
function b64Run(m: string): string {
	const slashes = (m.match(/\//g) ?? []).length;
	const looksLikePath = m.startsWith('/') || slashes > m.length / 16;
	return !looksLikePath && /[A-Z]/.test(m) && /[a-z]/.test(m) && /[0-9]/.test(m) ? '[redacted:b64]' : m;
}

// Defence in depth only: no real secret can exist in a tab (ADR no-real-secret-in-a-tab).
// Order matters: specific provider shapes before the generic hex/base64 runs.
const REDACTIONS: readonly Redaction[] = [
	{ re: /SECLAB_SNTL_[A-Za-z0-9]{8,}/g, to: '[sentinel]' },
	{ re: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)/g, to: '[redacted:private-key]' },
	{ re: /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})/g, to: '[redacted:github]' },
	{ re: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, to: '[redacted:aws]' },
	{ re: /\bxox[abposr]-[A-Za-z0-9-]{10,}/g, to: '[redacted:slack]' },
	{ re: /\b(?:sk|rk)-[A-Za-z0-9_-]{20,}/g, to: '[redacted:api-key]' },
	{ re: /\bglpat-[A-Za-z0-9_-]{20,}/g, to: '[redacted:gitlab]' },
	{ re: /\bnpm_[A-Za-z0-9]{36}\b/g, to: '[redacted:npm]' },
	{ re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, to: '[redacted:jwt]' },
	{ re: /\b([a-z][a-z0-9+.-]{0,15}:\/\/)[^/\s:@]{1,256}:[^/\s@]{1,256}@/gi, to: '$1[redacted]@' },
	{ re: /((?:^|\s|['"])--?(?:password|passwd|pass|token|secret|api[-_]?key|access[-_]?key|auth|credentials?)[=:])\S+/gi, to: '$1[redacted]' },
	{ re: /\b((?:proxy-)?authorization|x-api-key|cookie|set-cookie|private-token)(\s*[:=]\s*)[^\r\n"']+/gi, to: '$1$2[redacted]' },
	{ re: /\b[0-9a-fA-F]{32,}\b/g, to: '[redacted:hex]' },
	{ re: /[A-Za-z0-9+/_-]{40,}={0,2}/g, to: b64Run },
];

// Header values (`-H "Authorization: …"`) are covered by the header-name rule above.
const SECRET_FLAG = /^--?(?:password|passwd|pass|token|secret|api[-_]?key|access[-_]?key|auth|credentials?)$/i;

export function redact(s: string): { text: string; changed: boolean } {
	let out = s;
	for (const r of REDACTIONS) {
		out = out.replace(r.re, r.to as string);
	}
	return { text: out, changed: out !== s };
}

/** Redact an argv: each item, plus the value after a bare secret flag or a credential header. */
export function redactArgv(argv: readonly string[]): { argv: string[]; changed: boolean } {
	let changed = false;
	const out = argv.map((a, i) => {
		const prev = i > 0 ? argv[i - 1] : '';
		if (SECRET_FLAG.test(prev) && !a.startsWith('-')) {
			changed = true;
			return '[redacted]';
		}
		const r = redact(a);
		changed ||= r.changed;
		return r.text;
	});
	return { argv: out, changed };
}

/** Redact then escape: the one function to apply to any tab-influenced string. */
export function clean(s: string, max: number): { text: string; changed: boolean } {
	const r = redact(s);
	return { text: safeText(r.text, max), changed: r.changed };
}
