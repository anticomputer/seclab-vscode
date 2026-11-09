// The container half of differential.ts: builds the corpus from each rule's own pattern and records
// our scanner's verdict per line. Runs with --network none in a node container, on a copy of the
// patch's seclabSecretScan.ts and seclabSecretRules.ts. Writes /w/corpus.txt and /w/ours.json.

import * as fs from 'node:fs';
// @ts-ignore: copied next to this file by differential.ts
import { SECLAB_SECRET_RULES } from './seclabSecretRules.ts';
// @ts-ignore: copied next to this file by differential.ts
import { seclabSecretRuleHit } from './seclabSecretScan.ts';

const ALNUM = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const pick = <T>(a: readonly T[]): T => a[Math.floor(Math.random() * a.length)];

// A random string matching a pattern, for the regex subset the rules use: literals, escapes,
// classes, groups (capturing, non-capturing, named, inline-flag), alternation, quantifiers.
// Lookarounds and anchors produce nothing. Good enough to land most samples inside a rule.
function sample(src: string): string {
	let i = 0;
	const esc = (e: string): string[] => {
		switch (e) {
			case 'd': return '0123456789'.split('');
			case 'w': return (ALNUM + '_').split('');
			case 's': return [' '];
			case 'n': case 'r': case 't': return [' '];
			case 'b': case 'B': case 'A': case 'z': return [''];
			case 'x': { const h = src.slice(i, i + 2); i += 2; return [String.fromCharCode(parseInt(h, 16))]; }
			default: return [e];
		}
	};
	const cls = (): string[] => {
		let neg = false;
		const chars: string[] = [];
		if (src[i] === '^') {
			neg = true;
			i++;
		}
		let first = true;
		while (i < src.length && (src[i] !== ']' || first)) {
			first = false;
			let c = src[i++];
			let set: string[];
			if (c === '\\') {
				set = esc(src[i++]);
				if (set.length !== 1) {
					chars.push(...set);
					continue;
				}
				c = set[0];
			}
			if (src[i] === '-' && src[i + 1] && src[i + 1] !== ']') {
				i++;
				let hi = src[i++];
				if (hi === '\\') {
					hi = esc(src[i++])[0];
				}
				for (let k = c.charCodeAt(0); k <= hi.charCodeAt(0); k++) {
					chars.push(String.fromCharCode(k));
				}
				continue;
			}
			chars.push(c);
		}
		i++;
		const printable = chars.filter(c => c >= ' ' && c <= '~');
		return neg ? ALNUM.split('').filter(c => !chars.includes(c)) : (printable.length ? printable : ['a']);
	};
	const quant = (): [number, number] => {
		let lo = 1;
		let hi = 1;
		const c = src[i];
		const m = /^\{(\d+)(,(\d*))?\}/.exec(src.slice(i));
		if (c === '?') { lo = 0; hi = 1; i++; } else if (c === '*') { lo = 0; hi = 8; i++; } else if (c === '+') { lo = 1; hi = 8; i++; } else if (m) {
			lo = +m[1];
			hi = m[2] ? (m[3] ? +m[3] : lo + 8) : lo;
			i += m[0].length;
		}
		if (src[i] === '?' || src[i] === '+') {
			i++;
		}
		return [lo, Math.min(hi, lo + 40)];
	};
	const times = ([lo, hi]: [number, number]) => lo + Math.floor(Math.random() * (hi - lo + 1));
	// Parses one alternation level into a list of alternatives of atoms (each atom a generator).
	type Gen = () => string;
	const alternation = (): Gen => {
		const alts: Gen[][] = [[]];
		while (i < src.length && src[i] !== ')') {
			const c = src[i++];
			if (c === '|') {
				alts.push([]);
				continue;
			}
			let atom: Gen;
			if (c === '(') {
				let look = false;
				if (src[i] === '?') {
					if (src[i + 1] === ':') {
						i += 2;
					} else if (src[i + 1] === '<' && src[i + 2] !== '=' && src[i + 2] !== '!') {
						i = src.indexOf('>', i) + 1;
					} else if (src[i + 1] === '=' || src[i + 1] === '!' || src[i + 1] === '<') {
						look = true;
						i += src[i + 1] === '<' ? 3 : 2;
					} else {
						i = src.indexOf(':', i) + 1;
					}
				}
				const inner = alternation();
				i++;
				atom = look ? () => '' : inner;
			} else if (c === '[') {
				const set = cls();
				atom = () => pick(set);
			} else if (c === '\\') {
				const set = esc(src[i++]);
				atom = () => pick(set);
			} else if (c === '.') {
				atom = () => pick(ALNUM.split(''));
			} else if (c === '^' || c === '$') {
				atom = () => '';
			} else {
				atom = () => c;
			}
			const q = quant();
			const a = atom;
			alts[alts.length - 1].push(() => {
				let s = '';
				for (let k = times(q); k > 0; k--) {
					s += a();
				}
				return s;
			});
		}
		return () => pick(alts).map(g => g()).join('');
	};
	return alternation()();
}

const lines: string[] = [];
for (const r of SECLAB_SECRET_RULES as Array<{ id: string; source: string }>) {
	for (let n = 0; n < 4; n++) {
		let s = '';
		try {
			s = sample(r.source);
		} catch {
			continue;
		}
		if (s && !/[\n\r"\\]/.test(s)) {
			lines.push(`${JSON.stringify(`probe.${r.id.replace(/[^a-z0-9]/gi, '')}`)}: ${JSON.stringify(s)}`);
		}
	}
}
for (const v of ['true', '4', 'on', 'monospace', 'hunter2', 'correct horse battery staple', 'https://example.test/x', 'seclabcanary_ds_0123', 'C:/Program Files/x', '#ffcc00']) {
	for (const k of ['editor.fontFamily', 'probe.apiToken', 'probe.password', 'http.proxy']) {
		lines.push(`${JSON.stringify(k)}: ${JSON.stringify(v)}`);
	}
}
fs.writeFileSync('/w/corpus.txt', lines.join('\n') + '\n');
fs.writeFileSync('/w/ours.json', JSON.stringify(lines.map(l => seclabSecretRuleHit(l) ?? null)));
