// Keeps the shared files that patch 0036 ships identical to their source under
// build/secret-rules/src/ (EDR configuration-snapshot). The Tab Manager imports the same files, so
// both sides of the "setting withheld" notice run identical code.
//   node build/secret-rules/sync-patch.ts --check   # exit 1 on any difference (run by the unit tests)
//   node build/secret-rules/sync-patch.ts --write   # rewrite the new-file sections from src/
// Also checks the rule table was generated from the gitleaks commit pinned in build/tools/tools.json.

import * as fs from 'node:fs';
import * as path from 'node:path';

const repo = path.resolve(import.meta.dirname, '../..');
export const PATCH = path.join(repo, 'patches', '0036-seclab-tab-configuration-snapshot.patch');
const SRC = path.join(import.meta.dirname, 'src');
export const SHARED = ['seclabSecretRules.ts', 'seclabSecretScan.ts', 'seclabWithhold.ts'];
const TARGET = 'src/vs/workbench/api/browser';

/** The `diff -ruN` new-file section for `content` at `file`. */
export function newFileSection(file: string, content: string): string {
	const lines = content.split('\n');
	const noEol = lines[lines.length - 1] !== '';
	if (!noEol) {
		lines.pop();
	}
	return `diff -ruN a/${file} b/${file}\n--- a/${file}\t1970-01-01 00:00:00\n+++ b/${file}\t1970-01-01 00:00:00\n@@ -0,0 +1,${lines.length} @@\n`
		+ lines.map(l => `+${l}\n`).join('') + (noEol ? '\\ No newline at end of file\n' : '');
}

function sections(patch: string): Array<{ file: string; text: string }> {
	return patch.split(/(?=^diff -ruN )/m).filter(Boolean).map(text => {
		const m = /^diff -ruN a\/(\S+) b\/\S+/.exec(text);
		if (!m) {
			throw new Error(`unexpected patch text: ${text.slice(0, 60)}`);
		}
		return { file: m[1], text };
	});
}

export function problems(patchText: string, read: (f: string) => string = f => fs.readFileSync(path.join(SRC, f), 'utf8')): string[] {
	const out: string[] = [];
	const secs = sections(patchText);
	for (const f of SHARED) {
		const file = `${TARGET}/${f}`;
		const sec = secs.find(s => s.file === file);
		if (!sec) {
			out.push(`${file}: not in the patch`);
		} else if (sec.text !== newFileSection(file, read(f))) {
			out.push(`${file}: differs from build/secret-rules/src/${f} (run --write)`);
		}
	}
	const pinned = JSON.parse(fs.readFileSync(path.join(repo, 'build', 'tools', 'tools.json'), 'utf8')).gitleaks.commit as string;
	if (!read('seclabSecretRules.ts').includes(`(${pinned})`)) {
		out.push(`seclabSecretRules.ts was not generated from the pinned gitleaks commit ${pinned} (rerun generate.ts)`);
	}
	return out;
}

if (import.meta.main) {
	const args = process.argv.slice(2);
	const mode = args[0];
	const patchFile = args[1] === '--patch' && args[2] ? path.resolve(args[2]) : PATCH;
	const text = fs.readFileSync(patchFile, 'utf8');
	if (mode === '--write') {
		const secs = sections(text);
		const rebuilt = secs.map(s => {
			const f = SHARED.find(x => s.file === `${TARGET}/${x}`);
			return f ? newFileSection(s.file, fs.readFileSync(path.join(SRC, f), 'utf8')) : s.text;
		});
		for (const f of SHARED) {
			if (!secs.some(s => s.file === `${TARGET}/${f}`)) {
				rebuilt.push(newFileSection(`${TARGET}/${f}`, fs.readFileSync(path.join(SRC, f), 'utf8')));
			}
		}
		fs.writeFileSync(patchFile, rebuilt.join(''));
	} else if (mode !== '--check') {
		console.error('usage: sync-patch.ts --check | --write [--patch FILE]');
		process.exit(2);
	}
	const p = problems(fs.readFileSync(patchFile, 'utf8'));
	for (const x of p) {
		console.error(`sync-patch: ${x}`);
	}
	process.exitCode = p.length ? 1 : 0;
}
