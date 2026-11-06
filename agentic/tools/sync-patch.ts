// Keeps the new files that patch 0015 ships identical to their sources under agentic/patch-src/.
// The upstream edits live only in the patch; the new files are edited in patch-src and
// written into the patch with --write.
//   node agentic/tools/sync-patch.ts --check   # exit 1 on any difference (run by the unit tests)
//   node agentic/tools/sync-patch.ts --write   # regenerate the new-file sections from patch-src

import * as fs from 'node:fs';
import * as path from 'node:path';

const repo = path.resolve(import.meta.dirname, '../..');
export const PATCHES = ['patches/0015-seclab-ahp-gate.patch', 'patches/0017-seclab-fixed-tab-settings.patch'];
const SRC = path.join(repo, 'agentic', 'patch-src');

interface Section { file: string; text: string; isNew: boolean }

function split(patch: string): Section[] {
	return patch.split(/(?=^diff --git )/m).filter(Boolean).map(text => {
		const m = /^diff --git a\/(\S+) b\/\S+/.exec(text);
		if (!m) {
			throw new Error(`unexpected patch text: ${text.slice(0, 60)}`);
		}
		return { file: m[1], text, isNew: /^new file mode /m.test(text) };
	});
}

/** The new-file section git writes for `content` at `file` (mode 100644). */
export function newFileSection(file: string, content: string): string {
	const lines = content.split('\n');
	const noEol = lines[lines.length - 1] !== '';
	if (!noEol) {
		lines.pop();
	}
	return `diff --git a/${file} b/${file}\nnew file mode 100644\nindex 0000000..0000000\n--- /dev/null\n+++ b/${file}\n@@ -0,0 +1,${lines.length} @@\n`
		+ lines.map(l => `+${l}\n`).join('') + (noEol ? '\\ No newline at end of file\n' : '');
}

/** Content lines of a new-file section, joined. */
function sectionContent(text: string): string {
	const body = text.slice(text.indexOf('\n@@') + 1);
	const lines = body.split('\n').slice(1);
	let out = '';
	for (const l of lines) {
		if (l.startsWith('+')) {
			out += l.slice(1) + '\n';
		} else if (l.startsWith('\\')) {
			out = out.slice(0, -1);
		}
	}
	return out;
}

export function check(): string[] {
	const problems: string[] = [];
	const shipped = new Set<string>();
	for (const p of PATCHES) {
		for (const s of split(fs.readFileSync(path.join(repo, p), 'utf8')).filter(s => s.isNew)) {
			shipped.add(s.file);
			const src = path.join(SRC, s.file);
			if (!fs.existsSync(src)) {
				problems.push(`${p}: new file ${s.file} has no source under agentic/patch-src`);
			} else if (sectionContent(s.text) !== fs.readFileSync(src, 'utf8')) {
				problems.push(`${p}: ${s.file} differs from agentic/patch-src (run --write)`);
			}
		}
	}
	for (const f of fs.readdirSync(SRC, { recursive: true, withFileTypes: true }).filter(d => d.isFile())) {
		const rel = path.relative(SRC, path.join(f.parentPath, f.name));
		if (!shipped.has(rel)) {
			problems.push(`agentic/patch-src/${rel} is shipped by no patch`);
		}
	}
	return problems;
}

function write(): void {
	for (const p of PATCHES) {
		const full = path.join(repo, p);
		const sections = split(fs.readFileSync(full, 'utf8')).map(s => s.isNew ? newFileSection(s.file, fs.readFileSync(path.join(SRC, s.file), 'utf8')) : s.text);
		fs.writeFileSync(full, sections.join(''));
	}
}

if (import.meta.main) {
	const mode = process.argv[2];
	if (mode === '--write') {
		write();
	}
	if (mode !== '--write' && mode !== '--check') {
		console.error('usage: sync-patch.ts --check|--write');
		process.exit(2);
	}
	const problems = check();
	for (const p of problems) {
		console.error(p);
	}
	process.exit(problems.length ? 1 : 0);
}
