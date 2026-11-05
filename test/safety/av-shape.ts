// Endpoint-protection (AV) shapes that must never exist as host files (EDR fixture-safety).
// Endpoint protection quarantines Contagious-Interview-shaped workspaces
// and keeps flagging variants on the user's machine, so these checks are about the
// *shape*, not live-ness: an armed-only, RFC 5737-only fixture is still detected.
//   av-loader (workspace level): a folder-open or hidden task in tasks.json, and either the task
//     file itself or a script its command names in the same workspace carries loader traits
//     (fetch tool, inline node/eval, nohup/detach, browser/wallet/keychain data paths).
//   av-fetch-eval (any file): a fetch tool together with inline node/eval or a pipe into an
//     interpreter in one file.
// Exempt: encoded `*.parts.json` (assembled in memory, executed only inside a tab).
// Pure functions over (path, text): fixture-lint, its --av pass and clean-host share them.

import * as path from 'node:path';

const FETCH_CMD = new RegExp(String.raw`\b(curl|wget)\s+(-|"|'|https?:|\$|[A-Za-z0-9.-]+\.[a-z]{2,})|\b(irm|iwr|Invoke-RestMethod|Invoke-WebRequest|certutil|bitsadmin)\b|urllib\.request|\bhttps?\.get\s*\(`, 'i');
const INLINE_EVAL = /\bnode\s+(-e|--eval|-p|--print)\b|\beval\s*\(|\bnew\s+Function\s*\(|\|\s*(sudo\s+)?(sh|bash|zsh|dash|node|python3?|perl|ruby|pwsh|powershell|iex)\b/;
const DETACH = /\bnohup\b|\bsetsid\b|\bdisown\b|\bdetached\s*:\s*true\b|&\s*>\s*\/dev\/null\s*&|\)\s*&\s*$/m;
const DATA_PATHS = /Login Data|google-chrome|Google\/Chrome|BraveSoftware|Mozilla\/Firefox|\bCookies\b|Local Extension Settings|nkbihfbeogaeaoehlefnkodbefgpgknn|\bsolana\b|\bid\.json\b|Exodus|Electrum|MetaMask|\bkeychain\b|login\.keychain|\.keychain-db/i;
const LOADER_TRAITS: Array<[string, RegExp]> = [['fetch tool', FETCH_CMD], ['inline node/eval', INLINE_EVAL], ['nohup/detach', DETACH], ['browser/wallet/keychain data', DATA_PATHS]];

export function exempt(rel: string): boolean {
	return rel.endsWith('.parts.json');
}

/** Loader traits present in a text (names, for the message). */
export function loaderTraits(text: string): string[] {
	return LOADER_TRAITS.filter(([, re]) => re.test(text)).map(([n]) => n);
}

/** A tasks.json carrying a folder-open or hidden task. */
export function autoTask(text: string): boolean {
	return /folderOpen/.test(text) || /"reveal"\s*:\s*"(never|silent)"|"hide"\s*:\s*true|"close"\s*:\s*true/.test(text);
}

/** Workspace-relative paths a tasks.json's commands/args name (best effort, JSONC-tolerant). */
export function referencedScripts(taskText: string): string[] {
	const strings = [...taskText.matchAll(/"(?:command|args|script|program)"\s*:\s*(\[[^\]]*\]|"(?:[^"\\]|\\.)*")/g)].flatMap(m => [...m[1].matchAll(/"((?:[^"\\]|\\.)*)"/g)].map(s => s[1]));
	const out = new Set<string>();
	for (const s of strings) {
		for (const tok of s.split(/[\s;&|()'"`]+/)) {
			const t = tok.replace(/^\$\{workspaceFolder\}\/?/, '').replace(/^\.\//, '');
			if (/^[\w.@+-][\w.@+/-]*\.(sh|bash|zsh|js|cjs|mjs|ts|py|ps1|pl|rb|cmd|bat)$/.test(t) && !t.includes('..')) {
				out.add(t);
			}
		}
	}
	return [...out];
}

/**
 * All AV-shape findings for a set of files. `files` maps repo- or workspace-relative paths to
 * text; `read` lets a caller resolve scripts that are not in the map (e.g. a directory walk).
 */
export function avFindings(files: Map<string, string>, read: (rel: string) => string | undefined = () => undefined): string[] {
	const out: string[] = [];
	for (const [rel, text] of files) {
		if (exempt(rel)) {
			continue;
		}
		if (FETCH_CMD.test(text) && INLINE_EVAL.test(text)) {
			out.push(`${rel}: av-fetch-eval: a fetch tool and inline node/eval or a pipe into an interpreter in one file (AV loader shape; store as parts, assemble in the tab)`);
		}
		if (path.posix.basename(rel) !== 'tasks.json' || !autoTask(text)) {
			continue;
		}
		const own = loaderTraits(text);
		if (own.length) {
			out.push(`${rel}: av-loader: folder-open/hidden task with ${own.join(', ')} in the task file (AV signature; store as parts, assemble in the tab)`);
		}
		// The workspace root is the parent of .vscode/ (or the task file's own dir).
		const dir = path.posix.dirname(rel);
		const root = path.posix.basename(dir) === '.vscode' ? path.posix.dirname(dir) : dir;
		for (const s of referencedScripts(text)) {
			const sRel = root === '.' ? s : `${root}/${s}`;
			const sText = files.get(sRel) ?? read(sRel);
			const traits = sText === undefined || exempt(sRel) ? [] : loaderTraits(sText);
			if (traits.length) {
				out.push(`${rel}: av-loader: folder-open/hidden task runs ${sRel}, which has ${traits.join(', ')} (split-file loader shape; store as parts, assemble in the tab)`);
			}
		}
	}
	return out;
}
