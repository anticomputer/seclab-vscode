// Endpoint-protection (AV) shapes that must never exist as host files (EDR fixture-safety).
// Microsoft Defender quarantines Contagious-Interview-shaped workspaces (Trojan:Script/MalTask.A)
// and keeps flagging variants on the user's corporate endpoint, so these checks are about the
// *shape*, not live-ness: an armed-only, RFC 5737-only fixture is still detected.
//   av-loader (workspace level): a workspace with a folder-open or hidden task (in
//     .vscode/tasks.json or a *.code-workspace) fails if ANY file in it carries loader traits
//     (fetch, inline node/eval, nohup/detach, browser/wallet/keychain data paths). No attempt
//     to resolve which script a task runs: cwd, npm run, extensionless or renamed scripts all
//     defeat that (review SS-2), and fixtures are small.
//   av-fetch-eval (any file): a fetch together with inline node/eval or a pipe into an
//     interpreter in one file.
// Exempt: encoded `*.parts.json` (assembled in memory, executed only inside a tab).
// Pure functions over (path, text): fixture-lint, its --av pass, materialiseFixture and
// clean-host share them.

import * as path from 'node:path';

const FETCH_CMD = new RegExp(String.raw`\b(curl|wget)\s+(-|"|'|https?:|\$|[A-Za-z0-9.-]+\.[a-z]{2,})|\b(irm|iwr|Invoke-RestMethod|Invoke-WebRequest|certutil|bitsadmin)\b|urllib\.request|\bhttps?\.(get|request)\s*\(|\bfetch\s*\(\s*['"\x60]https?:|\baxios\b|\brequire\(\s*['"]request['"]\s*\)`, 'i');
const INLINE_EVAL = /\bnode\s+(-e|--eval|-p|--print)\b|\beval\s*\(|\bFunction\s*\(|\bvm\.runIn\w*\s*\(|\|\s*(sudo\s+)?(sh|bash|zsh|dash|node|python3?|perl|ruby|pwsh|powershell|iex)\b/;
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

/** A tasks.json / *.code-workspace carrying a folder-open or hidden task. */
export function autoTask(text: string): boolean {
	return /folderOpen/.test(text) || /"reveal"\s*:\s*"(never|silent)"|"hide"\s*:\s*true|"close"\s*:\s*true/.test(text);
}

/** The workspace root an auto-task file governs, or undefined if `rel` is not a task file. */
export function taskRoot(rel: string): string | undefined {
	const base = path.posix.basename(rel);
	const dir = path.posix.dirname(rel);
	if (base === 'tasks.json') {
		return path.posix.basename(dir) === '.vscode' ? path.posix.dirname(dir) : dir;
	}
	return base.endsWith('.code-workspace') ? dir : undefined;
}

/**
 * All AV-shape findings for a set of files, keyed by repo- or workspace-relative posix path.
 * The map must hold every file of a workspace (any name or extension) for the workspace rule
 * to see it.
 */
export function avFindings(files: Map<string, string>): string[] {
	const out: string[] = [];
	const roots = new Map<string, string>();
	for (const [rel, text] of files) {
		if (exempt(rel)) {
			continue;
		}
		if (FETCH_CMD.test(text) && INLINE_EVAL.test(text)) {
			out.push(`${rel}: av-fetch-eval: a fetch and inline node/eval or a pipe into an interpreter in one file (AV loader shape; store as parts, assemble in the tab)`);
		}
		const root = taskRoot(rel);
		if (root !== undefined && autoTask(text)) {
			roots.set(root, rel);
		}
	}
	for (const [root, taskFile] of roots) {
		const prefix = root === '.' ? '' : `${root}/`;
		for (const [rel, text] of files) {
			if (!rel.startsWith(prefix) || exempt(rel)) {
				continue;
			}
			const traits = loaderTraits(text);
			if (traits.length) {
				out.push(`${rel}: av-loader: ${traits.join(', ')} in a workspace with a folder-open/hidden task (${taskFile}) (AV loader shape; store as parts, assemble in the tab)`);
			}
		}
	}
	return out;
}
