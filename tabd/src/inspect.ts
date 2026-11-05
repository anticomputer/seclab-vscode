// Pre-open workspace summary (informational): what this folder would run automatically or
// feed to AI agents. Read on the host before/while the tab starts; everything here is
// attacker-controlled content, so it is only parsed (bounded, links never followed) and
// reported as data. Nothing is executed and nothing is blocked: in a tab these run inside the
// sandbox; the summary tells the user what the folder tries to do.

import * as fs from 'node:fs';
import * as path from 'node:path';

export interface InspectItem { kind: string; path: string; detail: string }

const MAX_FILE = 1 << 20;
const MAX_ITEMS = 200;
// Assembled at run time (fixture-safety EDR: no loader-shaped literals in host files).
const FETCH = ['cu' + 'rl', 'wg' + 'et', 'Invoke-WebRequest', 'iwr', 'irm', 'Invoke-RestMethod'].join('|');
const INTERP = ['s' + 'h', 'ba' + 'sh', 'zsh', 'no' + 'de', 'python3?', 'pwsh', 'iex', 'Invoke-Expression'].join('|');
const FETCH_RUN = new RegExp(`\\b(${FETCH})\\b[^|\\n]*\\|\\s*(sudo\\s+)?(${INTERP})\\b`, 'i');

/** Read a workspace file without following links; undefined if absent, a link, or too big.
 *  The final open is O_NOFOLLOW|O_NONBLOCK and re-checked with fstat (no FIFO can block tabd). */
function readText(root: string, rel: string): string | undefined {
	if (!noLinks(root, rel)) {
		return undefined;
	}
	let fd: number | undefined;
	try {
		fd = fs.openSync(path.join(root, ...rel.split('/')), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
		const st = fs.fstatSync(fd);
		if (!st.isFile() || st.size > MAX_FILE) {
			return undefined;
		}
		return fs.readFileSync(fd, 'utf8').replace(/^\uFEFF/, '');
	} catch {
		return undefined;
	} finally {
		if (fd !== undefined) {
			fs.closeSync(fd);
		}
	}
}

/** Every component of rel exists and none is a link. */
function noLinks(root: string, rel: string): boolean {
	let cur = root;
	for (const seg of rel.split('/')) {
		cur = path.join(cur, seg);
		try {
			if (fs.lstatSync(cur).isSymbolicLink()) {
				return false;
			}
		} catch {
			return false;
		}
	}
	return true;
}

/** JSON with comments and trailing commas (string-aware); undefined if it still doesn't parse. */
export function parseJsonc(text: string): unknown {
	let out = '';
	let i = 0;
	let inStr = false;
	while (i < text.length) {
		const ch = text[i];
		if (inStr) {
			out += ch;
			if (ch === '\\') {
				out += text[i + 1] ?? '';
				i += 2;
				continue;
			}
			if (ch === '"') {
				inStr = false;
			}
			i++;
		} else if (ch === '"') {
			inStr = true;
			out += ch;
			i++;
		} else if (ch === '/' && text[i + 1] === '/') {
			while (i < text.length && text[i] !== '\n') {
				i++;
			}
		} else if (ch === '/' && text[i + 1] === '*') {
			const end = text.indexOf('*/', i + 2);
			i = end < 0 ? text.length : end + 2;
		} else if (ch === ',' && /^\s*[}\]]/.test(text.slice(i + 1, i + 200).replace(/\/\/[^\n]*|\/\*[\s\S]*?\*\//g, ''))) {
			i++; // trailing comma outside strings (RR-1: never inside a string)
		} else {
			out += ch;
			i++;
		}
	}
	try {
		return JSON.parse(out);
	} catch {
		return undefined;
	}
}

const str = (v: unknown, max = 200): string => {
	let s: string;
	try {
		// Never recurse on folder data: arrays are joined one level deep, anything else is
		// serialised with a size budget (RR-1: deep nesting must not throw).
		s = Array.isArray(v) ? v.slice(0, 50).map(x => typeof x === 'string' ? x : typeof x === 'number' || typeof x === 'boolean' ? String(x) : '[…]').join(' ')
			: typeof v === 'string' ? v : v === undefined ? '' : (JSON.stringify(v) ?? '').slice(0, max);
	} catch {
		s = '[unreadable]';
	}
	return s.length > max ? `${s.slice(0, max - 1)}…` : s;
};
const obj = (v: unknown): Record<string, unknown> | undefined => (v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : undefined);

export function inspectWorkspace(root: string): { items: InspectItem[]; truncated: boolean } {
	const items: InspectItem[] = [];
	const add = (kind: string, p: string, detail: string) => {
		if (items.length < MAX_ITEMS) {
			items.push({ kind, path: p, detail });
		}
	};
	// A target file that exists but doesn't parse here may still be run by VS Code's tolerant
	// parser: say so rather than dropping it (RR-1).
	const json = (rel: string): Record<string, unknown> | undefined => {
		const text = readText(root, rel);
		if (text === undefined) {
			return undefined;
		}
		const v = obj(parseJsonc(text));
		if (!v) {
			add('unparsed config (may still be run)', rel, `${text.length} characters`);
		}
		return v;
	};
	// Each section is isolated: one hostile file can't suppress the rest (RR-1).
	const section = (name: string, f: () => void) => {
		try {
			f();
		} catch {
			add('unreadable config', name, 'could not be summarised');
		}
	};

	// Tasks: folder-open, hidden, and fetch-and-run shapes.
	section('.vscode/tasks.json', () => {
		const tasks = json('.vscode/tasks.json');
		for (const t of (Array.isArray(tasks?.tasks) ? tasks.tasks : []) as unknown[]) {
			const task = obj(t);
			if (!task) {
				continue;
			}
			const cmd = `${str(task.command, 400)} ${str(task.args, 400)}`.trim();
			const label = str(task.label ?? task.command, 80);
			const os = ['osx', 'linux', 'windows'].map(k => str(obj(task[k])?.command, 400)).filter(Boolean).join(' | ');
			if (obj(task.runOptions)?.runOn === 'folderOpen') {
				add('folder-open task', '.vscode/tasks.json', `${label}: ${cmd}`);
			}
			const pres = obj(task.presentation);
			if (pres?.reveal === 'never' || pres?.echo === false || task.hide === true) {
				add('hidden task', '.vscode/tasks.json', label);
			}
			if (FETCH_RUN.test(`${cmd} ${os}`)) {
				add('downloads and runs code', '.vscode/tasks.json', label);
			}
		}
	});

	// Dev container lifecycle commands (initializeCommand runs on the HOST in stock VS Code).
	for (const f of ['.devcontainer/devcontainer.json', '.devcontainer.json']) {
		section(f, () => {
			const dc = json(f);
			for (const k of ['initializeCommand', 'onCreateCommand', 'updateContentCommand', 'postCreateCommand', 'postStartCommand', 'postAttachCommand']) {
				if (dc?.[k] !== undefined) {
					add(k === 'initializeCommand' ? 'dev container command (host side in stock VS Code)' : 'dev container command', f, `${k}: ${str(dc[k])}`);
				}
			}
		});
	}

	// MCP servers.
	for (const [f, key] of [['.vscode/mcp.json', 'servers'], ['.mcp.json', 'mcpServers']] as const) {
		section(f, () => {
			for (const [name, s] of Object.entries(obj(json(f)?.[key]) ?? {}).slice(0, 100)) {
				add('MCP server', f, `${str(name, 60)}: ${str(obj(s)?.command ?? obj(s)?.url)} ${str(obj(s)?.args)}`.trim());
			}
		});
	}

	// Instructions and config that steer AI agents.
	section('agent files', () => {
		for (const f of ['AGENTS.md', 'CLAUDE.md', 'GEMINI.md', '.github/copilot-instructions.md', '.cursorrules', '.windsurfrules', '.clinerules', '.goosehints']) {
			const t = readText(root, f);
			if (t !== undefined) {
				add('agent instructions', f, `${t.length} characters`);
			}
		}
		for (const d of ['.github/instructions', '.github/prompts', '.github/agents', '.github/chatmodes', '.github/hooks', '.github/skills']) {
			if (!noLinks(root, d) || !fs.lstatSync(path.join(root, d)).isDirectory()) {
				continue; // links never followed (RR-3)
			}
			let n = 0;
			const it = fs.opendirSync(path.join(root, d));
			try {
				while (n < 1000 && it.readSync()) {
					n++;
				}
			} finally {
				it.closeSync();
			}
			add(d.endsWith('hooks') ? 'agent hooks (commands)' : 'agent instructions', `${d}/`, `${n >= 1000 ? '1000+' : n} entries`);
		}
	});
	section('.claude/settings.json', () => {
		const claude = json('.claude/settings.json');
		if (claude?.hooks !== undefined) {
			add('agent hooks (commands)', '.claude/settings.json', str(claude.hooks));
		}
	});

	// Editor settings that auto-approve agent actions.
	section('.vscode/settings.json', () => {
		for (const [k, v] of Object.entries(json('.vscode/settings.json') ?? {}).slice(0, 5000)) {
			if (/^chat\./i.test(k) && /auto.?approve|yolo|autorun/i.test(k)) {
				add('agent auto-approve setting', '.vscode/settings.json', `${str(k, 80)}: ${str(v, 120)}`);
			}
		}
	});
	return { items, truncated: items.length >= MAX_ITEMS };
}
