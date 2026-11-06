// seclab tab logs: read a tab's observability log (ADR tab-observability §4). Reads the JSONL
// segments the supervisor writes; it never talks to a running supervisor (no listener exists).
//   node tabd/tools/tab-logs.ts [-f] [--format text|json|falco|llm] [--min PRIORITY]
//                               [--state-dir DIR | --user-data-dir DIR] <tabId|all>
// --format falco prints Falco-compatible JSON lines for a SIEM forwarder (file-sink exporter);
// --format llm fences tab-influenced text as data for an LLM (tabd/src/obs/llm.ts).

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { parseArgs } from 'node:util';
import { listSegments, segName } from '../src/obs/hub.ts';
import { LlmRenderer } from '../src/obs/llm.ts';
import { isTabId, PRIORITIES, priorityRank, toFalco, type ObsEvent, type Priority } from '../src/obs/schema.ts';
import { safeText } from '../src/obs/text.ts';

const { values, positionals } = parseArgs({
	allowPositionals: true,
	options: {
		'follow': { type: 'boolean', short: 'f', default: false },
		'format': { type: 'string', default: 'text' },
		'min': { type: 'string', default: 'debug' },
		'state-dir': { type: 'string' },
		'user-data-dir': { type: 'string' },
	},
});
function die(msg: string): never {
	process.stderr.write(`seclab tab logs: ${msg}\n`);
	process.exit(2);
}
const target = positionals[0];
if (!target || (target !== 'all' && !isTabId(target))) {
	die('usage: seclab tab logs [-f] [--format text|json|falco|llm] [--min PRIORITY] [--state-dir DIR | --user-data-dir DIR] <tabId|all>');
}
if (!['text', 'json', 'falco', 'llm'].includes(values.format!)) {
	die('--format must be text, json, falco or llm');
}
if (!(PRIORITIES as readonly string[]).includes(values.min!)) {
	die(`--min must be one of ${PRIORITIES.join(', ')}`);
}
const minRank = priorityRank(values.min as Priority);
const userData = values['user-data-dir'] ?? path.join(os.homedir(), 'Library', 'Application Support', 'seclab-vscode');
const stateDir = values['state-dir'] ?? path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');
const eventsDir = path.join(stateDir, 'events');
if (!fs.existsSync(eventsDir)) {
	die(`no event logs under ${eventsDir}`);
}

const BADGE: Record<string, string> = { 'trusted': 'TRUSTED', 'host-observed': 'HOST-OBS', 'tab-vm-root': 'TAB-ROOT', 'tab-reported': 'TAB-SAYS' };
// LLM-facing output: tab-influenced text fenced as data (tabd/src/obs/llm.ts).
const llm = new LlmRenderer();
if (values.format === 'llm') {
	process.stdout.write(`${llm.header()}\n\n`);
}
function render(e: ObsEvent): string {
	if (values.format === 'json') {
		return JSON.stringify(e);
	}
	if (values.format === 'falco') {
		return JSON.stringify(toFalco(e));
	}
	if (values.format === 'llm') {
		return llm.render(e);
	}
	// The supervisor already escaped every field; escape again for the terminal anyway.
	const who = e.proc?.pid !== undefined ? ` pid=${e.proc.pid}` : '';
	return `${e.tabId} #${e.seq} ${e.time} ${e.priority.toUpperCase().padEnd(13)} ${(BADGE[e.integrity] ?? '?').padEnd(8)} ${e.source}/${e.class}${e.rule ? ` [${e.rule}]` : ''}${who} ${safeText(e.summary, 512)}`;
}

interface Cursor { seg: number; offset: number; partial: string }
const cursors = new Map<string, Cursor>();

function drain(tabId: string): void {
	const dir = path.join(eventsDir, tabId);
	const segs = listSegments(dir);
	let c = cursors.get(tabId);
	if (!c) {
		c = { seg: segs[0] ?? 1, offset: 0, partial: '' };
		cursors.set(tabId, c);
	}
	if (segs.length && c.seg < segs[0]) {
		c.seg = segs[0]; // rotated away while we weren't looking
		c.offset = 0;
		c.partial = '';
	}
	for (;;) {
		const file = path.join(dir, segName(c.seg));
		let size = 0;
		try {
			size = fs.statSync(file).size;
		} catch {
			return;
		}
		if (size > c.offset) {
			const fd = fs.openSync(file, 'r');
			const buf = Buffer.alloc(Math.min(size - c.offset, 8 << 20));
			fs.readSync(fd, buf, 0, buf.length, c.offset);
			fs.closeSync(fd);
			c.offset += buf.length;
			const lines = (c.partial + buf.toString('utf8')).split('\n');
			c.partial = lines.pop() ?? '';
			for (const l of lines) {
				if (!l) {
					continue;
				}
				let e: ObsEvent;
				try {
					e = JSON.parse(l) as ObsEvent;
				} catch {
					continue;
				}
				if (priorityRank(e.priority) <= minRank) {
					process.stdout.write(`${render(e)}\n`);
				}
			}
			continue;
		}
		if (segs.includes(c.seg + 1)) {
			c.seg++;
			c.offset = 0;
			c.partial = '';
			continue;
		}
		return;
	}
}

const tabs = () => (target === 'all' ? fs.readdirSync(eventsDir).filter(isTabId).sort() : [target]);
for (const t of tabs()) {
	drain(t);
}
if (values.follow) {
	setInterval(() => {
		for (const t of tabs()) {
			drain(t);
		}
	}, 500);
}
