// Tab observability event schema, v1. The single source of truth: tabd/schema/event.v1.json
// and docs/tabd/EVENTS.md are generated from this file (tabd/src/obs/gen-docs.ts).
// ADR: docs/adr/20261104-tab-observability.md.

import { TAB_ID_RE } from '../validate.ts';
import { clean, redactArgv, safeText } from './text.ts';

export const SCHEMA_VERSION = 1;

/** Falco's priority names, highest first. */
export const PRIORITIES = ['emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'informational', 'debug'] as const;
export type Priority = typeof PRIORITIES[number];

export const INTEGRITY = {
	'trusted': 'Produced outside the tab by host components (tabd, broker, RPC filter, host watchers). The tab can neither forge nor suppress it.',
	'host-observed': 'Observed by a sensor outside the tab\'s namespaces on the host kernel (OCI: Falco). Only a kernel escape can suppress it; the content (argv, paths) is still chosen by the tab.',
	'tab-vm-root': 'Observed by the collector running as root inside the tab\'s own microVM (sbx). Root inside the tab can forge or suppress it; the tab user cannot.',
} as const;
export type Integrity = keyof typeof INTEGRITY;
/** Weakest first. A derived event takes the weakest integrity of its inputs. */
export const INTEGRITY_ORDER: readonly Integrity[] = ['tab-vm-root', 'host-observed', 'trusted'];

export const SOURCES: Record<string, { integrity: Integrity | 'derived'; desc: string }> = {
	'tabd': { integrity: 'trusted', desc: 'Supervisor lifecycle, fence verification, observation state.' },
	'scan': { integrity: 'trusted', desc: 'Pre-mount secret scan (counts and redacted locations only).' },
	'broker': { integrity: 'trusted', desc: 'Broker `audit.event` notifications from the control channel tabd owns.' },
	'rpc-filter': { integrity: 'trusted', desc: 'RPC capability filter decisions, reported by the trusted client over `tab.events.report`.' },
	'sbx-policy': { integrity: 'trusted', desc: '`sbx policy log --json` for the tab, polled and diffed.' },
	'workspace-watch': { integrity: 'trusted', desc: 'Host-side watcher on the workspace directory (no process attribution).' },
	'gate': { integrity: 'trusted', desc: 'Workspace write-back gate decisions (reserved).' },
	'sbx-collector': { integrity: 'tab-vm-root', desc: '`seclab-obs-collect` inside an sbx tab VM: strace, honeypot inotify, heartbeats.' },
	'falco': { integrity: 'host-observed', desc: 'Falco modern_ebpf on the Docker host, filtered to tab containers.' },
	'detector': { integrity: 'derived', desc: 'tabd detection rules over the stream; integrity is the weakest of the causes.' },
};
export type Source = keyof typeof SOURCES;

export const CLASSES = {
	'tab.lifecycle': { ocsf: 6002, desc: 'Tab claimed, starting, running, stopped, removed, quarantined.' },
	'fence.verify': { ocsf: 2003, desc: 'Fence verification result.' },
	'scan.result': { ocsf: 2006, desc: 'Secret scan result (no values).' },
	'egress.request': { ocsf: 4002, desc: 'Broker allowed, denied or blocked a request.' },
	'egress.approval': { ocsf: 4002, desc: 'Broker prompt opened or resolved.' },
	'credential.use': { ocsf: 3002, desc: 'Broker credential event (never a value).' },
	'broker.status': { ocsf: 6002, desc: 'Broker lifecycle, policy and control events.' },
	'rpc.decision': { ocsf: 6003, desc: 'RPC capability filter verdict.' },
	'policy.log': { ocsf: 4001, desc: 'sbx proxy allowed or blocked a destination (aggregated count delta).' },
	'workspace.change': { ocsf: 1001, desc: 'A workspace file was created, changed or removed (host watcher).' },
	'process.exec': { ocsf: 1007, desc: 'A process executed a program.' },
	'process.exit': { ocsf: 1007, desc: 'A process exited.' },
	'file.open': { ocsf: 1001, desc: 'A file was opened (deep mode or sensitive path).' },
	'file.write': { ocsf: 1001, desc: 'A file was opened for writing or created.' },
	'file.delete': { ocsf: 1001, desc: 'A file was unlinked.' },
	'file.rename': { ocsf: 1001, desc: 'A file was renamed or linked.' },
	'file.chmod': { ocsf: 1001, desc: 'File mode changed.' },
	'net.connect': { ocsf: 4001, desc: 'A socket connect attempt.' },
	'priv.change': { ocsf: 1007, desc: 'setuid/setgid family call.' },
	'proc.ptrace': { ocsf: 1007, desc: 'ptrace call.' },
	'proc.signal': { ocsf: 1007, desc: 'A signal sent to another process.' },
	'proc.sensitive': { ocsf: 1007, desc: 'mount, unshare, setns, bpf, memfd_create and similar.' },
	'honeypot.access': { ocsf: 1001, desc: 'A seeded honeypot file was opened, read, changed or removed.' },
	'sensor.status': { ocsf: 6002, desc: 'Sensor started, ready, untraced process found, events dropped, gap.' },
	'detection': { ocsf: 2004, desc: 'A detection rule matched; `cause` lists the triggering events.' },
} as const;
export type EventClass = keyof typeof CLASSES;

export const OBSERVATION_STATES = {
	'observed': 'A sensor is connected and heartbeating.',
	'degraded': 'Connected, but events were dropped or a process escaped tracing.',
	'unobserved': 'No sensor heartbeat: the sensor died, was killed or never started. In-tab activity is not being recorded.',
	'unavailable': 'This driver or template has no sensor.',
} as const;
export type ObservationState = keyof typeof OBSERVATION_STATES;

export const LIMITS = {
	summary: 512, exe: 512, argvItems: 32, argvItem: 256, path: 1024, addr: 128, lineage: 8,
	detailKeys: 16, detailValue: 256, cause: 16, rule: 64, ref: 1024,
} as const;

export interface ProcInfo {
	pid?: number; ppid?: number; uid?: number; exe?: string; argv?: string[];
	lineage?: Array<{ pid: number; exe: string }>;
}
export interface ObsEvent {
	v: 1;
	seq: number;
	time: string;
	tabId: string;
	source: Source;
	integrity: Integrity;
	class: EventClass;
	priority: Priority;
	summary: string;
	rule?: string;
	proc?: ProcInfo;
	file?: { path: string; op?: string };
	net?: { addr: string; port?: number; family?: 'inet' | 'inet6' | 'unix' | 'other'; result?: string };
	detail?: Record<string, string | number | boolean>;
	cause?: number[];
	sensorTime?: string;
	redacted?: true;
}

/** An event before tabd stamps v, seq, time and tabId. */
export type EventDraft = Omit<ObsEvent, 'v' | 'seq' | 'time' | 'tabId'>;

export class EventError extends Error { }

const DETAIL_KEY_RE = /^[a-zA-Z][a-zA-Z0-9_.]{0,31}$/;
const RULE_RE = /^[a-z][a-z0-9.-]{0,63}$/;
const REF_RE = /^(?:rpc|cmd|chan):[\x21-\x7e]{1,1024}$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;

function int(v: unknown, min: number, max: number): number | undefined {
	return typeof v === 'number' && Number.isInteger(v) && v >= min && v <= max ? v : undefined;
}

/**
 * Build a canonical event from untrusted input: pick known fields only, check enums and
 * types, redact and escape every string, cap every collection. Throws EventError when a
 * required field is missing or an enum is unknown. Never returns input objects.
 */
export function normalizeDraft(input: unknown): EventDraft {
	if (typeof input !== 'object' || input === null || Array.isArray(input)) {
		throw new EventError('event must be an object');
	}
	const o = input as Record<string, unknown>;
	const source = o.source;
	if (typeof source !== 'string' || !Object.hasOwn(SOURCES, source)) {
		throw new EventError('unknown source');
	}
	const integrity = o.integrity;
	if (typeof integrity !== 'string' || !Object.hasOwn(INTEGRITY, integrity)) {
		throw new EventError('unknown integrity');
	}
	const fixed = SOURCES[source].integrity;
	if (fixed !== 'derived' && fixed !== integrity) {
		throw new EventError(`source ${source} must have integrity ${fixed}`);
	}
	const cls = o.class;
	if (typeof cls !== 'string' || !Object.hasOwn(CLASSES, cls)) {
		throw new EventError('unknown class');
	}
	const priority = o.priority;
	if (typeof priority !== 'string' || !(PRIORITIES as readonly string[]).includes(priority)) {
		throw new EventError('unknown priority');
	}
	if (typeof o.summary !== 'string') {
		throw new EventError('summary required');
	}
	let redacted = false;
	const txt = (s: string, max: number) => {
		const r = clean(s, max);
		redacted ||= r.changed;
		return r.text;
	};
	const out: EventDraft = {
		source: source as Source, integrity: integrity as Integrity, class: cls as EventClass,
		priority: priority as Priority, summary: txt(o.summary, LIMITS.summary),
	};
	if (o.rule !== undefined) {
		if (typeof o.rule !== 'string' || !RULE_RE.test(o.rule)) {
			throw new EventError('invalid rule id');
		}
		out.rule = o.rule;
	}
	if (o.proc !== undefined) {
		out.proc = normalizeProc(o.proc, txt, () => { redacted = true; });
	}
	if (o.file !== undefined) {
		const f = o.file as Record<string, unknown>;
		if (typeof f !== 'object' || f === null || typeof f.path !== 'string') {
			throw new EventError('invalid file');
		}
		out.file = { path: txt(f.path, LIMITS.path) };
		if (typeof f.op === 'string') {
			out.file.op = safeText(f.op, 32);
		}
	}
	if (o.net !== undefined) {
		const n = o.net as Record<string, unknown>;
		if (typeof n !== 'object' || n === null || typeof n.addr !== 'string') {
			throw new EventError('invalid net');
		}
		out.net = { addr: txt(n.addr, LIMITS.addr) };
		const port = int(n.port, 0, 65535);
		if (port !== undefined) {
			out.net.port = port;
		}
		if (n.family === 'inet' || n.family === 'inet6' || n.family === 'unix' || n.family === 'other') {
			out.net.family = n.family;
		}
		if (typeof n.result === 'string') {
			out.net.result = safeText(n.result, 64);
		}
	}
	if (o.detail !== undefined) {
		if (typeof o.detail !== 'object' || o.detail === null || Array.isArray(o.detail)) {
			throw new EventError('invalid detail');
		}
		const d: Record<string, string | number | boolean> = {};
		let n = 0;
		for (const [k, v] of Object.entries(o.detail)) {
			if (n >= LIMITS.detailKeys || !DETAIL_KEY_RE.test(k)) {
				continue;
			}
			if (k === 'ref') {
				// RPC-filter join key: exact or absent, never truncated.
				if (typeof v !== 'string' || !REF_RE.test(v)) {
					throw new EventError('invalid ref');
				}
				d.ref = v;
			} else if (typeof v === 'string') {
				d[k] = txt(v, LIMITS.detailValue);
			} else if (typeof v === 'boolean' || (typeof v === 'number' && Number.isFinite(v))) {
				d[k] = v;
			} else {
				continue;
			}
			n++;
		}
		out.detail = d;
	}
	if (o.cause !== undefined) {
		if (!Array.isArray(o.cause)) {
			throw new EventError('invalid cause');
		}
		out.cause = o.cause.map(c => int(c, 1, Number.MAX_SAFE_INTEGER)).filter((c): c is number => c !== undefined).slice(0, LIMITS.cause);
	}
	if (typeof o.sensorTime === 'string' && ISO_RE.test(o.sensorTime)) {
		out.sensorTime = o.sensorTime;
	}
	if (redacted) {
		out.redacted = true;
	}
	return out;
}

function normalizeProc(input: unknown, txt: (s: string, max: number) => string, markRedacted: () => void): ProcInfo {
	if (typeof input !== 'object' || input === null || Array.isArray(input)) {
		throw new EventError('invalid proc');
	}
	const p = input as Record<string, unknown>;
	const out: ProcInfo = {};
	const pid = int(p.pid, 0, 0x3fffffff), ppid = int(p.ppid, 0, 0x3fffffff), uid = int(p.uid, 0, 0xffffffff);
	if (pid !== undefined) {
		out.pid = pid;
	}
	if (ppid !== undefined) {
		out.ppid = ppid;
	}
	if (uid !== undefined) {
		out.uid = uid;
	}
	if (typeof p.exe === 'string') {
		out.exe = txt(p.exe, LIMITS.exe);
	}
	if (Array.isArray(p.argv)) {
		const items = p.argv.filter((a): a is string => typeof a === 'string').slice(0, LIMITS.argvItems);
		const r = redactArgv(items);
		if (r.changed) {
			markRedacted();
		}
		out.argv = r.argv.map(a => safeText(a, LIMITS.argvItem));
		if (p.argv.length > LIMITS.argvItems) {
			out.argv.push(`… ${p.argv.length - LIMITS.argvItems} more`);
		}
	}
	if (Array.isArray(p.lineage)) {
		out.lineage = p.lineage.slice(0, LIMITS.lineage).flatMap(l => {
			const e = l as Record<string, unknown>;
			const lpid = int(e?.pid, 0, 0x3fffffff);
			return lpid !== undefined && typeof e.exe === 'string' ? [{ pid: lpid, exe: txt(e.exe, LIMITS.exe) }] : [];
		});
	}
	return out;
}

export function priorityRank(p: Priority): number {
	return PRIORITIES.indexOf(p);
}

export function weakestIntegrity(list: readonly Integrity[]): Integrity {
	for (const i of INTEGRITY_ORDER) {
		if (list.includes(i)) {
			return i;
		}
	}
	return 'trusted';
}

export function isTabId(v: unknown): v is string {
	return typeof v === 'string' && TAB_ID_RE.test(v);
}

/** Falco-compatible rendering for SIEM forwarders (falcosidekick and friends). */
export function toFalco(e: ObsEvent): Record<string, unknown> {
	return {
		time: e.time,
		priority: e.priority.charAt(0).toUpperCase() + e.priority.slice(1),
		rule: e.rule ?? e.class,
		output: e.summary,
		source: `seclab.${e.source}`,
		hostname: e.tabId,
		tags: ['seclab', `integrity:${e.integrity}`, `class:${e.class}`, `ocsf:${CLASSES[e.class].ocsf}`],
		output_fields: {
			'seclab.seq': e.seq, 'seclab.tab': e.tabId, 'seclab.integrity': e.integrity,
			'proc.pid': e.proc?.pid ?? null, 'proc.ppid': e.proc?.ppid ?? null, 'proc.exepath': e.proc?.exe ?? null,
			'proc.cmdline': e.proc?.argv?.join(' ') ?? null, 'fd.name': e.file?.path ?? null,
			'fd.sip': e.net?.addr ?? null, 'fd.sport': e.net?.port ?? null,
		},
	};
}
