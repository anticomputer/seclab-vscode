// Detection rules for the tab threat model (ADR tab-observability §5). They run in tabd over
// normalised events from every source, so one ruleset covers sbx (strace), OCI (Falco) and
// trusted host sources. A detection takes the weakest integrity of its causes.

import type { EventDraft, Integrity, ObsEvent, Priority } from './schema.ts';
import { weakestIntegrity } from './schema.ts';

export interface TabContext {
	/** ms epoch when the tab's REH was (re)started by this supervisor. */
	openedAt?: number;
	/** Broker endpoint as seen from inside the tab (addresses and port), when a broker is wired. */
	brokerPort?: number;
	brokerAddrs?: ReadonlySet<string>;
	/** Workspace root (host path == in-tab path). */
	workspace?: string;
}

export interface RuleInfo { readonly id: string; readonly priority: Priority; readonly desc: string }

export const RULES: readonly RuleInfo[] = [
	{ id: 'loader.pipe-to-interpreter', priority: 'critical', desc: 'A download tool\'s output is piped straight into an interpreter (node, a shell, python, perl, ruby).' },
	{ id: 'loader.eval', priority: 'warning', desc: 'An interpreter runs inline code that decodes or evaluates a payload (`node -e`, `python -c` with eval/exec/base64/child_process).' },
	{ id: 'task.network-tool', priority: 'warning', desc: 'A network tool runs inside the tab; critical when spawned from the extension host within 60 s of open (folder-open task pattern).' },
	{ id: 'process.detach', priority: 'warning', desc: 'A process detaches from its parent (`nohup`, `setsid`, `daemonize`, `screen -dm`, `tmux new -d`).' },
	{ id: 'credential.honeypot-read', priority: 'critical', desc: 'A seeded honeypot (ssh key, cloud or browser credentials, wallet, keyring) was read.' },
	{ id: 'credential.path-open', priority: 'warning', desc: 'A credential-like path was opened.' },
	{ id: 'sensor.honeypot-tamper', priority: 'warning', desc: 'A honeypot was modified, moved or deleted.' },
	{ id: 'workspace.host-executable-write', priority: 'warning', desc: 'A file the host may execute or load was written in the workspace (git hooks, `.envrc`, `.vscode/*.json`, `package.json`, Makefile, CI workflows, …); critical within 60 s of open.' },
	{ id: 'workspace.package-scripts', priority: 'warning', desc: '`package.json` scripts changed.' },
	{ id: 'egress.bypass', priority: 'warning', desc: 'A connect to anything other than loopback or the tab\'s broker (an attempt to bypass the proxy).' },
	{ id: 'escape.container-socket', priority: 'critical', desc: 'A connect to a container runtime socket (docker, containerd, podman).' },
	{ id: 'priv.escalation', priority: 'critical', desc: 'A setuid-family call to root succeeded.' },
	{ id: 'priv.sensitive-syscall', priority: 'warning', desc: 'mount, unshare, setns, bpf, memfd_create, module load, chroot, perf_event_open or keyring calls.' },
	{ id: 'proc.ptrace-attach', priority: 'warning', desc: 'A process attached to another with ptrace.' },
	{ id: 'sensor.tamper', priority: 'critical', desc: 'A signal or ptrace aimed at the sensor or init.' },
	{ id: 'beacon.periodic', priority: 'warning', desc: 'Repeated connection attempts to one destination at a regular interval (C2 beacon pattern).' },
	{ id: 'suspicious-content', priority: 'informational', desc: 'Text aimed at an AI agent (prompt injection: "ignore previous instructions", role markers, chat-template or tool-call syntax) in a command line, file name, path or hostname. Informational: the stream is data, never instructions.' },
];
const RULE = new Map(RULES.map(r => [r.id, r]));

const NETWORK_TOOL = /^(?:curl|wget|nc|ncat|netcat|socat|telnet|ftp|tftp|openssl|dig|nslookup)$/;
const SHELL = /^(?:sh|bash|dash|zsh|ash|ksh)$/;
const INTERP = /^(?:node|nodejs|python3?(?:\.\d+)?|perl|ruby|php|deno|bun)$/;
const PIPE_TO_INTERP = /\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:[\w./-]*\/)?(?:node|nodejs|sh|bash|dash|zsh|python3?|perl|ruby)\b/;
const EVAL_PAYLOAD = /\beval\s*\(|\bFunction\s*\(|child_process|\batob\s*\(|base64|\bexec\s*\(|\bcompile\s*\(|require\s*\(\s*['"]https?['"]|fromCharCode/;
const DETACH = /^(?:nohup|setsid|daemonize|disown|start-stop-daemon)$/;
const EXT_HOST = /extensionHost|bootstrap-fork|seclab-code-server|server-main|ptyHost/;
const CRED_PATH = /\/(?:\.ssh\/|\.aws\/|\.git-credentials$|\.config\/gh\/|\.docker\/config\.json$|\.kube\/config$|\.gnupg\/|\.config\/solana\/|\.electrum\/|\.config\/Exodus\/|\.local\/share\/keyrings\/|\.mozilla\/firefox\/[^/]+\/(?:logins\.json|key4\.db|cookies\.sqlite)$|\.config\/(?:google-chrome|chromium|BraveSoftware\/Brave-Browser|microsoft-edge)\/[^/]+\/(?:Login Data|Cookies|Web Data|Local State)|\.npmrc$|\.pypirc$|\.netrc$|Library\/Keychains\/)/;
const HOST_EXEC = /(?:^|\/)(?:\.git\/hooks\/[^/]+|\.git\/config|\.gitmodules|\.envrc|\.env|\.vscode\/(?:tasks|settings|launch|extensions|mcp)\.json|[^/]+\.code-workspace|package\.json|\.npmrc|\.yarnrc(?:\.yml)?|Makefile|GNUmakefile|\.husky\/[^/]+|\.github\/workflows\/[^/]+|\.devcontainer\/[^/]+|\.pre-commit-config\.yaml|pyproject\.toml|setup\.py|setup\.cfg|build\.rs|Cargo\.toml|gradlew|gradle\/wrapper\/[^/]+|\.mvn\/[^/]+|\.tool-versions|\.nvmrc|\.python-version|eslint\.config\.[cm]?[jt]s|\.eslintrc(?:\.[cm]?js)?|prettier\.config\.[cm]?js|\.prettierrc\.[cm]?js|jest\.config\.[cm]?[jt]s|vite\.config\.[cm]?[jt]s|tsconfig\.json)$/;
const LOOPBACK = /^(?:127\.|::1$|::ffff:127\.|localhost$)/;
const RUNTIME_SOCKET = /(?:docker|containerd|podman|crio)[^/]*\.sock$/;
// Instruction-like text aimed at an LLM reading the stream. Matched on already-escaped text, so
// separators may appear as \x0a etc.; kept deliberately broad (the rule is informational).
const PROMPT_INJECTION = [
	/\b(?:ignore|disregard|forget|override)\b[\s\S]{0,40}\b(?:previous|prior|above|earlier|all|system|your)\b[\s\S]{0,40}\b(?:instructions?|prompts?|rules|guidelines|messages?)/i,
	/(?:^|[\s"'\\(>:;,|])(?:system|assistant|developer)\s*:/i,
	/<\|?\s*(?:im_start|im_end|system|endoftext|eot_id|start_header_id)\s*\|?>/i,
	/\[\/?INST\]|<<\/?SYS>>/,
	/<\/?\s*(?:tool_call|tool_use|function_calls?|invoke|system|instructions?)\b/i,
	/"(?:function_call|tool_calls?)"\s*:/i,
	/\byou are (?:now )?(?:an?|the) (?:ai|assistant|agent|llm|language model|chatbot)\b/i,
	/\b(?:new|updated|real) (?:system )?instructions?\s*:/i,
	/\b(?:as an ai|dear (?:ai|assistant|agent|llm)|note to (?:the )?(?:ai|assistant|agent|llm))\b/i,
];

export function looksLikePromptInjection(s: string): boolean {
	return PROMPT_INJECTION.some(re => re.test(s));
}

export function isCredentialPath(p: string): boolean {
	return CRED_PATH.test(p);
}

export function isHostExecutablePath(p: string): boolean {
	return HOST_EXEC.test(p);
}

const base = (p: string | undefined) => (p ?? '').slice((p ?? '').lastIndexOf('/') + 1);

interface Beacon { times: number[]; reportedAt: number }

export class Detector {
	private readonly beacons = new Map<string, Beacon>();

	/** Return detection drafts for one event (never for detections themselves). */
	check(e: ObsEvent, ctx: TabContext): EventDraft[] {
		if (e.class === 'detection') {
			return [];
		}
		const hits: Array<{ id: string; priority?: Priority; summary: string }> = [];
		const early = ctx.openedAt !== undefined && Date.parse(e.time) - ctx.openedAt < 60_000;
		const argv = e.proc?.argv ?? [];
		const name = base(e.proc?.exe ?? argv[0]);
		const lineage = (e.proc?.lineage ?? []).map(l => l.exe).join(' <- ');
		const fromExtHost = EXT_HOST.test(lineage);

		switch (e.class) {
			case 'process.exec': {
				const joined = argv.join(' ');
				if (SHELL.test(name) && PIPE_TO_INTERP.test(joined)) {
					hits.push({ id: 'loader.pipe-to-interpreter', summary: `download piped to an interpreter: ${joined}` });
				}
				if (INTERP.test(name)) {
					const inline = argv.findIndex(a => /^(?:-e|--eval|-p|--print|-c|-E)$/.test(a));
					if (inline >= 0 && EVAL_PAYLOAD.test(argv.slice(inline + 1).join(' '))) {
						hits.push({ id: 'loader.eval', summary: `inline loader: ${joined}` });
					}
				}
				if (NETWORK_TOOL.test(name)) {
					hits.push({ id: 'task.network-tool', priority: early && fromExtHost ? 'critical' : undefined, summary: `${name} run${fromExtHost ? ' from the extension host' : ''}${early ? ' right after open' : ''}: ${joined}` });
				}
				if (DETACH.test(name) || (name === 'screen' && argv.some(a => /^-d?m/.test(a))) || (name === 'tmux' && argv.includes('-d'))) {
					hits.push({ id: 'process.detach', priority: early && fromExtHost ? 'critical' : undefined, summary: `detached process: ${joined}` });
				}
				break;
			}
			case 'honeypot.access': {
				const kind = e.detail?.kind;
				hits.push(kind === 'read'
					? { id: 'credential.honeypot-read', summary: `honeypot read: ${e.file?.path ?? '?'}` }
					: { id: 'sensor.honeypot-tamper', summary: `honeypot ${String(kind)}: ${e.file?.path ?? '?'}` });
				break;
			}
			case 'file.open':
				if (e.file && CRED_PATH.test(e.file.path)) {
					hits.push({ id: 'credential.path-open', summary: `credential path opened by ${name || '?'}: ${e.file.path}` });
				}
				break;
			case 'file.write': case 'file.rename': case 'file.chmod': case 'workspace.change': {
				const p = e.file?.path ?? '';
				const inWs = !ctx.workspace || p.startsWith(`${ctx.workspace}/`) || !p.startsWith('/');
				if (inWs && HOST_EXEC.test(p) && e.detail?.change !== 'deleted') {
					hits.push({ id: 'workspace.host-executable-write', priority: early ? 'critical' : undefined, summary: `host-executable file written: ${p}` });
				}
				if (e.class === 'workspace.change' && e.detail?.scriptsChanged === true) {
					hits.push({ id: 'workspace.package-scripts', summary: `package.json scripts changed: ${p}` });
				}
				if (e.class === 'file.write' && CRED_PATH.test(p)) {
					hits.push({ id: 'credential.path-open', summary: `credential path written: ${p}` });
				}
				break;
			}
			case 'net.connect': {
				const n = e.net;
				if (!n) {
					break;
				}
				if (n.family === 'unix') {
					if (RUNTIME_SOCKET.test(n.addr)) {
						hits.push({ id: 'escape.container-socket', summary: `container runtime socket: ${n.addr} (${n.result ?? '?'})` });
					}
					break;
				}
				const isBroker = ctx.brokerPort !== undefined && n.port === ctx.brokerPort && (ctx.brokerAddrs?.has(n.addr) ?? false);
				if (!isBroker && !LOOPBACK.test(n.addr)) {
					hits.push({ id: 'egress.bypass', summary: `direct connect to ${n.addr}:${n.port ?? '?'} by ${name || '?'} (${n.result ?? '?'})` });
				}
				this.beacon(`${n.addr}:${n.port ?? ''}`, Date.parse(e.time), hits);
				break;
			}
			case 'egress.request':
				// Per-request broker decisions only: policy.log is polled (its timing is ours).
				if (e.detail?.decision === 'denied' || e.detail?.decision === 'blocked') {
					this.beacon(String(e.detail?.host ?? e.net?.addr ?? ''), Date.parse(e.time), hits);
				}
				break;
			case 'priv.change':
				if (e.priority === 'critical') {
					hits.push({ id: 'priv.escalation', summary: e.summary });
				}
				break;
			case 'proc.sensitive':
				hits.push({ id: 'priv.sensitive-syscall', summary: e.summary });
				break;
			case 'proc.ptrace':
				hits.push(e.detail?.tamper === true ? { id: 'sensor.tamper', summary: e.summary } : { id: 'proc.ptrace-attach', summary: e.summary });
				break;
			case 'proc.signal':
				if (e.detail?.tamper === true) {
					hits.push({ id: 'sensor.tamper', summary: e.summary });
				}
				break;
		}
		const integrity: Integrity = weakestIntegrity([e.integrity]);
		// Prompt injection aimed at whoever (or whatever) reads this stream.
		const texts: Array<[string, string]> = [];
		if (e.proc?.argv?.length) {
			texts.push(['command line', e.proc.argv.join(' ')]);
		}
		if (e.proc?.exe) {
			texts.push(['program', e.proc.exe]);
		}
		if (e.file?.path) {
			texts.push(['path', e.file.path]);
		}
		if (e.net?.addr) {
			texts.push(['address', e.net.addr]);
		}
		for (const k of ['from', 'host', 'paths']) {
			const v = e.detail?.[k];
			if (typeof v === 'string') {
				texts.push([k, v]);
			}
		}
		const hit = texts.find(([, t]) => looksLikePromptInjection(t));
		if (hit) {
			hits.push({ id: 'suspicious-content', summary: `instruction-like text aimed at an AI agent in a ${hit[0]} (shown as data only)` });
		}
		return hits.map(h => ({
			source: 'detector', integrity, class: 'detection', rule: h.id,
			priority: h.priority ?? RULE.get(h.id)!.priority, summary: h.summary,
			...(e.proc ? { proc: e.proc } : {}), ...(e.file ? { file: e.file } : {}), ...(e.net ? { net: e.net } : {}),
			cause: [e.seq],
		}));
	}

	private beacon(key: string, t: number, hits: Array<{ id: string; summary: string }>): void {
		if (!key || !Number.isFinite(t)) {
			return;
		}
		let b = this.beacons.get(key);
		if (!b) {
			if (this.beacons.size >= 512) {
				this.beacons.delete(this.beacons.keys().next().value!);
			}
			b = { times: [], reportedAt: 0 };
			this.beacons.set(key, b);
		}
		// Coalesce bursts (several sockets per attempt, or a fetch right before the first beacon).
		if (b.times.length && t - b.times[b.times.length - 1] < 250) {
			return;
		}
		b.times.push(t);
		if (b.times.length > 6) {
			b.times.shift();
		}
		if (b.times.length < 4 || t - b.reportedAt < 600_000) {
			return;
		}
		const gaps = b.times.slice(1).map((x, i) => x - b.times[i]);
		const mean = gaps.reduce((a, c) => a + c, 0) / gaps.length;
		const sd = Math.sqrt(gaps.reduce((a, c) => a + (c - mean) ** 2, 0) / gaps.length);
		if (mean >= 1_000 && mean <= 120_000 && sd / mean < 0.25) {
			b.reportedAt = t;
			hits.push({ id: 'beacon.periodic', summary: `${b.times.length} attempts to ${key} every ~${(mean / 1000).toFixed(1)} s` });
		}
	}
}
