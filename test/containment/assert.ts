// Containment assertions shared by the automated runner (run.ts) and the editor-driven
// check (check-evidence.ts). Evidence comes from fixtures/malicious-workspace/.seclab/probe.sh.

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

/**
 * One vector's evidence, as written by a hostile fixture. Every field is therefore
 * `unknown`: `readEvidence` parses attacker-chosen JSON, so the declared shape is a
 * claim, not a fact, and typing it as `string` made the compiler bless
 * `ev.secret_env.trim()` on a value that could be `null` (review round 9 alert 2).
 * Narrow before use.
 */
export interface Evidence {
	vector?: unknown;
	hostname?: unknown;
	uid?: unknown;
	seclab_tab_env?: unknown;
	canary_read?: unknown;
	othertab_read?: unknown;
	docker_sock_writable?: unknown;
	sudo?: unknown;
	secret_env?: unknown;
	ui_bridge?: unknown;
	http_proxy?: unknown;
	HTTPS_PROXY?: unknown;
	egress?: unknown;
}

/**
 * `knownGap`: a documented, accepted-until-fixed gap (e.g. "M4"). A failing check with a
 * known gap prints XFAIL and does not fail the run; when it starts passing it prints XPASS
 * so the marker gets removed. Never use it to hide an unexplained failure.
 */
export interface Check { vector: string; name: string; ok: boolean; detail: string; knownGap?: string }

const BLOCKED = new Set(['000', '403', '']);

/** Evidence for one vector. `read` reads a workspace file through the tab (the write-back
 *  gate keeps tab writes out of the host checkout until reviewed); default: the host file. */
export function readEvidence(ws: string, vector: string, read?: (p: string) => string | undefined): Evidence | undefined {
	const f = path.join(ws, '.seclab-evidence', `${vector}.json`);
	const text = read ? read(f) : (fs.existsSync(f) ? fs.readFileSync(f, 'utf8') : undefined);
	try {
		return text ? JSON.parse(text) as Evidence : undefined;
	} catch {
		return undefined;
	}
}

/** Assertions for one vector. `expectHostname` is the tab's hostname when known. `proxy`: what
 *  the tab's egress must point at: its own broker (`broker:8080` on the OCI pod network, or
 *  `host.docker.internal:<port>` from an sbx VM, plan tabd-broker-wiring B2) or the blackhole
 *  (`--broker none`); exactly that, never either (review XX-4). */
export type ProxyExpectation = 'oci-broker' | 'sbx-broker' | 'blackhole';
export const brokerProxy = (driver: string): ProxyExpectation => driver === 'oci' ? 'oci-broker' : 'sbx-broker';
const PROXY_RE: Record<ProxyExpectation, RegExp> = {
	'oci-broker': /^http:\/\/seclab:[A-Za-z0-9_-]{32}@broker:8080$/,
	'sbx-broker': /^http:\/\/seclab:[A-Za-z0-9_-]{32}@host\.docker\.internal:[1-9][0-9]{0,4}$/,
	'blackhole': /^http:\/\/127\.0\.0\.1:9$/,
};
export function checkEvidence(ev: Evidence | undefined, vector: string, opts: { marker: string; expectHostname?: string; proxy: ProxyExpectation }): Check[] {
	const c = (name: string, ok: boolean, detail = ''): Check => ({ vector, name, ok, detail });
	// Every field below is fixture-authored. `readEvidence` guards JSON.parse but not the
	// SHAPE, so `{"egress":null}` or an omitted `secret_env` is valid JSON that used to
	// throw a TypeError out of this function (review round 9 alert 2). A missing or
	// wrong-typed field is a failing check with the raw value shown, never a crash: the
	// harness must not be steerable by the thing it is assessing.
	const str = (v: unknown): string => typeof v === 'string' ? v : '';

	if (!ev) {
		return [c('ran (evidence written into the workspace)', false, 'no evidence file')];
	}
	const out: Check[] = [c('ran (evidence written into the workspace)', true)];
	// A present field of the wrong type is malformed evidence, not the benign value.
	// Without this, `"ui_bridge": 7` read as "" and passed the credential-bridge check:
	// narrowing must not silently convert an unparseable claim into a reassuring one.
	const STRING_FIELDS = ['hostname', 'uid', 'seclab_tab_env', 'canary_read', 'othertab_read',
		'docker_sock_writable', 'sudo', 'secret_env', 'ui_bridge', 'http_proxy', 'HTTPS_PROXY'] as const;
	const illTyped = STRING_FIELDS.filter(k => ev[k] !== undefined && typeof ev[k] !== 'string');
	if (illTyped.length > 0) {
		out.push(c('evidence fields are well-typed', false, `not strings: ${illTyped.join(', ')}`));
	}
	out.push(c('ran inside the tab, not on the host', typeof ev.hostname === 'string' && ev.hostname !== os.hostname() && ev.seclab_tab_env === '1' &&
		(opts.expectHostname === undefined || ev.hostname === opts.expectHostname), `hostname=${str(ev.hostname)} SECLAB_TAB=${str(ev.seclab_tab_env)}`));
	out.push(c('cannot read host file outside the workspace (canary)', ev.canary_read === 'no', str(ev.canary_read)));
	out.push(c('cannot read another tab\'s workspace', ev.othertab_read === 'no', str(ev.othertab_read)));
	out.push(c('cannot write host file outside the workspace', !fs.existsSync(`${opts.marker}.${vector}`), `${opts.marker}.${vector}`));
	out.push(c('no writable docker.sock', ev.docker_sock_writable === 'no', str(ev.docker_sock_writable)));
	out.push(c('no sudo', ev.sudo === 'no', str(ev.sudo)));
	out.push(c('no host secrets / agent sockets in env', typeof ev.secret_env === 'string' && ev.secret_env.trim() === '', str(ev.secret_env)));
	// The REH's git extension exports an askpass socket (VSCODE_GIT_IPC_HANDLE) inside the
	// tab; through it git can reach the UI-side auth providers. Only the RPC capability
	// filter (M4) closes that; until then it's an explicit known gap, not a silent pass.
	const bridge = str(ev.ui_bridge).trim();
	out.push({ ...c('no tab-to-UI credential bridge in env (git askpass)', bridge === '', bridge),
		knownGap: bridge ? 'M4 RPC capability filter (docs/adr/20261104-rpc-capability-filter.md)' : undefined });
	// Egress points at exactly what this tab must use: its own broker or the blackhole. The
	// runtime-injected value never wins, and both cases agree.
	const want = PROXY_RE[opts.proxy];
	out.push(c(`runtime-injected proxy env never wins (both cases point at the ${opts.proxy})`, want.test(str(ev.http_proxy)) && str(ev.http_proxy) === str(ev.HTTPS_PROXY),
		`http_proxy=${str(ev.http_proxy).replace(/:[^:@/]+@/, ':***@')} HTTPS_PROXY=${str(ev.HTTPS_PROXY).replace(/:[^:@/]+@/, ':***@')}`));
	const egress = ev.egress && typeof ev.egress === 'object' && !Array.isArray(ev.egress) ? ev.egress as Record<string, unknown> : undefined;
	if (!egress) {
		out.push(c('recorded its egress probes', false, `egress=${JSON.stringify(ev.egress ?? null).slice(0, 120)}`));
	}
	for (const [k, raw] of Object.entries((egress ?? {}) as Record<string, unknown>)) {
		const v = str(raw);
		if (k === 'dns_external') {
			out.push(c('no external DNS', v === 'blocked', v));
		} else {
			out.push(c(`egress blocked: ${k}`, BLOCKED.has(v), `http_code=${v}`));
		}
	}
	return out;
}

export function report(checks: Check[]): boolean {
	let ok = true;
	for (const ch of checks) {
		ok &&= ch.ok || !!ch.knownGap;
		const tag = ch.ok ? (ch.knownGap ? 'XPASS' : 'PASS') : (ch.knownGap ? 'XFAIL' : 'FAIL');
		console.log(`${tag}  [${ch.vector}] ${ch.name}${ch.ok ? '' : `  -> ${ch.detail}`}${ch.knownGap ? `  (known gap: ${ch.knownGap})` : ''}`);
	}
	const failed = checks.filter(c => !c.ok && !c.knownGap).length;
	const xfail = checks.filter(c => !c.ok && c.knownGap).length;
	console.log(`\n${checks.length - failed - xfail}/${checks.length} checks passed${xfail ? `, ${xfail} known gap(s) (XFAIL)` : ''}${failed ? `, ${failed} FAILED` : ''}`);
	return ok;
}

/** One line of the trusted-side RPC filter decision log (patch 0005). */
export interface RpcDecision {
	source?: string;
	class?: string;
	priority?: string;
	summary?: string;
	detail?: { surface?: string; ref?: string; verdict?: string; reason?: string; constraint?: string; claimedExtensionId?: string; count?: number };
}

/**
 * Every decision the RPC filter logged in a profile's window logs. Host-side: the filter
 * writes through ILoggerService into `<userData>/logs/<session>/window<N>/seclabRpcFilter.log`,
 * which nothing inside a tab can reach, so a denial read from here is observed rather than
 * inferred from an absent marker. Unparseable lines are skipped, never guessed at: the file is
 * trusted-side but its `ref` and `claimedExtensionId` fields carry tab-chosen strings, so
 * callers must match on exact fields and never on free text (EDR prompt-injection-hygiene).
 */
export function rpcDecisions(userDataDir: string): RpcDecision[] {
	const logs = path.join(userDataDir, 'logs');
	const files: string[] = [];
	const walk = (dir: string, depth: number): void => {
		if (depth > 4) {
			return;
		}
		for (const e of (() => { try { return fs.readdirSync(dir, { withFileTypes: true }); } catch { return []; } })()) {
			const p = path.join(dir, e.name);
			if (e.isDirectory()) {
				walk(p, depth + 1);
			} else if (e.isFile() && e.name === 'seclabRpcFilter.log') {
				files.push(p);
			}
		}
	};
	walk(logs, 0);
	const out: RpcDecision[] = [];
	for (const f of files) {
		for (const line of fs.readFileSync(f, 'utf8').split('\n')) {
			const i = line.indexOf('{'); // ILoggerService prefixes each entry with a timestamp and level
			if (i < 0) {
				continue;
			}
			try {
				const d = JSON.parse(line.slice(i)) as RpcDecision;
				if (d.class === 'rpc.decision') {
					out.push(d);
				}
			} catch { /* a truncated or capped line is not a decision */ }
		}
	}
	return out;
}
