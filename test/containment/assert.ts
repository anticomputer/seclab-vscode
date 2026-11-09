// Containment assertions shared by the automated runner (run.ts) and the editor-driven
// check (check-evidence.ts). Evidence comes from fixtures/malicious-workspace/.seclab/probe.sh.

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

export interface Evidence {
	vector: string;
	hostname: string;
	uid: string;
	seclab_tab_env: string;
	canary_read: string;
	othertab_read: string;
	docker_sock_writable: string;
	sudo: string;
	secret_env: string;
	ui_bridge?: string;
	http_proxy: string;
	HTTPS_PROXY: string;
	egress: Record<string, string>;
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
	if (!ev) {
		return [c('ran (evidence written into the workspace)', false, 'no evidence file')];
	}
	const out: Check[] = [c('ran (evidence written into the workspace)', true)];
	out.push(c('ran inside the tab, not on the host', ev.hostname !== os.hostname() && ev.seclab_tab_env === '1' &&
		(opts.expectHostname === undefined || ev.hostname === opts.expectHostname), `hostname=${ev.hostname} SECLAB_TAB=${ev.seclab_tab_env}`));
	out.push(c('cannot read host file outside the workspace (canary)', ev.canary_read === 'no', ev.canary_read));
	out.push(c('cannot read another tab\'s workspace', ev.othertab_read === 'no', ev.othertab_read));
	out.push(c('cannot write host file outside the workspace', !fs.existsSync(`${opts.marker}.${vector}`), `${opts.marker}.${vector}`));
	out.push(c('no writable docker.sock', ev.docker_sock_writable === 'no', ev.docker_sock_writable));
	out.push(c('no sudo', ev.sudo === 'no', ev.sudo));
	out.push(c('no host secrets / agent sockets in env', ev.secret_env.trim() === '', ev.secret_env));
	// The REH's git extension exports an askpass socket (VSCODE_GIT_IPC_HANDLE) inside the
	// tab; through it git can reach the UI-side auth providers. Only the RPC capability
	// filter (M4) closes that; until then it's an explicit known gap, not a silent pass.
	const bridge = (ev.ui_bridge ?? '').trim();
	out.push({ ...c('no tab-to-UI credential bridge in env (git askpass)', bridge === '', bridge),
		knownGap: bridge ? 'M4 RPC capability filter (docs/adr/20261104-rpc-capability-filter.md)' : undefined });
	// Egress points at exactly what this tab must use: its own broker or the blackhole. The
	// runtime-injected value never wins, and both cases agree.
	const want = PROXY_RE[opts.proxy];
	out.push(c(`runtime-injected proxy env never wins (both cases point at the ${opts.proxy})`, want.test(ev.http_proxy ?? '') && ev.http_proxy === ev.HTTPS_PROXY,
		`http_proxy=${(ev.http_proxy ?? '').replace(/:[^:@/]+@/, ':***@')} HTTPS_PROXY=${(ev.HTTPS_PROXY ?? '').replace(/:[^:@/]+@/, ':***@')}`));
	for (const [k, v] of Object.entries(ev.egress)) {
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
