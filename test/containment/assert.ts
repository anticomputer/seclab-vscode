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
	http_proxy: string;
	HTTPS_PROXY: string;
	egress: Record<string, string>;
}

export interface Check { vector: string; name: string; ok: boolean; detail: string }

const BLOCKED = new Set(['000', '403', '']);
const BLACKHOLE = 'http://127.0.0.1:9';

export function readEvidence(ws: string, vector: string): Evidence | undefined {
	const f = path.join(ws, '.seclab-evidence', `${vector}.json`);
	return fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, 'utf8')) as Evidence : undefined;
}

/** Assertions for one vector. `expectHostname` is the tab's hostname when known. */
export function checkEvidence(ev: Evidence | undefined, vector: string, opts: { marker: string; expectHostname?: string }): Check[] {
	const c = (name: string, ok: boolean, detail = ''): Check => ({ vector, name, ok, detail });
	if (!ev) {
		return [c('ran (evidence written into the workspace)', false, 'no evidence file')];
	}
	const out: Check[] = [c('ran (evidence written into the workspace)', true)];
	out.push(c('ran inside the tab, not on the host', ev.hostname !== os.hostname() && ev.seclab_tab_env === '1' &&
		(opts.expectHostname === undefined || ev.hostname === opts.expectHostname), `hostname=${ev.hostname} SECLAB_TAB=${ev.seclab_tab_env}`));
	out.push(c('cannot read host file outside the workspace (canary)', ev.canary_read === 'no', ev.canary_read));
	out.push(c('cannot read another tab\'s workspace', ev.othertab_read === 'no', ev.othertab_read));
	out.push(c('cannot write host file outside the workspace', !fs.existsSync(opts.marker), opts.marker));
	out.push(c('no writable docker.sock', ev.docker_sock_writable === 'no', ev.docker_sock_writable));
	out.push(c('no sudo', ev.sudo === 'no', ev.sudo));
	out.push(c('no host secrets / agent sockets in env', ev.secret_env.trim() === '', ev.secret_env));
	out.push(c('runtime-injected proxy env never wins (both cases overridden)', ev.http_proxy === BLACKHOLE && ev.HTTPS_PROXY === BLACKHOLE, `http_proxy=${ev.http_proxy} HTTPS_PROXY=${ev.HTTPS_PROXY}`));
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
		ok &&= ch.ok;
		console.log(`${ch.ok ? 'PASS' : 'FAIL'}  [${ch.vector}] ${ch.name}${ch.ok ? '' : `  -> ${ch.detail}`}`);
	}
	const failed = checks.filter(c => !c.ok).length;
	console.log(`\n${checks.length - failed}/${checks.length} checks passed`);
	return ok;
}
