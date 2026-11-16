// Containment level B, headless (the RPC escape probes and the editor-run vectors): the real
// editor opens the prepared tab, driven over its CDP pipe instead of a window.ts launch, so the
// proof runs on Linux under Xvfb in CI. The steps are check-evidence.ts's own:
//   1. prepare <profile> oci   (fixture workspace, claimed tab, rogue + benign extensions in it)
//   2. launch the tab window with exactly the env prepare recorded in <run dir>/launch.json
//   3. wait for the rogue extension's probe record and the benign control's record
//   4. close: the CDP pipe closes and the editor quits (before teardown)
//   5. check <profile>         (assert the evidence, then tear the run down)
// CDP is pipe-only (--remote-debugging-pipe), never a port. launch.json is a record of what
// prepare set: any other key, a different app or profile, or a folder that isn't a tab is
// refused, and a run whose clipboard probes are armed needs an app with the canary clipboard.
//   node test/driver/level-b.ts --app APP --profile DIR [--wait-ms N] [-- EXTRA_EDITOR_ARGS]

import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { DrivenEditor } from './editor.ts';
import { appHasCanaryClipboard, checkUserDataDir } from '../harness.ts';

// The only env names prepare sets (check-evidence.ts); anything else in the record is refused.
const LAUNCH_ENV = new Set(['SECLAB_EDITOR_CANARY', 'SECLAB_PROBE_NONCE', 'SECLAB_PROBE_RUNDIR', 'SECLAB_PROBE_BEACON_PORT', 'SECLAB_TEST_CLIPBOARD_CANARY']);
export interface LaunchRecord { app: string | null; userData: string; folderUri: string; env: Record<string, string> }

/** Why prepare's launch record can't be used for this run, or undefined. */
export function launchProblem(r: unknown, want: { app: string; profile: string; runDir: string }, hasCanaryClipboard: boolean): string | undefined {
	if (!r || typeof r !== 'object' || Array.isArray(r)) {
		return 'not an object';
	}
	const keys = Object.keys(r).sort().join(',');
	if (keys !== 'app,env,folderUri,userData') {
		return `unexpected keys: ${keys}`;
	}
	const l = r as LaunchRecord;
	if (l.app !== want.app) {
		return 'the record names another app';
	}
	if (l.userData !== want.profile) {
		return 'the record names another profile';
	}
	if (typeof l.folderUri !== 'string' || !/^vscode-remote:\/\/seclab\+t-[a-z0-9]+\/\S+$/.test(l.folderUri)) {
		return 'the folder is not a seclab tab';
	}
	if (!l.env || typeof l.env !== 'object' || Array.isArray(l.env)) {
		return 'env is not an object';
	}
	for (const [k, v] of Object.entries(l.env)) {
		if (!LAUNCH_ENV.has(k) || typeof v !== 'string' || /[\0\n]/.test(v)) {
			return `unexpected env entry ${k}`;
		}
	}
	if (l.env.SECLAB_PROBE_RUNDIR !== want.runDir) {
		return 'the probe run dir is not this run\'s';
	}
	// window.ts's refusal (canary clipboard): never arm the clipboard probes without the hook.
	const targets = path.join(want.runDir, 'ws-editor', '.seclab', 'targets');
	const claims = fs.existsSync(targets) && /^clipboard=/m.test(fs.readFileSync(targets, 'utf8'));
	if ((l.env.SECLAB_TEST_CLIPBOARD_CANARY !== undefined || claims) && !hasCanaryClipboard) {
		return 'the run arms the canary clipboard, but the app has no canary-clipboard hook';
	}
	return undefined;
}

async function main(): Promise<number> {
	const argv = process.argv.slice(2);
	const dash = argv.indexOf('--');
	const extra = dash >= 0 ? argv.splice(dash).slice(1) : [];
	const opt = (k: string) => (argv.indexOf(k) >= 0 ? argv[argv.indexOf(k) + 1] : undefined);
	const app = opt('--app') && path.resolve(opt('--app')!);
	const profile = opt('--profile') && path.resolve(opt('--profile')!);
	const waitMs = Number(opt('--wait-ms') ?? 240_000);
	if (!app || !profile || !(waitMs > 0)) {
		console.error('usage: level-b.ts --app APP --profile DIR [--wait-ms N] [-- EXTRA_EDITOR_ARGS]');
		return 2;
	}
	checkUserDataDir(profile);
	const repo = path.resolve(import.meta.dirname, '../..');
	const runDir = path.resolve(process.env.SECLAB_EVIDENCE_DIR ?? path.join(repo, '.work', 'containment-editor'));
	const checkEvidence = (mode: 'prepare' | 'check') => spawnSync(process.execPath,
		[path.join(repo, 'test', 'containment', 'check-evidence.ts'), mode, profile, ...(mode === 'prepare' ? ['oci'] : [])],
		{ stdio: 'inherit', env: { ...process.env, SECLAB_TEST_APP: app } }).status;

	if (checkEvidence('prepare') !== 0) {
		console.error('level-b: prepare failed');
		return 1;
	}
	const record: unknown = JSON.parse(fs.readFileSync(path.join(runDir, 'launch.json'), 'utf8'));
	const bad = launchProblem(record, { app, profile, runDir }, appHasCanaryClipboard(app));
	if (bad) {
		console.error(`level-b: refusing the launch record: ${bad}`);
		checkEvidence('check'); // tears the prepared run down
		return 1;
	}
	const launch = record as LaunchRecord;
	const evDir = path.join(runDir, 'ws-editor', '.seclab-evidence');
	const done = () => ['rpc-probes.json', 'benign.json'].every(f => fs.existsSync(path.join(evDir, f)));
	let ed: DrivenEditor | undefined;
	let finished = false;
	try {
		ed = await DrivenEditor.launch({ app, userData: profile, folderUri: launch.folderUri, env: launch.env, args: extra });
		for (const until = Date.now() + waitMs; !done() && Date.now() < until;) {
			await new Promise(r => setTimeout(r, 1_000));
		}
		finished = done();
		// A moment more for late writes (host-effect markers, the positive control's last steps).
		await new Promise(r => setTimeout(r, 5_000));
		console.log(finished ? 'level-b: the probes and the positive control finished' : `level-b: no probe record after ${waitMs} ms (check says what is missing)`);
	} catch (e) {
		console.error(`level-b: driven run failed: ${(e as Error).message.slice(0, 300)}`);
	} finally {
		// The pipe closes and the editor quits before check's teardown runs.
		await ed?.close().catch(() => undefined);
	}
	return checkEvidence('check') === 0 && finished ? 0 : 1;
}

if (process.argv[1] === import.meta.filename) {
	process.exit(await main());
}
