/**
 * Harness hygiene (PR review, 2026-11-17): a harness reaps the previous run before wiping its run
 * directory, and an interrupted run still reaches its teardown gate.
 *   - exitOnSignals: SIGINT and SIGTERM end the process through `exit`, so an exit handler runs
 *     (checked in a child process);
 *   - each listed harness calls reapOrRefuse(base, …) before it first removes `base`, and
 *     registers exitOnSignals() (checked on the source, each rule failing on a mutant).
 *   - reapPreviousRun refuses when a runtime can't be listed or removal left a resource behind,
 *     and keeps the profile then (checked in a child process with stand-in docker and sbx).
 *
 * Run: node test/containment/harness-hygiene.test.ts   (or ./seclab test harness-hygiene)
 */

import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import * as net from 'node:net';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

const HERE = import.meta.dirname;
const SCRATCH = process.env.SECLAB_SCRATCH ?? path.join(HERE, '..', '..', '.work', 'harness-hygiene');
/**
 * The reap refuses a run directory outside the test roots (~/.seclab-test/ or this worktree's
 * .work/). In the container the worktree is read-only and SECLAB_SCRATCH is a tmpfs, so the
 * runner points HOME into that tmpfs and the reap fixtures live under its .seclab-test/.
 */
const REAP_ROOT = process.env.SECLAB_SCRATCH ? path.join(os.homedir(), '.seclab-test', 'harness-hygiene') : SCRATCH;
/** The harnesses that wipe a run directory and run an editor or tab. */
const HARNESSES = ['host-terminal.ts', 'reh-push.ts', 'response-probe.ts', 'search-probe.ts', 'auto-reply-probe.ts'];

function problems(src: string): string[] {
	const p: string[] = [];
	const reap = src.search(/\breapOrRefuse\(base, '[a-z-]+'\);/);
	const wipe = src.indexOf('fs.rmSync(base,');
	if (reap < 0 || wipe < 0 || reap > wipe) {
		p.push('the run directory is wiped before the previous run is reaped');
	}
	if (!/\nexitOnSignals\(\);\n/.test(src)) {
		p.push('an interrupted run skips the teardown gate');
	}
	return p;
}

async function signalled(sig: 'SIGINT' | 'SIGTERM'): Promise<{ code: number | null; ran: boolean }> {
	fs.mkdirSync(SCRATCH, { recursive: true });
	const marker = path.join(SCRATCH, `exit-${sig}`);
	fs.rmSync(marker, { force: true });
	const script = `import { exitOnSignals } from ${JSON.stringify(path.join(HERE, 'teardown.ts'))};
import * as fs from 'node:fs';
exitOnSignals();
process.on('exit', () => fs.writeFileSync(${JSON.stringify(marker)}, 'ran'));
console.log('ready');
setInterval(() => {}, 1000);`;
	const child = spawn(process.execPath, ['--input-type=module', '-e', script], { stdio: ['ignore', 'pipe', 'inherit'] });
	await new Promise<void>((res, rej) => {
		child.stdout.on('data', d => String(d).includes('ready') && res());
		child.once('exit', () => rej(new Error('child exited before it was ready')));
	});
	child.kill(sig);
	const code = await new Promise<number | null>(res => child.once('exit', c => res(c)));
	return { code, ran: fs.existsSync(marker) };
}

/**
 * Run reapPreviousRun on a previous run with one tab, against stand-in docker and sbx: `docker`
 * either fails every call (`unlisted`) or lists the tab's container and ignores `rm` (`stuck`).
 * An sbx tab owns Docker resources too (its broker container and egress network).
 */
function reapWith(mode: 'unlisted' | 'stuck' | 'clean', driver: 'oci' | 'sbx' = 'oci'): { refused: boolean; problems: string[]; profileKept: boolean } {
	const dir = path.join(REAP_ROOT, `reap-${driver}-${mode}`);
	fs.rmSync(dir, { recursive: true, force: true });
	const bin = path.join(dir, 'bin');
	const profile = path.join(dir, 'ud');
	fs.mkdirSync(bin, { recursive: true });
	fs.mkdirSync(profile, { recursive: true });
	const tab = 't-' + 'a'.repeat(26);
	const docker = mode === 'unlisted' ? 'exit 1'
		: mode === 'stuck' ? `case "$1 $2" in "ps -a"|"ps -aq") echo seclab-${tab};; esac; exit 0`
			: 'exit 0';
	fs.writeFileSync(path.join(bin, 'docker'), `#!/bin/sh\n${docker}\n`, { mode: 0o755 });
	fs.writeFileSync(path.join(bin, 'sbx'), '#!/bin/sh\n[ "$1" = ls ] && echo "[]"\nexit 0\n', { mode: 0o755 });
	fs.writeFileSync(path.join(dir, 'run.json'), JSON.stringify({ startedAt: 'x', driver, tabs: [tab], userDataDir: profile }));
	const script = `import { reapPreviousRun } from ${JSON.stringify(path.join(HERE, 'teardown.ts'))};
const r = reapPreviousRun(${JSON.stringify(dir)});
console.log(JSON.stringify({ refused: r.refused, problems: r.problems }));`;
	const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
		encoding: 'utf8', env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, SECLAB_SBX: path.join(bin, 'sbx') },
	});
	assert.equal(r.status, 0, r.stderr.slice(0, 300));
	const out = JSON.parse(r.stdout.trim().split('\n').pop()!);
	const profileKept = fs.existsSync(profile);
	fs.rmSync(dir, { recursive: true, force: true });
	return { ...out, profileKept };
}

/** The response probe can't pass with its image vectors silently left out (PR review on #48). */
function imageRules(ext: string, harness: string): string[] {
	const p: string[] = [];
	if (!/p >= 1024 && p < 65536/.test(ext)) {
		p.push('the extension drops valid image ports');
	}
	if (!/mark\('ready', \{[^}]*imagesArmed: images !== ''/.test(ext)) {
		p.push('the extension does not report whether its images are armed');
	}
	if (!/c\('setup', ready\.imagesArmed === true,/.test(harness)) {
		p.push('the harness does not require the image vectors');
	}
	return p;
}

const tests: Array<[string, () => void | Promise<void>]> = [
	['response probe: its image vectors are required, each rule failing on a mutant', () => {
		const ext = fs.readFileSync(path.join(HERE, 'response-probe', 'extension.js'), 'utf8');
		const harness = fs.readFileSync(path.join(HERE, 'response-probe.ts'), 'utf8');
		assert.deepEqual(imageRules(ext, harness), []);
		const mutants: Array<[string, string, string, 'ext' | 'harness']> = [
			['ports from 1025 only', 'p >= 1024 && p < 65536', 'p > 1024 && p < 65536', 'ext'],
			['no armed report', "imagesArmed: images !== ''", 'imagesArmed: true', 'ext'],
			['the harness ignores it', 'ready.imagesArmed === true,', 'true,', 'harness'],
		];
		for (const [name, from, to, which] of mutants) {
			const src = which === 'ext' ? ext : harness;
			assert.ok(src.includes(from), `mutant "${name}" no longer applies; update it`);
			const m = src.replace(from, to);
			assert.notDeepEqual(which === 'ext' ? imageRules(m, harness) : imageRules(ext, m), [], `mutant survived: ${name}`);
		}
	}],
	['loopback counters: a fixed SECLAB_BEACON_PORT goes to one listener, the rest get their own ports', async () => {
		const { loopbackCounters } = await import(path.join(HERE, '..', 'harness.ts'));
		const free = await new Promise<number>(res => { const t = net.createServer().listen(0, '127.0.0.1', () => { const p = (t.address() as net.AddressInfo).port; t.close(() => res(p)); }); });
		const before = process.env.SECLAB_BEACON_PORT;
		process.env.SECLAB_BEACON_PORT = String(free);
		try {
			const c = await loopbackCounters(3);
			try {
				assert.equal(c.ports[0], free);
				assert.equal(new Set(c.ports).size, 3, `ports not distinct: ${c.ports}`);
				for (const p of c.ports) {
					await new Promise<void>(res => net.connect(p, '127.0.0.1').on('close', () => res()).on('error', () => res()));
				}
				await new Promise(r => setTimeout(r, 100));
				assert.deepEqual(c.hits, [1, 1, 1]);
			} finally {
				c.close();
			}
		} finally {
			if (before === undefined) {
				delete process.env.SECLAB_BEACON_PORT;
			} else {
				process.env.SECLAB_BEACON_PORT = before;
			}
		}
	}],
	['the reap refuses, keeping the profile, when docker cannot list or removal leaves a container', () => {
		const unlisted = reapWith('unlisted');
		assert.ok(unlisted.refused && unlisted.problems.some(p => /could not list.*docker/.test(p)) && unlisted.profileKept, JSON.stringify(unlisted));
		const stuck = reapWith('stuck');
		assert.ok(stuck.refused && stuck.problems.some(p => /remain: container seclab-t-a+/.test(p)) && stuck.profileKept, JSON.stringify(stuck));
		const sbxUnlisted = reapWith('unlisted', 'sbx');
		assert.ok(sbxUnlisted.refused && sbxUnlisted.problems.some(p => /could not list.*docker/.test(p)) && sbxUnlisted.profileKept, JSON.stringify(sbxUnlisted));
		assert.deepEqual(reapWith('clean', 'sbx'), { refused: false, problems: [], profileKept: false });
		const clean = reapWith('clean');
		assert.deepEqual(clean, { refused: false, problems: [], profileKept: false });
	}],
	['SIGINT and SIGTERM reach the exit handler', async () => {
		assert.deepEqual(await signalled('SIGINT'), { code: 130, ran: true });
		assert.deepEqual(await signalled('SIGTERM'), { code: 143, ran: true });
	}],
	['each harness reaps before it wipes and tears down on a signal', () => {
		for (const h of HARNESSES) {
			assert.deepEqual(problems(fs.readFileSync(path.join(HERE, h), 'utf8')), [], h);
		}
	}],
	['each rule fails on a mutant of the real harness', () => {
		for (const h of HARNESSES) {
			const src = fs.readFileSync(path.join(HERE, h), 'utf8');
			const reapCall = src.match(/\breapOrRefuse\(base, '[a-z-]+'\);\n/)![0];
			const mutants: Array<[string, string, string]> = [
				['no reap', reapCall, ''],
				['reap after the wipe', reapCall + 'fs.rmSync(base,', 'fs.rmSync(base,'],
				['no signal handlers', '\nexitOnSignals();\n', '\n'],
			];
			for (const [name, from, to] of mutants) {
				assert.ok(src.includes(from), `${h}: mutant "${name}" no longer applies; update it`);
				const mutated = name === 'reap after the wipe' ? src.replace(reapCall, '').replace(/(fs\.rmSync\(base,[^\n]*\n)/, `$1${reapCall}`) : src.replace(from, to);
				assert.notDeepEqual(problems(mutated), [], `${h}: mutant survived: ${name}`);
			}
		}
	}],
];

let failed = 0;
for (const [name, fn] of tests) {
	try {
		await fn();
		console.log(`ok   ${name}`);
	} catch (err) {
		failed++;
		console.log(`FAIL ${name}\n     ${(err as Error).message.split('\n')[0]}`);
	}
}
console.log(`\n${tests.length - failed}/${tests.length} passed`);
process.exit(failed ? 1 : 0);
