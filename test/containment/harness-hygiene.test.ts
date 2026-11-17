/**
 * Harness hygiene (PR review, 2026-11-17): a harness reaps the previous run before wiping its run
 * directory, and an interrupted run still reaches its teardown gate.
 *   - exitOnSignals: SIGINT and SIGTERM end the process through `exit`, so an exit handler runs
 *     (checked in a child process);
 *   - each listed harness calls reapOrRefuse(base, …) before it first removes `base`, and
 *     registers exitOnSignals() (checked on the source, each rule failing on a mutant).
 *
 * Run: node test/containment/harness-hygiene.test.ts   (or ./seclab test harness-hygiene)
 */

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

const HERE = import.meta.dirname;
const SCRATCH = process.env.SECLAB_SCRATCH ?? path.join(HERE, '..', '..', '.work', 'harness-hygiene');
/** The harnesses that wipe a run directory and run an editor or tab. */
const HARNESSES = ['host-terminal.ts', 'reh-push.ts'];

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

const tests: Array<[string, () => void | Promise<void>]> = [
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
