// Unit tests for the probe safety guards.
//
// These guards are the only thing standing between "a probe demonstrates an
// escape" and "a probe attacks the user's Mac", so they are tested directly
// rather than trusted. Run in a container:
//   docker run --rm -v "$PWD":/repo -w /repo node:24.22.1-trixie \
//     node test/containment/probe-safety.test.ts

import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { createRequire } from 'node:module';

const require_ = createRequire(import.meta.url);
const safety = require_('./rogue-extension/probe-safety.js');

let failures = 0;
function test(name: string, fn: () => void): void {
	try {
		fn();
		console.log(`PASS  ${name}`);
	} catch (err) {
		failures++;
		console.log(`FAIL  ${name}\n      ${(err as Error).message}`);
	}
}

// A throwaway run directory. Not /tmp for anything that matters, but this is a
// unit test with no durable state.
const runDir = fs.mkdtempSync(path.join(os.tmpdir(), 'seclab-safety-'));
const marker = path.join(runDir, 'PWNED');
const canary = path.join(runDir, 'canary.txt');
fs.writeFileSync(canary, 'CANARY\n');

test('unarmed without a nonce', () => {
	delete process.env.SECLAB_PROBE_NONCE;
	const ctx = safety.context({ rundir: runDir, marker, canary });
	assert.equal(ctx.armed, false);
});

test('unarmed when the env nonce has no file on disk', () => {
	process.env.SECLAB_PROBE_NONCE = 'abc123';
	process.env.SECLAB_PROBE_RUNDIR = runDir;
	const ctx = safety.context({ rundir: runDir, marker, canary });
	assert.equal(ctx.armed, false, 'env alone must not arm the probes');
});

test('unarmed on nonce mismatch', () => {
	fs.writeFileSync(path.join(runDir, '.seclab-probe-nonce'), 'different');
	const ctx = safety.context({ rundir: runDir, marker, canary });
	assert.equal(ctx.armed, false);
});

fs.writeFileSync(path.join(runDir, '.seclab-probe-nonce'), 'abc123');
const ctx = safety.context({ rundir: runDir, marker, canary, beacon: '18099' });

test('armed when env and the run-directory file agree', () => {
	assert.equal(ctx.armed, true);
});

test('accepts a path inside the run directory', () => {
	assert.equal(safety.safePath(ctx, marker, 't'), marker);
});

for (const bad of [
	'/Users/someone/.ssh/id_rsa',
	'/Users/someone/.aws/credentials',
	'/etc/passwd',
	`${os.homedir()}/Library/Keychains/login.keychain-db`,
]) {
	test(`refuses real user data: ${bad}`, () => {
		assert.throws(() => safety.safePath(ctx, bad, 't'), /probe safety/);
	});
}

test('refuses a path outside the run directory', () => {
	assert.throws(() => safety.safePath(ctx, '/usr/local/bin/x', 't'), /outside the run directory/);
});

test('refuses traversal out of the run directory', () => {
	assert.throws(() => safety.safePath(ctx, path.join(runDir, '..', 'escape'), 't'),
		/outside the run directory/);
});

test('refuses a symlink pointing out of the run directory', () => {
	const link = path.join(runDir, 'link-out');
	fs.symlinkSync('/usr/local', link);
	assert.throws(() => safety.safePath(ctx, path.join(link, 'bin', 'x'), 't'),
		/outside the run directory/);
});

test('accepts the local beacon', () => {
	assert.equal(safety.safeUrl(ctx, 'http://127.0.0.1:18099/x', 't'), 'http://127.0.0.1:18099/x');
});

for (const bad of [
	'https://example.com/',
	'http://localhost:18099/x',          // name, not the literal loopback address
	'http://127.0.0.1:9999/x',           // wrong port
	'http://127.0.0.1:18099.evil.com/x', // prefix trick
]) {
	test(`refuses network target: ${bad}`, () => {
		assert.throws(() => safety.safeUrl(ctx, bad, 't'), /probe safety/);
	});
}

test('markerCommand only ever touches the marker', () => {
	const cmd = safety.markerCommand(ctx, '.mcp');
	assert.match(cmd, /^touch '/);
	assert.ok(cmd.includes(`${marker}.mcp`), cmd);
	assert.ok(!cmd.includes(';') && !cmd.includes('&&') && !cmd.includes('|'), cmd);
});

test('markerCommand refuses a suffix that escapes the run directory', () => {
	assert.throws(() => safety.markerCommand(ctx, '/../../../etc/x'), /probe safety/);
});

test('SafetyError is tagged so classify() cannot score it as a denial', () => {
	try {
		safety.safePath(ctx, '/etc/passwd', 't');
		assert.fail('expected a throw');
	} catch (err) {
		assert.equal((err as { seclabSafety?: boolean }).seclabSafety, true);
	}
});

fs.rmSync(runDir, { recursive: true, force: true });
console.log(`\n${failures === 0 ? 'all safety guards hold' : `${failures} FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
