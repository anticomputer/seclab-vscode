// Unit tests for the headless driver's transport and launcher (no editor needed).
//   node --test test/driver/driver.test.ts

import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { PassThrough } from 'node:stream';
import { test } from 'node:test';
import { CdpPipe } from './cdp.ts';
import { editorEnv, executable, hasBootstrapPolicy, BOOTSTRAP_POLICY_MARK } from './editor.ts';
import { editorLaunchCommand, tabImageProblem } from '../harness.ts';

function pair() {
	const toEditor = new PassThrough();
	const fromEditor = new PassThrough();
	const sent: any[] = [];
	let buf = '';
	toEditor.on('data', (c: Buffer) => {
		buf += c.toString('utf8');
		for (let i = buf.indexOf('\0'); i >= 0; i = buf.indexOf('\0')) {
			sent.push(JSON.parse(buf.slice(0, i)));
			buf = buf.slice(i + 1);
		}
	});
	return { cdp: new CdpPipe(toEditor, fromEditor), fromEditor, sent };
}

const tick = () => new Promise(r => setImmediate(r));

test('requests are NUL-framed and answers matched by id, out of order and split across chunks', async () => {
	const { cdp, fromEditor, sent } = pair();
	const a = cdp.send('A.one', { x: 1 });
	const b = cdp.send('B.two', {}, 'S1');
	await tick();
	assert.deepEqual(sent, [{ id: 1, method: 'A.one', params: { x: 1 } }, { id: 2, method: 'B.two', params: {}, sessionId: 'S1' }]);
	const reply = JSON.stringify({ id: 2, result: { b: true } }) + '\0' + JSON.stringify({ id: 1, result: { a: 'é' } }) + '\0';
	const bytes = Buffer.from(reply);
	fromEditor.write(bytes.subarray(0, 7));
	fromEditor.write(bytes.subarray(7, bytes.indexOf('é') + 1)); // splits a multibyte character
	fromEditor.write(bytes.subarray(bytes.indexOf('é') + 1));
	assert.deepEqual(await b, { b: true });
	assert.deepEqual(await a, { a: 'é' });
});

test('an error answer rejects with the method name', async () => {
	const { cdp, fromEditor } = pair();
	const p = cdp.send('Page.captureScreenshot');
	fromEditor.write(JSON.stringify({ id: 1, error: { code: -32000, message: 'nope' } }) + '\0');
	await assert.rejects(p, /cdp Page\.captureScreenshot: nope/);
});

test('events reach listeners with their session', async () => {
	const { cdp, fromEditor } = pair();
	const seen: unknown[] = [];
	const off = cdp.on((m, p, s) => seen.push([m, p, s]));
	fromEditor.write(JSON.stringify({ method: 'Target.targetCreated', params: { t: 1 }, sessionId: 'S' }) + '\0');
	await tick();
	off();
	fromEditor.write(JSON.stringify({ method: 'X.y', params: {} }) + '\0');
	await tick();
	assert.deepEqual(seen, [['Target.targetCreated', { t: 1 }, 'S']]);
});

test('the pipe closing rejects pending and later requests', async () => {
	const { cdp, fromEditor } = pair();
	const p = cdp.send('A.b');
	fromEditor.end();
	await assert.rejects(p, /pipe closed/);
	await assert.rejects(cdp.send('C.d'), /pipe closed/);
});

test('a request with no answer times out', async () => {
	const { cdp } = pair();
	await assert.rejects(cdp.send('Slow.call', {}, undefined, 50), /no answer in 50 ms/);
});

test('the editor gets a clean environment, never the launcher\'s secrets', () => {
	process.env.GITHUB_TOKEN = 'seclabcanary_launcher_token';
	process.env.SECLAB_LAUNCHER_ONLY = '1';
	const env = editorEnv({ userData: '/x/profile', env: { FOO: 'bar' } });
	delete process.env.GITHUB_TOKEN;
	delete process.env.SECLAB_LAUNCHER_ONLY;
	assert.equal(env.GITHUB_TOKEN, undefined);
	assert.equal(env.SECLAB_LAUNCHER_ONLY, undefined);
	assert.equal(env.FOO, 'bar');
	assert.equal(env.SECLAB_BACKGROUND_WINDOWS, '1');
	assert.equal(env.VSCODE_PORTABLE, '/x/profile-portable');
	assert.equal(env.VSCODE_CLI, '1', 'no shell-environment resolution, so no login shell (RRR-1)');
});

test('a build is exec-safe only if its bootstrap carries the policy mark; Linux reads the binary from product.json', () => {
	const scratch = fs.mkdtempSync(path.join(process.env.SECLAB_SCRATCH ?? path.join(import.meta.dirname, '../../.work/test-scratch'), 'driver-'));
	try {
		const res = process.platform === 'darwin' ? path.join(scratch, 'Contents', 'Resources', 'app') : path.join(scratch, 'resources', 'app');
		fs.mkdirSync(path.join(res, 'out'), { recursive: true });
		assert.equal(hasBootstrapPolicy(scratch), false);
		fs.writeFileSync(path.join(res, 'out', 'mainImpl.js'), 'console.log(1)');
		assert.equal(hasBootstrapPolicy(scratch), false);
		fs.writeFileSync(path.join(res, 'out', 'mainImpl.js'), `/* ${BOOTSTRAP_POLICY_MARK} */`);
		assert.equal(hasBootstrapPolicy(scratch), true);
		if (process.platform === 'linux') {
			fs.writeFileSync(path.join(res, 'product.json'), JSON.stringify({ applicationName: 'seclab-vscode' }));
			assert.equal(executable(scratch), path.join(scratch, 'seclab-vscode'));
			fs.writeFileSync(path.join(res, 'product.json'), JSON.stringify({ applicationName: '../bin/sh' }));
			assert.throws(() => executable(scratch), /no applicationName/);
			fs.writeFileSync(path.join(res, 'product.json'), JSON.stringify({ applicationName: '..' }));
			assert.throws(() => executable(scratch), /no applicationName/);
		}
	} finally {
		fs.rmSync(scratch, { recursive: true, force: true });
	}
});

test('SECLAB_TAB_IMAGE: only our tab images, and only the kind the driver runs', () => {
	assert.equal(tabImageProblem('seclab-tab:b-1453-dcd3ad6', 'sbx'), undefined);
	assert.equal(tabImageProblem('seclab-tab-oci:b-1453-dcd3ad6', 'oci'), undefined);
	assert.equal(tabImageProblem('seclab-tab-oci:test-containment', 'oci'), undefined);
	assert.match(tabImageProblem('seclab-tab-oci:b-x', 'sbx') ?? '', /not a sbx tab image/);
	assert.match(tabImageProblem('seclab-tab:b-x', 'oci') ?? '', /not a oci tab image/);
	for (const bad of ['seclab-broker:dev', 'seclab-tab', 'seclab-tab:', 'seclab-tab:B-UPPER', 'evil/seclab-tab:b-x', 'seclab-tab:b-x@sha256:00']) {
		assert.match(tabImageProblem(bad, 'sbx') ?? '', /must name a seclab-tab image/, bad);
	}
});

test('every tab suite runner forwards SECLAB_TAB_IMAGE to tabd (PR 25 review)', () => {
	// The ./seclab test suites that start tabd: each passes tabImageArgs, so a proof image is
	// never silently replaced by the shared :local one.
	const repo = path.resolve(import.meta.dirname, '../..');
	for (const f of ['tabd/test/e2e.ts', 'tabd/test/e2e-broker.ts', 'test/containment/run.ts', 'test/canary/run.ts', 'test/secrets/run.ts', 'test/observability/run.ts']) {
		const text = fs.readFileSync(path.join(repo, f), 'utf8');
		assert.match(text, /tabImageArgs\(driver\)/, f);
		assert.match(text, /'tabd\/src\/main\.ts'\)[^\n]*(\n[^\n]*){0,2}\.\.\.tab[Ii]mage/, f);
	}
});

test('a printed launch line carries the commit the run was prepared for (PR 42 review)', () => {
	const saved = process.env.SECLAB_APP_SHA;
	try {
		delete process.env.SECLAB_APP_SHA;
		assert.match(editorLaunchCommand('/u', 'vscode-remote://x/y'), /^node test\/window\.ts launch /);
		process.env.SECLAB_APP_SHA = 'a'.repeat(40);
		const line = editorLaunchCommand('/u', 'vscode-remote://x/y', { K: 'v' });
		assert.match(line, new RegExp(`^SECLAB_APP_SHA=${'a'.repeat(40)} node test/window\\.ts launch `));
		assert.doesNotMatch(line, /--env SECLAB_APP_SHA/);
		process.env.SECLAB_APP_SHA = '$(id)';
		assert.match(editorLaunchCommand('/u', 'vscode-remote://x/y'), /^node /);
	} finally {
		if (saved === undefined) {
			delete process.env.SECLAB_APP_SHA;
		} else {
			process.env.SECLAB_APP_SHA = saved;
		}
	}
});
