// Unit tests for the headless driver's transport and launcher (no editor needed).
//   node --test test/driver/driver.test.ts

import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { PassThrough } from 'node:stream';
import { test } from 'node:test';
import { CdpPipe } from './cdp.ts';
import { editorEnv, executable, hasBootstrapPolicy, BOOTSTRAP_POLICY_MARK } from './editor.ts';

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
	process.env.SECLAB_HOST_CAPS = 'screen-capture';
	const env = editorEnv({ userData: '/x/profile', env: { FOO: 'bar' } });
	delete process.env.GITHUB_TOKEN;
	delete process.env.SECLAB_HOST_CAPS;
	assert.equal(env.GITHUB_TOKEN, undefined);
	assert.equal(env.SECLAB_HOST_CAPS, undefined);
	assert.equal(env.FOO, 'bar');
	assert.equal(env.SECLAB_BACKGROUND_WINDOWS, '1');
	assert.equal(env.VSCODE_PORTABLE, '/x/profile-portable');
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
