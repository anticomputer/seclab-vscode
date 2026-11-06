// The rogue-REH hook's arming, end to end in a real OCI tab running the containment test build
// (EDR test-build-variants). Local only: needs seclab-tab-oci:test-containment
// (`./seclab fetch macos-containment RUN` then `./seclab image oci --test-variant containment`).
//   node test/builds/rogue-reh-arming.ts
// A harmless stand-in payload is staged where the hook looks (~/.seclab-test/rogue-reh/probes.js
// in the tab). The hook must not load it with no targets, an expired run, or a malformed nonce,
// and must load it once for a well-formed, unexpired run. Refuses to start (require-hooks) if the
// image lacks the hook, so a missing hook can't pass as "never armed".

import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import { teardownGate, writeManifest, writeSnapshot } from '../containment/teardown.ts';

const IMAGE = 'seclab-tab-oci:test-containment';
const repo = path.resolve(import.meta.dirname, '../..');
execFileSync(process.execPath, [path.join(import.meta.dirname, 'require-hooks.ts'), '--variant', 'containment', '--hook', 'rogue-reh', '--image', IMAGE], { stdio: 'inherit' });

const work = path.join(repo, '.work', 'rogue-reh-arming');
const state = path.join(work, 'state');
const ws = path.join(work, 'tabs', 'ws1');
fs.rmSync(work, { recursive: true, force: true });
fs.mkdirSync(ws, { recursive: true });
fs.mkdirSync(state, { recursive: true, mode: 0o700 });
writeSnapshot(work);
writeManifest(work, { driver: 'oci', stateDirs: [state] });
process.on('exit', code => {
	if (!teardownGate(work) && code === 0) {
		process.exitCode = 1;
	}
});

const client = new TabdClient({
	command: process.execPath,
	args: [path.join(repo, 'tabd/src/main.ts'), '--state-dir', state, '--driver', 'oci', '--image', IMAGE, '--broker', 'none', '--allowed-root', path.join(work, 'tabs')],
	env: { HOME: process.env.HOME, USER: process.env.USER, PATH: '/usr/bin:/bin' },
});
client.on('stderr', (s: string) => process.stderr.write(`[tabd] ${s}`));
await client.initialize('rogue-reh-arming', '0');
const { tab } = await client.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
const tabId = tab.metadata.name;
writeManifest(work, { tabs: [tabId] });
const ctr = `seclab-${tabId}`;
let failed = false;
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
/** A shell snippet in the tab, as the tab user, with the tab's own environment (same HOME as the REH). */
const inTab = (script: string, input?: string) => spawnSync('docker', ['exec', '-i', '-u', '1000:1000', '--', ctr, '/opt/seclab/bin/seclab-tab-env', 'sh', '-c', script], { encoding: 'utf8', input, timeout: 30_000 });
const check = async (name: string, fn: () => Promise<void>) => {
	try {
		await fn();
		console.log(`ok   ${name}`);
	} catch (e) {
		failed = true;
		console.log(`FAIL ${name}: ${(e as Error).message}`);
	}
};
const DIR = '"$HOME/.seclab-test/rogue-reh"';
const loaded = () => inTab(`cat ${DIR}/evidence/loaded 2>/dev/null`).stdout.trim();
const stageTargets = (lines: string) => inTab(`cat > ${DIR}/targets`, lines);
try {
	await client.request('tab.ensureRunning', { tabId });
	// The stand-in payload: records that it was loaded and what it was handed. Nothing else.
	const payload = `module.exports = { main(socketServer, router) { const fs = require('fs'); fs.mkdirSync(process.env.SECLAB_ROGUE_REH_OUT, { recursive: true }); fs.writeFileSync(process.env.SECLAB_ROGUE_REH_OUT + '/loaded', JSON.stringify({ server: typeof socketServer?.registerChannel, router: typeof router })); } };\n`;
	const st = inTab(`mkdir -p ${DIR} && cat > ${DIR}/probes.js`, payload);
	assert.equal(st.status, 0, st.stderr);
	const now = Math.floor(Date.now() / 1000);
	const arm = randomBytes(16).toString('hex');

	await check('no targets file: not armed', async () => {
		await sleep(9000);
		assert.equal(loaded(), '');
	});
	await check('an expired run: not armed', async () => {
		stageTargets(`arm=${arm}\nrun=/x\nuntil=${now - 60}\n`);
		await sleep(9000);
		assert.equal(loaded(), '');
	});
	await check('a malformed nonce: not armed', async () => {
		stageTargets(`arm=not-a-nonce\nrun=/x\nuntil=${now + 600}\n`);
		await sleep(9000);
		assert.equal(loaded(), '');
	});
	await check('a well-formed, unexpired run: the hook loads the payload once, with the server and router', async () => {
		stageTargets(`arm=${arm}\nrun=/x\nuntil=${now + 600}\n`);
		let got = '';
		for (let i = 0; i < 20 && !got; i++) {
			await sleep(1000);
			got = loaded();
		}
		assert.deepEqual(JSON.parse(got || '{}'), { server: 'function', router: 'object' });
	});
} finally {
	await client.request('tab.remove', { tabId }).catch(e => {
		failed = true;
		console.log(`remove: ${(e as Error).message}`);
	});
	client.dispose();
}
console.log(failed ? 'rogue-reh-arming: FAILED' : 'rogue-reh-arming: all checks passed');
process.exitCode = failed ? 1 : 0;
