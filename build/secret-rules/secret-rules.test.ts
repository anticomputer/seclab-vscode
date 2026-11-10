// Unit tests for the shared credential classifier (build/secret-rules/src, patch 0036) and the
// patch sync. Secret-shaped values are generated at run time, never written in the repo (fixture
// rule: nothing in a real token format). Pure; runs in the unit-test node container.

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { test } from 'node:test';
import { newFileSection, PATCH, problems, SHARED } from './sync-patch.ts';

// The shared files import each other as `.js` (the workbench's convention); load copies as `.ts`.
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secret-rules-'));
for (const f of SHARED) {
	fs.writeFileSync(path.join(dir, f), fs.readFileSync(path.join(import.meta.dirname, 'src', f), 'utf8').replaceAll(/from '\.\/(\w+)\.js'/g, "from './$1.ts'"));
}
const { withholdReason, SECLAB_SETTINGS_WITHHELD_MARKER } = await import(path.join(dir, 'seclabWithhold.ts'));
const { seclabSecretRuleHit } = await import(path.join(dir, 'seclabSecretScan.ts'));

const alnum = (n: number) => Array.from(randomBytes(n), b => 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'[b % 62]).join('');

test('credential names are withheld whatever the value (weak passwords included)', () => {
	assert.equal(withholdReason('probe.apiToken', 'seclabcanary_x'), 'credential-name');
	assert.equal(withholdReason('probe.password', 'hunter2'), 'credential-name');
	assert.equal(withholdReason('probe.clientSecret', ''), 'credential-name');
	assert.equal(withholdReason('terminal.integrated.env.linux', { PATH: '/usr/bin' }), 'credential-name');
	assert.equal(withholdReason('http.headers', { Authorization: 'x' }), 'credential-name');
	// Registered at run time with a changing scope upstream; the name alone must withhold it.
	assert.equal(withholdReason('http.proxyAuthorization', 'Basic seclabcanary_x'), 'credential-name');
	assert.equal(withholdReason('http.proxyAuthorization', null), 'credential-name');
});

test('secret-shaped strings are withheld under a neutral name', () => {
	const github = `ghp_${alnum(36)}`;
	assert.ok(seclabSecretRuleHit(`"probe.value": "${github}"`), 'the scanner itself sees the generated token');
	assert.equal(withholdReason('probe.value', github), 'secret-value');
	assert.equal(withholdReason('probe.list', ['a', github]), 'secret-value');
	assert.equal(withholdReason('probe.nested', { inner: { deeper: github } }), 'secret-value');
});

test('ordinary settings cross', () => {
	assert.equal(withholdReason('editor.tabSize', 4), undefined);
	assert.equal(withholdReason('editor.fontFamily', 'Menlo, monospace'), undefined);
	assert.equal(withholdReason('files.exclude', { '**/.git': true }), undefined);
	assert.equal(withholdReason('workbench.colorTheme', 'Default Dark Modern'), undefined);
});

test('the build marker is the agreed literal', () => {
	assert.equal(SECLAB_SETTINGS_WITHHELD_MARKER, 'seclabSettingsWithheld:v1');
});

test('sync: a section built from src passes, a changed one fails', () => {
	const read = (f: string) => fs.readFileSync(path.join(import.meta.dirname, 'src', f), 'utf8');
	const good = SHARED.map(f => newFileSection(`src/vs/workbench/api/browser/${f}`, read(f))).join('');
	assert.deepEqual(problems(good, read), []);
	const bad = good.replace('+export function withholdReason', '+export function withholdReasonX');
	assert.equal(problems(bad, read).length, 1);
});

test('sync: the queued patch matches src', { skip: !fs.existsSync(PATCH) && 'patch 0036 is not queued yet' }, () => {
	assert.deepEqual(problems(fs.readFileSync(PATCH, 'utf8')), []);
});
