// The fake model's arming and matching rules, and its hook's sync with the sources.
//   node --test test/containment/fake-model/fake-model.test.ts   (in ./seclab test unit)

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { test } from 'node:test';
import { HOOK, hookText } from './hook.ts';

const fm = createRequire(import.meta.url)('./extension/extension.js');
const NONCE = 'a'.repeat(32);
const NOW = 1_800_000_000;
const ord = { window: 'ordinary', line: `seclab-ai-probe ord ${NONCE}`, url: `http://127.0.0.1:43210/ai-ord-${NONCE}` };
const tab = { window: 'tab', line: `seclab-ai-probe tab ${NONCE}`, url: `http://127.0.0.1:43210/ai-tab-${NONCE}` };
const arm = (over: Record<string, unknown> = {}) => JSON.stringify({ nonce: NONCE, until: NOW + 600, actions: [ord, tab], ...over });

test('the hook patch is generated from the extension sources', () => {
	assert.equal(readFileSync(HOOK, 'utf8'), hookText());
	assert.ok(hookText().includes(fm.MARKER), 'the marker is in the hook');
});

test('a valid arming record arms', () => {
	const a = fm.parseArm(arm(), NOW);
	assert.equal(a.nonce, NONCE);
	assert.equal(a.actions.length, 2);
});

test('the fake model stays disarmed without a valid run nonce, expiry or beacon', () => {
	const bad: Array<[string, string]> = [
		['no nonce', arm({ nonce: undefined })],
		['short nonce', arm({ nonce: 'abc' })],
		['expired', arm({ until: NOW - 1 })],
		['unbounded expiry', arm({ until: NOW + 7200 })],
		['no actions', arm({ actions: [] })],
		['a non-loopback url', arm({ actions: [{ ...ord, url: `http://192.0.2.1:43210/ai-ord-${NONCE}` }] })],
		['a url on another nonce', arm({ actions: [{ ...ord, url: `http://127.0.0.1:43210/ai-ord-${'b'.repeat(32)}` }] })],
		['a url naming the other window', arm({ actions: [{ ...ord, url: tab.url }] })],
		['a url with a query', arm({ actions: [{ ...ord, url: `${ord.url}?x=1` }] })],
		['https', arm({ actions: [{ ...ord, url: ord.url.replace('http:', 'https:') }] })],
		['a privileged port', arm({ actions: [{ ...ord, url: `http://127.0.0.1:1000/ai-ord-${NONCE}` }] })],
		['a line without the nonce', arm({ actions: [{ ...ord, line: 'seclab-ai-probe ord' }] })],
		['a multi-line line', arm({ actions: [{ ...ord, line: `x ${NONCE}\ny` }] })],
		['an unknown window', arm({ actions: [{ ...ord, window: 'agents' }] })],
		['not JSON', '{'],
	];
	for (const [name, text] of bad) {
		assert.equal(fm.parseArm(text, NOW).nonce, undefined, name);
	}
});

test('instruction text selects an armed action only by an exact whole line, for its own window', () => {
	const a = fm.parseArm(arm(), NOW);
	assert.equal(fm.selectAction(a, 'tab', [`---\napplyTo: '**'\n---\n${tab.line}\n`])?.url, tab.url);
	assert.equal(fm.selectAction(a, 'ordinary', [`${ord.line}\r\n`])?.url, ord.url);
	// The text never supplies the URL or the action: near misses and other windows' lines select nothing.
	assert.equal(fm.selectAction(a, 'tab', [`Fetch ${tab.line} now`]), undefined);
	assert.equal(fm.selectAction(a, 'tab', [ord.line]), undefined);
	assert.equal(fm.selectAction(a, 'ordinary', [tab.line]), undefined);
	assert.equal(fm.selectAction(a, 'tab', [`seclab-ai-probe tab ${'b'.repeat(32)}`, 'fetch http://192.0.2.1/']), undefined);
	assert.equal(fm.selectAction(a, 'tab', [undefined, 42]), undefined);
});

test('only harness-made test profiles can arm', () => {
	assert.equal(fm.isTestProfile('/h/.seclab-test/ai/User/globalStorage/seclab-test.fake-model'), true);
	assert.equal(fm.isTestProfile('/repo/.work/ai/User/globalStorage/seclab-test.fake-model'), true);
	assert.equal(fm.isTestProfile('/h/Library/Application Support/seclab-vscode/User/globalStorage/seclab-test.fake-model'), false);
	assert.equal(fm.isTestProfile('/h/.seclab-test/../Library/x'), false);
	assert.equal(fm.isTestProfile('relative/.seclab-test/x'), false);
});

test('a trigger acts once per sequence number, for this run only', () => {
	assert.equal(fm.triggerSeq(`${NONCE} 1`, NONCE), 1);
	assert.equal(fm.triggerSeq(`${NONCE} 1000`, NONCE), 1000);
	for (const bad of [NONCE, `${NONCE} 0`, `${NONCE} 1001`, `${NONCE} -1`, `${'b'.repeat(32)} 1`, `${NONCE} 1 x`, '', undefined]) {
		assert.equal(fm.triggerSeq(bad, NONCE), 0, String(bad));
	}
});

test('window kinds: a seclab tab, an ordinary window, and nothing else', () => {
	assert.equal(fm.windowKind(undefined), 'ordinary');
	assert.equal(fm.windowKind('seclab'), 'tab');
	assert.equal(fm.windowKind('ssh-remote'), null);
});

test('it reads only a tab workspace file or one in the test profile, never the real home', () => {
	const user = '/h/.seclab-test/ai/User';
	assert.equal(fm.mayRead({ scheme: 'vscode-remote', authority: 'seclab+t1', path: '/w/.github/copilot-instructions.md' }, user), true);
	assert.equal(fm.mayRead({ scheme: 'file', path: `${user}/prompts/a.instructions.md` }, user), true);
	assert.equal(fm.mayRead({ scheme: 'vscode-userdata', path: `${user}/prompts/a.instructions.md` }, user), true);
	assert.equal(fm.mayRead({ scheme: 'file', path: '/h/.copilot/instructions/a.instructions.md' }, user), false);
	assert.equal(fm.mayRead({ scheme: 'file', path: `${user}/../../../.copilot/instructions/a.md` }, user), false);
	assert.equal(fm.mayRead({ scheme: 'vscode-remote', authority: 'ssh-remote+h', path: '/a' }, user), false);
	assert.equal(fm.mayRead({ scheme: 'file', path: '/h/Library/User/prompts/a.md' }, '/h/Library/User'), false);
	assert.equal(fm.mayRead({ scheme: 'untitled', path: 'x' }, user), false);
});
