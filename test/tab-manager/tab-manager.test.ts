// Tab Manager unit tests: the extension's own modules against a recording `vscode` stub
// (test/tab-manager/vscode-stub.ts) and a fake tabd client. Covers review findings that had no
// test. Kept outside extensions/ so no test code is overlaid into the build.
//   node --test test/tab-manager/tab-manager.test.ts

import * as assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import { test } from 'node:test';
import { pathToFileURL } from 'node:url';
import * as path from 'node:path';

const stubUrl = pathToFileURL(path.join(import.meta.dirname, 'vscode-stub.ts')).href;
registerHooks({
	resolve(specifier, context, next) {
		return specifier === 'vscode' ? { url: stubUrl, shortCircuit: true } : next(specifier, context);
	},
});
const vscode = await import('./vscode-stub.ts');
const { PackageFeeds } = await import('../../extensions/seclab-tab-manager/src/packages.ts');
const { EgressPrompts } = await import('../../extensions/seclab-tab-manager/src/prompts.ts');
const { WriteBackReview } = await import('../../extensions/seclab-tab-manager/src/writeback.ts');

type Req = { method: string; params: Record<string, unknown> };
function fakeClient(reply: (method: string, params: Record<string, unknown>) => unknown) {
	const requests: Req[] = [];
	const client = {
		request: async (method: string, params: Record<string, unknown>) => {
			requests.push({ method, params });
			return reply(method, params);
		},
	};
	return { requests, getClient: async () => client as never };
}
const settle = () => new Promise(r => setTimeout(r, 20));

// ---- EEE-3: turning package feeds on needs a fresh typed code -------------------------------

async function turnOn(input: (opts: { prompt: string; validateInput: (v: string) => string | undefined }) => unknown) {
	vscode.reset();
	const { requests, getClient } = fakeClient(m => (m === 'tab.packages.get' ? { cfs: false } : { applied: true }));
	const feeds = new PackageFeeds(getClient, () => 't-1', vscode.log as never);
	vscode.answers.showWarningMessage = ['Use Package Feeds'];
	vscode.answers.showInputBox = [input];
	await vscode.commandsRegistered.get('seclab.packageFeeds')!();
	feeds.dispose();
	return requests.filter(r => r.method === 'tab.packages.set');
}
const codeOf = (opts: { prompt: string }) => /Type ([A-Z]{4}) /.exec(opts.prompt)![1];

test('EEE-3: accepting the modal alone (a timed Enter) never turns feeds on; only the fresh code does', async () => {
	assert.equal((await turnOn(() => '')).length, 0, 'empty input');
	assert.equal((await turnOn(() => undefined)).length, 0, 'input box dismissed');
	assert.equal((await turnOn(o => (codeOf(o) === 'AAAA' ? 'BBBB' : 'AAAA'))).length, 0, 'a guessed code');
	assert.equal((await turnOn(o => codeOf(o).toLowerCase())).length, 0, 'the code in the wrong case');
	const on = await turnOn(o => codeOf(o));
	assert.deepEqual(on.map(r => r.params), [{ tabId: 't-1', cfs: true }], 'the right code turns it on');
});

test('EEE-3: the code is fresh each time and the input box rejects anything else', async () => {
	const codes = new Set<string>();
	for (let i = 0; i < 6; i++) {
		await turnOn(o => {
			codes.add(codeOf(o));
			assert.equal(o.validateInput(codeOf(o)), undefined);
			assert.match(o.validateInput('ZZZZZ') ?? '', /^Type [A-Z]{4}$/);
			return undefined;
		});
	}
	assert.ok(codes.size > 1, `the same code every time: ${[...codes]}`);
});

// ---- BBB-1: faked editor activity doesn't open the broker's user-action gate ----------------

test('BBB-1: selection changes count as user activity only in a focused, active window, from keyboard or mouse', async () => {
	vscode.reset();
	const { requests, getClient } = fakeClient(() => ({}));
	const prompts = new EgressPrompts(getClient, vscode.log as never);
	prompts.watchUserActivity('t-1');
	const { Keyboard, Mouse, Command } = vscode.TextEditorSelectionChangeKind;
	vscode.window.state.focused = false;
	vscode.fireSelectionChange({ kind: Mouse });
	vscode.window.state.focused = true;
	vscode.window.state.active = false;
	vscode.fireSelectionChange({ kind: Keyboard });
	vscode.window.state.active = true;
	vscode.fireSelectionChange({ kind: Command });
	await settle();
	assert.equal(requests.length, 0, 'a command-driven, unfocused or inactive change opened the gate');
	vscode.fireSelectionChange({ kind: Mouse });
	await settle();
	assert.deepEqual(requests.map(r => [r.method, r.params]), [['tab.userAction', { tabId: 't-1' }]]);
	prompts.dispose();
});

// ---- OO-2 / PP-1: what the user approves is what they saw ------------------------------------

const b64 = (s: string | Buffer) => Buffer.from(s).toString('base64');
async function review(tab: Record<string, unknown>) {
	vscode.reset();
	const { requests, getClient } = fakeClient(m => {
		if (m === 'tab.writeback.status') {
			return { gated: true, active: true, pending: [{ path: '.vscode/tasks.json', kind: 'modify', reasons: ['runs code'] }] };
		}
		if (m === 'tab.writeback.content') {
			return { sig: 's1', host: { kind: 'file', b64: b64('{}\n'), size: 3 }, tab };
		}
		return { result: 'applied' };
	});
	const ctx = { subscriptions: [] as Array<{ dispose(): void }> };
	const wb = new WriteBackReview(ctx as never, getClient, 't-1', vscode.log as never);
	vscode.answers.showQuickPick = [(items: Array<unknown>) => items[0]];
	vscode.answers.showWarningMessage = [undefined]; // the user closes the approval dialog
	await vscode.commandsRegistered.get('seclab.reviewChanges')!();
	const diff = vscode.calls.find(c => c.fn === 'executeCommand' && c.args[0] === 'vscode.diff')!;
	const shown = wb.provideTextDocumentContent(diff.args[2] as never);
	const dialog = vscode.calls.find(c => c.fn === 'showWarningMessage' && String(c.args[0]).startsWith('Apply the tab'))!;
	for (const d of ctx.subscriptions) {
		d.dispose();
	}
	return { shown, buttons: dialog.args.slice(2) as string[], decided: requests.some(r => r.method === 'tab.writeback.decide') };
}

test('OO-2: a truncated tab version offers neither plain Approve nor Always, and says the rest is not shown', async () => {
	const r = await review({ kind: 'file', b64: b64('{"tasks": []}\n'), truncated: true, size: 9_000_000 });
	assert.ok(!r.buttons.includes('Approve') && !r.buttons.includes('Always allow for this tab and path'), JSON.stringify(r.buttons));
	assert.ok(r.buttons.includes('Approve without seeing all of it'));
	assert.equal(r.buttons[0], 'Reject (keep the original)', 'Reject is the default button (OO-4)');
	assert.match(r.shown, /NOT SHOWN: the rest of this file/);
	assert.equal(r.decided, false, 'closing the dialog decides nothing');
	const full = await review({ kind: 'file', b64: b64('{"tasks": []}\n'), size: 14 });
	assert.ok(full.buttons.includes('Approve') && full.buttons.includes('Always allow for this tab and path'), 'control: a complete version offers both');
});

test('OO-2: non-UTF-8 content is shown escaped, byte by byte', async () => {
	const r = await review({ kind: 'file', b64: b64(Buffer.from([0x61, 0xff, 0x00, 0x62, 0x0a])), size: 5 });
	assert.match(r.shown, /a\\xff\\x00b/);
});

test('PP-1: blank runs and long lines cannot push a payload off-screen', async () => {
	const payload = `{"command": "safe"${' '.repeat(400)}, "args": ["HIDDEN-AFTER-BLANKS"]}`;
	const r = await review({ kind: 'file', b64: b64(payload), size: payload.length });
	assert.match(r.shown, /⟨400 blanks⟩/);
	assert.ok(r.shown.includes('HIDDEN-AFTER-BLANKS'), 'the payload after the blanks is on screen');
	const wide = `${'界'.repeat(100)}TAIL`;
	const w = await review({ kind: 'file', b64: b64(wide), size: Buffer.byteLength(wide) });
	for (const line of w.shown.split('\n')) {
		const cols = [...line].reduce((n, ch) => n + (/[\u4e00-\u9fff]/.test(ch) ? 2 : 1), 0);
		assert.ok(cols <= 80, `a line ${cols} columns wide: ${line}`);
	}
	assert.match(w.shown, /↪ .*TAIL/s, 'wide characters wrap by display width');
});
