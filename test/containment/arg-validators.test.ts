/**
 * The RPC filter's named argument validators.
 *
 * Run: node test/containment/arg-validators.test.ts   (or ./seclab test arg-validators)
 *
 * This imports the SHIPPED module, rpc-filter/patch-src/seclabArgValidators.ts, which has no
 * imports so that it can be tested directly rather than through a model. What it needs from the
 * workbench is injected; the fakes here stand in for those services only.
 *
 * Each validator is also proved by injection: the check that refuses the dangerous shape is
 * removed from a copy of the source, and the dangerous shape must then PASS. A suite whose
 * negative cases would still pass against a validator with the check deleted pins nothing.
 */

import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as shipped from '../../rpc-filter/patch-src/seclabArgValidators.ts';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SRC_PATH = join(REPO, 'rpc-filter', 'patch-src', 'seclabArgValidators.ts');
const SRC = readFileSync(SRC_PATH, 'utf8');
const TAB = 'seclab+t-aaaaaaaaaaaaaaaaaaaaaaaaaa';

type Mod = typeof shipped;
type Ctx = Parameters<Mod['seclabValidate']>[2];

/** A window as the filter would describe it. Overridable per test. */
function ctx(over: Partial<Ctx> = {}): Ctx {
	const context = new Map<string, unknown>([['editorTextFocus', true], ['someone.elses', 'x']]);
	return {
		authority: TAB,
		checkTabUri: (raw: unknown) => {
			const u = raw as { scheme?: unknown; authority?: unknown };
			if (u.scheme === 'untitled') {
				return undefined;
			}
			if (u.scheme !== 'vscode-remote') {
				return `scheme ${String(u.scheme)} is not reachable from a tab`;
			}
			return u.authority === TAB ? undefined : 'authority is not this tab';
		},
		isCommandRegistered: id => id === 'workbench.action.files.save' || id === 'already.registered',
		isTrustedCommandId: id => id.startsWith('workbench.') || id === 'simpleBrowser.show',
		commandDenyPrefixes: ['seclab.'],
		isCoreContextKey: key => key === 'editorTextFocus' || key === 'remoteName',
		contextKeyValue: key => context.get(key),
		contextValueFingerprint: v => JSON.stringify(v),
		tabContextKeys: new Map(),
		...over,
	};
}

const v = (m: Mod, name: string, args: unknown[], c: Ctx = ctx()) => m.seclabValidate(name, args, c);
const ok = (m: Mod, name: string, args: unknown[], c?: Ctx) => assert.equal(v(m, name, args, c), undefined, `${name} refused ${JSON.stringify(args)}`);
const no = (m: Mod, name: string, args: unknown[], c?: Ctx) => assert.notEqual(v(m, name, args, c), undefined, `${name} accepted ${JSON.stringify(args)}`);

const ERR = { $isError: true, name: 'Error', message: 'boom', stack: '' };
const EXT_ID = { value: 'seclab-test.benign-workspace', _lower: 'seclab-test.benign-workspace' };
const tabUri = (path = '/w/a.ts') => ({ $mid: 1, scheme: 'vscode-remote', authority: TAB, path });
const POS = { lineNumber: 1, column: 1 };

// The dangerous shape for each validator, and the source edit that removes the check refusing it.
interface Defect { name: string; validator: string; dangerous: unknown[]; ctx?: () => Ctx; from: string; to: string }
const DEFECTS: Defect[] = [
	{
		name: 'a missing-dependency report (install prompt)', validator: 'activationErrorNoInstallPrompt',
		dangerous: [EXT_ID, ERR, { dependency: 'evil.publisher-ext' }],
		from: 'if (args[2] !== null && args[2] !== undefined) {', to: 'if (false) {',
	},
	{
		name: 'registering a trusted command id before the trusted side does', validator: 'tabCommandRegistration',
		dangerous: ['workbench.action.lazilyRegistered'],
		from: 'if (ctx.isTrustedCommandId(id)) {', to: 'if (false) {',
	},
	{
		name: 'registering an id someone already registered', validator: 'tabCommandRegistration',
		dangerous: ['already.registered'],
		from: 'if (ctx.isCommandRegistered(id)) {', to: 'if (false) {',
	},
	{
		name: 'registering under the fork\'s reserved prefix', validator: 'tabCommandRegistration',
		dangerous: ['seclab.reviewChanges'],
		from: 'if (ctx.commandDenyPrefixes.some(p => id.startsWith(p))) {', to: 'if (false) {',
	},
	{
		name: 'a storage key that is not an extension id', validator: 'extensionStorageInit',
		dangerous: [true, 'extensionsIdentifiers/disabled'],
		from: "?? extensionId(args[1], 'argument 1');\n};\n\n/** `$setValue", to: ";\n};\n\n/** `$setValue",
	},
	{
		name: 'a host file URI for a provider command', validator: 'tabModelPosition',
		dangerous: [{ $mid: 1, scheme: 'file', path: '/seclab-canary/host-only-marker' }, POS],
		from: 'const reason = ctx.checkTabUri(uri);', to: 'const reason = undefined;',
	},
	{
		name: 'a core context key', validator: 'setContextKey',
		dangerous: ['remoteName', 'spoofed'],
		from: 'if (ctx.isCoreContextKey(key)) {', to: 'if (false) {',
	},
	{
		name: 'a context key someone else set', validator: 'setContextKey',
		dangerous: ['someone.elses', 'spoofed'],
		from: 'if (!mine) {', to: 'if (false) {',
	},
];

const tests: Array<[string, () => void | Promise<void>]> = [];
const test = (name: string, fn: () => void | Promise<void>) => tests.push([name, fn]);

// --- fail-closed dispatch -------------------------------------------------------------------
test('an unknown validator name denies', () => {
	assert.match(v(shipped, 'noSuchValidator', []) ?? '', /not implemented/);
});
test('a validator that throws denies, with the reason', () => {
	const c = ctx({ isCommandRegistered: () => { throw new Error('registry unavailable'); } });
	assert.match(v(shipped, 'tabCommandRegistration', ['my.cmd'], c) ?? '', /failed: registry unavailable/);
});
test('every validator rejects an empty argument list', () => {
	for (const name of shipped.SECLAB_VALIDATORS.keys()) {
		no(shipped, name, []);
	}
});

// --- $onExtensionActivationError ------------------------------------------------------------
test('activation error: the ordinary report passes, with null or absent dependency', () => {
	ok(shipped, 'activationErrorNoInstallPrompt', [EXT_ID, ERR, null]);
	ok(shipped, 'activationErrorNoInstallPrompt', [EXT_ID, ERR]);
});
test('activation error: any truthy or odd dependency value is refused', () => {
	for (const dep of [{ dependency: 'x.y' }, 'x.y', 1, true, [], {}, false, 0, '']) {
		no(shipped, 'activationErrorNoInstallPrompt', [EXT_ID, ERR, dep]);
	}
});
test('activation error: a non-identifier or non-error is refused', () => {
	no(shipped, 'activationErrorNoInstallPrompt', ['seclab-test.x', ERR, null]);
	no(shipped, 'activationErrorNoInstallPrompt', [EXT_ID, 'boom', null]);
	no(shipped, 'activationErrorNoInstallPrompt', [EXT_ID, ERR, null, 'extra']);
});

// --- $registerCommand -----------------------------------------------------------------------
test('register command: an extension\'s own id passes', () => {
	ok(shipped, 'tabCommandRegistration', ['seclab-test.benign.ping']);
	ok(shipped, 'tabCommandRegistration', ['git.commit']);
});
test('register command: reserved, trusted, registered and malformed ids are refused', () => {
	for (const id of ['seclab.openFolder', 'workbench.action.terminal.newLocal', 'simpleBrowser.show',
		'already.registered', '', 'has space', 'x'.repeat(257), 42, null]) {
		no(shipped, 'tabCommandRegistration', [id]);
	}
});

// --- storage ---------------------------------------------------------------------------------
test('storage: both scopes of an extension id pass, set needs an object', () => {
	ok(shipped, 'extensionStorageInit', [true, 'seclab-test.benign-workspace']);
	ok(shipped, 'extensionStorageInit', [false, 'vscode.git']);
	ok(shipped, 'extensionStorageSet', [true, 'vscode.git', { a: 1 }]);
});
test('storage: keys that are not extension ids, and non-object state, are refused', () => {
	// The shape check keeps the argument an extension id; an id-shaped key such as
	// `workbench.panel` passes it, and the per-tab partition (patch 0011) is what keeps that
	// key inside the tab's own `seclab-tab:<tabId>/` prefix.
	for (const key of ['extensionsIdentifiers/disabled', 'seclab-tab:t-x/vscode.git', 'a', '', 7]) {
		no(shipped, 'extensionStorageInit', [true, key]);
	}
	no(shipped, 'extensionStorageInit', ['true', 'vscode.git']);
	no(shipped, 'extensionStorageSet', [true, 'vscode.git', 'not-an-object']);
	no(shipped, 'extensionStorageSet', [true, 'vscode.git', [1]]);
});

// --- secrets ---------------------------------------------------------------------------------
test('secrets: bounded keys and values under an extension id pass', () => {
	ok(shipped, 'secretByKey', ['vscode.git', 'token']);
	ok(shipped, 'secretSet', ['vscode.git', 'token', 'seclabcanary_not_a_secret']);
	ok(shipped, 'secretKeys', ['vscode.git']);
});
test('secrets: odd shapes are refused', () => {
	no(shipped, 'secretByKey', ['not an id', 'k']);
	no(shipped, 'secretByKey', ['vscode.git', 'k'.repeat(1025)]);
	no(shipped, 'secretSet', ['vscode.git', 'k', { v: 1 }]);
	no(shipped, 'secretSet', ['vscode.git', 'k', 'v'.repeat(64 * 1024 + 1)]);
});

// --- provider commands -----------------------------------------------------------------------
test('provider commands: this tab\'s resource and a position pass', () => {
	ok(shipped, 'tabModelPosition', [tabUri(), POS]);
	ok(shipped, 'tabModelPosition', [tabUri(), POS, '.', 10]);
});
test('provider commands: host files, other tabs, unmarshalled URIs and bad positions are refused', () => {
	no(shipped, 'tabModelPosition', [{ $mid: 1, scheme: 'file', path: '/seclab-canary/host-only-marker' }, POS]);
	no(shipped, 'tabModelPosition', [{ $mid: 1, scheme: 'vscode-userdata', path: '/User/settings.json' }, POS]);
	no(shipped, 'tabModelPosition', [{ ...tabUri(), authority: 'seclab+t-bbbbbbbbbbbbbbbbbbbbbbbbbb' }, POS]);
	no(shipped, 'tabModelPosition', [{ scheme: 'vscode-remote', authority: TAB, path: '/w' }, POS]);
	no(shipped, 'tabModelPosition', [tabUri(), { lineNumber: 0, column: 1 }]);
	no(shipped, 'tabModelPosition', [tabUri(), POS, 'x'.repeat(17)]);
	no(shipped, 'tabModelPosition', [tabUri(), POS, '.', 1e9]);
});

// --- _setContext -----------------------------------------------------------------------------
test('setContext: an extension\'s own key with small values passes, and it may set it again', () => {
	const values = new Map<string, unknown>();
	const c = ctx({ contextKeyValue: k => values.get(k) });
	ok(shipped, 'setContextKey', ['myExt.active', true], c);
	values.set('myExt.active', true);
	ok(shipped, 'setContextKey', ['myExt.active', false], c);
	ok(shipped, 'setContextKey', ['myExt.files', [tabUri(), 'a', 1, null]], c);
	ok(shipped, 'setContextKey', ['myExt.map', { a: 1, b: 'x' }], c);
	ok(shipped, 'setContextKey', ['myExt.cleared'], c);
});
test('setContext: core, reserved, foreign-set, malformed keys and large or nested values are refused', () => {
	no(shipped, 'setContextKey', ['editorTextFocus', true]);
	no(shipped, 'setContextKey', ['remoteName', 'local']);
	no(shipped, 'setContextKey', ['seclab.tabs.active', true]);
	no(shipped, 'setContextKey', ['seclab:anything', true]);
	no(shipped, 'setContextKey', ['config.editor.fontSize', 1]);
	no(shipped, 'setContextKey', ['someone.elses', 'y']);
	no(shipped, 'setContextKey', ['has space', 1]);
	no(shipped, 'setContextKey', ['k', { nested: { deep: 1 } }]);
	no(shipped, 'setContextKey', ['k', 'x'.repeat(4097)]);
	no(shipped, 'setContextKey', ['k', new Array(1001).fill(1)]);
	no(shipped, 'setContextKey', ['k', [{ $mid: 1, scheme: 'file', path: '/x', evil: { deep: 1 } }]]);
});
test('setContext: a key the tab set, then someone else overwrote, is no longer the tab\'s', () => {
	const values = new Map<string, unknown>();
	const c = ctx({ contextKeyValue: k => values.get(k) });
	ok(shipped, 'setContextKey', ['raced.key', 'tab'], c);
	values.set('raced.key', 'trusted');
	no(shipped, 'setContextKey', ['raced.key', 'tab-again'], c);
});
test('setContext: with no context service the key reads as foreign, so a set key is refused', () => {
	const UNKNOWN = Object.freeze({});
	const c = ctx({ contextKeyValue: () => UNKNOWN, contextValueFingerprint: x => x === UNKNOWN ? 'unknown' : JSON.stringify(x) });
	no(shipped, 'setContextKey', ['myExt.active', true], c);
});

// --- injected defects ------------------------------------------------------------------------
const scratch = mkdtempSync(join(tmpdir(), 'seclab-argval-'));
let n = 0;
async function mutated(from: string, to: string): Promise<Mod> {
	const hits = SRC.split(from).length - 1;
	assert.equal(hits, 1, `defect anchor must occur exactly once in the shipped source (found ${hits}): ${from}`);
	const file = join(scratch, `mutant-${n++}.ts`);
	writeFileSync(file, SRC.replace(from, to));
	return await import(file) as Mod;
}
for (const d of DEFECTS) {
	test(`injected defect: removing the check admits ${d.name}`, async () => {
		const c = d.ctx ? d.ctx() : ctx();
		no(shipped, d.validator, d.dangerous, c);
		const m = await mutated(d.from, d.to);
		assert.equal(v(m, d.validator, d.dangerous, d.ctx ? d.ctx() : ctx()), undefined,
			'the mutant still refuses the dangerous shape, so this test would not notice the check being removed');
	});
}

let failed = 0;
for (const [name, fn] of tests) {
	try {
		await fn();
		console.log(`ok   ${name}`);
	} catch (err) {
		failed++;
		console.error(`FAIL ${name}\n     ${(err as Error).message}`);
	}
}
console.log(`\n${tests.length - failed}/${tests.length} passed`);
process.exit(failed ? 1 : 0);
