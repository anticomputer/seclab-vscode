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
		// Stands in for URI.revive plus the filter's canonical comparison: a URI carrying a
		// cached `external` or `fsPath` that disagrees with its components is not canonical.
		reviveUri: (raw: unknown) => {
			const u = raw as { scheme?: unknown; authority?: unknown; path?: unknown; external?: unknown; fsPath?: unknown };
			if (!u || typeof u !== 'object' || typeof u.scheme !== 'string') {
				return undefined;
			}
			const own = `${u.scheme}://${String(u.authority ?? '')}${String(u.path ?? '')}`;
			const canonical = (u.external === undefined || u.external === own) && (u.fsPath === undefined || u.fsPath === u.path);
			return { scheme: u.scheme, authority: String(u.authority ?? ''), canonical };
		},
		isCommandRegistered: id => id === 'workbench.action.files.save' || id === 'already.registered',
		isTrustedCommandId: id => id.startsWith('workbench.') || id === 'simpleBrowser.show',
		commandDenyPrefixes: ['seclab.'],
		isCoreContextKey: key => key === 'editorTextFocus' || key === 'remoteName',
		contextKeyValue: key => context.get(key),
		contextValueFingerprint: v => JSON.stringify(v),
		tabContextKeys: new Map(),
		tabRegisteredCommands: new Set(),
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
		from: 'const reason = checkTabUri(uri, ctx);', to: 'const reason = undefined;',
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
	{
		name: 'a URI whose cached fsPath points somewhere else', validator: 'tabModelPosition',
		dangerous: [{ $mid: 1, scheme: 'vscode-remote', authority: TAB, path: '/w/a.ts', fsPath: '/seclab-canary/host-only-marker' }, POS],
		from: "if (!u.canonical) {\n\t\treturn 'URI carries a cached form that is not its own';", to: "if (false) {\n\t\treturn 'URI carries a cached form that is not its own';",
	},
	{
		name: 'an untitled: URI where only the tab\'s file system is allowed', validator: 'tabDocumentOpen',
		dangerous: [{ $mid: 1, scheme: 'untitled', authority: TAB, path: '/Untitled-1' }],
		from: "if (u.scheme !== 'vscode-remote') {", to: "if (u.scheme !== 'vscode-remote' && u.scheme !== 'untitled') {",
	},
	{
		name: 'unregistering a command the tab never registered', validator: 'tabCommandUnregistration',
		dangerous: ['workbench.action.files.save'],
		from: "if (typeof id !== 'string' || !ctx.tabRegisteredCommands.has(id)) {", to: "if (typeof id !== 'string') {",
	},
	{
		name: 'opening a host file as a document', validator: 'tabDocumentOpen',
		dangerous: [{ $mid: 1, scheme: 'vscode-userdata', path: '/User/settings.json' }],
		from: "return tabUri(args[0], 'argument 0', ctx);\n};\n\nconst SHOW_OPTIONS", to: "return undefined;\n};\n\nconst SHOW_OPTIONS",
	},
	{
		name: 'showing a host file in an editor', validator: 'tabDocumentShow',
		dangerous: [{ $mid: 1, scheme: 'file', path: '/seclab-canary/host-only-marker' }, {}],
		from: "return tabUri(args[0], 'argument 0', ctx);\n};\n\n/**\n * `$ensureActivation", to: "return undefined;\n};\n\n/**\n * `$ensureActivation",
	},
	{
		name: 'activating a file system other than the tab\'s', validator: 'tabFileSystemActivation',
		dangerous: ['vscode-userdata'],
		from: "(args[0] === 'vscode-remote' || args[0] === 'file' ? undefined : 'only the tab\\'s own file system schemes')", to: 'undefined',
	},
	{
		name: 'a host path nested in file search options', validator: 'tabFileSearch',
		dangerous: [null, { extraFileResources: [{ $mid: 1, scheme: 'file', path: '/seclab-canary/host-only-marker' }] }],
		from: 'const r = tabUri(u, k, ctx);', to: 'const r = undefined;',
	},
	{
		name: 'an unknown file search option', validator: 'tabFileSearch',
		dangerous: [null, { someFutureUris: ['x'] }],
		from: 'if (!FILE_SEARCH_KEYS.has(k)) {', to: 'if (false) {',
	},
	{
		name: 'expandPatterns choosing host search roots', validator: 'tabFileSearch',
		dangerous: [null, { includePattern: '**/*', expandPatterns: true }],
		from: "if (k === 'expandPatterns' && v !== false) {", to: 'if (false) {',
	},
	{
		name: 'a notebook-type selector field', validator: 'tabHoverProvider',
		dangerous: [1, [{ $serialized: true, notebookType: 'jupyter-notebook' }]],
		from: "if (!['$serialized', 'scheme', 'language', 'pattern', 'exclusive', 'isBuiltin'].includes(key)) {", to: 'if (false) {',
	},
	{
		name: 'a non-boolean isBuiltin', validator: 'tabHoverProvider',
		dangerous: [1, [{ $serialized: true, isBuiltin: { not: 'a boolean' } }]],
		from: "if (f[key] !== undefined && typeof f[key] !== 'boolean') {", to: 'if (false) {',
	},
	{
		name: 'a non-string scheme', validator: 'tabHoverProvider',
		dangerous: [1, [{ $serialized: true, scheme: { not: 'a string' } }]],
		from: "if (f[key] !== undefined && (typeof f[key] !== 'string' || (f[key] as string).length > MAX_FILTER_STRING)) {", to: 'if (false) {',
	},
	{
		name: 'an absolute include pattern segment', validator: 'tabFileSearch',
		dangerous: [null, { includePattern: '/seclab-canary/**' }],
		from: "&& !s.split(',').some(seg => searchPathSegment(seg.trim()));", to: ';',
	},
	{
		name: 'a search provider for the host file system', validator: 'tabSearchProvider',
		dangerous: [1, 'file'],
		from: "(args[1] === 'vscode-remote' ? undefined : 'a tab serves search only for vscode-remote')", to: 'undefined',
	},
	{
		name: 'a text match naming a host file', validator: 'tabTextMatches',
		dangerous: [1, 1, [{ resource: { $mid: 1, scheme: 'file', path: '/seclab-canary/host-only-marker' }, results: [{ previewText: 'x' }] }]],
		from: 'const r = checkTabUri(item.resource, ctx);', to: 'const r = undefined;',
	},
	{
		name: 'a text match result whose own uri is a host file', validator: 'tabTextMatches',
		dangerous: [1, 1, [{ resource: { $mid: 1, scheme: 'vscode-remote', authority: TAB, path: '/w/a.ts' }, results: [{ uri: { $mid: 1, scheme: 'vscode-userdata', path: '/User/settings.json' }, previewText: 'x', rangeLocations: [] }] }]],
		from: 'const u = checkTabUri(res.uri, ctx);', to: 'const u = undefined;',
	},
	{
		// review SRCH-1(a): the consumer reads an item with results as a text match on its resource.
		name: 'a file result carrying results on a host resource', validator: 'tabFileMatches',
		dangerous: [1, 1, [{ ...tabUri(), results: [{ previewText: 'x' }], resource: { $mid: 1, scheme: 'file', path: '/seclab-canary/host-only-marker' } }]],
		from: 'if (item.results || !onlyKeys(item, URI_KEYS)) {', to: 'if (false) {',
	},
	{
		// review SRCH-1(b): without results the consumer revives the match object itself.
		name: 'a text match without results', validator: 'tabTextMatches',
		dangerous: [1, 1, [{ resource: tabUri() }]],
		from: 'if (!Array.isArray(item.results) || item.results.length === 0 || item.results.length > MAX_TEXT_MATCHES) {', to: 'if (false) {',
	},
	{
		name: 'a text match carrying URI fields beside its resource', validator: 'tabTextMatches',
		dangerous: [1, 1, [{ resource: tabUri(), results: [{ previewText: 'x' }], scheme: 'file', path: '/seclab-canary/host-only-marker' }]],
		from: 'if (!onlyKeys(item, TEXT_MATCH_KEYS)) {', to: 'if (false) {',
	},
	{
		// review SRCH2-1: revive() turns a result carrying `$mid` into that type (here a host URI).
		name: 'a text result that revives as a host URI', validator: 'tabTextMatches',
		dangerous: [1, 1, [{ resource: tabUri(), results: [{ $mid: 1, scheme: 'file', path: '/seclab-canary/host-only-marker', previewText: 'x', rangeLocations: [] }] }]],
		from: 'if (!isPlainObject(res) || !onlyKeys(res, TEXT_RESULT_KEYS)) {', to: 'if (!isPlainObject(res)) {',
	},
	{
		name: 'a match resource that revives as another type', validator: 'tabTextMatches',
		dangerous: [1, 1, [{ resource: { ...tabUri(), $mid: 2, source: '.*', flags: '' }, results: [{ previewText: 'x' }] }]],
		from: 'if (!plainUri(item.resource)) {', to: 'if (false) {',
	},
	{
		// review SRCH-4: untitled buffers aren't the tab's file system.
		name: 'an untitled file result', validator: 'tabFileMatches',
		dangerous: [1, 1, [{ $mid: 1, scheme: 'untitled', path: 'Untitled-1' }]],
		from: 'const r = checkTabUri(item, ctx);', to: 'const r = undefined;',
	},
];

const tests: Array<[string, () => void | Promise<void>]> = [];
const test = (name: string, fn: () => void | Promise<void>) => tests.push([name, fn]);

// --- fail-closed dispatch -------------------------------------------------------------------
test('tab providers and search: the legitimate shapes pass', () => {
	ok(shipped, 'tabHoverProvider', [1, [{ $serialized: true, language: 'plaintext' }]]);
	ok(shipped, 'tabHoverProvider', [1, [{ $serialized: true, scheme: 'vscode-remote', language: 'typescript', pattern: '**/*.ts' }]]);
	ok(shipped, 'tabCompletionProvider', [1, [{ $serialized: true, language: 'plaintext' }], ['@', '#'], true, EXT_ID]);
	no(shipped, 'tabCompletionProvider', [1, [{ $serialized: true, language: 'plaintext' }], ['@@'], true, EXT_ID]);
	no(shipped, 'tabHoverProvider', [1, []]);
	ok(shipped, 'tabSearchProvider', [3, 'vscode-remote']);
	no(shipped, 'tabSearchProvider', [3, 'vscode-userdata']);
	ok(shipped, 'tabTextMatches', [1, 2, [{ resource: tabUri(), results: [{ previewText: 'x', rangeLocations: [] }, { uri: tabUri('/w/b.ts'), text: 'ctx', lineNumber: 1 }] }]]);
	no(shipped, 'tabTextMatches', [1, 2, [{ resource: tabUri(), results: [{ previewText: 'x'.repeat(70 * 1024) }] }]]);
	ok(shipped, 'tabFileMatches', [1, 2, [tabUri(), { ...tabUri('/w/b.ts'), fsPath: '/w/b.ts', _sep: 1, external: `vscode-remote://${TAB}/w/b.ts` }]]);
	no(shipped, 'tabFileMatches', [1, 2, Array.from({ length: 10001 }, () => tabUri())]);
	no(shipped, 'tabFileMatches', [1, 2, [{ ...tabUri(), authority: 'seclab+other' }]]);
});

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
	// `workbench.panel` passes it, and the per-tab partition (patch 0032) is what keeps that
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
	no(shipped, 'tabModelPosition', [{ ...tabUri(), fsPath: '/Users/someone/.config/x' }, POS]);
	no(shipped, 'tabModelPosition', [{ ...tabUri(), external: 'file:///seclab-canary/host-only-marker' }, POS]);
	no(shipped, 'tabModelPosition', [{ $mid: 1, scheme: 'untitled', path: '/Untitled-1' }, POS]);
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

// --- core editing set ------------------------------------------------------------------------
test('unregister command: only an id this tab registered, once', () => {
	const c = ctx();
	no(shipped, 'tabCommandUnregistration', ['my.cmd'], c);
	ok(shipped, 'tabCommandRegistration', ['my.cmd'], c);
	ok(shipped, 'tabCommandUnregistration', ['my.cmd'], c);
	no(shipped, 'tabCommandUnregistration', ['my.cmd'], c);
	no(shipped, 'tabCommandUnregistration', ['seclab.openFolder'], c);
});
test('open document: this tab\'s resource passes; host, userdata, untitled and other tabs are refused', () => {
	ok(shipped, 'tabDocumentOpen', [tabUri()]);
	ok(shipped, 'tabDocumentOpen', [tabUri(), { encoding: 'utf8' }]);
	no(shipped, 'tabDocumentOpen', [{ $mid: 1, scheme: 'file', path: '/seclab-canary/host-only-marker' }]);
	no(shipped, 'tabDocumentOpen', [{ $mid: 1, scheme: 'vscode-userdata', path: '/User/settings.json' }]);
	no(shipped, 'tabDocumentOpen', [{ $mid: 1, scheme: 'untitled', path: '/seclab-canary/x' }]);
	no(shipped, 'tabDocumentOpen', [{ ...tabUri(), authority: 'seclab+t-bbbbbbbbbbbbbbbbbbbbbbbbbb' }]);
	no(shipped, 'tabDocumentOpen', [tabUri(), { encoding: 7 }]);
	no(shipped, 'tabDocumentOpen', [tabUri(), 'utf8']);
});
test('open document: openTextDocument(uri) sends the URI itself as options, and it passes', () => {
	// extHost.api.impl.ts: `options = options ?? uriOrFileNameOrOptions` (measured on the
	// patched build 2026-11-09: refused, so no extension could open a document).
	ok(shipped, 'tabDocumentOpen', [tabUri(), tabUri()]);
	ok(shipped, 'tabDocumentOpen', [tabUri(), { encoding: 'utf8', other: 1 }]);
});
test('show document: this tab\'s resource with known options passes; odd options and host files are refused', () => {
	ok(shipped, 'tabDocumentShow', [tabUri(), { preserveFocus: true, pinned: false, position: 1 }]);
	ok(shipped, 'tabDocumentShow', [tabUri(), { selection: { startLineNumber: 1, startColumn: 1, endLineNumber: 1, endColumn: 2 } }]);
	no(shipped, 'tabDocumentShow', [tabUri(), { preserveFocus: 'no' }]);
	no(shipped, 'tabDocumentShow', [tabUri(), { revealIfOpen: true }]);
	no(shipped, 'tabDocumentShow', [{ $mid: 1, scheme: 'file', path: '/x' }, {}]);
});
test('fs activation: the tab\'s own schemes only (file is what a remote extension host sends)', () => {
	// Measured on the patched build 2026-11-09: every workspace.fs call sends 'file' first.
	ok(shipped, 'tabFileSystemActivation', ['vscode-remote']);
	ok(shipped, 'tabFileSystemActivation', ['file']);
	for (const s of ['vscode-userdata', 'git', 'onFileSystem:x', '', 1, 'File']) {
		no(shipped, 'tabFileSystemActivation', [s]);
	}
});
test('file search: workspace-wide and tab-folder searches pass; nested host URIs and unknown options are refused', () => {
	ok(shipped, 'tabFileSearch', [null, { _reason: 'startFileSearch', includePattern: '**/*', maxResults: 5, excludePattern: [{ pattern: '**/node_modules' }] }]);
	ok(shipped, 'tabFileSearch', [null, { includePattern: 'src/**/*.ts', expandPatterns: false }]);
	ok(shipped, 'tabFileSearch', [tabUri('/w'), { filePattern: 'a', sortByScore: true, extraFileResources: [tabUri()] }]);
	no(shipped, 'tabFileSearch', [{ $mid: 1, scheme: 'file', path: '/Users' }, {}]);
	no(shipped, 'tabFileSearch', [null, { changedFileUris: [{ $mid: 1, scheme: 'file', path: '/x' }] }]);
	no(shipped, 'tabFileSearch', [null, { excludePattern: [{ pattern: 'x', uri: { $mid: 1, scheme: 'vscode-userdata', path: '/' } }] }]);
	no(shipped, 'tabFileSearch', [null, { maxResults: -1 }]);
	no(shipped, 'tabFileSearch', [null, { includePattern: { evil: true } }]);
	no(shipped, 'tabFileSearch', [null, 'options']);
});
test('file search: a pattern may not choose the search roots (round 10 finding 1)', () => {
	// With expandPatterns, QueryBuilder derives the roots from the include pattern and ignores
	// argument 0; in a window without a folder those are host paths.
	no(shipped, 'tabFileSearch', [null, { includePattern: '/seclab-canary/**', expandPatterns: true }]);
	no(shipped, 'tabFileSearch', [tabUri('/w'), { includePattern: '**/*', expandPatterns: true }]);
	no(shipped, 'tabFileSearch', [null, { expandPatterns: 1 }]);
	// The segments parseSearchPaths would make roots are refused even without expandPatterns.
	for (const p of ['/seclab-canary/**', '~/x/**', './a', '../b', 'C:/x', '\\\\server\\share', 'src/**,/etc/**', ['ok/**', '../up']]) {
		no(shipped, 'tabFileSearch', [null, { includePattern: p }]);
	}
	no(shipped, 'tabFileSearch', [null, { excludePattern: [{ pattern: '/seclab-canary' }] }]);
});

const SEL = (f: Record<string, unknown> = {}) => [{ $serialized: true, ...f }];
const COMPLETION = (selector: unknown) => [1, selector, ['.'], true, EXT_ID];
test('provider selectors: a bundled provider\'s real selector passes, for hover and completion (review on #48)', () => {
	// DocumentSelector.from as the typescript-language-features extension sends it from a REH:
	// file mapped to vscode-remote, the other semantic schemes as they are, isBuiltin from the
	// extension. Patch 0033 drops the filters for other schemes (seclabFromTab(...).selector).
	const ts = [
		{ $serialized: true, language: 'typescript', scheme: 'vscode-remote', isBuiltin: true },
		{ $serialized: true, language: 'typescript', scheme: 'untitled', isBuiltin: true },
		{ $serialized: true, language: 'typescript', scheme: 'vscode-notebook-cell', isBuiltin: true },
		{ $serialized: true, language: 'typescript', isBuiltin: true },
	];
	for (const selector of [ts, SEL(), SEL({ scheme: 'vscode-remote', pattern: '**/*.ts', exclusive: false, isBuiltin: false })]) {
		ok(shipped, 'tabHoverProvider', [1, selector]);
		ok(shipped, 'tabCompletionProvider', COMPLETION(selector));
	}
});
test('provider selectors: notebook types, RelativePatterns, odd values and non-filters are refused, for hover and completion', () => {
	const bad: unknown[] = [
		SEL({ notebookType: 'jupyter-notebook' }), SEL({ pattern: { base: '/Users', pattern: '**' } }), SEL({ scheme: { evil: 1 } }),
		SEL({ isBuiltin: 'yes' }), SEL({ language: 'x'.repeat(10000) }), SEL({ scheme: 'x'.repeat(10000) }), SEL({ exclusive: 'yes' }),
		SEL({ unknownKey: 1 }), [{ scheme: 'vscode-remote' }], [], 'typescript', [SEL()[0], { $serialized: true, notebookType: 'x' }],
	];
	for (const selector of bad) {
		no(shipped, 'tabHoverProvider', [1, selector]);
		no(shipped, 'tabCompletionProvider', COMPLETION(selector));
	}
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
