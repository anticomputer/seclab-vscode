// Patch 0060 (review SRCH-3; project owner, 2026-11-18): the host user's exclude and watcher
// patterns never reach a sandboxed tab. Three paths carried them:
//   - every search query sent to the tab's search provider (RemoteSearchProvider.doSearch, where
//     all queries meet, QueryBuilder's and hand-built ones alike);
//   - the watch requests the window sends the tab for its workspace (WorkspaceWatcher);
//   - the configuration snapshot the tab's extension host receives (patch 0036), which let a
//     core structure with only boolean leaves cross from the host user's settings.
// The suite runs upstream's own code for each, with the series' earlier patches and whatever
// 0060 this tree has, against host canary patterns. On a tree without 0060 (main before it) all
// three carry the host's patterns, and the tab case fails. Each mutant of 0060 must bring its
// leak back.
//
//   ./seclab test search-excludes   (SECLAB_UPSTREAM_SRC = the pinned src/vs, read-only)

import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SRC = process.env.SECLAB_UPSTREAM_SRC;
if (!SRC) {
	console.error('search-excludes: set SECLAB_UPSTREAM_SRC to the pinned src/vs (./seclab test search-excludes does)');
	process.exit(1);
}
const patchFile = (name: string) => {
	const p = join(REPO, 'patches', name);
	return existsSync(p) ? readFileSync(p, 'utf8') : '';
};
const P0036 = patchFile('0036-seclab-tab-configuration-snapshot.patch');
const P0051 = patchFile('0051-seclab-sanitise-tab-search-responses.patch');
const P0060 = patchFile('0060-seclab-no-host-search-excludes-in-tabs.patch');
assert.ok(P0036, '0036 is on every tree this suite runs on');

const SEARCH = 'workbench/api/browser/mainThreadSearch.ts';
const WATCHER = 'workbench/contrib/files/browser/workspaceWatcher.ts';
const SNAPSHOT = 'workbench/api/browser/seclabConfigurationSnapshot.ts';
const SETTINGS = 'workbench/services/configuration/common/seclabTabSettings.ts';

/** One file's section of a `diff -ruN` patch. */
const section = (patch: string, rel: string) => patch.split(/^(?=diff -ruN )/m).find(p => p.split('\n')[0].includes(`/src/vs/${rel} `));

/** Apply one file's hunks, each exactly once. */
function apply(source: string, patch: string, rel: string): string {
	const sec = section(patch, rel);
	if (!sec) {
		return source;
	}
	let out = source;
	for (const hunk of sec.split(/\n(?=@@ )/).slice(1)) {
		const lines = hunk.split('\n').slice(1).filter(l => l.length > 0 && l[0] !== '\\');
		const old = lines.filter(l => l[0] === ' ' || l[0] === '-').map(l => l.slice(1)).join('\n');
		const neu = lines.filter(l => l[0] === ' ' || l[0] === '+').map(l => l.slice(1)).join('\n');
		assert.equal(out.split(old).length - 1, 1, `a hunk no longer applies to ${rel}`);
		out = out.replace(old, () => neu);
	}
	return out;
}

/** A new file a patch creates (its one hunk starts at -0,0), or undefined. */
const created = (patch: string, rel: string) => section(patch, rel)?.includes('\n@@ -0,0 ') ? section(patch, rel)!.split('\n').filter(l => l.startsWith('+') && !l.startsWith('+++')).map(l => l.slice(1)).join('\n') : undefined;

/** The method or function at `head`, brace-matched. */
function slice(source: string, head: RegExp): string | undefined {
	const m = head.exec(source);
	if (!m) {
		return undefined;
	}
	let i = m.index + m[0].length;
	for (let depth = 1; depth > 0; i++) {
		depth += source[i] === '(' ? 1 : source[i] === ')' ? -1 : 0;
	}
	let j = source.indexOf('{', i) + 1;
	for (let depth = 1; depth > 0; j++) {
		depth += source[j] === '{' ? 1 : source[j] === '}' ? -1 : 0;
	}
	return source.slice(m.index, j).trim();
}
const asFunction = (m: string) => m.startsWith('function ') ? m : m.replace(/^(?:(?:private|protected|public|static) )*/, 'function ');
/** A module's code with its imports and `export`s removed, to evaluate in a scope of stubs. */
const moduleBody = (src: string) => src.replace(/^import .*$/mg, '').replace(/^export /mg, '');
function evaluate<T>(code: string, result: string, deps: Record<string, unknown>): T {
	const js = stripTypeScriptTypes(`(function () {\n${code}\nreturn ${result};\n})`, { mode: 'transform' }).trim().replace(/;$/, '');
	return new Function(...Object.keys(deps), `return ${js}();`)(...Object.values(deps));
}

const TAB = 'seclab+tab1';
const tab = (path: string) => ({ scheme: 'vscode-remote', authority: TAB, path });
const HOST_FILES = '**/seclabcanary_hx1.txt';
const HOST_SEARCH = '**/seclabcanary_hs1.txt';
const HOST_WATCH = '**/seclabcanary_hw1';
const HOST_INCLUDE = 'seclabcanary_hi1';
const HOST_WS = '**/seclabcanary_hws1';
type Layers = Record<string, unknown>;
const LAYERS: Record<string, Layers> = {
	'files.exclude': { defaultValue: { '**/.git': true }, userLocalValue: { [HOST_FILES]: true, '**/.git': false }, userRemoteValue: { '**/remote-files': true }, workspaceValue: { '**/ws-files': true, [HOST_WS]: true }, workspaceFolderValue: { '**/folder-files': true } },
	'search.exclude': { defaultValue: { '**/node_modules': true }, userLocalValue: { [HOST_SEARCH]: true }, policyValue: { '**/policy-search': true }, workspaceFolderValue: {} },
	'files.watcherExclude': { defaultValue: { '**/.git/objects/**': true }, userLocalValue: { [HOST_WATCH]: true }, workspaceFolderValue: { '**/folder-watch': true } },
	'files.watcherInclude': { defaultValue: [], userLocalValue: [HOST_INCLUDE], workspaceFolderValue: ['own-include'] },
};
const merged = (key: string) => {
	const l = LAYERS[key];
	const vs = ['defaultValue', 'applicationValue', 'userLocalValue', 'userRemoteValue', 'workspaceValue', 'workspaceFolderValue', 'policyValue', 'memoryValue'].map(k => l[k]).filter(v => v !== undefined);
	return vs.every(v => !Array.isArray(v)) ? Object.assign({}, ...vs) : vs[vs.length - 1];
};
/** `wsFile`: where the workspace's own settings file is (a `.code-workspace`), or undefined for a folder. */
const services = (wsFile?: { scheme: string; authority: string; path: string }) => ({
	configurationService: {
		inspect: (key: string) => LAYERS[key] ?? {},
		getValue: () => ({ files: { exclude: merged('files.exclude'), watcherExclude: merged('files.watcherExclude'), watcherInclude: merged('files.watcherInclude') } }),
	},
	contextService: { getWorkspace: () => ({ configuration: wsFile }) },
});

/** The series' code for `rel` with `patch` as this tree's 0060: earlier patches, then 0060. */
function source(rel: string, patch: string): string | undefined {
	const made = created(P0036, rel) ?? created(patch, rel);
	const base = made ?? (existsSync(join(SRC!, rel)) ? readFileSync(join(SRC!, rel), 'utf8') : undefined);
	return base === undefined ? undefined : made && created(patch, rel) ? base : apply(rel === SEARCH ? apply(base, P0051, rel) : base, patch, rel);
}

/** The helper module 0060 adds, evaluated with `svc`'s services, or undefined on a tree without it. */
function helpers(patch: string): Record<string, (...a: unknown[]) => unknown> | undefined {
	const src = source(SETTINGS, patch);
	return src === undefined ? undefined : evaluate(moduleBody(src), '{ seclabOnTab, seclabTabOwnValue, seclabWithoutHostExcludes }',
		{ Schemas: { vscodeRemote: 'vscode-remote' }, seclabIsTabAuthority: (a: string) => /^seclab\+/.test(a) });
}

/** The query a tab's search provider is sent for `query`, through RemoteSearchProvider.doSearch. */
async function sentQuery(patch: string, query: Record<string, unknown>, wsFile?: { scheme: string; authority: string; path: string }): Promise<Record<string, unknown>> {
	const src = source(SEARCH, patch)!;
	const h = helpers(patch);
	const svc = services(wsFile);
	// The window's MainThreadSearch builds what RemoteSearchProvider gets: on a tree with 0060, its
	// `excludes`, evaluated from the constructor's own text.
	const seclab: Record<string, unknown> = { authority: TAB, fromTab: { searchMessages: (m: unknown) => m } };
	const built = /\n(\t\tconst strip = [\s\S]*?\n\t\t\}\);)\n/.exec(src);
	if (built && h) {
		seclab.excludes = evaluate(built[1], 'excludes', { _configurationService: svc.configurationService, seclabContextService: svc.contextService, seclabWithoutHostExcludes: h.seclabWithoutHostExcludes });
	}
	let sent: Record<string, unknown> = {};
	const doSearch = evaluate<(...a: unknown[]) => Promise<unknown>>(asFunction(slice(src, /\n\tdoSearch\(/)!), 'doSearch', {
		CancellationToken: { None: {} },
		SearchOperation: class { id = 1; matches = new Map(); keywords = []; },
	});
	await doSearch.call({ _seclab: seclab, _searches: new Map(), _provideSearchResults: (q: Record<string, unknown>) => { sent = q; return Promise.resolve({}); } }, query);
	return sent;
}

/** What the window asks the tab to watch for its workspace folder, through WorkspaceWatcher.watchWorkspace. */
function watched(patch: string): Array<{ path: string; excludes: string[] }> {
	const src = source(WATCHER, patch)!;
	const h = helpers(patch);
	const svc = services();
	const out: Array<{ path: string; excludes: string[] }> = [];
	const uri = (u: { scheme: string; authority: string; path: string }) => ({ ...u, with: (c: object) => uri({ ...u, ...c }) });
	const folder = { uri: uri(tab('/work/ws')), toResource: (p: string) => uri(tab(`/work/ws/${p}`)) };
	const fn = evaluate<(...a: unknown[]) => void>(asFunction(slice(src, /\n\tprivate watchWorkspace\(/)!), 'watchWorkspace', {
		ResourceMap: class extends Map<unknown, unknown> { constructor(_key?: unknown) { super(); } override set(k: { path: string }, v: unknown) { return super.set(k.path, v); } },
		DisposableStore: class { add() { } },
		URI: { file: (p: string) => uri({ scheme: 'file', authority: '', path: p }) },
		isAbsolute: (p: string) => p.startsWith('/'),
		seclabOnTab: h?.seclabOnTab, seclabTabOwnValue: h?.seclabTabOwnValue,
	});
	fn.call({
		configurationService: svc.configurationService, contextService: svc.contextService,
		uriIdentityService: { extUri: { isEqualOrParent: (a: { path: string }, b: { path: string }) => (a.path + '/').startsWith(b.path + '/') } },
		fileService: { watch: (u: { path: string }, o: { excludes: string[] }) => { out.push({ path: u.path, excludes: o.excludes }); return {}; } },
		watchedWorkspaces: new Map(),
	}, folder);
	return out;
}

/** The keys the tab's extension host receives from a layer, through 0036's filter with `patch` as this tree's 0060. */
function snapshotKeys(patch: string, contents: Record<string, unknown>, hostValues: boolean): string[] {
	const registry = Object.fromEntries([...Object.keys(LAYERS), 'editor.tabSize'].map(k => [k, { scope: 5 }]));
	const filter = evaluate<(...a: unknown[]) => { keys: string[] }>(moduleBody(source(SNAPSHOT, patch)!), 'filterContents', {
		Registry: { as: () => ({ getConfigurationProperties: () => registry }) },
		Extensions: { Configuration: 'configuration' },
		ConfigurationScope: { APPLICATION: 1, MACHINE: 2, APPLICATION_MACHINE: 3, WINDOW: 4, RESOURCE: 5, LANGUAGE_OVERRIDABLE: 6, MACHINE_OVERRIDABLE: 7 },
		OVERRIDE_PROPERTY_REGEX: /^\[.*\]$/,
		getConfigurationValue: (c: Record<string, unknown>, k: string) => c[k],
		addToValueTree: (o: Record<string, unknown>, k: string, v: unknown) => { o[k] = v; },
		withholdReason: () => undefined,
	});
	return filter(contents, Object.keys(contents), { tabExtensions: new Set(), workspaceInTab: true, windowAuthority: TAB }, hostValues, [], []).keys.sort();
}

const CANARIES = [HOST_FILES, HOST_SEARCH, HOST_WATCH, HOST_INCLUDE, HOST_WS];
const QUERY = () => ({
	folderQueries: [{ folder: tab('/work/ws'), excludePattern: [{ pattern: { ...merged('files.exclude'), ...merged('search.exclude'), '**/typed': true } }] }],
	excludePattern: { [HOST_FILES]: true, '**/typed-top': true },
});
const HOST_LAYER = { 'files.exclude': { [HOST_FILES]: true }, 'search.exclude': { [HOST_SEARCH]: true }, 'files.watcherExclude': { [HOST_WATCH]: true }, 'editor.tabSize': 4 };
const OUTSIDE = { scheme: 'file', authority: '', path: '/Users/someone/w.code-workspace' };

/** What reaches the tab of the host's patterns, on a tree with `patch` as its 0060. */
async function leaks(patch: string): Promise<string[]> {
	const out: string[] = [];
	const has = (v: unknown, c = CANARIES) => c.some(x => JSON.stringify(v).includes(x));
	if (has(await sentQuery(patch, QUERY()), [HOST_FILES, HOST_SEARCH])) {
		out.push('a search query sent to the tab carries the host user\'s excludes');
	}
	if (has(await sentQuery(patch, QUERY(), OUTSIDE), [HOST_WS])) {
		out.push('a search query sent to the tab carries a workspace file\'s excludes from outside the tab');
	}
	if (has(watched(patch), [HOST_WATCH, HOST_INCLUDE])) {
		out.push('a watch request sent to the tab carries the host user\'s watcher patterns');
	}
	const s = snapshotKeys(patch, HOST_LAYER, true);
	if (Object.keys(HOST_LAYER).some(k => k !== 'editor.tabSize' && s.includes(k))) {
		out.push('the tab\'s extension host receives the host user\'s excludes');
	}
	return out;
}

const cases: Array<[string, () => Promise<void> | void]> = [
	['the baseline sends the host user\'s patterns to the tab every way', async () => {
		assert.deepEqual(await leaks(''), [
			'a search query sent to the tab carries the host user\'s excludes',
			'a search query sent to the tab carries a workspace file\'s excludes from outside the tab',
			'a watch request sent to the tab carries the host user\'s watcher patterns',
			'the tab\'s extension host receives the host user\'s excludes',
		]);
	}],
	['a tab gets none of the host user\'s patterns and keeps its own', async () => {
		// On a tree without 0060 this reports every leak.
		assert.deepEqual(await leaks(P0060), []);
		// Defaults, the tab's own layers and what the user typed stay; a default the host turned off
		// takes the default's value; the workspace file on the tab counts as the tab's.
		const q = await sentQuery(P0060, QUERY()) as { excludePattern: Record<string, unknown>; folderQueries: Array<{ excludePattern: Array<{ pattern: Record<string, unknown> }> }> };
		// (A single folder's workspace settings are the folder's own, on the tab, so HOST_WS stays here.)
		assert.deepEqual(q.folderQueries[0].excludePattern[0].pattern, { '**/.git': true, '**/remote-files': true, '**/ws-files': true, [HOST_WS]: true, '**/folder-files': true, '**/node_modules': true, '**/typed': true });
		assert.deepEqual(q.excludePattern, { '**/typed-top': true });
		const inTab = await sentQuery(P0060, QUERY(), tab('/work/w.code-workspace')) as { folderQueries: Array<{ excludePattern: Array<{ pattern: Record<string, unknown> }> }> };
		assert.ok(Object.hasOwn(inTab.folderQueries[0].excludePattern[0].pattern, HOST_WS));
		assert.deepEqual(watched(P0060), [{ path: '/work/ws', excludes: ['**/.git/objects/**', '**/folder-watch'] }, { path: '/work/ws/own-include', excludes: ['**/.git/objects/**', '**/folder-watch'] }]);
		assert.deepEqual(snapshotKeys(P0060, HOST_LAYER, false), ['editor.tabSize', 'files.exclude', 'files.watcherExclude', 'search.exclude']);
		assert.deepEqual(snapshotKeys(P0060, HOST_LAYER, true), ['editor.tabSize']);
	}],
	['a window that is not a tab\'s keeps upstream\'s queries', async () => {
		const src = source(SEARCH, P0060)!;
		assert.ok(/const fromTab = seclabFromTab\(/.test(src) && /this\._seclab = fromTab \?/.test(src), 'only a tab window gets the excludes step');
		let sent: unknown;
		const doSearch = evaluate<(...a: unknown[]) => Promise<unknown>>(asFunction(slice(src, /\n\tdoSearch\(/)!), 'doSearch', { CancellationToken: { None: {} }, SearchOperation: class { id = 1; matches = new Map(); keywords = []; } });
		await doSearch.call({ _seclab: undefined, _searches: new Map(), _provideSearchResults: (q: unknown) => { sent = q; return Promise.resolve({}); } }, QUERY());
		assert.deepEqual(sent, QUERY());
		const h = helpers(P0060)!;
		assert.equal(h.seclabOnTab({ scheme: 'file', authority: '', path: '/w' }), false);
		assert.equal(h.seclabOnTab({ scheme: 'vscode-remote', authority: 'ssh-remote+box', path: '/w' }), false);
	}],
	['each mutant of 0060 brings its leak back', async () => {
		const mutants: Array<[string, string, string, string]> = [
			['doSearch skips the excludes', '+			query = seclab.excludes(query);', '+			void seclab;', 'a search query sent to the tab carries the host user\'s excludes'],
			['host layers ignored', '+			l.host.filter(isRecord).forEach(v => Object.keys(v).forEach(k => host.add(k)));', '+			void l.host;', 'a search query sent to the tab carries the host user\'s excludes'],
			['folder excludes kept', '+			folderQueries: query.folderQueries.map(f => ({ ...f, excludePattern: f.excludePattern?.map(e => ({ ...e, pattern: strip(e.pattern, [f.folder]) })) })),', '+			folderQueries: query.folderQueries,', 'a search query sent to the tab carries the host user\'s excludes'],
			['any workspace file is the tab\'s', '+	const wsOnTab = !ws || (ws.scheme === resource.scheme && ws.authority.toLowerCase() === resource.authority.toLowerCase());', '+	const wsOnTab = true;', 'a search query sent to the tab carries a workspace file\'s excludes from outside the tab'],
			['watcher reads the merged settings', '+		if (seclabOnTab(workspace.uri) && config.files) {', '+		if (false) {', 'a watch request sent to the tab carries the host user\'s watcher patterns'],
			['snapshot lets the keys cross', ' || SECLAB_HOST_ONLY_KEYS.has(key)', '', 'the tab\'s extension host receives the host user\'s excludes'],
		];
		for (const [name, from, to, leak] of mutants) {
			assert.equal(P0060.split(from).length - 1, 1, `mutant ${name}: its text occurs once in 0060`);
			// A mutant must bring its leak back, not merely break the build under test.
			const found = await leaks(P0060.replace(from, to));
			assert.ok(found.includes(leak), `mutant not caught (${name}): found ${JSON.stringify(found)}`);
		}
	}],
];

let failed = 0;
for (const [name, fn] of cases) {
	try {
		await fn();
		console.log(`ok   ${name}`);
	} catch (e) {
		failed++;
		console.log(`FAIL ${name}\n     ${String((e as Error).message).split('\n').join('\n     ')}`);
	}
}
console.log(failed ? `${failed} failed` : `${cases.length} passed`);
process.exit(failed ? 1 : 0);
