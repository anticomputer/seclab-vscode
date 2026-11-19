// Patch 0060 (review SRCH-3; project owner, 2026-11-18): the host user's exclude and watcher
// patterns never reach a sandboxed tab. They reached it three ways:
//   - in search queries, wherever the window builds the settings part of one: QueryBuilder's folder
//     queries, and the queries features build by hand (explorer find, the chat file picker,
//     prompt-file discovery);
//   - in the watch requests the window sends the tab for its workspace (WorkspaceWatcher);
//   - in the configuration snapshot the tab's extension host receives (patch 0036), which let a
//     core structure with only boolean leaves cross from the host user's settings.
// Patterns a caller passes are never touched, so a query says nothing about the host's settings
// (review SRCH3-4). The suite runs upstream's own code for each path, with this tree's 0060,
// against host canary patterns, and checks that every call building a query's excludes from
// settings goes through 0060's helper. On a tree without 0060 (main before it) every path
// carries the host's patterns, and the tab case fails. Each mutant of 0060 must bring its leak back.
//
//   ./seclab test search-excludes   (SECLAB_UPSTREAM_SRC = the pinned src/vs, read-only)

import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
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
const QUERY_BUILDER = 'workbench/services/search/common/queryBuilder.ts';
const CHAT_CONTEXT = 'workbench/contrib/search/browser/searchChatContext.ts';
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
const asFunction = (m: string) => m.startsWith('function ') ? m : m.replace(/^(?:(?:private|protected|public|static) )*(async )?/, '$1function ');
/** A module's code with its imports and `export`s removed, to evaluate in a scope of stubs. */
const moduleBody = (src: string) => src.replace(/^import .*$/mg, '').replace(/^export /mg, '');
function evaluate<T>(code: string, result: string, deps: Record<string, unknown>): T {
	const js = stripTypeScriptTypes(`(function () {\n${code}\nreturn ${result};\n})`, { mode: 'transform' }).trim().replace(/;$/, '');
	return new Function(...Object.keys(deps), `return ${js}();`)(...Object.values(deps));
}

// The filter module's own tab test, from this tree (it compares case-insensitively since round 4).
const SECLAB_AUTHORITY = new Function(`return ${/\nconst SECLAB_AUTHORITY = (\/.*\/\w*);/.exec(readFileSync(join(REPO, 'rpc-filter', 'patch-src', 'seclabRpcFilter.ts'), 'utf8'))![1]};`)() as RegExp;
const seclabIsTabAuthority = (a: string) => typeof a === 'string' && SECLAB_AUTHORITY.test(a);
const TAB = 'seclab+tab1';
const tab = (path: string) => ({ scheme: 'vscode-remote', authority: TAB, path });
const HOST_FILES = '**/seclabcanary_hx1.txt';
const HOST_SEARCH = '**/seclabcanary_hs1.txt';
const HOST_WATCH = '**/seclabcanary_hw1';
const HOST_INCLUDE = 'seclabcanary_hi1';
const HOST_WS = '**/seclabcanary_hws1';
type Layers = Record<string, unknown>;
const LAYERS: Record<string, Layers> = {
	'files.exclude': { defaultValue: { '**/.git': true }, userLocalValue: { [HOST_FILES]: true, '**/.git': false }, userRemoteValue: { '**/remote-files': true }, workspaceValue: { [HOST_WS]: true }, workspaceFolderValue: { '**/folder-files': true } },
	'search.exclude': { defaultValue: { '**/node_modules': true }, userLocalValue: { [HOST_SEARCH]: true }, policyValue: { '**/policy-search': true }, memoryValue: { '**/memory-search': true }, workspaceFolderValue: {} },
	'files.watcherExclude': { defaultValue: { '**/.git/objects/**': true }, userLocalValue: { [HOST_WATCH]: true }, workspaceFolderValue: { '**/folder-watch': true } },
	'files.watcherInclude': { defaultValue: [], userLocalValue: [HOST_INCLUDE], workspaceFolderValue: ['own-include'] },
};
const merged = (key: string) => {
	const l = LAYERS[key];
	const vs = ['defaultValue', 'applicationValue', 'userLocalValue', 'userRemoteValue', 'workspaceValue', 'workspaceFolderValue', 'policyValue', 'memoryValue'].map(k => l[k]).filter(v => v !== undefined);
	return vs.every(v => !Array.isArray(v)) ? Object.assign({}, ...vs) : vs[vs.length - 1];
};
const configurationService = {
	inspect: (key: string) => LAYERS[key] ?? {},
	getValue: (k?: unknown) => typeof k === 'string' ? undefined : ({ files: { exclude: merged('files.exclude'), watcherExclude: merged('files.watcherExclude'), watcherInclude: merged('files.watcherInclude') }, search: { exclude: merged('search.exclude') } }),
};

/** Each file's sections in the shipped series, in apply order, by path relative to src/vs. */
const SERIES_TOUCHES = new Map<string, string[]>();
for (const name of readFileSync(join(REPO, 'patches', 'series'), 'utf8').split('\n').map(l => l.trim()).filter(l => l.endsWith('.patch'))) {
	for (const sec of patchFile(name).split(/^(?=diff -ruN )/m).slice(1)) {
		const m = / b\/src\/vs\/(\S+)$/.exec(sec.split('\n')[0]);
		if (m) {
			SERIES_TOUCHES.set(m[1], [...(SERIES_TOUCHES.get(m[1]) ?? []), name]);
		}
	}
}
const P0060_NAME = '0060-seclab-no-host-search-excludes-in-tabs.patch';

/**
 * `rel` as the whole shipped series leaves it, with `patch` in 0060's place (review: PR #68):
 * upstream's file or nothing, then every patch that touches it, in order. Undefined if neither.
 */
function source(rel: string, patch: string): string | undefined {
	const names = [...(SERIES_TOUCHES.get(rel) ?? [])];
	if (!names.includes(P0060_NAME) && section(patch, rel)) {
		names.push(P0060_NAME);
	}
	let out = existsSync(join(SRC!, rel)) ? readFileSync(join(SRC!, rel), 'utf8') : undefined;
	for (const name of names) {
		const text = name === P0060_NAME ? patch : patchFile(name);
		if (!section(text, rel)) {
			continue;
		}
		out = created(text, rel) ?? apply(out ?? '', text, rel);
	}
	return out;
}

/** What `name` needs from 0060's helper module, or nothing on a tree without it. */
function helpers(patch: string): Record<string, unknown> {
	const src = source(SETTINGS, patch);
	const names = src === undefined ? [] : [...src.matchAll(/\nexport function (\w+)/g)].map(m => m[1]);
	return src === undefined ? {} : evaluate(moduleBody(src), `{ ${names.join(', ')} }`,
		{ Schemas: { vscodeRemote: 'vscode-remote' }, seclabIsTabAuthority });
}

const getExcludes = () => evaluate<(c: unknown, s?: boolean) => Record<string, unknown> | undefined>(asFunction(slice(readFileSync(join(SRC!, 'workbench/services/search/common/search.ts'), 'utf8'), /\nexport function getExcludes\(/)!.replace(/^export /, '')), 'getExcludes',
	{ objects: { mixin: (d: object, s: object) => Object.assign(d, s), deepClone: (v: unknown) => structuredClone(v) } });

/** The exclude keys of the folder query upstream's QueryBuilder builds for `folder`. */
function folderQueryExcludes(patch: string, folder = tab('/work/ws'), callerPattern?: Record<string, unknown>): string[] {
	const query = source(QUERY_BUILDER, patch)!;
	const deps = { ...helpers(patch), URI: { isUri: (u: unknown) => !!u && typeof (u as { scheme?: unknown }).scheme === 'string' }, getExcludes: getExcludes(), isEqual: (a: unknown, b: unknown) => a === b, basename: (u: { path: string }) => u.path.split('/').pop(), isISearchPatternBuilder: () => false };
	const self: Record<string, unknown> = { configurationService, uriIdentityService: { extUri: { isEqual: () => false } } };
	// (Round 1's version of 0060 kept its step as a QueryBuilder method.)
	for (const name of ['getExcludesForFolder', 'seclabFolderConfig']) {
		const m = slice(query, new RegExp(`\\n\\tprivate ${name}\\(`));
		if (m) {
			self[name] = evaluate<(...a: unknown[]) => unknown>(asFunction(m), name, { ...deps, Schemas: { vscodeRemote: 'vscode-remote' }, seclabIsTabAuthority }).bind(self);
		}
	}
	const root = evaluate<(...a: unknown[]) => { excludePattern: Array<{ pattern: Record<string, unknown> }> }>(asFunction(slice(query, /\n\tprivate getFolderQueryForRoot\(/)!), 'getFolderQueryForRoot', deps);
	const searchPathExcludes = callerPattern ? { searchPaths: [{ searchPath: folder, pattern: callerPattern }] } : {};
	return Object.keys(root.call(self, folder, {}, searchPathExcludes, false).excludePattern[0]?.pattern ?? {}).sort();
}

/** The exclude keys of the query the chat file picker builds by hand (searchFilesAndFolders) for a tab folder. */
async function chatQueryExcludes(patch: string): Promise<string[]> {
	const src = source(CHAT_CONTEXT, patch)!;
	let sent: { excludePattern?: Record<string, unknown> } = {};
	// A top-level function ends at the first closing brace in column 0 (its return type holds braces).
	const at = src.indexOf('\nexport async function searchFilesAndFolders(');
	const fnText = src.slice(at + 1, src.indexOf('\n}\n', at) + 2).replace(/^export /, '');
	const fn = evaluate<(...a: unknown[]) => Promise<unknown>>(fnText, 'searchFilesAndFolders', {
		...helpers(patch), getExcludes: getExcludes(), QueryType: { File: 1 }, fuzzyMatchingGlobPattern: (p: string) => p, continousMatchingGlobPattern: (p: string) => p,
		isCancellationError: () => false, getMatchingFoldersFromFiles: () => [],
	});
	await fn(tab('/work/ws'), 'x', true, undefined, undefined, configurationService, { fileSearch: async (q: typeof sent) => { sent = q; return { results: [] }; } });
	return Object.keys(sent.excludePattern ?? {}).sort();
}

/** The exclude keys sessions telemetry's file count sends for a session whose workspace URI is a host path and whose folder is on the tab. */
async function telemetryExcludes(patch: string): Promise<string[]> {
	const src = source('sessions/contrib/sessions/browser/sessionsTelemetry.contribution.ts', patch)!;
	const sent: string[] = [];
	const fn = evaluate<(...a: unknown[]) => Promise<unknown>>(asFunction(slice(src, /\n\tprivate async _computeWorkspaceFileCount\(/)!), '_computeWorkspaceFileCount', {
		...helpers(patch), getExcludes: getExcludes(), QueryType: { File: 1 }, MAX_WORKSPACE_FILE_COUNT: 1000,
	});
	await fn.call({
		_configurationService: configurationService,
		_searchService: { fileSearch: async (q: { excludePattern?: Record<string, unknown> }) => { sent.push(...Object.keys(q.excludePattern ?? {})); return { results: [] }; } },
	}, { uri: { scheme: 'file', authority: '', path: '/Users/someone/session' }, folders: [{ root: tab('/work/ws') }] });
	return sent.sort();
}

/**
 * The query a tab's search provider is sent, through RemoteSearchProvider.doSearch in a tab window,
 * with whatever step this tree's MainThreadSearch constructor gives it (evaluated from its text).
 */
async function sentQuery(patch: string, query: Record<string, unknown>): Promise<unknown> {
	const src = source(SEARCH, patch)!;
	const built = /\n(\t\tconst strip = [\s\S]*?\n\t\t\}\);)\n/.exec(src);
	const excludes = built ? evaluate(built[1], 'excludes', { ...helpers(patch), _configurationService: configurationService, seclabContextService: { getWorkspace: () => ({}) } }) : (q: unknown) => q;
	let sent: unknown;
	const doSearch = evaluate<(...a: unknown[]) => Promise<unknown>>(asFunction(slice(src, /\n\tdoSearch\(/)!), 'doSearch', { CancellationToken: { None: {} }, SearchOperation: class { id = 1; matches = new Map(); keywords = []; } });
	await doSearch.call({ _seclab: { authority: TAB, fromTab: { searchMessages: (m: unknown) => m }, excludes }, _searches: new Map(), _provideSearchResults: (q: unknown) => { sent = q; return Promise.resolve({}); } }, query);
	return sent;
}

/** What the window asks the tab to watch for its workspace folder, through WorkspaceWatcher.watchWorkspace. */
function watched(patch: string): Array<{ path: string; excludes: string[] }> {
	const src = source(WATCHER, patch)!;
	const out: Array<{ path: string; excludes: string[] }> = [];
	const uri = (u: { scheme: string; authority: string; path: string }) => ({ ...u, with: (c: object) => uri({ ...u, ...c }) });
	const folder = { uri: uri(tab('/work/ws')), toResource: (p: string) => uri(tab(`/work/ws/${p}`)) };
	const fn = evaluate<(...a: unknown[]) => void>(asFunction(slice(src, /\n\tprivate watchWorkspace\(/)!), 'watchWorkspace', {
		...helpers(patch),
		ResourceMap: class extends Map<unknown, unknown> { constructor(_key?: unknown) { super(); } override set(k: { path: string }, v: unknown) { return super.set(k.path, v); } },
		DisposableStore: class { add() { } },
		URI: { file: (p: string) => uri({ scheme: 'file', authority: '', path: p }) },
		isAbsolute: (p: string) => p.startsWith('/'),
	});
	fn.call({
		configurationService,
		uriIdentityService: { extUri: { isEqualOrParent: (a: { path: string }, b: { path: string }) => (a.path + '/').startsWith(b.path + '/') } },
		fileService: { watch: (u: { path: string }, o: { excludes: string[] }) => { out.push({ path: u.path, excludes: o.excludes }); return {}; } },
		watchedWorkspaces: new Map(),
	}, folder);
	return out;
}

const SNAPSHOT_KEYS = ['files.exclude', 'search.exclude', 'files.watcherExclude', 'files.watcherInclude', 'files.readonlyInclude', 'files.readonlyExclude', 'explorer.autoRevealExclude'];
/** The keys the tab's extension host receives from a layer, through 0036's filter with `patch` as this tree's 0060. */
function snapshotKeys(patch: string, contents: Record<string, unknown>, hostValues: boolean): string[] {
	const registry = Object.fromEntries([...SNAPSHOT_KEYS, 'editor.tabSize'].map(k => [k, { scope: 5 }]));
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
// Each key's host value has only boolean leaves and keys without a scheme or `@`, as 0036's text rule lets through.
const HOST_LAYER: Record<string, unknown> = { ...Object.fromEntries(SNAPSHOT_KEYS.map(k => [k, { '**/seclabcanary_snap1/**': true }])), 'files.watcherInclude': [], 'editor.tabSize': 4 };

/** The new files each shipped patch creates, by path relative to src/vs (review SRCH3-15). */
const SERIES = readFileSync(join(REPO, 'patches', 'series'), 'utf8').split('\n').map(l => l.trim()).filter(l => l.endsWith('.patch'));
const PATCH_CREATED = new Map<string, string>();
for (const name of SERIES) {
	const text = patchFile(name);
	for (const sec of text.split(/^(?=diff -ruN )/m).slice(1)) {
		const m = / b\/src\/vs\/(\S+\.ts)$/.exec(sec.split('\n')[0]);
		if (m && sec.includes('\n@@ -0,0 ')) {
			PATCH_CREATED.set(m[1], text);
		}
	}
}
const isSource = (f: string) => f.endsWith('.ts') && !f.endsWith('.d.ts') && !/(^|\/)test\//.test(f);
/** Every non-test TypeScript file under the pinned src/vs and every one a patch creates, relative to src/vs. */
const ALL_FILES = [...new Set([...(readdirSync(SRC!, { recursive: true }) as string[]), ...PATCH_CREATED.keys(), ...SERIES_TOUCHES.keys()])].filter(isSource);

/**
 * Callers of search's `getExcludes` that only filter locally, with why; every other caller builds
 * the settings part of a query a tab may receive, and must go through 0060's helper for the very
 * folder it queries (review SRCH3-7).
 */
const LOCAL_ONLY: Record<string, string> = {
	'workbench/services/history/browser/historyService.ts': 'filters the window\'s own history list; nothing is sent',
};
/** Readers of `watcherExclude` other than WorkspaceWatcher, with why none sends a host value to a tab. */
const WATCHER_READERS: Record<string, string> = {
	'platform/files/common/files.ts': 'the setting\'s type',
	'platform/files/node/watcher/parcel/parcelWatcher.ts': 'applies the excludes a watch request carries',
	'platform/files/node/watcher/nodejs/nodejsWatcherLib.ts': 'applies the excludes a watch request carries',
	'workbench/api/browser/seclabConfigurationSnapshot.ts': 'names the key to withhold its host value from the tab (0036, 0060)',
	'workbench/api/common/extHostFileSystemEventService.ts': 'runs in the extension host: in a tab it reads the tab\'s snapshot, which 0060 filters',
	'workbench/contrib/files/browser/files.contribution.ts': 'the setting\'s registration',
	'workbench/contrib/preferences/browser/settingsTreeModels.ts': 'the Settings editor, in the window',
};
// Any import of search's module, in any shape, and a call of `getExcludes` (bare or through a namespace;
// `x.getExcludes()` with no argument is another API).
const IMPORTS_SEARCH = /from '(?:\.\/|[^']*\/services\/search\/common\/)search\.js'/;
const CALLS_GET_EXCLUDES = /(?<![\w])(?:\w+\.)?getExcludes\((?!\))/;
const WRAPPED = /seclabWithTabExcludes\((?:this\.)?(\w+), ([\w.]+), (?:this\.)?\1\.getValue<ISearchConfiguration>\(\{ resource: \2 \}\)\)/g;

/** Files that build a tab-bound query's or watch request's excludes from settings without 0060's helper. */
function unwrappedCalls(patch: string): string[] {
	const out: string[] = [];
	const extra = [...patch.matchAll(/^diff -ruN a\/src\/vs\/(\S+) /mg)].map(m => m[1]).filter(f => isSource(f) && !ALL_FILES.includes(f));
	for (const f of [...ALL_FILES, ...extra]) {
		// The file as the whole series (with this 0060) leaves it, so a patch that makes a file a
		// caller is scanned too (PR review on #68); files no patch touches are read as upstream's.
		const touched = SERIES_TOUCHES.has(f) || !!section(patch, f);
		const patched = f.endsWith('search/common/search.ts') ? '' : touched ? source(f, patch) ?? '' : readFileSync(join(SRC!, f), 'utf8');
		const upstream = patched;
		if (IMPORTS_SEARCH.test(patched) && CALLS_GET_EXCLUDES.test(patched) && !LOCAL_ONLY[f]) {
			const src = patched;
			const reads = src.split('getValue<ISearchConfiguration>({ resource').length - 1;
			const wrapped = [...src.matchAll(WRAPPED)].length;
			if (!reads || wrapped !== reads) {
				out.push(f);
			}
		}
		if (/watcherExclude/.test(upstream) && !WATCHER_READERS[f] && !/seclabTabOwnValue(?:<\w+>)?\(/.test(patched)) {
			out.push(f);
		}
	}
	return out;
}

const CANARIES = [HOST_FILES, HOST_SEARCH, HOST_WS, '**/policy-search', '**/memory-search'];
/** What reaches the tab of the host's patterns, on a tree with `patch` as its 0060. */
async function leaks(patch: string): Promise<string[]> {
	const out: string[] = [];
	const host = (keys: string[]) => keys.some(k => CANARIES.includes(k));
	if (host(folderQueryExcludes(patch))) {
		out.push('a search query QueryBuilder sends the tab carries host excludes');
	}
	if (host(await chatQueryExcludes(patch)) || host(await telemetryExcludes(patch))) {
		out.push('a search query built by hand carries host excludes');
	}
	if (unwrappedCalls(patch).length) {
		out.push('a query builds its excludes from settings without 0060\'s helper');
	}
	if (JSON.stringify(watched(patch)).match(/seclabcanary_h[wi]1/)) {
		out.push('a watch request sent to the tab carries the host user\'s watcher patterns');
	}
	if (snapshotKeys(patch, HOST_LAYER, true).some(k => SNAPSHOT_KEYS.includes(k))) {
		out.push('the tab\'s extension host receives the host user\'s path patterns');
	}
	return out;
}

const cases: Array<[string, () => Promise<void> | void]> = [
	["the baseline sends the host user's patterns to the tab every way", async () => {
		assert.deepEqual(await leaks(''), [
			'a search query QueryBuilder sends the tab carries host excludes',
			'a search query built by hand carries host excludes',
			'a query builds its excludes from settings without 0060\'s helper',
			'a watch request sent to the tab carries the host user\'s watcher patterns',
			'the tab\'s extension host receives the host user\'s path patterns',
		]);
	}],
	["a tab gets none of the host user's patterns and keeps its own", async () => {
		// On a tree without 0060 this reports every leak.
		assert.deepEqual(await leaks(P0060), []);
		// The guard reads the files patches create as well as upstream's.
		assert.ok(ALL_FILES.includes(SNAPSHOT) && ALL_FILES.includes('workbench/services/extensions/common/seclabRpcFilter.ts'), 'patch-created files are scanned');
		// The defaults (a default the host turned off keeps its default), the tab's remote user
		// settings and the folder's own settings stay; a workspace file's settings don't.
		const own = ['**/.git', '**/folder-files', '**/node_modules', '**/remote-files'];
		assert.deepEqual(folderQueryExcludes(P0060), own);
		assert.deepEqual(await chatQueryExcludes(P0060), own);
		assert.deepEqual(await telemetryExcludes(P0060), own);
		assert.deepEqual(watched(P0060), [{ path: '/work/ws', excludes: ['**/.git/objects/**', '**/folder-watch'] }, { path: '/work/ws/own-include', excludes: ['**/.git/objects/**', '**/folder-watch'] }]);
		assert.deepEqual(snapshotKeys(P0060, HOST_LAYER, false), [...SNAPSHOT_KEYS, 'editor.tabSize'].sort());
		assert.deepEqual(snapshotKeys(P0060, HOST_LAYER, true), ['editor.tabSize']);
	}],
	["a caller's own patterns reach the tab untouched, so a query says nothing about the host's", async () => {
		// Where every query leaves for the tab, nothing is removed (round 2's key strip was an oracle).
		const q = { folderQueries: [{ folder: tab('/work/ws'), excludePattern: [{ pattern: { [HOST_FILES]: true } }] }], excludePattern: { [HOST_SEARCH]: true } };
		assert.deepEqual(await sentQuery(P0060, structuredClone(q)), q);
		assert.equal(source(SEARCH, P0060), source(SEARCH, ''), '0060 leaves the chokepoint as 0051 has it');
		// A caller's exclude for the folder that matches a host pattern stays in the folder query.
		assert.ok(folderQueryExcludes(P0060, tab('/work/ws'), { [HOST_FILES]: true }).includes(HOST_FILES));
		assert.ok(!folderQueryExcludes(P0060, tab('/work/ws')).includes(HOST_FILES));
	}],
	["a window that is not a tab's keeps upstream's settings", async () => {
		const upstream = folderQueryExcludes('', { scheme: 'file', authority: '', path: '/work/ws' });
		assert.ok(upstream.includes(HOST_FILES) && upstream.includes(HOST_SEARCH));
		assert.deepEqual(folderQueryExcludes(P0060, { scheme: 'file', authority: '', path: '/work/ws' }), upstream);
		assert.deepEqual(folderQueryExcludes(P0060, { scheme: 'vscode-remote', authority: 'ssh-remote+box', path: '/work/ws' }), upstream);
		// An authority in another case is still the tab's (review SRCH3-8).
		assert.ok(!folderQueryExcludes(P0060, { scheme: 'vscode-remote', authority: 'SECLAB+tab1', path: '/work/ws' }).includes(HOST_FILES));
	}],
	["each mutant of 0060 brings its leak back", async () => {
		const mutants: Array<[string, string, string, string]> = [
			['QueryBuilder unwrapped', '+		const folderConfig = seclabWithTabExcludes(this.configurationService, folderUri, this.configurationService.getValue<ISearchConfiguration>({ resource: folderUri }));', '+		const folderConfig = this.configurationService.getValue<ISearchConfiguration>({ resource: folderUri });', 'a search query QueryBuilder sends the tab carries host excludes'],
			['chat picker unwrapped', '+	const searchExcludePattern = getExcludes(seclabWithTabExcludes(configurationService, workspace, configurationService.getValue<ISearchConfiguration>({ resource: workspace }))) || {};', '+	const searchExcludePattern = getExcludes(configurationService.getValue<ISearchConfiguration>({ resource: workspace })) || {};', 'a search query built by hand carries host excludes'],
			['telemetry per workspace, not per folder', '+			const excludePattern = getExcludes(seclabWithTabExcludes(this._configurationService, folder.root, this._configurationService.getValue<ISearchConfiguration>({ resource: folder.root })));', '+			const excludePattern = getExcludes(seclabWithTabExcludes(this._configurationService, workspace.uri, this._configurationService.getValue<ISearchConfiguration>({ resource: folder.root })));', 'a search query built by hand carries host excludes'],
			['empty-file search walk unwrapped', 'getExcludes(seclabWithTabExcludes(this.configurationService, folder.workingDirectory, this.configurationService.getValue<ISearchConfiguration>({ resource: folder.workingDirectory })))', 'getExcludes(this.configurationService.getValue<ISearchConfiguration>({ resource: folder.workingDirectory }))', 'a query builds its excludes from settings without 0060\'s helper'],
			['explorer find unwrapped', '+		const searchExcludePattern = getExcludes(seclabWithTabExcludes(this.configurationService, root.resource, this.configurationService.getValue<ISearchConfiguration>({ resource: root.resource }))) || {};', '+		const searchExcludePattern = getExcludes(this.configurationService.getValue<ISearchConfiguration>({ resource: root.resource })) || {};', 'a query builds its excludes from settings without 0060\'s helper'],
			['own layers take the host user\'s', '+	const own = [i.defaultValue, i.userRemoteValue, i.workspaceFolderValue]', '+	const own = [i.defaultValue, i.userLocalValue, i.userRemoteValue, i.workspaceFolderValue]', 'a search query QueryBuilder sends the tab carries host excludes'],
			['own layers take a workspace file\'s', '+	const own = [i.defaultValue, i.userRemoteValue, i.workspaceFolderValue]', '+	const own = [i.defaultValue, i.userRemoteValue, i.workspaceValue, i.workspaceFolderValue]', 'a search query QueryBuilder sends the tab carries host excludes'],
			['watcher reads the merged settings', '+		if (seclabOnTab(workspace.uri) && config.files) {', '+		if (false) {', 'a watch request sent to the tab carries the host user\'s watcher patterns'],
			['snapshot lets the keys cross', ' || SECLAB_HOST_ONLY_KEYS.has(key)', '', 'the tab\'s extension host receives the host user\'s path patterns'],
			['snapshot forgets readonlyInclude', "'files.readonlyInclude', ", '', 'the tab\'s extension host receives the host user\'s path patterns'],
		];
		// A patch that makes a file a caller, unwrapped, must be caught though upstream's file has none.
		const target = 'workbench/services/search/common/searchHelpers.ts';
		const head = readFileSync(join(SRC!, target), 'utf8').split('\n').slice(0, 3);
		const added = `diff -ruN a/src/vs/${target} b/src/vs/${target}\n--- a/src/vs/${target}\n+++ b/src/vs/${target}\n@@ -1,3 +1,5 @@\n`
			+ `+import { getExcludes, ISearchConfiguration } from './search.js';\n+export const seclabMutant = (c: { getValue<T>(o: object): T }, r: unknown) => getExcludes(c.getValue<ISearchConfiguration>({ resource: r }));\n`
			+ head.map(l => ` ${l}`).join('\n') + '\n';
		assert.ok((await leaks(P0060 + added)).includes('a query builds its excludes from settings without 0060\'s helper'), 'mutant not caught (a patch adds an unwrapped caller)');
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
