// Patch 0060 (review SRCH-3; project owner, 2026-11-18): the host user's files.exclude and
// search.exclude never reach a sandboxed tab. Two paths carried them:
//   - the search query the window sends the tab's search provider (QueryBuilder's folder queries);
//   - the configuration snapshot the tab's extension host receives (patch 0036), which let a
//     core structure with only boolean leaves cross from the host user's settings.
// The suite runs upstream's own QueryBuilder.getFolderQueryForRoot and 0036's snapshot filter,
// with whatever 0060 this tree has, against host canary patterns. On a tree without 0060 (main
// before it) both carry the host's patterns, and the tab cases fail. Each mutant of 0060 must
// bring its leak back.
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
const P0060 = patchFile('0060-seclab-no-host-search-excludes-in-tabs.patch');
assert.ok(P0036, '0036 is on every tree this suite runs on');

const QUERY = 'workbench/services/search/common/queryBuilder.ts';
const SNAPSHOT = 'workbench/api/browser/seclabConfigurationSnapshot.ts';

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

/** A new file a patch creates. */
const created = (patch: string, rel: string) => section(patch, rel)!.split('\n').filter(l => l.startsWith('+') && !l.startsWith('+++')).map(l => l.slice(1)).join('\n');

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
function evaluate<T>(code: string, result: string, deps: Record<string, unknown>): T {
	const js = stripTypeScriptTypes(`(function () {\n${code}\nreturn ${result};\n})`, { mode: 'transform' }).trim().replace(/;$/, '');
	return new Function(...Object.keys(deps), `return ${js}();`)(...Object.values(deps));
}

const TAB = 'seclab+tab1';
const HOST_FILES = '**/seclabcanary_hx1.txt';
const HOST_SEARCH = '**/seclabcanary_hs1.txt';
const layers = {
	'files.exclude': { defaultValue: { '**/.git': true }, userLocalValue: { [HOST_FILES]: true }, userRemoteValue: { '**/remote-files': true }, workspaceValue: { '**/ws-files': true }, workspaceFolderValue: { '**/folder-files': true } },
	'search.exclude': { defaultValue: { '**/node_modules': true }, userLocalValue: { [HOST_SEARCH]: true }, userRemoteValue: { '**/remote-search': true }, workspaceValue: { '**/ws-search': true }, workspaceFolderValue: {} },
} as const;
const merged = (key: keyof typeof layers) => { const l = layers[key]; return { ...l.defaultValue, ...l.userLocalValue, ...l.userRemoteValue, ...l.workspaceValue, ...l.workspaceFolderValue }; };

/** The exclude patterns of the folder query upstream's QueryBuilder builds for `folder`, with `patch` applied. */
function folderExcludes(patch: string, folder: { scheme: string; authority: string; path: string }): string[] {
	const query = apply(readFileSync(join(SRC!, QUERY), 'utf8'), patch, QUERY);
	const search = readFileSync(join(SRC!, 'workbench/services/search/common/search.ts'), 'utf8');
	const getExcludes = evaluate(asFunction(slice(search, /\nexport function getExcludes\(/)!.replace(/^export /, '')), 'getExcludes',
		{ objects: { mixin: (d: object, s: object) => Object.assign(d, s), deepClone: (v: unknown) => structuredClone(v) } });
	const URI = { isUri: (u: unknown) => !!u && typeof (u as { scheme?: unknown }).scheme === 'string' };
	const deps = { URI, Schemas: { vscodeRemote: 'vscode-remote' }, seclabIsTabAuthority: (a: string) => /^seclab\+/.test(a), getExcludes, isEqual: () => false, basename: (u: { path: string }) => u.path.split('/').pop(), isISearchPatternBuilder: () => false };
	const self: Record<string, unknown> = {
		configurationService: {
			getValue: () => ({ files: { exclude: merged('files.exclude'), encoding: 'utf8' }, search: { exclude: merged('search.exclude'), useIgnoreFiles: true } }),
			inspect: (key: keyof typeof layers) => layers[key],
		},
		uriIdentityService: { extUri: { isEqual: () => false } },
	};
	for (const name of ['getExcludesForFolder', 'seclabFolderConfig']) {
		const m = slice(query, new RegExp(`\\n\\tprivate ${name}\\(`));
		if (m) {
			self[name] = evaluate<(...a: unknown[]) => unknown>(asFunction(m), name, deps).bind(self);
		}
	}
	const root = evaluate<(...a: unknown[]) => { excludePattern: Array<{ pattern: Record<string, unknown> }> }>(asFunction(slice(query, /\n\tprivate getFolderQueryForRoot\(/)!), 'getFolderQueryForRoot', deps);
	const q = root.call(self, folder, {}, {}, false);
	return Object.keys(q.excludePattern[0]?.pattern ?? {}).sort();
}

/** The keys the tab's extension host receives from a layer, through 0036's filter with `patch` applied. */
function snapshotKeys(patch: string, contents: Record<string, unknown>, hostValues: boolean): string[] {
	const src = apply(created(P0036, SNAPSHOT), patch, SNAPSHOT)
		.replace(/^import .*$/mg, '')
		.replace(/^export /mg, '');
	const registry = { 'files.exclude': { scope: 4 }, 'search.exclude': { scope: 4 }, 'editor.tabSize': { scope: 5 } };
	const deps = {
		Registry: { as: () => ({ getConfigurationProperties: () => registry }) },
		Extensions: { Configuration: 'configuration' },
		ConfigurationScope: { APPLICATION: 1, MACHINE: 2, APPLICATION_MACHINE: 3, WINDOW: 4, RESOURCE: 5, LANGUAGE_OVERRIDABLE: 6, MACHINE_OVERRIDABLE: 7 },
		OVERRIDE_PROPERTY_REGEX: /^\[.*\]$/,
		getConfigurationValue: (c: Record<string, unknown>, k: string) => c[k],
		addToValueTree: (o: Record<string, unknown>, k: string, v: unknown) => { o[k] = v; },
		withholdReason: () => undefined,
	};
	const filter = evaluate<(...a: unknown[]) => { keys: string[] }>(src, 'filterContents', deps);
	return filter(contents, Object.keys(contents), { tabExtensions: new Set(), workspaceInTab: true, windowAuthority: TAB }, hostValues, [], []).keys.sort();
}

const tabFolder = { scheme: 'vscode-remote', authority: TAB, path: '/work/ws' };
const hostLayer = { 'files.exclude': { [HOST_FILES]: true }, 'search.exclude': { [HOST_SEARCH]: true }, 'editor.tabSize': 4 };

/** What reaches the tab of the host user's patterns, on a tree with `patch` as its 0060. */
function leaks(patch: string): string[] {
	const out: string[] = [];
	const q = folderExcludes(patch, tabFolder);
	if (q.includes(HOST_FILES) || q.includes(HOST_SEARCH)) {
		out.push('the query sent to the tab carries the host user\'s excludes');
	}
	const s = snapshotKeys(patch, hostLayer, true);
	if (s.includes('files.exclude') || s.includes('search.exclude')) {
		out.push('the tab\'s extension host receives the host user\'s excludes');
	}
	return out;
}

const cases: Array<[string, () => void]> = [
	['the baseline sends the host user\'s excludes to the tab both ways', () => {
		assert.deepEqual(leaks(''), ['the query sent to the tab carries the host user\'s excludes', 'the tab\'s extension host receives the host user\'s excludes']);
	}],
	['a tab gets neither the host user\'s excludes nor loses its own', () => {
		// On a tree without 0060 this reports both leaks.
		assert.deepEqual(leaks(P0060), []);
		// Defaults and the tab's own workspace and folder settings stay (the project owner's scope).
		assert.deepEqual(folderExcludes(P0060, tabFolder), ['**/.git', '**/folder-files', '**/node_modules', '**/ws-files', '**/ws-search']);
		// The tab's own layers still carry its excludes to its extension host, and other host keys still cross.
		assert.deepEqual(snapshotKeys(P0060, hostLayer, false), ['editor.tabSize', 'files.exclude', 'search.exclude']);
		assert.deepEqual(snapshotKeys(P0060, hostLayer, true), ['editor.tabSize']);
	}],
	['a folder that is not a tab\'s keeps upstream\'s excludes', () => {
		const upstream = folderExcludes('', { scheme: 'file', authority: '', path: '/work/ws' });
		assert.ok(upstream.includes(HOST_FILES) && upstream.includes(HOST_SEARCH));
		assert.deepEqual(folderExcludes(P0060, { scheme: 'file', authority: '', path: '/work/ws' }), upstream);
		assert.deepEqual(folderExcludes(P0060, { scheme: 'vscode-remote', authority: 'ssh-remote+box', path: '/work/ws' }), upstream);
	}],
	['each mutant of 0060 brings its leak back', () => {
		const mutants: Array<[string, string, string, string]> = [
			['query reads the merged settings', '+		const folderConfig = this.seclabFolderConfig(folderUri);', '+		const folderConfig = this.configurationService.getValue<ISearchConfiguration>({ resource: folderUri });', 'the query sent to the tab carries the host user\'s excludes'],
			['query treats a tab as any remote', '+		if (folderUri.scheme !== Schemas.vscodeRemote || !seclabIsTabAuthority(folderUri.authority)) {', '+		if (true) {', 'the query sent to the tab carries the host user\'s excludes'],
			['snapshot lets the keys cross', '|| SECLAB_HOST_ONLY_KEYS.has(key)', '', 'the tab\'s extension host receives the host user\'s excludes'],
		];
		for (const [name, from, to, leak] of mutants) {
			assert.equal(P0060.split(from).length - 1, 1, `mutant ${name}: its text occurs once in 0060`);
			// A mutant must bring its leak back, not merely break the build under test.
			const found = leaks(P0060.replace(from, to));
			assert.ok(found.includes(leak), `mutant not caught (${name}): found ${JSON.stringify(found)}`);
		}
	}],
];

let failed = 0;
for (const [name, fn] of cases) {
	try {
		fn();
		console.log(`ok   ${name}`);
	} catch (e) {
		failed++;
		console.log(`FAIL ${name}\n     ${String((e as Error).message).split('\n').join('\n     ')}`);
	}
}
console.log(failed ? `${failed} failed` : `${cases.length} passed`);
process.exit(failed ? 1 : 0);
