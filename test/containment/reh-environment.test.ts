/**
 * Patch 0059 (reviews R5-17, ENV-1 to ENV-6): in a `seclab+` window every location a tab's server
 * names must be on the tab's own file system (`vscode-remote` on the window's authority), and is
 * rebuilt from its components. Upstream trusted all of it, so a server could name the host user's
 * settings file as the tab's `settingsPath`: the window read it as the tab's settings layer (patch
 * 0036 passes that layer to the tab) and wrote the tab's settings into it.
 *
 * This runs upstream's own code, sliced from the pinned files, unpatched (the control: it takes
 * every lie) and with 0059's hunks, with the shipped `seclabTabUris` from the filter source:
 * - RemoteExtensionEnvironmentChannelClient.getEnvironmentData (the environment reply);
 * - AbstractRemoteAgentService.getEnvironment (a refusal must not read as "no remote");
 * - the profiles channel (replies and events), file change events and the extension scan.
 * Each mutant of the check must let its lie through.
 *
 * Run: ./seclab test reh-environment   (mounts the pinned src/vs/workbench/services; SECLAB_SERVICES_SRC points at it)
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SRC = process.env.SECLAB_SERVICES_SRC;
if (!SRC) {
	console.error('reh-environment: set SECLAB_SERVICES_SRC to the pinned src/vs/workbench/services (./seclab test reh-environment does)');
	process.exit(1);
}
const PATCH = readFileSync(join(REPO, 'patches', '0059-seclab-tab-server-environment-stays-in-the-tab.patch'), 'utf8');
const FILTER = readFileSync(join(REPO, 'rpc-filter', 'patch-src', 'seclabRpcFilter.ts'), 'utf8');
const FILES = {
	environment: 'remote/common/remoteAgentEnvironmentChannel.ts',
	agent: 'remote/common/abstractRemoteAgentService.ts',
	profiles: 'userDataProfile/common/remoteUserDataProfiles.ts',
	watcher: 'remote/common/remoteFileSystemProviderClient.ts',
	scanner: 'remote/common/remoteExtensionsScanner.ts',
	extensions: 'extensionManagement/electron-browser/extensionManagementServerService.ts',
} as const;
type Key = keyof typeof FILES;

/** Apply one file's hunks of a `diff -ruN` patch, each exactly once. */
function applyFile(source: string, patch: string, rel: string): string {
	const sec = patch.split(/^(?=diff -ruN )/m).find(p => p.split('\n')[0].includes(`/services/${rel} `));
	if (!sec) {
		return source;
	}
	let out = source;
	for (const hunk of sec.split(/\n(?=@@ )/).slice(1)) {
		const lines = hunk.split('\n').slice(1).filter(l => l.length > 0 && l[0] !== '\\');
		const old = lines.filter(l => l[0] === ' ' || l[0] === '-').map(l => l.slice(1)).join('\n');
		const neu = lines.filter(l => l[0] === ' ' || l[0] === '+').map(l => l.slice(1)).join('\n');
		assert.equal(out.split(old).length - 1, 1, `a 0059 hunk no longer applies to ${rel}`);
		out = out.replace(old, neu);
	}
	return out;
}

/** The function or method that starts at `head` in `source`, brace-matched, or undefined. */
function slice(source: string, head: RegExp): string | undefined {
	const m = head.exec(source);
	if (!m) {
		return undefined;
	}
	let i = m.index + m[0].length;
	for (let depth = 1; depth > 0; i++) {
		depth += source[i] === '(' ? 1 : source[i] === ')' ? -1 : 0;
	}
	const open = source.indexOf('{', i);
	let j = open + 1;
	for (let depth = 1; depth > 0; j++) {
		depth += source[j] === '{' ? 1 : source[j] === '}' ? -1 : 0;
	}
	return source.slice(m.index, j).trim();
}

/** Evaluate `code` (TypeScript) with `deps` in scope, returning the value of `result`. */
function evaluate<T>(code: string, result: string, deps: Record<string, unknown>): T {
	const js = stripTypeScriptTypes(`(function () {\n${code}\nreturn ${result};\n})`, { mode: 'transform' }).trim().replace(/;$/, '');
	return new Function(...Object.keys(deps), `return ${js}();`)(...Object.values(deps));
}

/** A method as a standalone function: `async name(…) {…}` becomes `async function name(…) {…}`. */
const asFunction = (m: string) => m.replace(/^(?:(?:private|protected|public|static) )*(async )?/, '$1function ').replace(/^(async )?function ([A-Za-z_$][\w$]*)<[^>(]*>\(/, '$1function $2(');

interface Build {
	sources: Record<Key, string>;
	refusals: string[];
	deps: Record<string, unknown>;
}

function build(patched: boolean, patch = PATCH, filter = FILTER): Build {
	const refusals: string[] = [];
	const sources = Object.fromEntries((Object.entries(FILES) as Array<[Key, string]>).map(([k, rel]) => {
		const text = readFileSync(join(SRC!, rel), 'utf8');
		return [k, patched ? applyFile(text, patch, rel) : text];
	})) as Record<Key, string>;
	const tabUris = slice(filter, /\nexport function seclabTabUris<T>\(/)!.replace(/^export /, '');
	const onTab = slice(filter, /\nexport function seclabTabUri<T>\(/)!.replace(/^export /, '');
	const serverChannel = slice(filter, /\nexport function seclabTabServerChannel\(/)!.replace(/^export /, '');
	const keys = /\nconst SECLAB_URI_KEYS = [^\n]+/.exec(filter)![0];
	const marks = /\nconst SECLAB_URI_MARKS = [^\n]+/.exec(filter)![0];
	const helpers = evaluate<Record<string, unknown>>(`${keys}\n${marks}\n${tabUris}\n${onTab}\n${serverChannel}`, '{ seclabTabUris, seclabTabUri, seclabTabServerChannel }', {
		seclabIsTabAuthority: (a: unknown) => typeof a === 'string' && /^seclab\+/.test(a),
		seclabRefuseServerLocation: (_a: string, site: string) => { refusals.push(site); },
	});
	const deps: Record<string, unknown> = {
		...helpers,
		seclabIsTabAuthority: (a: unknown) => typeof a === 'string' && /^seclab\+/.test(a),
		seclabRefuseServerLocation: (_a: string, site: string) => { refusals.push(site); },
		URI: { revive: (u: unknown) => u },
		revive: (v: unknown) => v,
		ProtocolConstants: { ReconnectionGraceTime: 10800000 },
		Event: {},
		platform: { language: 'en' },
	};
	return { sources, refusals, deps };
}

const TAB = 'seclab+tab1';
const remote = (authority: string, path: string) => ({ $mid: 1, scheme: 'vscode-remote', authority, path });
const HOST = { $mid: 1, scheme: 'file', authority: '', path: '/Users/someone/Library/Application Support/editor/User/settings.json' };
const profile = (authority: string) => ({
	id: 'default', name: 'Default', isDefault: true, useDefaultFlags: { settings: true },
	location: remote(authority, '/home/agent/.seclab-reh/data/User'), settingsResource: remote(authority, '/home/agent/.seclab-reh/data/User/settings.json'),
	extensionsResource: remote(authority, '/home/agent/.seclab-reh/extensions/extensions.json'), mcpResource: remote(authority, '/home/agent/.seclab-reh/data/User/mcp.json'),
});
/** A reply as a genuine server sends it: its URI transformer puts every URI on the window's authority. */
function genuine(authority: string): Record<string, unknown> {
	const r = (p: string) => remote(authority, p);
	return {
		pid: 1, connectionToken: 't', appRoot: r('/opt/seclab-reh'), execPath: '/opt/seclab-reh/node', tmpDir: r('/tmp'),
		settingsPath: r('/home/agent/.seclab-reh/data/Machine/settings.json'), mcpResource: r('/home/agent/.seclab-reh/data/User/mcp.json'),
		logsPath: r('/home/agent/.seclab-reh/data/logs/1'), extensionHostLogsPath: r('/home/agent/.seclab-reh/data/logs/1/exthost1'),
		globalStorageHome: r('/home/agent/.seclab-reh/data/User/globalStorage'), workspaceStorageHome: r('/home/agent/.seclab-reh/data/User/workspaceStorage'),
		localHistoryHome: r('/home/agent/.seclab-reh/data/User/History'), userHome: r('/home/agent'),
		os: 3, arch: 'arm64', marks: [{ name: 'code/server/start', startTime: 1 }], useHostProxy: false,
		profiles: { home: r('/home/agent/.seclab-reh/data/User/profiles'), all: [profile(authority)] },
		isUnsupportedGlibc: false,
	};
}

/** Each way a lying server could move a location out of the tab, in its environment reply. */
const LIES: Array<[string, (r: Record<string, unknown>) => void]> = [
	['the host user settings file as settingsPath', r => { r.settingsPath = HOST; }],
	['another tab as mcpResource', r => { r.mcpResource = remote('seclab+tab2', '/home/agent/mcp.json'); }],
	['the authority in another case as userHome', r => { r.userHome = remote(TAB.toUpperCase(), '/home/agent'); }],
	['a host scheme carrying the tab authority', r => { r.globalStorageHome = { $mid: 1, scheme: 'file', authority: TAB, path: '/Users/someone/globalStorage' }; }],
	['a host file inside a profile', r => { (r.profiles as { all: Array<Record<string, unknown>> }).all[0].settingsResource = HOST; }],
	['a host file nested deeper than the walk', r => {
		let v: Record<string, unknown> = { uri: HOST };
		for (let i = 0; i < 40; i++) {
			v = { v };
		}
		r.marks = [v];
	}],
	// ENV-1: URI fields on the reply itself, or on a container, must not make the walk skip it.
	['URI fields on the reply hiding a host settingsPath', r => { Object.assign(r, { scheme: 'vscode-remote', authority: TAB, path: '/' }); r.settingsPath = HOST; }],
	['a URI marker and fields on the reply hiding a host settingsPath', r => { Object.assign(r, { $mid: 1, scheme: 'vscode-remote', authority: TAB, path: '/' }); r.settingsPath = HOST; }],
	// ENV-8: URI.revive ignores $mid, so any other marker, or none, is still a URI to the window.
	...[2, 0, null, '1'].map(mid => [`a host file marked $mid ${JSON.stringify(mid)}`, (r: Record<string, unknown>) => { r.settingsPath = { ...HOST, $mid: mid }; }] as [string, (r: Record<string, unknown>) => void]),
	['a host fsPath with no scheme or $mid', r => { r.userHome = { path: '/Users/someone', fsPath: '/Users/someone' }; }],
	['URI fields on a profile hiding its host settings', r => {
		const p = (r.profiles as { all: Array<Record<string, unknown>> }).all[0];
		Object.assign(p, { scheme: 'vscode-remote', path: '/' });
		p.authority = TAB;
		p.settingsResource = HOST;
	}],
];
const lie = (mutate: (r: Record<string, unknown>) => void) => {
	const r = genuine(TAB);
	mutate(r);
	return r;
};

async function environment(b: Build, authority: string, reply: unknown): Promise<{ refused: boolean; env?: Record<string, unknown> }> {
	const fn = evaluate<(c: unknown, a: string, p: unknown) => Promise<Record<string, unknown>>>(
		asFunction(slice(b.sources.environment, /\n\tstatic async getEnvironmentData\(/)!), 'getEnvironmentData', b.deps);
	try {
		return { refused: false, env: await fn({ call: async () => structuredClone(reply) }, authority, undefined) };
	} catch (e) {
		assert.match((e as Error).message, /outside the tab/);
		return { refused: true };
	}
}

async function getEnvironment(b: Build, authority: string): Promise<'null' | 'rejected'> {
	const fn = evaluate<() => Promise<unknown>>(asFunction(slice(b.sources.agent, /\n\tgetEnvironment\(/)!), 'getEnvironment', b.deps);
	try {
		await fn.call({ _environmentService: { remoteAuthority: authority }, getRawEnvironment: () => Promise.reject(new Error('refused')) });
		return 'null';
	} catch {
		return 'rejected';
	}
}

/** The channel the profiles service gets: patched, the wrapper; else the raw channel. */
async function profiles(b: Build, authority: string, reply: unknown, event: unknown): Promise<{ replyRefused: boolean; events: unknown[] }> {
	const raw = { call: async () => structuredClone(reply), listen: () => (l: (e: unknown) => void) => { l(structuredClone(event)); return { dispose() { } }; } };
	// Patched, the service is given seclabTabServerChannel(…, 'profiles'); upstream, the raw channel.
	const wrapped = /seclabTabServerChannel\(connection\.getChannel\('userDataProfiles'\), connection\.remoteAuthority, 'profiles'\)/.test(b.sources.profiles);
	const channel = wrapped ? (b.deps.seclabTabServerChannel as (c: unknown, a: string, s: string) => typeof raw)(raw, authority, 'profiles') : raw;
	let replyRefused = false;
	try {
		await channel.call('createProfile');
	} catch {
		replyRefused = true;
	}
	const events: unknown[] = [];
	channel.listen('onDidChangeProfiles')((e: unknown) => events.push(e));
	return { replyRefused, events };
}

/** The extension management channel: patched, wrapped with `manifest` left alone; else raw. */
async function management(b: Build, authority: string, reply: unknown, event: unknown): Promise<{ replyRefused: boolean; reply?: unknown; events: unknown[] }> {
	const raw = { call: async () => structuredClone(reply), listen: () => (l: (e: unknown) => void) => { l(structuredClone(event)); return { dispose() { } }; } };
	const m = /seclabTabServerChannel\(remoteAgentConnection\.getChannel<IChannel>\('extensions'\), remoteAgentConnection\.remoteAuthority, 'extension-management', new Set\(\['manifest'\]\)\)/.test(b.sources.extensions);
	const channel = m ? (b.deps.seclabTabServerChannel as (c: unknown, a: string, s: string, k: Set<string>) => typeof raw)(raw, authority, 'extension-management', new Set(['manifest'])) : raw;
	let replyRefused = false;
	let got: unknown;
	try {
		got = await channel.call('getInstalled');
	} catch {
		replyRefused = true;
	}
	const events: unknown[] = [];
	channel.listen('onDidInstallExtensions')((e: unknown) => events.push(e));
	return { replyRefused, reply: got, events };
}
const local = (authority: string, location: unknown) => ({
	identifier: { id: 'tab.ext' }, location, readmeUrl: remote(authority, '/ext/README.md'),
	// A manifest names files by `path`, and may carry `scheme` keys (resourceLabelFormatters).
	manifest: { name: 'ext', contributes: { grammars: [{ path: './g.json' }], resourceLabelFormatters: [{ scheme: 'file', authority: '', formatting: {} }] } },
});

function watcher(b: Build, authority: string, changes: unknown[]): unknown[] {
	const raw = { call: async () => undefined, listen: () => (l: (e: unknown) => void) => { l(structuredClone(changes)); return { dispose() { } }; } };
	const wrap = slice(b.sources.watcher, /\nfunction seclabTabWatcherChannel\(/);
	const channel = wrap ? evaluate<(c: unknown, a: string) => typeof raw>(wrap, 'seclabTabWatcherChannel', b.deps)(raw, authority) : raw;
	const got: unknown[] = [];
	channel.listen('fileChange')((e: unknown) => got.push(...(e as unknown[])));
	return got;
}

async function scan(b: Build, authority: string, extensions: unknown[]): Promise<unknown[]> {
	const fn = evaluate<() => Promise<unknown[]>>(asFunction(slice(b.sources.scanner, /\n\tasync scanExtensions\(/)!), 'scanExtensions', b.deps);
	return fn.call({
		activeLanguagePackService: { getExtensionIdProvidingCurrentLocale: async () => undefined },
		withChannel: (cb: (c: unknown) => Promise<unknown>) => cb({ call: async () => structuredClone(extensions) }),
		userDataProfileService: { currentProfile: { isDefault: true } },
		extensionManagementService: { getInstalledWorkspaceExtensionLocations: () => [] },
		environmentService: { remoteAuthority: authority, extensionDevelopmentLocationURI: undefined },
		logService: { error: () => { } },
	});
}

const extensions = (authority: string) => [
	{ identifier: { value: 'tab.own' }, extensionLocation: { ...remote(authority, '/home/agent/.seclab-reh/extensions/tab.own'), fsPath: '/Users/someone/.vscode/extensions/x' } },
	{ identifier: { value: 'tab.hostdir' }, extensionLocation: { $mid: 1, scheme: 'file', authority: '', path: '/Users/someone/.vscode/extensions/x' } },
];
const changes = (authority: string) => [{ type: 0, resource: { ...remote(authority, '/w/a.txt'), external: 'file:///Users/someone/a.txt', fsPath: '/Users/someone/a.txt' } }, { type: 0, resource: HOST }];
const ids = (xs: unknown[]) => xs.map(x => (x as { identifier: { value: string } }).identifier.value);

/** Every way the host's locations reached the window, for one build. */
async function leaks(b: Build): Promise<string[]> {
	const out: string[] = [];
	for (const [name, mutate] of LIES) {
		if (!(await environment(b, TAB, lie(mutate))).refused) {
			out.push(`environment: ${name}`);
		}
	}
	const kept = (await environment(b, TAB, { ...genuine(TAB), settingsPath: { ...remote(TAB, '/home/agent/s.json'), external: 'file:///Users/someone/settings.json', fsPath: '/Users/someone/settings.json' } })).env;
	if (kept && ('external' in (kept.settingsPath as object) || 'fsPath' in (kept.settingsPath as object))) {
		out.push('environment: host strings in a revived URI');
	}
	if (await getEnvironment(b, TAB) === 'null') {
		out.push('a refused environment reads as no remote');
	}
	const p = await profiles(b, TAB, { ...profile(TAB), settingsResource: HOST }, { added: [], removed: [], updated: [], all: [{ ...profile(TAB), mcpResource: HOST }] });
	if (!p.replyRefused) {
		out.push('profiles: a reply naming a host file');
	}
	if (p.events.length > 0) {
		out.push('profiles: an event naming a host file');
	}
	if (watcher(b, TAB, changes(TAB)).length !== 1) {
		out.push('watcher: a change to a host file');
	}
	const scanned = await scan(b, TAB, extensions(TAB));
	if (ids(scanned).includes('tab.hostdir')) {
		out.push('extensions: one in a host directory');
	}
	const w = watcher(b, TAB, changes(TAB));
	if (JSON.stringify(scanned).includes('/Users/someone') || JSON.stringify(w).includes('/Users/someone')) {
		out.push('host strings kept in a checked tab URI');
	}
	const mg = await management(b, TAB, [local(TAB, HOST)], [{ identifier: { id: 'tab.ext' }, local: local(TAB, HOST), profileLocation: remote(TAB, '/p') }]);
	if (!mg.replyRefused) {
		out.push('extension management: a reply naming a host location');
	}
	if (mg.events.length > 0) {
		out.push('extension management: an event naming a host location');
	}
	return out;
}
const EVERY_LEAK = [...LIES.map(l => `environment: ${l[0]}`), 'environment: host strings in a revived URI', 'a refused environment reads as no remote',
	'profiles: a reply naming a host file', 'profiles: an event naming a host file', 'watcher: a change to a host file', 'extensions: one in a host directory',
	'host strings kept in a checked tab URI', 'extension management: a reply naming a host location', 'extension management: an event naming a host location'];

const tests: Array<[string, () => Promise<void>]> = [
	['the baseline takes every location a tab server names', async () => {
		// The control: on main each lie reaches the window, so the patched refusals below mean something.
		assert.deepEqual(await leaks(build(false)), EVERY_LEAK);
	}],
	['a tab window takes none of them, and logs each refusal', async () => {
		const b = build(true);
		assert.deepEqual(await leaks(b), []);
		assert.deepEqual([...new Set(b.refusals)].sort(), ['environment', 'extension-management', 'extensions', 'profiles', 'watcher']);
	}],
	['a tab window takes a genuine server unchanged', async () => {
		const b = build(true);
		const r = await environment(b, TAB, genuine(TAB));
		assert.equal(r.refused, false);
		assert.deepEqual(r.env!.settingsPath, { ...genuine(TAB).settingsPath as object, query: '', fragment: '' });
		assert.deepEqual((r.env!.profiles as { all: unknown[] }).all.length, 1);
		const p = await profiles(b, TAB, profile(TAB), { added: [], removed: [], updated: [], all: [profile(TAB)] });
		assert.equal(p.replyRefused, false);
		assert.equal(p.events.length, 1);
		assert.deepEqual(ids(await scan(b, TAB, extensions(TAB).slice(0, 1))), ['tab.own']);
		const mg = await management(b, TAB, [local(TAB, remote(TAB, '/ext'))], { local: local(TAB, remote(TAB, '/ext')), profileLocation: remote(TAB, '/p') });
		assert.equal(mg.replyRefused, false);
		assert.deepEqual((mg.reply as Array<{ manifest: unknown }>)[0].manifest, local(TAB, null).manifest);
		assert.equal(mg.events.length, 1);
		assert.deepEqual(b.refusals, []);
	}],
	['a window that is not a tab keeps upstream behaviour', async () => {
		const other = 'ssh-remote+box';
		const b = build(true);
		assert.equal((await environment(b, other, { ...genuine(other), settingsPath: HOST })).refused, false);
		assert.equal(await getEnvironment(b, other), 'null');
		assert.equal((await profiles(b, other, { ...profile(other), settingsResource: HOST }, { added: [], removed: [], updated: [], all: [] })).replyRefused, false);
		assert.equal(watcher(b, other, changes(other)).length, 2);
		assert.equal((await scan(b, other, extensions(other))).length, 2);
		assert.equal((await management(b, other, [local(other, HOST)], {})).replyRefused, false);
		assert.deepEqual(b.refusals, []);
	}],
	['each mutant of 0059 lets its lie through', async () => {
		const mutants: Array<[string, { patch?: [string, string]; filter?: [string, string] }, string]> = [
			['any scheme', { filter: ["o.scheme !== 'vscode-remote' || ", ''] }, 'environment: a host scheme carrying the tab authority'],
			['any authority', { filter: [' || o.authority !== remoteAuthority', ''] }, 'environment: another tab as mcpResource'],
			['containers may carry URI fields', { filter: ['Object.keys(o).some(k => !SECLAB_URI_KEYS.has(k)) || ', ''] }, 'environment: a URI marker and fields on the reply hiding a host settingsPath'],
			['a URI only when marked $mid 1', { filter: ['		if (SECLAB_URI_MARKS.some(k => Object.hasOwn(o, k))) {', '		if (o.$mid === 1) {'] }, 'environment: a host file marked $mid 2'],
			['only $mid or scheme marks a URI', { filter: ["const SECLAB_URI_MARKS = ['$mid', 'scheme', 'authority', 'external', 'fsPath', '_sep'];", "const SECLAB_URI_MARKS = ['$mid', 'scheme'];"] }, 'environment: a host fsPath with no scheme or $mid'],
			['deep values pass', { filter: ['		if (depth > 32) {\n			throw foreign();', '		if (depth > 32) {\n			return v;'] }, 'environment: a host file nested deeper than the walk'],
			['URIs not rebuilt', { filter: ["			return { $mid: 1, scheme: o.scheme, authority: o.authority, path: o.path ?? '', query: o.query ?? '', fragment: o.fragment ?? '' };", '			return o;'] }, 'environment: host strings in a revived URI'],
			['environment unchecked', { patch: ['+				data = seclabTabUris(remoteAuthority, data);', '+				data = data;'] }, 'environment: the host user settings file as settingsPath'],
			['refusal reads as no remote', { patch: ['+		if (seclabIsTabAuthority(this._environmentService.remoteAuthority)) {\n+			return this.getRawEnvironment();', '+		if (false) {\n+			return this.getRawEnvironment();'] }, 'a refused environment reads as no remote'],
			['channel events unchecked', { filter: ['				checked = check(e) as T;', '				checked = e as T;'] }, 'profiles: an event naming a host file'],
			['profiles channel unwrapped', { patch: ["seclabTabServerChannel(connection.getChannel('userDataProfiles'), connection.remoteAuthority, 'profiles')", "connection.getChannel('userDataProfiles')"] }, 'profiles: a reply naming a host file'],
			['watcher unchecked', { patch: ['+					return resource ? [{ ...(c as object), resource }] : [];', '+					return [c];'] }, 'watcher: a change to a host file'],
			['watcher keeps the sent resource', { patch: ['+					return resource ? [{ ...(c as object), resource }] : [];', '+					return resource ? [c] : [];'] }, 'host strings kept in a checked tab URI'],
			['scan unchecked', { patch: ['+						return location ? [{ ...e, extensionLocation: location }] : [];', '+						return [e];'] }, 'extensions: one in a host directory'],
			['management channel unwrapped', { patch: ["seclabTabServerChannel(remoteAgentConnection.getChannel<IChannel>('extensions'), remoteAgentConnection.remoteAuthority, 'extension-management', new Set(['manifest']))", "remoteAgentConnection.getChannel<IChannel>('extensions')"] }, 'extension management: a reply naming a host location'],
		];
		for (const [name, m, leak] of mutants) {
			const [pf, pt] = m.patch ?? ['', ''];
			const [ff, ft] = m.filter ?? ['', ''];
			if (m.patch) {
				assert.equal(PATCH.split(pf).length - 1, 1, `mutant text not found once in the patch: ${name}`);
			}
			if (m.filter) {
				assert.equal(FILTER.split(ff).length - 1, 1, `mutant text not found once in the filter: ${name}`);
			}
			const found = await leaks(build(true, m.patch ? PATCH.replace(pf, pt) : PATCH, m.filter ? FILTER.replace(ff, ft) : FILTER));
			assert.ok(found.includes(leak), `mutant not caught by its own leak (${leak}): ${name}; found ${JSON.stringify(found)}`);
		}
	}],
];

let failed = 0;
for (const [name, fn] of tests) {
	try {
		await fn();
		console.log(`ok   ${name}`);
	} catch (e) {
		failed++;
		console.log(`FAIL ${name}\n     ${(e as Error).message.split('\n').join('\n     ')}`);
	}
}
console.log(failed ? `${failed} failed` : `${tests.length} passed`);
process.exitCode = failed ? 1 : 0;
