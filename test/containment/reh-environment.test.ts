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
import { existsSync, readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { posix, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SRC = process.env.SECLAB_WORKBENCH_SRC;
if (!SRC) {
	console.error('reh-environment: set SECLAB_WORKBENCH_SRC to the pinned src/vs/workbench (./seclab test reh-environment does)');
	process.exit(1);
}
// Absent on a tree without the patch (main before it), where the suite runs upstream's code.
const PATCH_FILE = join(REPO, 'patches', '0059-seclab-tab-server-environment-stays-in-the-tab.patch');
const PATCH = existsSync(PATCH_FILE) ? readFileSync(PATCH_FILE, 'utf8') : '';
const FILTER = readFileSync(join(REPO, 'rpc-filter', 'patch-src', 'seclabRpcFilter.ts'), 'utf8');
const FILES = {
	environment: 'services/remote/common/remoteAgentEnvironmentChannel.ts',
	agent: 'services/remote/common/abstractRemoteAgentService.ts',
	profiles: 'services/userDataProfile/common/remoteUserDataProfiles.ts',
	watcher: 'services/remote/common/remoteFileSystemProviderClient.ts',
	scanner: 'services/remote/common/remoteExtensionsScanner.ts',
	extensions: 'services/extensionManagement/electron-browser/extensionManagementServerService.ts',
	loggers: 'contrib/remote/common/remote.contribution.ts',
	native: 'services/extensionManagement/electron-browser/nativeExtensionManagementService.ts',
	remoteManagement: 'services/extensionManagement/electron-browser/remoteExtensionManagementService.ts',
	mcpDiscovery: 'contrib/mcp/common/discovery/nativeMcpRemoteDiscovery.ts',
	mcpGlobal: 'contrib/mcp/common/mcpCopilotGlobalConfigurationService.ts',
	mcpManagement: 'services/mcp/common/mcpWorkbenchManagementService.ts',
	workbench: 'contrib/extensions/browser/extensionsWorkbenchService.ts',
	actions: 'contrib/extensions/browser/extensionsActions.ts',
	management: 'services/extensionManagement/common/extensionManagementService.ts',
	enablement: 'services/extensionManagement/browser/extensionEnablementService.ts',
	migration: 'contrib/extensions/browser/unsupportedExtensionsMigrationContribution.ts',
	localization: 'contrib/localization/electron-browser/localization.contribution.ts',
	gallery: 'services/extensionManagement/electron-browser/extensionGalleryManifestService.ts',
	main: 'workbench.common.main.ts',
	bisect: 'services/extensionManagement/browser/extensionBisect.ts',
	importExport: 'services/userDataProfile/browser/userDataProfileImportExportService.ts',
	profileResource: 'services/userDataProfile/browser/extensionsResource.ts',
	contribution: 'contrib/extensions/browser/extensions.contribution.ts',
} as const;
type Key = keyof typeof FILES;

/** Apply one file's hunks of a `diff -ruN` patch, each exactly once. */
function applyFile(source: string, patch: string, rel: string): string {
	const sec = patch.split(/^(?=diff -ruN )/m).find(p => p.split('\n')[0].includes(`/workbench/${rel} `));
	if (!sec) {
		return source;
	}
	let out = source;
	for (const hunk of sec.split(/\n(?=@@ )/).slice(1)) {
		const lines = hunk.split('\n').slice(1).filter(l => l.length > 0 && l[0] !== '\\');
		const old = lines.filter(l => l[0] === ' ' || l[0] === '-').map(l => l.slice(1)).join('\n');
		const neu = lines.filter(l => l[0] === ' ' || l[0] === '+').map(l => l.slice(1)).join('\n');
		assert.equal(out.split(old).length - 1, 1, `a 0059 hunk no longer applies to ${rel}`);
		out = out.replace(old, () => neu);
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
const asFunction = (m: string) => m.replace(/^(?:(?:private|protected|public|static|override) )*(async )?/, '$1function ').replace(/^(async )?function ([A-Za-z_$][\w$]*)<[^>(]*>\(/, '$1function $2(');

interface Build {
	sources: Record<Key, string>;
	refusals: string[];
	deps: Record<string, unknown>;
}

function build(patched: boolean, patch = PATCH, filter = FILTER): Build {
	const refusals: string[] = [];
	// A hunk for a file the suite doesn't list would go untested: every section must be one it lists (review ENV-42).
	const listed = new Set(Object.values(FILES).map(rel => `/workbench/${rel} `));
	for (const sec of patched ? patch.split(/^(?=diff -ruN )/m).slice(1) : []) {
		const head = sec.split('\n')[0];
		assert.ok([...listed].some(l => head.includes(l)), `0059 patches a file the suite doesn't list: ${head}`);
	}
	const sources = Object.fromEntries((Object.entries(FILES) as Array<[Key, string]>).map(([k, rel]) => {
		const text = readFileSync(join(SRC!, rel), 'utf8');
		return [k, patched ? applyFile(text, patch, rel) : text];
	})) as Record<Key, string>;
	// The filter's helpers that this version of it has (the suite also runs against reviewed
	// versions of the patch, which had fewer or other ones), and the module-level seclab functions
	// of the patched files.
	const named = (src: string, re: RegExp) => [...src.matchAll(re)].map(m => m[1]);
	const helperNames = named(filter, /\n(?:export )?function (seclab(?:TabUris|TabUri|UriOnTab|TabServerChannel|NoGallerySource|ExtensionManifest|UnrevivedManifest|TabExtensionsChannel|TabMcpChannel|HostExtensionsChannel))\b/g);
	const consts = ['SECLAB_URI_KEYS', 'SECLAB_URI_MARKS', 'SECLAB_MANIFEST_KEYS', 'SECLAB_HOST_EXTENSION_READS'].map(c => new RegExp(`\\nconst ${c}\\b[^\\n]+`).exec(filter)?.[0] ?? '').join('\n');
	const stubs: Record<string, unknown> = {
		seclabIsTabAuthority: (a: unknown) => typeof a === 'string' && /^seclab\+/.test(a),
		seclabRefuseServerLocation: (_a: string, site: string) => { refusals.push(site); },
		seclabRefuseEnvironment: () => { refusals.push('environment'); },
		Schemas: { vscodeRemote: 'vscode-remote', file: 'file' },
	};
	const helpers = evaluate<Record<string, unknown>>(
		`${consts}\n${helperNames.map(n => slice(filter, new RegExp(`\\n(?:export )?function ${n}(?:<T>)?\\(`))!.replace(/^export /, '')).join('\n')}`,
		`{ ${helperNames.join(', ')} }`, stubs);
	const moduleNames = [...new Set(Object.values(sources).flatMap(src => named(src, /\nfunction (seclab\w+)\(/g)))];
	const modules = evaluate<Record<string, unknown>>(
		moduleNames.map(n => Object.values(sources).map(src => slice(src, new RegExp(`\\nfunction ${n}\\(`))).find(Boolean)!).join('\n'),
		`{ ${moduleNames.join(', ')} }`, { ...stubs, ...helpers });
	const deps: Record<string, unknown> = {
		...stubs,
		...helpers,
		...modules,
		URI: { revive: (u: unknown) => u },
		revive: (v: unknown) => v,
		ProtocolConstants: { ReconnectionGraceTime: 10800000 },
		Event: {},
		platform: { language: 'en' },
		CancellationToken: { None: {} },
		posix,
		Promises: { settled: (ps: Promise<unknown>[]) => Promise.all(ps) },
		areSameExtensions: (a: { id: string }, b: { id: string }) => a.id === b.id,
		nls: { localize: (_k: string, m: string) => m },
		localize: (_k: string, m: string) => m,
		IWorkbenchEnvironmentService: {},
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
	// ENV-11: URI.revive reads a bare `{path}` as a file URI.
	['a host path with no other URI key', r => { r.userHome = { path: '/Users/someone' }; }],
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

/**
 * The seclab function a source wraps a channel in, found by the call around `getChannel(…)` (or
 * undefined: upstream hands the raw channel on). Called as `(raw, authority, site, skipKeys)`;
 * each version's wrapper takes the arguments it needs.
 */
function wrapper(b: Build, source: string, call: RegExp): ((raw: Channel, authority: string, site: string, skipKeys?: Set<string>) => Channel) | undefined {
	const name = call.exec(source)?.[1];
	const fn = name ? b.deps[name] : undefined;
	assert.ok(!name || typeof fn === 'function', `${name} wraps a channel, but this build has no such function`);
	return fn as ((raw: Channel, authority: string, site: string, skipKeys?: Set<string>) => Channel) | undefined;
}
interface Channel {
	call(command: string, arg?: unknown): Promise<unknown>;
	listen(event: string, arg?: unknown): (l: (e: unknown) => void) => { dispose(): void };
}

/** The channel the profiles service gets: patched, the wrapper; else the raw channel. */
async function profiles(b: Build, authority: string, reply: unknown, event: unknown): Promise<{ replyRefused: boolean; events: unknown[] }> {
	const raw = { call: async () => structuredClone(reply), listen: () => (l: (e: unknown) => void) => { l(structuredClone(event)); return { dispose() { } }; } };
	// Patched, the service is given seclabTabServerChannel(…, 'profiles'); upstream, the raw channel.
	const channel = wrapper(b, b.sources.profiles, /(seclab\w+)\(connection\.getChannel\('userDataProfiles'\)/)?.(raw, authority, 'profiles') ?? raw;
	let replyRefused = false;
	try {
		await channel.call('createProfile');
	} catch (e) {
		assert.match((e as Error).message, /outside the tab/);
		replyRefused = true;
	}
	const events: unknown[] = [];
	channel.listen('onDidChangeProfiles')((e: unknown) => events.push(e));
	return { replyRefused, events };
}

/** The extension management channel: patched, seclabTabExtensionsChannel; else raw. */
function managementChannel(b: Build, authority: string, reply: unknown, event: unknown) {
	const raw = { call: async () => structuredClone(reply), listen: () => (l: (e: unknown) => void) => { l(structuredClone(event)); return { dispose() { } }; } };
	return wrapper(b, b.sources.extensions, /(seclab\w+)\(remoteAgentConnection\.getChannel<IChannel>\('extensions'\)/)?.(raw, authority, 'extension-management', new Set(['manifest'])) ?? raw;
}

async function management(b: Build, authority: string, reply: unknown, event: unknown, command = 'getInstalled', eventName = 'onDidInstallExtensions'): Promise<{ replyRefused: boolean; reply?: unknown; events: unknown[] }> {
	const channel = managementChannel(b, authority, reply, event);
	let replyRefused = false;
	let got: unknown;
	try {
		got = await channel.call(command);
	} catch (e) {
		assert.match((e as Error).message, /outside the tab/);
		replyRefused = true;
	}
	const events: unknown[] = [];
	channel.listen(eventName)((e: unknown) => events.push(e));
	return { replyRefused, reply: got, events };
}

/** The remote logger channel: patched, wrapped with site 'loggers'; else raw. Returns what the window registers. */
async function loggers(b: Build, authority: string, registered: unknown[], event: unknown): Promise<{ replyRefused: boolean; events: unknown[] }> {
	const raw = { call: async () => structuredClone(registered), listen: () => (l: (e: unknown) => void) => { l(structuredClone(event)); return { dispose() { } }; } };
	const channel = wrapper(b, b.sources.loggers, /new RemoteLoggerChannelClient\(loggerService, (seclab\w+)\(channel,/)?.(raw, authority, 'loggers') ?? raw;
	let replyRefused = false;
	try {
		await channel.call('getRegisteredLoggers');
	} catch (e) {
		assert.match((e as Error).message, /outside the tab/);
		replyRefused = true;
	}
	const events: unknown[] = [];
	channel.listen('onDidChangeLoggers')((e: unknown) => events.push(e));
	return { replyRefused, events };
}

/** Whether the host's extension management, in a window on `authority`, installs a package from `vsix`. */
// NFC, as a workspace folder's URI carries it; ENV-21 sends it NFD.
const WS = '/Users/someone/proj\u00e9cts/ws';
async function hostInstall(b: Build, authority: string, vsix: { scheme: string; path?: string }): Promise<boolean> {
	const fn = evaluate<(v: unknown) => Promise<unknown>>(
		asFunction(slice(b.sources.native, /\n\toverride async install\(/)!).replace('super.install(', 'this.superInstall('), 'install', { ...b.deps, Schemas: { vscodeRemote: 'vscode-remote', file: 'file' } });
	let installed = false;
	try {
		await fn.call({
			nativeEnvironmentService: { remoteAuthority: authority },
			seclabWorkspace: { getWorkspace: () => ({ folders: [{ uri: remote(authority, `${WS}/`) }] }) },
			downloadVsix: async (v: unknown) => ({ location: v, cleanup: async () => { } }),
			superInstall: async () => { installed = true; },
		}, vsix);
	} catch (e) {
		// Only the patch's own refusal counts; any other error is the suite's.
		assert.match((e as Error).message, /sandboxed tab/);
	}
	return installed;
}

/** Whether the host installs the extensions a tab server's reply manifest names (packs, dependencies). */
async function hostDependencies(b: Build, authority: string): Promise<boolean> {
	const fn = evaluate<(l: unknown) => Promise<void>>(asFunction(slice(b.sources.remoteManagement, /\n\tprivate async installUIDependenciesAndPackedExtensions\(/)!), 'installUIDependenciesAndPackedExtensions', b.deps);
	let installed = false;
	await fn.call({
		seclabEnvironment: { remoteAuthority: authority },
		getAllUIDependenciesAndPackedExtensions: async (m: { extensionPack?: string[] }) => (m.extensionPack ?? []).map(id => ({ identifier: { id } })),
		localExtensionManagementServer: { extensionManagementService: { getInstalled: async () => [], installFromGallery: async () => { installed = true; } } },
		logService: { info: () => { } },
	}, { identifier: { id: 'tab.pack' }, manifest: { name: 'pack', extensionPack: ['attacker.ui-ext'] } });
	return installed;
}

/** The failed installs a tab server reports, as the window's startup retry would see them. */
async function failedInstalls(b: Build, authority: string): Promise<number> {
	const fn = evaluate<() => Promise<{ failed: unknown[] }>>(asFunction(slice(b.sources.scanner, /\n\t(?:async )?whenExtensionsReady\(/)!), 'whenExtensionsReady', b.deps);
	const r = await fn.call({
		withChannel: (cb: (c: unknown) => Promise<unknown>) => cb({ call: async () => ({ failed: [{ id: 'attacker.ext', installOptions: { profileLocation: HOST } }] }) }),
		environmentService: { remoteAuthority: authority },
	});
	return r.failed.length;
}

/** Whether a tab server's MCP discovery reply naming host directories reaches the window, at `site`. */
async function mcpDiscovery(b: Build, source: string, authority: string): Promise<boolean> {
	const raw = { call: async () => ({ platform: 1, homedir: { $mid: 1, scheme: 'file', authority: '', path: '/Users/someone' }, copilotHome: { $mid: 1, scheme: 'file', authority: '', path: '/Users/someone/.copilot' } }), listen: () => () => ({ dispose() { } }) };
	const channel = wrapper(b, source, /INativeMcpDiscoveryHelperService>\((seclab\w+)\(channel,/)?.(raw, authority, 'mcp-discovery') ?? raw;
	try {
		await channel.call('load');
		return true;
	} catch (e) {
		assert.match((e as Error).message, /outside the tab/);
		return false;
	}
}

/** The tab server's MCP management channel: whether a reply naming a host readme reaches the window, and a genuine reply. */
async function mcpManagement(b: Build, authority: string, reply: unknown, event?: unknown): Promise<{ refused: boolean; reply?: unknown; events: unknown[] }> {
	const raw = { call: async () => structuredClone(reply), listen: () => (l: (e: unknown) => void) => { if (event !== undefined) { l(structuredClone(event)); } return { dispose() { } }; } };
	const name = /(seclab\w+)\(remoteAgentConnection\.getChannel<IChannel>\('mcpManagement'\)/.exec(b.sources.mcpManagement)?.[1];
	const channel = name ? (b.deps[name] as (c: unknown, a: string, s: string, k: unknown) => typeof raw)(raw, authority, 'mcp-management', b.deps.seclabUnrevivedManifest) : raw;
	const events: unknown[] = [];
	channel.listen('onDidInstallMcpServers')((e: unknown) => events.push(e));
	try {
		return { refused: false, reply: await channel.call('getInstalled'), events };
	} catch (e) {
		assert.match((e as Error).message, /outside the tab/);
		return { refused: true, events };
	}
}
/**
 * The workbench's extension management with a host and a tab server: which servers an update of,
 * and an uninstall of, a tab extension whose manifest says it is a language pack reach.
 */
async function languagePackFanOut(b: Build, authority: string): Promise<{ updated: string[]; uninstalled: string[] }> {
	const updated: string[] = [];
	const uninstalled: string[] = [];
	const ext = { identifier: { id: 'attacker.pack' }, location: remote(authority, '/ext'), manifest: { name: 'pack', main: './x.js', contributes: { localizations: [{ languageId: 'fr' }] } } };
	const server = (id: string) => ({
		id, extensionManagementService: {
			installFromGallery: async () => { updated.push(id); return ext; },
			getInstalled: async () => [{ ...ext, isBuiltin: false }],
		},
	});
	const local = server('local');
	const tab = server('remote');
	const self: Record<string, unknown> = {
		servers: [local, tab],
		extensionManagementServerService: { localExtensionManagementServer: local, remoteExtensionManagementServer: tab, webExtensionManagementServer: null },
		instantiationService: { invokeFunction: (f: (a: unknown) => unknown) => f({ get: () => ({ remoteAuthority: authority }) }) },
		getServer: () => tab,
		uninstallExtensionFromWorkspace: async () => { },
		uninstallInServer: async (srv: { id: string }) => { uninstalled.push(srv.id); },
	};
	const deps = { ...b.deps, isLanguagePackExtension: (m: { contributes?: { localizations?: unknown[] } }) => !!m?.contributes?.localizations?.length, areSameExtensions: (a: { id: string }, c: { id: string }) => a.id === c.id };
	const guard = slice(b.sources.management, /\n\tprivate seclabFromTab\(/);
	if (guard) {
		self.seclabFromTab = evaluate<(...a: unknown[]) => boolean>(asFunction(guard), 'seclabFromTab', { ...deps, IWorkbenchEnvironmentService: {} });
	}
	await evaluate<(...a: unknown[]) => Promise<unknown>>(asFunction(slice(b.sources.management, /\n\tasync updateFromGallery\(/)!), 'updateFromGallery', { ...deps, Promises: { settled: (ps: Promise<unknown>[]) => Promise.all(ps) } }).call(self, { identifier: { id: 'attacker.pack' } }, ext);
	await evaluate<(...a: unknown[]) => Promise<unknown>>(asFunction(slice(b.sources.management, /\n\tasync uninstallExtensions\(/)!), 'uninstallExtensions', deps).call(self, [{ extension: ext }]);
	return { updated: updated.sort(), uninstalled: uninstalled.sort() };
}

/** Every command a window can send the host's extension management that changes it. */
const HOST_CHANGES = ['install', 'installFromLocation', 'installExtensionsFromProfile', 'installFromGallery', 'installGalleryExtensions', 'uninstall', 'uninstallExtensions',
	'toggleApplicationScope', 'copyExtensions', 'updateMetadata', 'resetPinnedStateForAllUserExtensions', 'cleanUp'];
// `download` fills the host's download cache to install in the tab (review ENV-35).
const HOST_READS = ['getInstalled', 'getManifest', 'getTargetPlatform', 'getExtensionsControlManifest', 'zip', 'download'];

/** The commands that reach the host's extension management from a window on `authority`. */
async function hostManagement(b: Build, authority: string): Promise<string[]> {
	const reached: string[] = [];
	const raw = { call: async (command: string) => { reached.push(command); return undefined; }, listen: () => () => ({ dispose() { } }) };
	const name = /createInstance\(NativeExtensionManagementService, (seclab\w+)\(sharedProcessService\.getChannel\('extensions'\)/.exec(b.sources.extensions)?.[1];
	const channel = name ? (b.deps[name] as (c: unknown, a: string) => typeof raw)(raw, authority) : raw;
	for (const command of [...HOST_CHANGES, ...HOST_READS]) {
		try {
			await channel.call(command);
		} catch (e) {
			assert.match((e as Error).message, /does not change the host/);
		}
	}
	return reached;
}

/** The extensions whose enablement changes when a tab window enables a tab extension whose pack names a host one. */
async function enablement(b: Build, authority: string, state = 2): Promise<string[]> {
	const changed: string[] = [];
	const own = { identifier: { id: 'tab.pack' }, location: { scheme: 'vscode-remote', authority, path: '/ext' } };
	const host = { identifier: { id: 'host.ext' }, location: { scheme: 'file', authority: '', path: '/Users/someone/.vscode/extensions/host.ext' } };
	const set = evaluate<(...a: unknown[]) => Promise<unknown>>(asFunction(slice(b.sources.enablement, /\n\tasync setEnablement\(/)!), 'setEnablement', {
		...b.deps, EnablementState: { EnabledGlobally: 1, EnabledWorkspace: 2, DisabledGlobally: 3, DisabledWorkspace: 4, DisabledByTrustRequirement: 5, DisabledByExtensionDependency: 6 },
	}).call({
		extensionsManager: { whenInitialized: async () => { }, extensions: [own, host] },
		getExtensionsToEnableRecursively: () => [host],
		throwErrorIfCannotChangeEnablement: () => { },
		throwErrorIfCannotChangeWorkspaceEnablement: () => { },
		getEnablementState: () => 3,
		isEnabledEnablementState: () => false,
		getDependenciesEnablementStates: () => [],
		_setUserEnablementState: async (e: { identifier: { id: string } }) => { changed.push(e.identifier.id); return true; },
		environmentService: { remoteAuthority: authority },
		_onEnablementChanged: { fire: () => { } },
	}, [own], state);
	try {
		await set;
	} catch (e) {
		assert.match((e as Error).message, /for the workspace/);
	}
	return changed;
}

/**
 * The host's global enablement in a window on `authority`: whether a click enables or disables a
 * host extension's id there, and whether an install event from the tab reaches its reset.
 */
async function globalEnablement(b: Build, authority: string): Promise<{ written: string[]; events: boolean }> {
	const written: string[] = [];
	const cls = b.sources.enablement.indexOf('export class SeclabGlobalExtensionEnablementService');
	if (cls < 0) {
		// Upstream's: every write lands, and the extension management's events reach it.
		return { written: ['enable', 'disable'], events: true };
	}
	const src = b.sources.enablement.slice(cls);
	const NONE = () => ({ dispose() { } });
	const ctor = slice(src, /\n\tconstructor\(/)!.replace(/^constructor/, 'function make').replace(/@I\w+ /g, '').replace('super(', 'this.superArgs = (');
	const self: Record<string, unknown> = {
		superEnable: async () => { written.push('enable'); return true; },
		superDisable: async () => { written.push('disable'); return true; },
	};
	const deps = { ...b.deps, Event: { None: NONE } };
	evaluate<(...a: unknown[]) => void>(ctor, 'make', deps).call(self, {}, { onDidInstallExtensions: () => NONE() }, { remoteAuthority: authority });
	self.seclabRefused = evaluate(asFunction(slice(src, /\n\tprivate seclabRefused\(/)!), 'seclabRefused', deps);
	for (const [name, sup] of [['enableExtension', 'superEnable'], ['disableExtension', 'superDisable']]) {
		const m = asFunction(slice(src, new RegExp(`\\n\\toverride async ${name}\\(`))!.replace(/^(async )?function override /, '$1function ')).replace(`super.${name}(`, `this.${sup}(`);
		await evaluate<(...a: unknown[]) => Promise<unknown>>(m, name, deps).call(self, { id: 'host.ext' });
	}
	const ems = (self.superArgs as unknown as unknown[] | undefined);
	return { written, events: (self.superArgs as { onDidInstallExtensions?: unknown } | undefined)?.onDidInstallExtensions !== NONE && ems !== undefined };
}

/** Whether the localization contribution listens to install and uninstall events in a window on `authority`. */
function localization(b: Build, authority: string): boolean {
	let listens = false;
	const ctor = slice(b.sources.localization, /\n\tconstructor\(/)!.replace(/^constructor/, 'function make').replace(/@I\w+ /g, '').replace(/(?:private|protected|public) readonly /g, '').replace('super();', '');
	evaluate<(...a: unknown[]) => void>(ctor, 'make', b.deps).call({
		checkAndInstall: () => { }, _register: (d: unknown) => d,
		extensionManagementService: { onDidInstallExtensions: () => { listens = true; }, onDidUninstallExtension: () => { listens = true; } },
	}, {}, {}, {}, {}, { onDidInstallExtensions: () => { listens = true; }, onDidUninstallExtension: () => { listens = true; } }, {}, {}, {}, { remoteAuthority: authority });
	return listens;
}

/** The marketplace access token each channel gets, in a window whose server is `authority`. */
function galleryTokens(b: Build, authority: string): Record<string, unknown> {
	const src = b.sources.gallery;
	const start = src.indexOf('const channels');
	const code = src.slice(start, src.indexOf('this.getExtensionGalleryManifest().then', start));
	const sent: Record<string, unknown> = {};
	const channel = (name: string) => ({ call: (_c: string, a: unknown[]) => { sent[name] = a[1]; return Promise.resolve(); } });
	const update = evaluate<(...a: unknown[]) => (m: unknown) => void>(`function make(sharedProcessService, remoteAgentService) {\n${code}\nreturn updateChannels;\n}`, 'make', b.deps)
		.call({ extensionGalleryAccessToken: 'TOKEN', extensionGalleryServiceIndexUrl: 'x', logService: { trace: () => { }, error: () => { } } },
			{ getChannel: () => channel('shared') }, { getConnection: () => ({ remoteAuthority: authority, getChannel: () => channel('remote') }) });
	update(null);
	return sent;
}

/** Whether a publisher trusted in a window on `authority` is kept for later installs. */
function trustKept(b: Build, authority: string): boolean {
	let stored = false;
	evaluate<(...a: unknown[]) => void>(asFunction(slice(b.sources.management, /\n\ttrustPublishers\(/)!), 'trustPublishers', { ...b.deps, TrustedPublishersStorageKey: 'k', StorageScope: { APPLICATION: -1 }, StorageTarget: { USER: 0 } }).call({
		instantiationService: { invokeFunction: (f: (a: unknown) => unknown) => f({ get: () => ({ remoteAuthority: authority }) }) },
		getTrustedPublishersFromStorage: () => ({}),
		storageService: { store: () => { stored = true; } },
	}, { publisher: 'p', publisherDisplayName: 'P' });
	return stored;
}

/** Whether the one-time migrations that write host-shared state run in a window on `authority`: publisher trust, the built-in chat extension's enablement. */
function migrations(b: Build, authority: string): string[] {
	const ran: string[] = [];
	const cls = b.sources.contribution.slice(b.sources.contribution.indexOf('class TrustedPublishersInitializer'));
	const ctor = slice(cls, /\n\tconstructor\(/)!.replace(/^constructor/, 'function make').replace(/@I\w+ /g, '');
	evaluate<(...a: unknown[]) => void>(ctor, 'make', { ...b.deps, StorageScope: { APPLICATION: -1 }, StorageTarget: { MACHINE: 1 }, ExtensionType: { User: 1 } })(
		{ getInstalled: () => { ran.push('publisher trust'); return new Promise(() => { }); } }, { profiles: [{}] }, {}, { get: () => undefined, store: () => { } }, { remoteAuthority: authority });
	// The chat migration reads its flag only when it may run (and stops there: the flag says it ran).
	const read: string[] = [];
	evaluate<() => void>(asFunction(slice(b.sources.enablement, /\n\tprivate ensureChatExtensionInitialDisabledState\(/)!), 'ensureChatExtensionInitialDisabledState', { ...b.deps, StorageScope: { PROFILE: 0 } }).call({
		_chatExtensionId: 'chat', environmentService: { remoteAuthority: authority, isSessionsWindow: false },
		storageService: { getBoolean: () => { read.push('chat'); return true; } },
	});
	return [...ran, ...read.map(() => 'chat enablement')];
}

/** Which host-shared extension settings a window on `authority` changes: bisect, auto-update, publisher trust removed, a profile from a template. */
async function hostSettings(b: Build, authority: string): Promise<string[]> {
	const changed: string[] = [];
	const attempt = async (what: string, f: () => Promise<unknown> | unknown) => {
		try {
			await f();
		} catch (e) {
			assert.match((e as Error).message, /sandboxed tab/);
		}
		void what;
	};
	await attempt('bisect', () => evaluate<(...a: unknown[]) => Promise<void>>(asFunction(slice(b.sources.bisect, /\n\tasync start\(/)!), 'start', { ...b.deps, StorageScope: { APPLICATION: -1 }, StorageTarget: { MACHINE: 1 }, BisectState: class { }, ExtensionBisectService: { _storageKey: 'k' } }).call({
		_envService: { remoteAuthority: authority }, isActive: false, _state: undefined,
		_storageService: { store: () => { changed.push('bisect'); }, flush: async () => { } },
	}, [{ identifier: { id: 'host.ext' } }]));
	await attempt('auto-update', () => evaluate<(...a: unknown[]) => Promise<void>>(asFunction(slice(b.sources.workbench, /\n\tasync updateAutoUpdateEnablementFor\(/)!), 'updateAutoUpdateEnablementFor', { ...b.deps, isString: (v: unknown) => typeof v === 'string' }).call({
		seclabEnvironment: { remoteAuthority: authority },
		isAutoUpdateEnabled: () => false, isAutoUpdateEnabledFor: () => true,
		extensionManagementService: { updateMetadata: async () => { changed.push('auto-update'); } },
		getPublishersToAutoUpdate: () => [], setPublishersToAutoUpdate: () => { changed.push('auto-update'); },
		getEnabledAutoUpdateExtensions: () => [], setEnabledAutoUpdateExtensions: () => { changed.push('auto-update'); },
		getDisabledAutoUpdateExtensions: () => [], setDisabledAutoUpdateExtensions: () => { changed.push('auto-update'); },
		_onChange: { fire: () => { } }, _onDidChangeExtensionsAutoUpdate: { fire: () => { } }, local: [], updateExtensionsPinnedState: async () => { },
	}, { identifier: { id: 'host.ext' }, publisher: 'host', local: { pinned: false } }, false));
	await attempt('untrust', () => evaluate<(...a: unknown[]) => void>(asFunction(slice(b.sources.management, /\n\tuntrustPublishers\(/)!), 'untrustPublishers', { ...b.deps, TrustedPublishersStorageKey: 'k', StorageScope: { APPLICATION: -1 }, StorageTarget: { USER: 0 } }).call({
		instantiationService: { invokeFunction: (f: (a: unknown) => unknown) => f({ get: () => ({ remoteAuthority: authority }) }) },
		getTrustedPublishersFromStorage: () => ({ host: {} }),
		storageService: { store: () => { changed.push('untrust'); } },
	}, 'host'));
	await attempt('sync ignore', () => evaluate<(...a: unknown[]) => Promise<void>>(asFunction(slice(b.sources.workbench, /\n\tasync toggleExtensionIgnoredToSync\(/)!), 'toggleExtensionIgnoredToSync', b.deps).call({
		seclabEnvironment: { remoteAuthority: authority }, local: [], getAllPackedExtensions: () => [], isExtensionIgnoredToSync: () => false,
		extensionsSyncManagementService: { updateIgnoredExtensions: async () => { changed.push('sync ignore'); } },
		userDataAutoSyncService: { triggerSync: async () => { } },
	}, { identifier: { id: 'host.ext' } }));
	const guard = slice(b.sources.importExport, /\n\tprivate seclabNoImport\(/);
	const self = {
		instantiationService: { invokeFunction: (f: (a: unknown) => unknown) => f({ get: () => ({ remoteAuthority: authority }) }) },
		getProfileToImport: async () => { changed.push('profile import'); return undefined; },
		seclabNoImport: guard ? evaluate(asFunction(guard), 'seclabNoImport', b.deps) : () => { },
	};
	await attempt('import', () => evaluate<(...a: unknown[]) => Promise<unknown>>(asFunction(slice(b.sources.importExport, /\n\tprivate async doCreateProfile\(/)!), 'doCreateProfile', b.deps).call(self, {}, false, true, undefined, () => { }));
	return changed;
}

/** Which "AI features" actions a tab extension claiming the chat extension's id is offered in a window on `authority`. */
function aiActions(b: Build, authority: string): string[] {
	const offered: string[] = [];
	for (const name of ['EnableAIFeaturesGloballyAction', 'DisableAIFeaturesGloballyAction']) {
		const cls = b.sources.actions.slice(b.sources.actions.indexOf(`class ${name} `));
		const self = {
			enabled: false,
			extension: { identifier: { id: 'pub.chat' }, local: { location: { scheme: 'vscode-remote', authority, path: '/ext' } }, enablementState: 1, state: 1 },
			productService: { defaultChatAgent: { chatExtensionId: 'pub.chat' } },
			configurationService: { inspect: () => ({ value: true }), getValue: () => false },
		};
		evaluate<() => void>(asFunction(slice(cls, /\n\tupdate\(/)!), 'update', {
			...b.deps, ExtensionIdentifier: { equals: (a: string, c: string) => a === c }, EnablementState: { DisabledWorkspace: 4, EnabledWorkspace: 2 }, ExtensionState: { Installed: 1 }, ChatAIDisabledSettingId: 'chat.disableAIFeatures',
		}).call(self);
		if (self.enabled) {
			offered.push(name);
		}
	}
	return offered;
}

/** Whether the unsupported-extensions migration runs on the tab's server in a window on `authority`. */
function migration(b: Build, authority: string): boolean {
	let ran = false;
	// Parameter decorators aren't JavaScript: dropped before evaluating.
	const ctor = slice(b.sources.migration, /\n\tconstructor\(/)!.replace(/^constructor/, 'function migrate').replace(/@I\w+ /g, '');
	evaluate<(...a: unknown[]) => void>(ctor, 'migrate', { ...b.deps, migrateUnsupportedExtensions: () => { ran = true; } })(
		{ remoteExtensionManagementServer: { extensionManagementService: {} }, webExtensionManagementServer: null }, {}, {}, {}, {}, { remoteAuthority: authority });
	return ran;
}

const ICON = { dark: 'https://198.51.100.7/i.png', light: 'https://198.51.100.7/i.png' };

/** Whether "Install Locally" (installInServer to the host) of a tab server's extension reaches the install. */
async function installLocally(b: Build, authority: string): Promise<boolean> {
	const fn = evaluate<(e: unknown, s: unknown) => Promise<void>>(asFunction(slice(b.sources.workbench, /\n\tasync installInServer\(/)!), 'installInServer', b.deps);
	const localServer = { id: 'local' };
	let installed = false;
	try {
		await fn.call({
			seclabEnvironment: { remoteAuthority: authority },
			extensionManagementServerService: { localExtensionManagementServer: localServer },
			doInstall: async () => { installed = true; },
		}, { identifier: { id: 'attacker.ext' } }, localServer);
	} catch (e) {
		assert.match((e as Error).message, /sandboxed tab/);
	}
	return installed;
}

/** Whether "Install Remote Extensions Locally..." installs the gallery entry a tab server's extension names on the host. */
async function installRemoteLocally(b: Build, authority: string): Promise<boolean> {
	const cls = b.sources.actions.slice(b.sources.actions.indexOf('export class InstallRemoteExtensionsInLocalAction'));
	const fn = evaluate<(e: unknown[]) => Promise<void>>(asFunction(slice(cls, /\n\tprotected async installExtensions\(/)!), 'installExtensions', b.deps);
	let installed = false;
	try {
		await fn.call({
			seclabEnvironment: { remoteAuthority: authority },
			extensionGalleryService: { isEnabled: () => true, getExtensions: async () => [{ identifier: { id: 'attacker.ext' } }] },
			extensionManagementServerService: { localExtensionManagementServer: { extensionManagementService: { getTargetPlatform: async () => 'darwin-arm64', installFromGallery: async () => { installed = true; }, install: async () => { installed = true; } } } },
			fileService: { del: async () => { } },
			logService: { error: () => { } },
		}, [{ identifier: { id: 'attacker.ext' }, local: {} }]);
	} catch (e) {
		assert.match((e as Error).message, /sandboxed tab/);
	}
	return installed;
}
const mcpServer = (authority: string, readme: unknown) => ({
	name: 'srv', config: { type: 'stdio', command: 'node', args: ['s.js'] }, mcpResource: remote(authority, '/home/agent/.seclab-reh/data/User/mcp.json'),
	readmeUrl: readme, manifest: { name: 'srv', packages: [{ registryType: 'npm', identifier: 'x', transport: { type: 'stdio' } }], remotes: [{ type: 'sse', url: 'http://192.0.2.1/', scheme: 'https', path: '/' }] },
});

const GALLERY = { identifier: { id: 'tab.ext', uuid: '00000000-0000-4000-8000-000000000000' }, name: 'ext', version: '1.0.0', assets: { manifest: { uri: 'http://192.0.2.1/m', fallbackUri: 'http://192.0.2.1/m' }, download: { uri: 'http://192.0.2.1/x.vsix', fallbackUri: 'http://192.0.2.1/x.vsix' } } };
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
	for (const eventName of ['onInstallExtension', 'onDidInstallExtensions']) {
		const g = await management(b, TAB, [], [{ identifier: { id: 'tab.ext' }, source: GALLERY, profileLocation: remote(TAB, '/p') }], 'getInstalled', eventName);
		if (JSON.stringify(g.events).includes('192.0.2.1')) {
			out.push(`extension management: ${eventName} carrying a gallery entry`);
		}
	}
	if (await hostInstall(b, TAB, remote(TAB, '/home/agent/x.vsix'))) {
		out.push('a tab package installs on the host');
	}
	if (await hostInstall(b, TAB, { scheme: 'file', path: `${WS.toUpperCase()}/out/x.vsix` })) {
		out.push('a host file in the tab workspace installs on the host');
	}
	if (await hostInstall(b, TAB, { scheme: 'file', path: `${WS.replace(/\/ws$/, '/other/../ws')}/x.vsix` })) {
		out.push('a host file in the tab workspace by a dot-dot path installs on the host');
	}
	if (await hostInstall(b, TAB, { scheme: 'file', path: `${WS.normalize('NFD')}/x.vsix` })) {
		out.push('a host file in the tab workspace by its NFD path installs on the host');
	}
	if (await mcpDiscovery(b, b.sources.mcpDiscovery, TAB)) {
		out.push('mcp discovery: a reply naming host directories');
	}
	if (await mcpDiscovery(b, b.sources.mcpGlobal, TAB)) {
		out.push('mcp global configuration: a reply naming host directories');
	}
	if (!(await mcpManagement(b, TAB, [mcpServer(TAB, HOST)])).refused) {
		out.push('mcp management: a reply naming a host readme');
	}
	const mi = await mcpManagement(b, TAB, [{ ...mcpServer(TAB, remote(TAB, '/r.md')), icon: ICON, galleryUrl: 'https://198.51.100.7/g', repositoryUrl: 'https://198.51.100.7/r' }],
		[{ name: 'srv', local: { ...mcpServer(TAB, remote(TAB, '/r.md')), icon: ICON }, mcpResource: remote(TAB, '/m.json') }]);
	if (JSON.stringify(mi.reply ?? null).includes('198.51.100.7') || JSON.stringify(mi.events).includes('198.51.100.7')) {
		out.push('mcp management: a server carrying URLs the renderer loads');
	}
	const me = await mcpManagement(b, TAB, [], [{ name: 'srv', local: mcpServer(TAB, HOST), mcpResource: remote(TAB, '/m.json') }]);
	if (me.events.length > 0) {
		out.push('mcp management: an event naming a host readme');
	}
	const mr = await mcpManagement(b, TAB, [{ ...mcpServer(TAB, remote(TAB, '/r.md')), config: { type: 'stdio', command: 'node', env: { HOME: HOST } } }]);
	if (!mr.refused) {
		out.push('mcp management: a host location as a config record value');
	}
	if (await installLocally(b, TAB)) {
		out.push('install locally: the host installs what the tab names');
	}
	if ((await hostManagement(b, TAB)).some(c => HOST_CHANGES.includes(c))) {
		out.push('the host takes an extension change from a tab window');
	}
	if ((await enablement(b, TAB)).includes('host.ext')) {
		out.push('a tab extension\'s pack changes a host extension\'s enablement');
	}
	const ge = await globalEnablement(b, TAB);
	if (ge.written.length > 0) {
		out.push('a tab window changes the host\'s global enablement');
	}
	if (ge.events) {
		out.push('a tab\'s install event reaches the host\'s global enablement');
	}
	if (localization(b, TAB)) {
		out.push('a tab\'s install events prompt to change the host\'s display language');
	}
	if (galleryTokens(b, TAB).remote !== undefined) {
		out.push('the tab\'s server gets the marketplace token');
	}
	if (trustKept(b, TAB)) {
		out.push('a publisher trusted in a tab window is trusted for the host');
	}
	if (!/registerSingleton\(IGlobalExtensionEnablementService, SeclabGlobalExtensionEnablementService,/.test(b.sources.main)) {
		out.push('the host\'s global enablement is registered unguarded');
	}
	if (!/createInstance\(SeclabGlobalExtensionEnablementService\)/.test(b.sources.profileResource)) {
		out.push('profile import builds an unguarded enablement service');
	}
	if (migrations(b, TAB).length > 0) {
		out.push('a tab window runs a one-time migration of host state');
	}
	for (const what of new Set(await hostSettings(b, TAB))) {
		out.push(`a tab window changes host extension settings: ${what}`);
	}
	if (aiActions(b, TAB).length > 0) {
		out.push('a tab extension offers the host\'s AI features setting');
	}
	if ((await enablement(b, TAB, 1)).length > 0) {
		out.push('a tab window makes a global enablement change');
	}
	if (migration(b, TAB)) {
		out.push('the unsupported-extensions migration runs on the tab\'s data');
	}
	const fan = await languagePackFanOut(b, TAB);
	if (fan.updated.includes('local')) {
		out.push('a tab language-pack manifest updates on the host');
	}
	if (fan.uninstalled.includes('local')) {
		out.push('a tab language-pack manifest uninstalls on the host');
	}
	const ml = await mcpManagement(b, TAB, [{ ...mcpServer(TAB, remote(TAB, '/r.md')), icon: ICON, local: 0 }]);
	if (JSON.stringify(ml.reply ?? null).includes('198.51.100.7')) {
		out.push('mcp management: a server claiming a local keeps its URLs');
	}
	if (await installRemoteLocally(b, TAB)) {
		out.push('install remote extensions locally: the host installs what the tab names');
	}
	if (await hostDependencies(b, TAB)) {
		out.push('a tab manifest installs its pack on the host');
	}
	if (await failedInstalls(b, TAB) > 0) {
		out.push('the tab server picks installs the window retries');
	}
	const nested = await management(b, TAB, [], [{ identifier: { id: 'tab.ext' }, context: { manifest: { settings: HOST } }, local: local(TAB, remote(TAB, '/ext')), profileLocation: remote(TAB, '/p') }]);
	if (nested.events.length > 0) {
		out.push('extension management: a host location under a manifest key elsewhere');
	}
	const lg = await loggers(b, TAB, [{ id: 'x', name: 'x', resource: HOST }], { added: [{ id: 'y', name: 'y', resource: HOST }], removed: [] });
	if (!lg.replyRefused) {
		out.push('loggers: a reply registering a host file');
	}
	if (lg.events.length > 0) {
		out.push('loggers: an event registering a host file');
	}
	return out;
}
const EVERY_LEAK = [...LIES.map(l => `environment: ${l[0]}`), 'environment: host strings in a revived URI', 'a refused environment reads as no remote',
	'profiles: a reply naming a host file', 'profiles: an event naming a host file', 'watcher: a change to a host file', 'extensions: one in a host directory',
	'host strings kept in a checked tab URI', 'extension management: a reply naming a host location', 'extension management: an event naming a host location',
	'extension management: onInstallExtension carrying a gallery entry', 'extension management: onDidInstallExtensions carrying a gallery entry',
	'a tab package installs on the host', 'a host file in the tab workspace installs on the host',
	'a host file in the tab workspace by a dot-dot path installs on the host', 'a host file in the tab workspace by its NFD path installs on the host',
	'mcp discovery: a reply naming host directories', 'mcp global configuration: a reply naming host directories', 'mcp management: a reply naming a host readme',
	'mcp management: a server carrying URLs the renderer loads', 'mcp management: an event naming a host readme', 'mcp management: a host location as a config record value',
	'install locally: the host installs what the tab names', 'the host takes an extension change from a tab window',
	'a tab extension\'s pack changes a host extension\'s enablement', 'a tab window changes the host\'s global enablement', 'a tab\'s install event reaches the host\'s global enablement',
	'a tab\'s install events prompt to change the host\'s display language', 'the tab\'s server gets the marketplace token', 'a publisher trusted in a tab window is trusted for the host',
	'the host\'s global enablement is registered unguarded', 'profile import builds an unguarded enablement service',
	'a tab window runs a one-time migration of host state', 'a tab window changes host extension settings: bisect',
	'a tab window changes host extension settings: auto-update', 'a tab window changes host extension settings: untrust',
	'a tab window changes host extension settings: sync ignore', 'a tab window changes host extension settings: profile import',
	'a tab extension offers the host\'s AI features setting', 'a tab window makes a global enablement change', 'the unsupported-extensions migration runs on the tab\'s data', 'a tab language-pack manifest updates on the host',
	'a tab language-pack manifest uninstalls on the host', 'mcp management: a server claiming a local keeps its URLs', 'install remote extensions locally: the host installs what the tab names',
	'a tab manifest installs its pack on the host',
	'the tab server picks installs the window retries', 'extension management: a host location under a manifest key elsewhere', 'loggers: a reply registering a host file', 'loggers: an event registering a host file'];

const tests: Array<[string, () => Promise<void>]> = [
	['the baseline takes every location a tab server names', async () => {
		// The control: on main each lie reaches the window, so the patched refusals below mean something.
		assert.deepEqual(await leaks(build(false)), EVERY_LEAK);
	}],
	['a tab window takes none of them, and logs each refusal', async () => {
		const b = build(true);
		assert.deepEqual(await leaks(b), []);
		assert.deepEqual([...new Set(b.refusals)].sort(), ['environment', 'extension-management', 'extensions', 'host-enablement', 'host-install', 'loggers', 'mcp-discovery', 'mcp-management', 'profiles', 'watcher']);
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
		// ENV-12: a manifest reply names files by `path` and labels by `scheme`, and is taken as sent.
		const manifest = local(TAB, null).manifest;
		const gm = await management(b, TAB, manifest, {}, 'getManifest');
		assert.equal(gm.replyRefused, false);
		assert.deepEqual(gm.reply, manifest);
		// An install from a VSIX on the tab keeps its source; only a gallery entry is removed.
		const vsix = await management(b, TAB, [], [{ identifier: { id: 'tab.ext' }, source: remote(TAB, '/x.vsix'), local: local(TAB, remote(TAB, '/ext')), profileLocation: remote(TAB, '/p') }]);
		assert.deepEqual((vsix.events[0] as Array<{ source: unknown }>)[0].source, { ...remote(TAB, '/x.vsix'), query: '', fragment: '' });
		const g = await management(b, TAB, [], [{ identifier: { id: 'tab.ext' }, source: GALLERY, local: local(TAB, remote(TAB, '/ext')), profileLocation: remote(TAB, '/p') }]);
		assert.equal((g.events[0] as Array<{ source: unknown; local: unknown }>)[0].source, undefined);
		assert.ok((g.events[0] as Array<{ local: unknown }>)[0].local);
		const lg = await loggers(b, TAB, [{ id: 'x', name: 'x', resource: remote(TAB, '/logs/x.log') }], { added: [{ id: 'y', name: 'y', resource: remote(TAB, '/logs/y.log') }], removed: [] });
		assert.equal(lg.replyRefused, false);
		assert.equal(lg.events.length, 1);
		// A host VSIX outside the tab's workspace still installs on the host from a tab window.
		assert.equal(await hostInstall(b, TAB, { scheme: 'file', path: '/Users/someone/Downloads/x.vsix' }), true);
		assert.equal(await hostInstall(b, TAB, { scheme: 'file', path: `${WS}-other/x.vsix` }), true);
		// MCP discovery on the tab, and an installed MCP server whose manifest carries URL parts.
		const genuineDiscovery = { call: async () => ({ platform: 3, homedir: remote(TAB, '/home/agent') }), listen: () => () => ({ dispose() { } }) };
		await (wrapper(b, b.sources.mcpDiscovery, /INativeMcpDiscoveryHelperService>\((seclab\w+)\(channel,/)!(genuineDiscovery, TAB, 'mcp-discovery')).call('load');
		const mm = await mcpManagement(b, TAB, [mcpServer(TAB, remote(TAB, '/srv/README.md'))]);
		assert.equal(mm.refused, false);
		// A tab window still reads the host's extensions, and enables the tab's own.
		const before0 = b.refusals.length;
		assert.deepEqual(await hostManagement(b, TAB), HOST_READS);
		assert.deepEqual(await enablement(b, TAB), ['tab.pack']);
		assert.deepEqual([...new Set(b.refusals.splice(before0))], ['host-install']);
		// The host keeps its own marketplace token.
		assert.equal(galleryTokens(b, TAB).shared, 'TOKEN');
		// A tab language pack still updates and uninstalls in the tab.
		const before = b.refusals.length;
		assert.deepEqual(await languagePackFanOut(b, TAB), { updated: ['remote'], uninstalled: ['remote'] });
		// The two fan-outs it refused, and nothing else; every other genuine step must log none (ENV-32).
		assert.deepEqual(b.refusals.splice(before), ['host-install', 'host-install']);
		// ENV-24: env and headers are the config author's records; their keys may be URI key names.
		const rec = await mcpManagement(b, TAB, [{ ...mcpServer(TAB, remote(TAB, '/r.md')), config: { type: 'http', url: 'http://192.0.2.1/', headers: { authority: 'x', path: '/' } } }, { ...mcpServer(TAB, remote(TAB, '/r.md')), config: { type: 'stdio', command: 'node', env: { path: '/usr/bin', scheme: 'a', PORT: 3000, UNSET: null } } }]);
		assert.equal(rec.refused, false);
		assert.deepEqual((mm.reply as Array<{ manifest: unknown }>)[0].manifest, mcpServer(TAB, null).manifest);
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
		assert.equal(JSON.stringify((await management(b, other, [], [{ source: GALLERY }])).events).includes('192.0.2.1'), true);
		assert.equal(await hostInstall(b, other, remote(other, '/x.vsix')), true);
		assert.equal(await hostDependencies(b, other), true);
		assert.equal(await failedInstalls(b, other), 1);
		assert.equal(await mcpDiscovery(b, b.sources.mcpDiscovery, other), true);
		assert.equal((await mcpManagement(b, other, [mcpServer(other, HOST)])).refused, false);
		assert.equal(await installLocally(b, other), true);
		assert.equal(await installRemoteLocally(b, other), true);
		assert.deepEqual(await languagePackFanOut(b, other), { updated: ['local', 'remote'], uninstalled: ['local', 'remote'] });
		assert.deepEqual(await hostManagement(b, other), [...HOST_CHANGES, ...HOST_READS]);
		assert.deepEqual(await enablement(b, other), ['tab.pack', 'host.ext']);
		assert.equal(migration(b, other), true);
		assert.deepEqual(migrations(b, other), ['publisher trust', 'chat enablement']);
		assert.deepEqual([...new Set(await hostSettings(b, other))], ['bisect', 'auto-update', 'untrust', 'sync ignore', 'profile import']);
		assert.deepEqual(aiActions(b, other), ['EnableAIFeaturesGloballyAction', 'DisableAIFeaturesGloballyAction']);
		assert.deepEqual(await enablement(b, other, 1), ['tab.pack', 'host.ext']);
		assert.deepEqual(await globalEnablement(b, other), { written: ['enable', 'disable'], events: true });
		assert.equal(localization(b, other), true);
		assert.deepEqual(galleryTokens(b, other), { shared: 'TOKEN', remote: 'TOKEN' });
		assert.equal(trustKept(b, other), true);
		assert.equal((await loggers(b, other, [{ id: 'x', name: 'x', resource: HOST }], { added: [], removed: [] })).replyRefused, false);
		assert.deepEqual(b.refusals, []);
	}],
	['each mutant of 0059 lets its lie through', async () => {
		const mutants: Array<[string, { patch?: [string, string]; filter?: [string, string] }, string]> = [
			['any scheme', { filter: ["o.scheme !== 'vscode-remote' || ", ''] }, 'environment: a host scheme carrying the tab authority'],
			['any authority', { filter: [' || o.authority !== remoteAuthority', ''] }, 'environment: another tab as mcpResource'],
			['containers may carry URI fields', { filter: ['Object.keys(o).some(k => !SECLAB_URI_KEYS.has(k)) || ', ''] }, 'environment: a URI marker and fields on the reply hiding a host settingsPath'],
			['a URI only when marked $mid 1', { filter: ['		if (SECLAB_URI_MARKS.some(k => Object.hasOwn(o, k))) {', '		if (o.$mid === 1) {'] }, 'environment: a host file marked $mid 2'],
			['only $mid or scheme marks a URI', { filter: ["const SECLAB_URI_MARKS = ['$mid', 'scheme', 'authority', 'path', 'external', 'fsPath', '_sep'];", "const SECLAB_URI_MARKS = ['$mid', 'scheme'];"] }, 'environment: a host fsPath with no scheme or $mid'],
			['path alone does not mark a URI', { filter: ["const SECLAB_URI_MARKS = ['$mid', 'scheme', 'authority', 'path', 'external', 'fsPath', '_sep'];", "const SECLAB_URI_MARKS = ['$mid', 'scheme', 'authority', 'external', 'fsPath', '_sep'];"] }, 'environment: a host path with no other URI key'],
			['deep values pass', { filter: ['		if (at.length > 32) {\n			throw foreign();', '		if (at.length > 32) {\n			return v;'] }, 'environment: a host file nested deeper than the walk'],
			['URIs not rebuilt', { filter: ["			return { $mid: 1, scheme: o.scheme, authority: o.authority, path: o.path ?? '', query: o.query ?? '', fragment: o.fragment ?? '' };", '			return o;'] }, 'environment: host strings in a revived URI'],
			['environment unchecked', { patch: ['+				data = seclabTabUris(remoteAuthority, data);', '+				data = data;'] }, 'environment: the host user settings file as settingsPath'],
			['refusal reads as no remote', { patch: ['+		if (seclabIsTabAuthority(this._environmentService.remoteAuthority)) {\n+			return this.getRawEnvironment();', '+		if (false) {\n+			return this.getRawEnvironment();'] }, 'a refused environment reads as no remote'],
			['channel events unchecked', { filter: ['				checked = check(e) as T;', '				checked = e as T;'] }, 'profiles: an event naming a host file'],
			['profiles channel unwrapped', { patch: ["seclabTabServerChannel(connection.getChannel('userDataProfiles'), connection.remoteAuthority, 'profiles')", "connection.getChannel('userDataProfiles')"] }, 'profiles: a reply naming a host file'],
			['watcher unchecked', { patch: ['+					return resource ? [{ ...(c as object), resource }] : [];', '+					return [c];'] }, 'watcher: a change to a host file'],
			['watcher keeps the sent resource', { patch: ['+					return resource ? [{ ...(c as object), resource }] : [];', '+					return resource ? [c] : [];'] }, 'host strings kept in a checked tab URI'],
			['scan unchecked', { patch: ['+						return location ? [{ ...e, extensionLocation: location }] : [];', '+						return [e];'] }, 'extensions: one in a host directory'],
			['management channel unwrapped', { patch: ["seclabTabExtensionsChannel(remoteAgentConnection.getChannel<IChannel>('extensions'), remoteAgentConnection.remoteAuthority)", "remoteAgentConnection.getChannel<IChannel>('extensions')"] }, 'extension management: a reply naming a host location'],
			['gallery sources kept', { filter: ["			return { ...e, source: undefined };", "			return e;"] }, 'extension management: onDidInstallExtensions carrying a gallery entry'],
			['only one install event stripped', { filter: ["event === 'onInstallExtension' || event === 'onDidInstallExtensions'", "event === 'onDidInstallExtensions'"] }, 'extension management: onInstallExtension carrying a gallery entry'],
			['host install from a tab window', { patch: ["+		if (authority && seclabIsTabAuthority(authority) && (vsix.scheme === Schemas.vscodeRemote || (vsix.scheme === Schemas.file && inTab(vsix.path)))) {", "+		if (false) {"] }, 'a tab package installs on the host'],
			['host files in the tab workspace install', { patch: ["(vsix.scheme === Schemas.vscodeRemote || (vsix.scheme === Schemas.file && inTab(vsix.path)))", "vsix.scheme === Schemas.vscodeRemote"] }, 'a host file in the tab workspace installs on the host'],
			['workspace match is case-sensitive', { patch: [".normalize('NFC').toLowerCase().replace", ".normalize('NFC').replace"] }, 'a host file in the tab workspace installs on the host'],
			['tab manifests install their packs on the host', { patch: ["review ENV-15).\n+		const authority = this.seclabEnvironment.remoteAuthority;\n+		if (authority && seclabIsTabAuthority(authority)) {", "review ENV-15).\n+		const authority = this.seclabEnvironment.remoteAuthority;\n+		if (false) {"] }, 'a tab manifest installs its pack on the host'],
			['startup retries the tab\'s failed installs', { patch: ["+		const authority = this.environmentService.remoteAuthority;\n+		if (authority && seclabIsTabAuthority(authority)) {\n+			if (summary", "+		const authority = this.environmentService.remoteAuthority;\n+		if (false) {\n+			if (summary"] }, 'the tab server picks installs the window retries'],
			['paths compared unresolved', { patch: ["posix.normalize(p).normalize('NFC').toLowerCase()", "p.toLowerCase()"] }, 'a host file in the tab workspace by a dot-dot path installs on the host'],
			['paths compared unnormalised', { patch: [".normalize('NFC').toLowerCase().replace", ".toLowerCase().replace"] }, 'a host file in the tab workspace by its NFD path installs on the host'],
			['mcp discovery unchecked', { patch: ["ProxyChannel.toService<INativeMcpDiscoveryHelperService>(seclabTabServerChannel(channel, connection.remoteAuthority, 'mcp-discovery'));", "ProxyChannel.toService<INativeMcpDiscoveryHelperService>(channel);"] }, 'mcp discovery: a reply naming host directories'],
			['mcp global configuration unchecked', { patch: ["ProxyChannel.toService<INativeMcpDiscoveryHelperService>(seclabTabServerChannel(channel, connection.remoteAuthority, 'mcp-discovery')).load());", "ProxyChannel.toService<INativeMcpDiscoveryHelperService>(channel).load());"] }, 'mcp global configuration: a reply naming host directories'],
			['mcp management unchecked', { patch: ["seclabTabMcpChannel(remoteAgentConnection.getChannel<IChannel>('mcpManagement'), remoteAgentConnection.remoteAuthority)", "remoteAgentConnection.getChannel<IChannel>('mcpManagement')"] }, 'mcp management: a reply naming a host readme'],
			['mcp servers keep their URLs', { filter: ["		const { icon: _i, galleryUrl: _g, repositoryUrl: _r, ...rest } = v as Record<string, unknown>;\n		return rest;", "		return v;"] }, 'mcp management: a server carrying URLs the renderer loads'],
			['mcp events reach the window unchecked', { filter: ["checked.listen<T>(event, arg)(e => listener.call(thisArgs, servers(e) as T), undefined, disposables)", "channel.listen<T>(event, arg)(e => listener.call(thisArgs, servers(e) as T), undefined, disposables)"] }, 'mcp management: an event naming a host readme'],
			['config records take any value', { filter: [" || Object.values(r).some(x => x !== null && typeof x !== 'string' && typeof x !== 'number')", ""] }, 'mcp management: a host location as a config record value'],
			['install locally from a tab window', { patch: ["+		if (authority && seclabIsTabAuthority(authority) && server === this.extensionManagementServerService.localExtensionManagementServer) {", "+		if (false) {"] }, 'install locally: the host installs what the tab names'],
			['install remote extensions locally from a tab window', { patch: ["+		// the tab's server's to name (patch 0059, review ENV-22).\n+		const authority = this.seclabEnvironment.remoteAuthority;\n+		if (authority && seclabIsTabAuthority(authority)) {", "+		// the tab's server's to name (patch 0059, review ENV-22).\n+		const authority = this.seclabEnvironment.remoteAuthority;\n+		if (false) {"] }, 'install remote extensions locally: the host installs what the tab names'],
			['language packs fan out from a tab', { patch: ["+		if (!authority || !seclabIsTabAuthority(authority) || server !== this.extensionManagementServerService.remoteExtensionManagementServer) {", "+		if (true) {"] }, 'a tab language-pack manifest updates on the host'],
			['uninstall fans out from a tab', { patch: ["isLanguagePackExtension(extension.manifest) && !this.seclabFromTab(server)) {\n \t\t\t\tconst otherServers", "isLanguagePackExtension(extension.manifest)) {\n \t\t\t\tconst otherServers"] }, 'a tab language-pack manifest uninstalls on the host'],
			['only a local is stripped', { filter: ["		const s = server(v);", "		const s = v && typeof v === 'object' && Object.hasOwn(v, 'local') ? v : server(v);"] }, 'mcp management: a server claiming a local keeps its URLs'],
			['bisect in a tab window', { patch: ["+		if (seclabIsTabAuthority(this._envService.remoteAuthority)) {\n+			throw new Error('Extension Bisect", "+		if (false) {\n+			throw new Error('Extension Bisect"] }, 'a tab window changes host extension settings: bisect'],
			['auto-update from a tab', { patch: ["(patch 0059, review ENV-45).\n+		const seclabTab = this.seclabEnvironment.remoteAuthority;\n+		if (seclabTab && seclabIsTabAuthority(seclabTab)) {", "(patch 0059, review ENV-45).\n+		const seclabTab = this.seclabEnvironment.remoteAuthority;\n+		if (false) {"] }, 'a tab window changes host extension settings: auto-update'],
			['untrust from a tab', { patch: ["(patch 0059, reviews ENV-46, ENV-50).\n+		const seclabTab = this.instantiationService.invokeFunction(accessor => accessor.get(IWorkbenchEnvironmentService).remoteAuthority);\n+		if (seclabTab && seclabIsTabAuthority(seclabTab)) {", "(patch 0059, reviews ENV-46, ENV-50).\n+		const seclabTab = this.instantiationService.invokeFunction(accessor => accessor.get(IWorkbenchEnvironmentService).remoteAuthority);\n+		if (false) {"] }, 'a tab window changes host extension settings: untrust'],
			['sync ignore from a tab', { patch: ["(patch 0059, review ENV-48).\n+		const seclabTab = this.seclabEnvironment.remoteAuthority;\n+		if (seclabTab && seclabIsTabAuthority(seclabTab)) {", "(patch 0059, review ENV-48).\n+		const seclabTab = this.seclabEnvironment.remoteAuthority;\n+		if (false) {"] }, 'a tab window changes host extension settings: sync ignore'],
			['AI features from a tab extension', { patch: ["+		if (seclabIsTabAuthority(this.extension.local.location.authority)) {", "+		if (false) {"] }, 'a tab extension offers the host\'s AI features setting'],
			['profile import in a tab', { patch: [" 	private async doCreateProfile(profileTemplate: IUserDataProfileTemplate, temporaryProfile: boolean, extensions: boolean, options: IUserDataProfileOptions | undefined, progress: (message: string) => void): Promise<IUserDataProfile | undefined> {\n+		this.seclabNoImport();\n", " 	private async doCreateProfile(profileTemplate: IUserDataProfileTemplate, temporaryProfile: boolean, extensions: boolean, options: IUserDataProfileOptions | undefined, progress: (message: string) => void): Promise<IUserDataProfile | undefined> {\n+\n"] }, 'a tab window changes host extension settings: profile import'],
			['upstream enablement registered', { patch: ["registerSingleton(IGlobalExtensionEnablementService, SeclabGlobalExtensionEnablementService,", "registerSingleton(IGlobalExtensionEnablementService, GlobalExtensionEnablementService,"] }, 'the host\'s global enablement is registered unguarded'],
			['profile import unguarded', { patch: ["createInstance(SeclabGlobalExtensionEnablementService))", "createInstance(GlobalExtensionEnablementService))"] }, 'profile import builds an unguarded enablement service'],
			['publisher-trust migration in a tab', { patch: ["if (!seclabIsTabAuthority(environmentService.remoteAuthority) && !storageService.get(", "if (!storageService.get("] }, 'a tab window runs a one-time migration of host state'],
			['chat migration in a tab', { patch: ["if (!this._chatExtensionId || seclabIsTabAuthority(this.environmentService.remoteAuthority) ||", "if (!this._chatExtensionId ||"] }, 'a tab window runs a one-time migration of host state'],
			['global enablement from a tab', { patch: ["+			if (newState === EnablementState.EnabledGlobally || newState === EnablementState.DisabledGlobally) {", "+			if (false) {"] }, 'a tab window makes a global enablement change'],
			['global enablement writable', { patch: ["+		if (this.seclabTab) {\n+			seclabRefuseServerLocation(this.seclabTab, 'host-enablement');", "+		if (false) {\n+			seclabRefuseServerLocation(this.seclabTab, 'host-enablement');"] }, 'a tab window changes the host\'s global enablement'],
			['install events reach global enablement', { patch: ["super(storageService, tab ? Object.assign(Object.create(extensionManagementService), { onDidInstallExtensions: Event.None }) : extensionManagementService);", "super(storageService, extensionManagementService);"] }, 'a tab\'s install event reaches the host\'s global enablement'],
			['localization listens in a tab window', { patch: ["+		if (seclabIsTabAuthority(environmentService.remoteAuthority)) {\n+			return;", "+		if (false) {\n+			return;"] }, 'a tab\'s install events prompt to change the host\'s display language'],
			['marketplace token to a tab', { patch: ["noToken ? undefined : this.extensionGalleryAccessToken", "this.extensionGalleryAccessToken"] }, 'the tab\'s server gets the marketplace token'],
			['publisher trust kept from a tab', { patch: ["review ENV-38).\n+		const seclabTab = this.instantiationService.invokeFunction(accessor => accessor.get(IWorkbenchEnvironmentService).remoteAuthority);\n+		if (seclabTab && seclabIsTabAuthority(seclabTab)) {", "review ENV-38).\n+		const seclabTab = this.instantiationService.invokeFunction(accessor => accessor.get(IWorkbenchEnvironmentService).remoteAuthority);\n+		if (false) {"] }, 'a publisher trusted in a tab window is trusted for the host'],
			['the host channel takes changes', { filter: ["			if (!SECLAB_HOST_EXTENSION_READS.has(command)) {", "			if (false) {"] }, 'the host takes an extension change from a tab window'],
			['the host channel unwrapped', { patch: ["seclabHostExtensionsChannel(sharedProcessService.getChannel('extensions'), environmentService.remoteAuthority)", "sharedProcessService.getChannel('extensions')"] }, 'the host takes an extension change from a tab window'],
			['enablement reaches host extensions', { patch: ["+			if (own.length !== extensions.length) {", "+			if (false) {"] }, 'a tab extension\'s pack changes a host extension\'s enablement'],
			['migration in a tab window', { patch: ["remoteExtensionManagementServer && !seclabIsTabAuthority(environmentService.remoteAuthority)) {", "remoteExtensionManagementServer) {"] }, 'the unsupported-extensions migration runs on the tab\'s data'],
			['any manifest key is skipped', { filter: ["	return key === 'manifest' && (owner.length === 0", "	return key === 'manifest' || (owner.length === 0"] }, 'extension management: a host location under a manifest key elsewhere'],
			['logger channel unwrapped', { patch: ["new RemoteLoggerChannelClient(loggerService, seclabTabServerChannel(channel, connection.remoteAuthority, 'loggers'))", "new RemoteLoggerChannelClient(loggerService, channel)"] }, 'loggers: an event registering a host file'],
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
			const found = await leaks(build(true, m.patch ? PATCH.replace(pf, () => pt) : PATCH, m.filter ? FILTER.replace(ff, () => ft) : FILTER));
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
