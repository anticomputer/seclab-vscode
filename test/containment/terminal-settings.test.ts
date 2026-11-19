/**
 * Patches 0053-0055 (reviews DOCSYNC-R5, RFU1R-2, RFU1R2-1, RFU1R-3, R5-1 to R5-8): what a
 * `seclab+` window sends its tab with a terminal. 0053: the tab's own terminal settings (env, cwd,
 * profiles, the automation and agent-host profiles), never the host user's, which 0036 already
 * withholds from the tab's extension host, and none of them to the window's own extension host;
 * the host's default profile name never picks among the names the REH offers. 0054: each
 * extension host gets only the environment collections it set itself, and no tab replaces another
 * host's. 0055: only the tab's own folders, documents and a workspace id derived from them. 0056:
 * a terminal icon is a codicon or an image on the tab's own file system.
 *
 * This runs upstream's own methods, sliced from the pinned checkout's files with every series
 * patch for those files applied, as the baseline (series without 0053-0055) and as shipped:
 * RemoteTerminalChannelClient.createProcess, TerminalProfileService._detectProfiles, the profile
 * resolver's automation and agent-host profile reads and icon check, the profile service's
 * default profile, EnvironmentVariableService.getMergedCollection, and MainThreadTerminalService's
 * collection restore, _updateDefaultProfile and $setEnvironmentVariableCollection.
 * The host user's settings carry a canary; the baseline must send it (or the case proves nothing),
 * the patched build must not, a non-tab remote window must still send it, and each mutant of the
 * patches must fail.
 *
 * Run: ./seclab test terminal-settings   (mounts the pinned upstream; SECLAB_VS_SRC points at
 * its src/vs)
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SRC = process.env.SECLAB_VS_SRC;
if (!SRC) {
	console.error('terminal-settings: set SECLAB_VS_SRC to the pinned src/vs (./seclab test terminal-settings does)');
	process.exit(1);
}
const FILES = {
	channel: 'workbench/contrib/terminal/common/remote/remoteTerminalChannel.ts',
	profiles: 'workbench/contrib/terminal/browser/terminalProfileService.ts',
	resolver: 'workbench/contrib/terminal/browser/terminalProfileResolverService.ts',
	envService: 'workbench/contrib/terminal/common/environmentVariableService.ts',
	mainThread: 'workbench/api/browser/mainThreadTerminalService.ts',
	quickpick: 'workbench/contrib/terminal/browser/terminalProfileQuickpick.ts',
	profileText: 'platform/terminal/common/terminalProfiles.ts',
	htmlContent: 'base/common/htmlContent.ts',
	helper: 'workbench/contrib/terminal/common/seclabTabTerminalSettings.ts',
	tooltip: 'workbench/contrib/terminal/browser/terminalTooltip.ts',
	links: 'workbench/contrib/terminalContrib/links/browser/terminalLinkManager.ts',
	actions: 'workbench/contrib/terminal/browser/terminalActions.ts',
} as const;
type Key = keyof typeof FILES;
const OURS = ['0053-seclab-no-host-terminal-settings-for-tabs.patch', '0054-seclab-tab-own-terminal-env-collections.patch', '0055-seclab-no-host-file-path-to-tab-terminals.patch', '0056-seclab-no-foreign-terminal-icons-in-tabs.patch',
	'0057-seclab-tab-profile-writes-stay-in-the-tab.patch', '0058-seclab-plain-text-terminal-profile-descriptions.patch'];
const series = readFileSync(join(REPO, 'patches', 'series'), 'utf8').split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
const readPatch = (name: string) => readFileSync(join(REPO, 'patches', name), 'utf8');

/** One file's section of a `diff -ruN` patch, or undefined. */
function section(patch: string, rel: string): string | undefined {
	return patch.split(/^(?=diff -ruN )/m).find(p => p.split('\n')[0].includes(`/vs/${rel} `));
}

/** Apply one file's hunks by replacing each hunk's old lines with its new lines, exactly once. */
function applyHunks(source: string, sec: string, what: string): string {
	let out = source;
	for (const hunk of sec.split(/\n(?=@@ )/).slice(1)) {
		const lines = hunk.split('\n').slice(1).filter(l => l.length > 0 && l[0] !== '\\');
		const old = lines.filter(l => l[0] === ' ' || l[0] === '-').map(l => l.slice(1)).join('\n');
		const neu = lines.filter(l => l[0] === ' ' || l[0] === '+').map(l => l.slice(1)).join('\n');
		if (old === '') {
			out = `${neu}\n`;
			continue;
		}
		assert.equal(out.split(old).length - 1, 1, `a hunk of ${what} no longer applies`);
		out = out.replace(old, neu);
	}
	return out;
}

/** Every file, with the series patches for it applied; `withOurs` false stops before 0053-0055. */
function sources(withOurs: boolean, patches: Record<string, string> = {}): Record<Key, string> {
	const out = {} as Record<Key, string>;
	for (const [key, rel] of Object.entries(FILES) as Array<[Key, string]>) {
		let text = key === 'helper' ? '' : readFileSync(join(SRC!, rel), 'utf8');
		for (const name of series) {
			if (!withOurs && OURS.includes(name)) {
				continue;
			}
			const sec = section(patches[name] ?? readPatch(name), rel);
			if (sec) {
				text = applyHunks(text, sec, `${name} to ${rel}`);
			}
		}
		out[key] = text;
	}
	return out;
}

/** A method of a class in `source`, as a JavaScript function (types stripped), or undefined. */
function method(source: string, name: string, deps: Record<string, unknown>): ((...a: unknown[]) => unknown) | undefined {
	const m = new RegExp(`\\n\\t?(?:export )?(?:(?:private|protected|public) )?(async )?(?:function )?${name.replace(/\$/g, '\\$')}(?:<[^>]*>)?\\(`).exec(source);
	if (!m) {
		return undefined;
	}
	let i = m.index + m[0].length;
	for (let depth = 1; depth > 0; i++) {
		depth += source[i] === '(' ? 1 : source[i] === ')' ? -1 : 0;
	}
	const params = source.slice(m.index + m[0].length, i - 1);
	const open = source.indexOf('{', i);
	let j = open + 1;
	for (let depth = 1; depth > 0; j++) {
		depth += source[j] === '{' ? 1 : source[j] === '}' ? -1 : 0;
	}
	const ts = `(${m[1] ?? ''}function ${name.replace(/\$/g, '_')}(${params}) ${source.slice(open, j)})`;
	const js = stripTypeScriptTypes(ts, { mode: 'transform' });
	return new Function(...Object.keys(deps), `return ${js};`)(...Object.values(deps));
}

/** The block (`{ … }`) that follows `head` in `source`, as a JavaScript function of `params`. */
function block(source: string, head: string, params: string[], deps: Record<string, unknown>): (...a: unknown[]) => unknown {
	const at = source.indexOf(head);
	assert.ok(at >= 0, `block not found: ${head}`);
	const open = source.indexOf('{', at + head.length - 1);
	let j = open + 1;
	for (let depth = 1; depth > 0; j++) {
		depth += source[j] === '{' ? 1 : source[j] === '}' ? -1 : 0;
	}
	const js = stripTypeScriptTypes(`(function (${params.join(', ')}) { ${source.slice(at, j)} })`, { mode: 'transform' });
	return new Function(...Object.keys(deps), `return ${js};`)(...Object.values(deps));
}

/** The helper's exports (patched build only). */
function helper(src: string): Record<string, (...a: unknown[]) => unknown> {
	if (!src) {
		const absent = () => { throw new Error('the baseline has no seclabTabTerminalSettings'); };
		return { seclabIsTabWindow: absent, seclabTabSetting: absent, seclabUriInTab: absent, seclabWorkspaceInTab: absent };
	}
	const js = stripTypeScriptTypes(src, { mode: 'transform' }).replace(/^import .*$/gm, '').replace(/^export /gm, '');
	return new Function(`${js}\nreturn { seclabIsTabWindow, seclabTabSetting, seclabUriInTab, seclabWorkspaceInTab };`)();
}

// ------------------------------------------------------------------ the host and the tab
const HOST = `seclabcanary_r5_host_${'0123456789abcdef'.repeat(2)}`;
type Layers = { defaultValue?: unknown; applicationValue?: unknown; userLocalValue?: unknown; userRemoteValue?: unknown; workspaceValue?: unknown; workspaceFolderValue?: unknown; policyValue?: unknown };
/** Host canaries in every layer the host owns; the tab's values in its own. */
const SETTINGS: Record<string, Layers> = {
	'terminal.integrated.env.linux': { defaultValue: {}, userLocalValue: { HOST_TOKEN: HOST }, userRemoteValue: { TAB_VAR: 'tab-remote' }, workspaceValue: { TAB_WS: 'tab-ws' } },
	'terminal.integrated.env.osx': { defaultValue: {}, applicationValue: { HOST_TOKEN: HOST } },
	'terminal.integrated.env.windows': { defaultValue: {}, policyValue: { HOST_TOKEN: HOST } },
	'terminal.integrated.cwd': { defaultValue: '', userLocalValue: `/Users/someone/${HOST}` },
	'terminal.integrated.profiles.linux': {
		defaultValue: { bash: { path: 'bash', icon: 'terminal-bash' } },
		userLocalValue: { hostp: { path: '/bin/sh', args: [HOST], env: { HOST_TOKEN: HOST } } },
		userRemoteValue: { tabp: { path: '/bin/sh', args: ['tab-arg'] }, bash: { args: ['-l'] } },
	},
	'terminal.integrated.defaultProfile.linux': { defaultValue: null, userLocalValue: 'hostp' },
	'terminal.integrated.automationProfile.linux': { defaultValue: null, userLocalValue: { path: '/bin/sh', args: [HOST] } },
	'terminal.integrated.agentHostProfile.linux': { defaultValue: null, policyValue: { path: '/bin/sh', args: [HOST] } },
	// R5-23: switches the process options carry; the host user's values differ from the defaults.
	'terminal.integrated.detectLocale': { defaultValue: 'auto', userLocalValue: 'on' },
	'terminal.integrated.shellIntegration.enabled': { defaultValue: true, userLocalValue: false },
	'terminal.integrated.suggest.enabled': { defaultValue: false, userLocalValue: true },
	'terminal.integrated.windowsUseConptyDll': { defaultValue: true, userLocalValue: false },
	'terminal.integrated.inheritEnv': { defaultValue: true, userLocalValue: false },
	// Upstream merges arrays by replacing, so the host user's list is the effective one when the tab sets none.
	'terminal.integrated.allowedLinkSchemes': { defaultValue: ['file', 'http', 'https'], userLocalValue: [`host${HOST}`] },
};
const isMap = (v: unknown) => !!v && typeof v === 'object' && !Array.isArray(v);
const deepMerge = (a: unknown, b: unknown): unknown => isMap(a) && isMap(b)
	? Object.fromEntries([...new Set([...Object.keys(a as object), ...Object.keys(b as object)])].map(k => [k, k in (b as object) ? deepMerge((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]) : (a as Record<string, unknown>)[k]]))
	: b;
const config = (settings: Record<string, Layers>) => ({
	whenRemoteConfigurationLoaded: async () => { },
	inspect: (key: string) => structuredClone(settings[key] ?? {}),
	// As upstream merges: defaults, application, local user, remote user, workspace, folder, policy.
	getValue: (key: string) => {
		const l = settings[key] ?? {};
		return [l.defaultValue, l.applicationValue, l.userLocalValue, l.userRemoteValue, l.workspaceValue, l.workspaceFolderValue, l.policyValue]
			.filter(v => v !== undefined).reduce(deepMerge, undefined);
	},
});
const FILTER_TAB = new Function(`return ${/\nconst SECLAB_AUTHORITY = (\/.*\/\w*);/.exec(readFileSync(join(REPO, 'rpc-filter', 'patch-src', 'seclabRpcFilter.ts'), 'utf8'))![1]};`)() as RegExp;
const TAB = 'seclab+tab1';
const sees = (v: unknown) => JSON.stringify(v ?? null).includes(HOST);
const uri = (scheme: string, authority: string, p: string) => ({ scheme, authority, path: p, fsPath: p });
/** The tab's own folder, or a window that also holds a host folder (patch 0036's case). */
const WORKSPACES = {
	tab: (a: string) => ({ id: 'w', folders: [{ uri: uri('vscode-remote', a, '/w'), name: 'w', index: 0 }] }),
	hostFolder: (a: string) => ({ id: `id-${HOST}`, folders: [{ uri: uri('vscode-remote', a, '/w'), name: 'w', index: 0 }, { uri: uri('file', '', `/Users/someone/${HOST}`), name: HOST, index: 1 }] }),
	hostFile: (a: string) => ({ id: `id-${HOST}`, configuration: uri('file', '', `/Users/someone/${HOST}.code-workspace`), folders: [{ uri: uri('vscode-remote', a, '/w'), name: 'w', index: 0 }] }),
};
type WorkspaceKind = keyof typeof WORKSPACES;

interface Observed {
	createProcess: Record<string, unknown> & { configuration: Record<string, unknown> };
	getProfiles: unknown[];
	automation: unknown;
	agentHost: unknown;
	collections: string[];
	localDefaultProfile: unknown[] | undefined;
	hostCollectionDeleted: boolean;
	localCollections: string[];
	pickedDefault: unknown;
	contributedDefault: unknown;
	foreignIcon: unknown;
	ownIcon: unknown;
	noConnection: unknown;
	inheritEnv: unknown;
	profileWrites: Array<{ key: string; value: unknown; target: number }>;
	descriptions: string[];
	detachSent: unknown[] | undefined;
	hover: string;
	folderCwd: unknown;
	contributedWrite: number | undefined;
	contributedValue: unknown;
	schemeWrites: Array<{ key: string; value: unknown; target: number | undefined }>;
}

async function observe(src: Record<Key, string>, authority: string, activeFile: unknown, kind: WorkspaceKind = 'tab'): Promise<Observed> {
	const h = helper(src.helper);
	const settings = structuredClone(SETTINGS);
	if (kind !== 'tab') {
		// A host-side workspace's settings are the host's.
		settings['terminal.integrated.env.linux'].workspaceValue = { HOST_WS: HOST };
	}
	const cfg = config(settings);
	const workspace = WORKSPACES[kind](authority);
	const Schemas = { file: 'file', vscodeUserData: 'vscode-userdata', vscodeRemote: 'vscode-remote' };
	// The filter module's own test, from this tree.
	const seclabIsTabAuthority = (a: unknown) => typeof a === 'string' && FILTER_TAB.test(a);

	// RemoteTerminalChannelClient.createProcess
	const createProcess = method(src.channel, 'createProcess', {
		// R5-26: a resolution, if the window runs one, yields a host setting's value.
		ConfigurationResolverExpression: { parse: () => ({ resolved: () => resolved ? [[{ inner: 'config:terminal.integrated.cwd' }, { value: HOST }]] : [] }) },
		EditorResourceAccessor: { getOriginalUri: (e: { resource?: unknown } | undefined) => e?.resource },
		SideBySideEditor: { PRIMARY: 1 }, Schemas,
		serializeEnvironmentVariableCollection: (m: Map<string, unknown>) => [...m.entries()],
		serializeEnvironmentDescriptionMap: (m: Map<string, unknown> | undefined) => m ? [...m.entries()] : [],
		RemoteTerminalChannelRequest: { CreateProcess: '$createProcess' },
		seclabIsTabWindow: h.seclabIsTabWindow, seclabTabSetting: h.seclabTabSetting, seclabUriInTab: h.seclabUriInTab,
	});
	assert.ok(createProcess, 'createProcess not found');
	const seclabWorkspaceId = method(src.channel, '_seclabWorkspaceId', {
		seclabIsTabWindow: h.seclabIsTabWindow, seclabUriInTab: h.seclabUriInTab, seclabWorkspaceInTab: h.seclabWorkspaceInTab,
		hash: (v: unknown) => JSON.stringify(v).length,
	});
	let sent: Observed['createProcess'] | undefined;
	let resolved = false;
	const terminalConfig = Object.fromEntries(['terminal.integrated.env.windows', 'terminal.integrated.env.osx', 'terminal.integrated.env.linux', 'terminal.integrated.cwd', 'terminal.integrated.detectLocale'].map(k => [k, cfg.getValue(k)]));
	const hostFolder = workspace.folders.find(f => f.uri.scheme === 'file') ?? workspace.folders[0];
	await createProcess!.call({
		_remoteAuthority: authority,
		_configurationService: cfg,
		_workspaceContextService: { getWorkspaceFolder: () => hostFolder, getWorkspace: () => workspace },
		_resolverService: { resolveAsync: async () => { resolved = true; } },
		_logService: { error: () => { } },
		_environmentVariableService: { getMergedCollection: () => ({ collections: new Map() }) },
		_remoteAuthorityResolverService: { resolveAuthority: async () => ({ options: {} }) },
		_environmentService: { debugExtensionHost: {} },
		_editorService: { activeEditor: { resource: activeFile } },
		_labelService: { getWorkspaceLabel: () => kind === 'hostFile' ? HOST : 'w' },
		_channel: { call: async (_c: string, args: Observed['createProcess']) => { sent = args; return {}; } },
		_seclabWorkspaceId: seclabWorkspaceId,
	}, { executable: '/bin/sh' }, terminalConfig, hostFolder.uri, {
		environmentVariableCollections: undefined, workspaceFolder: hostFolder,
		// As upstream's process manager builds them: the merged values, the host user's included.
		shellIntegration: { enabled: cfg.getValue('terminal.integrated.shellIntegration.enabled'), suggestEnabled: cfg.getValue('terminal.integrated.suggest.enabled'), nonce: 'n' },
		windowsUseConptyDll: cfg.getValue('terminal.integrated.windowsUseConptyDll'),
	}, false, 80, 24, '11', 3);

	// TerminalProfileService._detectProfiles
	const detect = method(src.profiles, '_detectProfiles', {
		isWeb: false, TerminalSettingPrefix: { Profiles: 'terminal.integrated.profiles.', DefaultProfile: 'terminal.integrated.defaultProfile.' },
		seclabIsTabWindow: h.seclabIsTabWindow, seclabTabSetting: h.seclabTabSetting,
	});
	assert.ok(detect, '_detectProfiles not found');
	let getProfiles: unknown[] = [];
	const profileDeps = {
		isWeb: false, isString: (v: unknown) => typeof v === 'string', hasKey: (o: object, k: object) => Object.keys(k).every(x => x in o),
		TerminalSettingPrefix: { Profiles: 'terminal.integrated.profiles.', DefaultProfile: 'terminal.integrated.defaultProfile.' },
		seclabIsTabWindow: h.seclabIsTabWindow, seclabTabSetting: h.seclabTabSetting,
	};
	// The REH offers a profile named after the host user's default, as a guess would (R5-10).
	const offered = [{ profileName: 'hostp', path: '/bin/sh', isAutoDetected: false }, { profileName: 'tabp', path: '/bin/sh', isAutoDetected: false }];
	const profileService: Record<string, unknown> = {
		_environmentService: { remoteAuthority: authority }, _seclabWorkspace: { getWorkspace: () => workspace },
		_terminalInstanceService: { getBackend: async () => ({ getProfiles: async (...a: unknown[]) => { getProfiles = a; return []; } }), getRegisteredBackends: () => [] },
		getPlatformKey: async () => 'linux', _configurationService: cfg, _availableProfiles: [], availableProfiles: offered,
		contributedProfiles: [{ title: 'hostp', extensionIdentifier: 'tab.ext', id: 'p' }], _getOsKey: () => 'linux',
	};
	const seclabSetting = method(src.profiles, '_seclabSetting', profileDeps);
	if (seclabSetting) {
		profileService._seclabSetting = seclabSetting;
	}
	await detect!.call(profileService, true);
	const pickedDefault = method(src.profiles, 'getDefaultProfile', profileDeps)!.call(profileService, 3);
	const contributedDefault = await method(src.profiles, 'getContributedDefaultProfile', profileDeps)!.call(profileService, {});

	// The resolver's automation and agent-host profiles (sent in $acceptDefaultProfile).
	const deps = {
		Codicon: { tools: 'tools' }, isString: (v: unknown) => typeof v === 'string', deepClone: (v: unknown) => structuredClone(v),
		seclabIsTabAuthority, seclabTabSetting: h.seclabTabSetting,
	};
	const self: Record<string, unknown> = {
		_configurationService: cfg, _remoteAgentService: { getConnection: () => ({ remoteAuthority: authority }) }, _seclabEnvironment: { remoteAuthority: authority },
		_workspaceContextService: { getWorkspace: () => workspace },
		_getOsKey: () => 'linux', _getCustomIcon: () => undefined, _terminalProfileService: { availableProfiles: [] },
		_isValidAutomationProfile: (p: unknown) => isMap(p) && typeof (p as { path?: unknown }).path === 'string',
	};
	for (const name of ['_seclabProfileSetting', '_seclabTabAuthority']) {
		const own = method(src.resolver, name, deps);
		if (own) {
			self[name] = own;
		}
	}
	const automation = method(src.resolver, '_getUnresolvedAutomationShellProfile', deps)!.call(self, { os: 3 });
	const agentHost = method(src.resolver, '_getUnresolvedAgentHostShellProfile', deps)!.call(self, { os: 3 });
	// The window's connection can't be null in a remote window today; the check must not rest on it (R5-13).
	const noConnection = method(src.resolver, '_getUnresolvedAutomationShellProfile', deps)!.call({ ...self, _remoteAgentService: { getConnection: () => null } }, { os: 3 });
	// R5-30: resolveShellLaunchConfig fills useShellEnvironment, which goes to the REH in createProcess.
	const launch: { useShellEnvironment?: unknown } = {};
	await method(src.resolver, 'resolveShellLaunchConfig', {
		...deps, generatedProfileName: 'Generated', TerminalSettingId: { TabsDefaultColor: 'terminal.integrated.tabs.defaultColor', InheritEnv: 'terminal.integrated.inheritEnv' },
	})!.call({ ...self, getDefaultProfile: async () => ({ path: 'bash', args: [], profileName: 'bash' }), getDefaultIcon: () => 'terminal' }, launch, { remoteAuthority: authority, os: 3 });
	const inheritEnv = launch.useShellEnvironment;
	// R5-9: a profile's image icon becomes a CSS url() the window fetches.
	const URI = {
		isUri: (u: unknown) => isMap(u) && (u as { $uri?: boolean }).$uri === true,
		revive: (u: object) => ({ ...u, $uri: true }),
	};
	const customIcon = method(src.resolver, '_getCustomIcon', {
		...deps, URI, isUriComponents: (u: unknown) => isMap(u) && typeof (u as { scheme?: unknown }).scheme === 'string',
		ThemeIcon: { fromId: (id: string) => ({ id }), isThemeIcon: (i: unknown) => isMap(i) && typeof (i as { id?: unknown }).id === 'string' && !('scheme' in (i as object)) },
		seclabUriInTab: h.seclabUriInTab,
	})!;
	const foreignIcon = customIcon.call(self, { scheme: 'https', authority: 'collector.example.invalid', path: `/${HOST}.png` });
	const ownIcon = customIcon.call(self, { scheme: 'vscode-remote', authority, path: '/w/icon.png' });

	// EnvironmentVariableService.getMergedCollection ($initEnvironmentVariableCollections, createProcess).
	const merged = method(src.envService, 'getMergedCollection', {
		MergedEnvironmentVariableCollection: class { collections: unknown; constructor(c: unknown) { this.collections = c; } },
		OperatingSystem: { Windows: 1, Macintosh: 2, Linux: 3 },
	})!.call({
		_logService: { warn: () => { } },
		_mergedCollectionsByAuthority: new Map(),
		collections: new Map<string, unknown>([
			['host.ui-extension', { map: new Map([['HOST_TOKEN', { variable: 'HOST_TOKEN', value: HOST, type: 1 }]]), remoteAuthority: null }],
			['other.host', { map: new Map([['X', { variable: 'X', value: HOST, type: 1 }]]), remoteAuthority: 'seclab+other' }],
			['tab.extension', { map: new Map([['PATH', { variable: 'PATH', value: '/tab/bin', type: 2 }], ['TAB_VAR', { variable: 'TAB_VAR', value: 'tab', type: 1 }]]), remoteAuthority: authority }],
		]),
	}, authority, 3) as { collections: Map<string, unknown> };

	// MainThreadTerminalService for the window's own (host-side) extension host: the default profile
	// it is sent, and whether the tab's extension host can delete the host's collection.
	const update = method(src.mainThread, '_updateDefaultProfile', { seclabIsTabAuthority });
	let localDefaultProfile: unknown[] | undefined;
	await update!.call({
		_environmentService: { remoteAuthority: authority }, _extHostContext: { remoteAuthority: null }, _os: 3,
		_terminalProfileResolverService: { getDefaultProfile: async (o: { allowAutomationShell?: boolean }) => ({ path: '/bin/sh', args: [o.allowAutomationShell ? 'tab-automation' : 'tab-default'] }) },
		_proxy: { $acceptDefaultProfile: (...a: unknown[]) => { localDefaultProfile = a; } },
	});
	const localCollections: string[] = [];
	block(src.mainThread, 'if (this._environmentVariableService.collections.size > 0) {', ['_extHostContext'], {
		OS: 3, seclabIsTabAuthority, serializeEnvironmentVariableCollection: () => [],
	}).call({
		_environmentService: { remoteAuthority: authority },
		_environmentVariableService: {
			collections: { size: 2 },
			getMergedCollection: () => ({ collections: new Map<string, unknown>([['host.ui-extension', { map: new Map(), remoteAuthority: null }], ['tab.claims-a-host-id', { map: new Map(), remoteAuthority: authority }]]) }),
		},
		_proxy: { $initEnvironmentVariableCollections: (c: Array<[string, unknown]>) => localCollections.push(...c.map(e => e[0])) },
	}, { remoteAuthority: null, remoteOS: 3 });
	// R5-14: "Select Default Profile" on a profile the REH returned.
	const ConfigurationTarget = { USER: 2, USER_LOCAL: 3, USER_REMOTE: 4 };
	const profileWrites: Observed['profileWrites'] = [];
	const quick: Record<string, unknown> = {
		_terminalProfileService: { getPlatformKey: async () => 'linux' },
		_configurationService: { ...cfg, updateValue: async (key: string, value: unknown, target: number) => { profileWrites.push({ key, value: structuredClone(value), target }); } },
		_seclabEnvironment: { remoteAuthority: authority }, _seclabWorkspace: { getWorkspace: () => workspace },
		_createAndShow: async () => ({ profileName: 'rehp', profile: { profileName: 'rehp', path: '/bin/sh', args: ['-c', 'tab-chosen'], env: { TAB: 'reh' } } }),
	};
	const quickDeps = { ConfigurationTarget, hasKey: (o: object, k: object) => Object.keys(k).every(x => x in o), TerminalSettingPrefix: { Profiles: 'terminal.integrated.profiles.', DefaultProfile: 'terminal.integrated.defaultProfile.' }, seclabIsTabWindow: h.seclabIsTabWindow, seclabTabSetting: h.seclabTabSetting };
	for (const name of ['_createNewProfileConfig', '_seclabTab', '_seclabTarget', '_seclabProfiles']) {
		const fn = method(src.quickpick, name, quickDeps);
		if (fn) {
			quick[name] = fn;
		}
	}
	await method(src.quickpick, 'showAndGetResult', quickDeps)!.call(quick, 'setDefault');

	// R5-15: profile descriptions the Settings editor renders as markdown.
	const escapeMarkdownSyntaxTokens = method(src.htmlContent, 'escapeMarkdownSyntaxTokens', {})!;
	// Upstream's, with ThemeIcon's name and modifier expressions inlined.
	const escapeIcons = (t: string) => t.replace(/(\\)?\$\([A-Za-z0-9-]+(?:~[A-Za-z]+)?\)/g, (m: string, e: string) => e ? m : `\\${m}`);
	const escapeUntrustedMarkdown = method(src.htmlContent, 'escapeUntrustedMarkdown', { escapeMarkdownSyntaxTokens, escapeIcons })!;
	const profileText = stripTypeScriptTypes(src.profileText, { mode: 'transform' }).replace(/^import .*$/gm, '').replace(/^export /gm, '');
	const { createProfileSchemaEnums } = new Function('Codicon', 'ThemeIcon', 'isString', 'isObject', 'localize', 'URI', 'isUriComponents', 'escapeMarkdownSyntaxTokens', 'escapeUntrustedMarkdown',
		`${profileText}\nreturn { createProfileSchemaEnums };`)(
		{ terminal: { id: 'terminal' } }, { isThemeIcon: (i: unknown) => isMap(i) && typeof (i as { id?: unknown }).id === 'string' }, (v: unknown) => typeof v === 'string', isMap,
		(_k: string, m: string) => m, { isUri: () => false }, () => false, escapeMarkdownSyntaxTokens, escapeUntrustedMarkdown) as { createProfileSchemaEnums: (p: unknown[], e?: unknown[]) => { markdownDescriptions: string[] } };
	const IMG = '![](https://collector.example.invalid/p.png)';
	// R5-20: an autolink, and a new line forging another entry's fields.
	const LINK = '<https://collector.example.invalid/a>';
	const descriptions = createProfileSchemaEnums(
		[{ profileName: `rehp ${IMG} ${LINK}`, path: `/bin/sh ${IMG}\n- path: forged`, args: [IMG], icon: `terminal) ${IMG} $(x` }],
		[{ title: `contributed ${IMG}`, extensionIdentifier: 'tab.ext', id: 'p', icon: 'terminal' }]).markdownDescriptions;

	// R5-16: a terminal dragged in from another window names that window's workspace.
	let detachSent: unknown[] | undefined;
	await method(src.channel, 'requestDetachInstance', { RemoteTerminalChannelRequest: { RequestDetachInstance: '$requestDetachInstance' }, seclabIsTabWindow: h.seclabIsTabWindow })!.call({
		_remoteAuthority: authority, _workspaceContextService: { getWorkspace: () => workspace },
		_channel: { call: async (_c: string, a: unknown[]) => { detachSent = a; return undefined; } }, _seclabWorkspaceId: seclabWorkspaceId,
	}, `id-other-${HOST}`, 1);
	const hostCollections = new Map<string, unknown>([['host.ui-extension', { map: new Map(), remoteAuthority: null }]]);
	method(src.mainThread, '$setEnvironmentVariableCollection', {
		seclabIsTabAuthority, deserializeEnvironmentVariableCollection: () => new Map(), deserializeEnvironmentDescriptionMap: () => new Map(),
	})!.call({
		_environmentService: { remoteAuthority: authority }, _extHostContext: { remoteAuthority: authority },
		_environmentVariableService: { collections: hostCollections, set: (k: string, v: unknown) => hostCollections.set(k, v), delete: (k: string) => hostCollections.delete(k) },
	}, 'host.ui-extension', false, undefined, []);

	// R5-18: the terminal tab's hover, with a title and command line the tab's shell and REH chose.
	class MarkdownString { constructor(public value: string) { } }
	const tooltipDeps = {
		MarkdownString, escapeUntrustedMarkdown, seclabIsTabWindow: h.seclabIsTabWindow, basename: (p: string) => p.split('/').pop(), asArray: (v: unknown) => Array.isArray(v) ? v : [v],
		localize: (_k: unknown, m: string, ...a: unknown[]) => m.replace(/\{(\d)\}/g, (_x, i) => String(a[+i])),
		StorageScope: { APPLICATION: -1 }, StorageTarget: { USER: 0 }, TerminalStorageKeys: { TabsShowDetailed: 'k' },
	};
	const getShellProcessTooltip = method(src.tooltip, 'getShellProcessTooltip', tooltipDeps)!;
	// R5-24: a status whose text is a launch error the tab's server sent, and an icon id it chose.
	const term = { remoteAuthority: authority, title: `bash ${IMG}`, processId: 7, statusList: { statuses: [{ id: 's', tooltip: `exit ${IMG}`, icon: { id: `x) ${IMG} $(y` } }] }, shellLaunchConfig: { executable: `/bin/sh${IMG}`, args: [IMG] } };
	// Its return type is an object literal, which the slicer would take for the body.
	const tooltipSrc = src.tooltip.replace('): { content: MarkdownString; actions: IHoverAction[] } {', ') {');
	const hover = (method(tooltipSrc, 'getInstanceHoverInfo', { ...tooltipDeps, getShellProcessTooltip })!(term, { get: () => '1', store: () => { } }) as { content: { value: string } }).content.value;

	// R5-19: "Allow <scheme>" on a link the tab's shell printed.
	const schemeWrites: Observed['schemeWrites'] = [];
	const at = src.links.indexOf('label: nls.localize(\'allow\'');
	const open = src.links.indexOf('run: () => {', at) + 'run: () => '.length;
	let end = open + 1;
	for (let depth = 1; depth > 0; end++) {
		depth += src.links[end] === '{' ? 1 : src.links[end] === '}' ? -1 : 0;
	}
	const allowRun = new Function('ConfigurationTarget', 'IWorkbenchEnvironmentService', 'IWorkspaceContextService', 'seclabIsTabWindow', 'seclabTabSetting',
		`return ${stripTypeScriptTypes(`(function (scheme, terminalConfigurationService, resolve) ${src.links.slice(open, end)})`, { mode: 'transform' }).trim().replace(/;$/, '')};`)(
		ConfigurationTarget, 'env', 'workspace', h.seclabIsTabWindow, h.seclabTabSetting) as (...a: unknown[]) => void;
	allowRun.call({
		_configurationService: { ...cfg, updateValue: (key: string, value: unknown, target?: number) => { schemeWrites.push({ key, value: structuredClone(value), target }); } },
		_instantiationService: { invokeFunction: (f: (a: unknown) => unknown) => f({ get: (id: string) => id === 'env' ? { remoteAuthority: authority } : { getWorkspace: () => workspace } }) },
	}, 'tabchosen', { config: { allowedLinkSchemes: cfg.getValue('terminal.integrated.allowedLinkSchemes') } }, () => { });

	// R5-22: a new terminal's cwd for a folder, as the window resolves it before the launch.
	const folderCwd = ((await method(src.actions, 'resolveWorkspaceFolderCwd', {
		TerminalSettingId: { Cwd: 'terminal.integrated.cwd' }, isString: (v: unknown) => typeof v === 'string', Schemas, seclabIsTabWindow: h.seclabIsTabWindow,
		isAbsolute: (p: string) => p.startsWith('/'), ConfigurationResolverExpression: { VARIABLE_LHS: '${' },
		URI: { from: (u: object) => u, joinPath: (u: { path: string }, p: string) => ({ ...u, path: `${u.path}/${p}` }) },
	})!(workspace.folders[0], cfg, { resolveAsync: async (_f: unknown, v: string) => v })) as { cwd: unknown }).cwd;
	// R5-25: an extension registering a contributed profile from a tab window.
	let contributedWrite: number | undefined;
	let contributedValue: unknown;
	const contributed: Record<string, unknown> = {
		getPlatformKey: async () => 'linux', _environmentService: { remoteAuthority: authority }, _seclabWorkspace: { getWorkspace: () => workspace },
		_configurationService: { ...cfg, updateValue: async (_k: string, v: unknown, target: number) => { contributedWrite = target; contributedValue = structuredClone(v); } },
	};
	const contributedSetting = method(src.profiles, '_seclabSetting', { seclabIsTabWindow: h.seclabIsTabWindow, seclabTabSetting: h.seclabTabSetting });
	if (contributedSetting) {
		contributed._seclabSetting = contributedSetting;
	}
	await method(src.profiles, 'registerContributedProfile', { ConfigurationTarget, TerminalSettingPrefix: { Profiles: 'terminal.integrated.profiles.' }, seclabIsTabWindow: h.seclabIsTabWindow })!.call(
		contributed, { extensionIdentifier: 'tab.ext', id: 'p', title: 'p', options: {} });

	assert.ok(sent, 'createProcess sent nothing');
	return {
		createProcess: sent!, getProfiles, automation, agentHost, collections: [...merged.collections.keys()].sort(), localDefaultProfile,
		hostCollectionDeleted: !hostCollections.has('host.ui-extension'), localCollections, pickedDefault, contributedDefault, foreignIcon, ownIcon, noConnection, inheritEnv,
		profileWrites, descriptions, detachSent, hover, folderCwd, contributedWrite, contributedValue, schemeWrites,
	};
}

const remoteFile = (authority: string) => uri('vscode-remote', authority, '/w/a.ts');
const hostFile = uri('file', '', `/Users/someone/${HOST}.txt`);

/** Every way the host's data could reach the tab, for one build and window. */
async function leaks(src: Record<Key, string>, authority: string): Promise<string[]> {
	const out: string[] = [];
	for (const [name, file] of [['host file', hostFile], ['another tab file', remoteFile('seclab+other')]] as const) {
		const o = await observe(src, authority, file);
		if (o.createProcess.activeFileResource !== undefined) {
			out.push(`active file: ${name}`);
		}
	}
	const o = await observe(src, authority, remoteFile(authority));
	const c = o.createProcess.configuration;
	for (const k of ['terminal.integrated.env.linux', 'terminal.integrated.env.osx', 'terminal.integrated.env.windows', 'terminal.integrated.cwd']) {
		if (sees(c[k])) {
			out.push(k);
		}
	}
	const opts = o.createProcess.options as { shellIntegration?: { enabled?: unknown; suggestEnabled?: unknown }; windowsUseConptyDll?: unknown } | undefined;
	if (c['terminal.integrated.detectLocale'] === 'on' || opts?.shellIntegration?.enabled === false || opts?.shellIntegration?.suggestEnabled === true || opts?.windowsUseConptyDll === false || o.inheritEnv === false) {
		out.push('host process switches');
	}
	if (sees(o.folderCwd)) {
		out.push('host cwd in a folder\'s launch');
	}
	if (o.contributedWrite === 2) {
		out.push('contributed profile written to host settings');
	}
	if (sees(o.contributedValue)) {
		out.push('host profiles copied into a contributed profile write');
	}
	if (sees(o.createProcess.resolvedVariables)) {
		out.push('host settings resolved for the tab');
	}
	if (sees(o.getProfiles[0])) {
		out.push('getProfiles profiles');
	}
	if (o.getProfiles[1] === 'hostp') {
		out.push('getProfiles default profile');
	}
	if (sees(o.automation)) {
		out.push('automation profile');
	}
	if (sees(o.agentHost)) {
		out.push('agent host profile');
	}
	if (o.collections.includes('host.ui-extension')) {
		out.push('host collection');
	}
	if (o.collections.includes('other.host')) {
		out.push('another host collection');
	}
	if (o.localDefaultProfile) {
		out.push('tab profile to the host extension host');
	}
	if (o.hostCollectionDeleted) {
		out.push('tab deletes a host collection');
	}
	if (o.localCollections.includes('tab.claims-a-host-id')) {
		out.push('tab collection to the host extension host');
	}
	if ((o.pickedDefault as { profileName?: string } | undefined)?.profileName === 'hostp') {
		out.push('host default profile picks a REH profile');
	}
	if ((o.contributedDefault as { title?: string } | undefined)?.title === 'hostp') {
		out.push('host default profile picks a contributed profile');
	}
	if (o.foreignIcon !== undefined) {
		out.push('foreign profile icon');
	}
	if (sees(o.noConnection)) {
		out.push('automation profile without a connection');
	}
	if (o.profileWrites.some(w => w.target !== 4)) {
		out.push('REH profile written to host settings');
	}
	if (o.profileWrites.some(w => w.target === 4 && sees(w.value))) {
		out.push('host profiles copied into the tab');
	}
	if (o.descriptions.some(d => /(^|[^\\])!\[/.test(d))) {
		out.push('markdown image in a profile description');
	}
	if (sees(o.detachSent)) {
		out.push('foreign workspace id on detach');
	}
	if (o.descriptions.some(d => /(^|[^\\])<https?:/.test(d) || d.includes('\n- path: forged'))) {
		out.push('link or forged line in a profile description');
	}
	if (/(^|[^\\])!\[/.test(o.hover)) {
		out.push('markdown image in the terminal hover');
	}
	if (o.schemeWrites.some(w => w.target !== 4)) {
		out.push('link scheme allowed in host settings');
	}
	if (o.schemeWrites.some(w => sees(w.value))) {
		out.push('host link schemes in the written list');
	}
	for (const kind of ['hostFolder', 'hostFile'] as const) {
		const w = await observe(src, authority, remoteFile(authority), kind);
		const { configuration, ...rest } = w.createProcess;
		if (sees(configuration['terminal.integrated.env.linux'])) {
			out.push(`${kind}: workspace settings`);
		}
		if (sees(rest)) {
			out.push(`${kind}: folder paths or name`);
		}
	}
	return out;
}
const EVERY_LEAK = ['active file: host file', 'active file: another tab file', 'terminal.integrated.env.linux', 'terminal.integrated.env.osx', 'terminal.integrated.env.windows',
	'terminal.integrated.cwd', 'host process switches', 'host cwd in a folder\'s launch', 'contributed profile written to host settings', 'host profiles copied into a contributed profile write', 'getProfiles profiles', 'getProfiles default profile', 'automation profile', 'agent host profile', 'host collection', 'another host collection',
	'tab profile to the host extension host', 'tab deletes a host collection', 'tab collection to the host extension host',
	'host default profile picks a REH profile', 'host default profile picks a contributed profile', 'foreign profile icon', 'automation profile without a connection',
	'REH profile written to host settings', 'markdown image in a profile description', 'foreign workspace id on detach',
	'link or forged line in a profile description', 'markdown image in the terminal hover', 'link scheme allowed in host settings', 'host link schemes in the written list',
	'hostFolder: workspace settings', 'hostFolder: folder paths or name', 'hostFile: workspace settings', 'hostFile: folder paths or name'];

/** A mutant of one of our patches: `from` replaced by `to` in its added lines, exactly once. */
// R5-29: upstream's inspect returns the configuration model's own objects, so a write that edits
// the value it read would edit the window's defaults. Only the defaults set this key here.
async function contributedOverLiveLayers(src: Record<Key, string>): Promise<{ defaults: unknown; written: unknown }> {
	const h = helper(src.helper);
	const layers: Layers = { defaultValue: { bash: { path: 'bash', icon: 'terminal-bash' } } };
	const workspace = WORKSPACES.tab(TAB);
	let written: unknown;
	const self: Record<string, unknown> = {
		getPlatformKey: async () => 'linux', _environmentService: { remoteAuthority: TAB }, _seclabWorkspace: { getWorkspace: () => workspace },
		_configurationService: { inspect: () => layers, getValue: () => layers.defaultValue, updateValue: async (_k: string, v: unknown) => { written = structuredClone(v); } },
	};
	self._seclabSetting = method(src.profiles, '_seclabSetting', { seclabIsTabWindow: h.seclabIsTabWindow, seclabTabSetting: h.seclabTabSetting });
	await method(src.profiles, 'registerContributedProfile', { ConfigurationTarget: { USER: 2, USER_LOCAL: 3, USER_REMOTE: 4 }, TerminalSettingPrefix: { Profiles: 'terminal.integrated.profiles.' }, seclabIsTabWindow: h.seclabIsTabWindow })!.call(
		self, { extensionIdentifier: 'tab.ext', id: 'p', title: 'p', options: {} });
	return { defaults: structuredClone(layers.defaultValue), written };
}

function mutant(name: string, from: string, to: string): Record<string, string> {
	const text = readPatch(name);
	assert.equal(text.split(from).length - 1, 1, `mutant text not found once in ${name}: ${from}`);
	return { [name]: text.replace(from, to) };
}

const tests: Array<[string, () => Promise<void>]> = [
	['0053 to 0058 are in the series after 0034', async () => {
		const at = (n: string) => series.indexOf(n);
		for (const n of OURS) {
			assert.ok(at(n) > at('0034-seclab-no-host-variables-for-tab-terminals.patch'), `${n} is not after 0034`);
		}
	}],
	['baseline sends the host terminal settings to a tab', async () => {
		// The control: each leak the patched build must close is open on the baseline here.
		assert.deepEqual(await leaks(sources(false), TAB), EVERY_LEAK);
	}],
	['a tab gets none of the host terminal settings', async () => {
		assert.deepEqual(await leaks(sources(true), TAB), []);
		// A tab authority in another case is the same tab, as the filter module's test has it (R5-21).
		assert.deepEqual(await leaks(sources(true), TAB.replace('seclab', 'SecLab')), []);
		const filter = readFileSync(join(REPO, 'rpc-filter', 'patch-src', 'seclabRpcFilter.ts'), 'utf8');
		const filterTest = /\nconst SECLAB_AUTHORITY = (\/.*\/\w*);/.exec(filter)![1];
		// Every inlined copy too, in each patched file (review R5-28).
		for (const [key, text] of Object.entries(sources(true))) {
			for (const m of text.matchAll(/\/\^seclab\\\+\/\w*/g)) {
				assert.equal(m[0], filterTest, `${key}: a tab test that isn't the filter module's`);
			}
		}
	}],
	['a tab keeps its own terminal settings and the defaults', async () => {
		const o = await observe(sources(true), TAB, remoteFile(TAB));
		assert.deepEqual({ ...o.createProcess.configuration['terminal.integrated.env.linux'] as object }, { TAB_VAR: 'tab-remote', TAB_WS: 'tab-ws' });
		assert.equal(o.createProcess.configuration['terminal.integrated.cwd'], '');
		assert.equal(o.createProcess.configuration['terminal.integrated.detectLocale'], 'auto');
		assert.equal(o.inheritEnv, true);
		const profiles = o.getProfiles[0] as Record<string, Record<string, unknown>>;
		assert.deepEqual(Object.keys(profiles).sort(), ['bash', 'tabp']);
		// Upstream merges maps recursively: a tab's partial override keeps the default's path (R5-5).
		assert.deepEqual({ ...profiles.bash }, { path: 'bash', icon: 'terminal-bash', args: ['-l'] });
		assert.equal(o.getProfiles[1], undefined);
		assert.equal(o.automation, undefined);
		assert.deepEqual(o.collections, ['tab.extension']);
		assert.deepEqual(o.createProcess.activeFileResource, remoteFile(TAB));
		assert.deepEqual((o.createProcess.workspaceFolders as Array<{ name: string }>).map(f => f.name), ['w']);
		assert.equal(o.createProcess.workspaceName, 'w');
		assert.equal(o.createProcess.workspaceId, 'w');
		assert.deepEqual(o.ownIcon, { scheme: 'vscode-remote', authority: TAB, path: '/w/icon.png', $uri: true });
		assert.deepEqual(o.localCollections, ['host.ui-extension']);
		// A contributed profile extends the tab's own profiles and the defaults (R5-27, R5-29).
		assert.deepEqual(Object.keys(o.contributedValue as object).sort(), ['bash', 'p', 'tabp']);
	}],
	["a contributed profile write leaves the window's defaults unchanged", async () => {
		const { defaults, written } = await contributedOverLiveLayers(sources(true));
		assert.deepEqual(defaults, { bash: { path: 'bash', icon: 'terminal-bash' } });
		assert.deepEqual(Object.keys(written as object).sort(), ['bash', 'p']);
	}],
	['the host extension host can still set an id a tab took first', async () => {
		// 0054 stops a tab displacing another host's collection, never the window's own host (R5-11).
		const owner = (src: Record<Key, string>) => {
			const collections = new Map<string, unknown>([['some.id', { map: new Map(), remoteAuthority: TAB }]]);
			method(src.mainThread, '$setEnvironmentVariableCollection', {
				seclabIsTabAuthority: (a: unknown) => typeof a === 'string' && /^seclab\+/.test(a),
				deserializeEnvironmentVariableCollection: () => new Map([['V', {}]]), deserializeEnvironmentDescriptionMap: () => new Map(),
			})!.call({
				_environmentService: { remoteAuthority: TAB }, _extHostContext: { remoteAuthority: null },
				_environmentVariableService: { collections, set: (k: string, v: unknown) => collections.set(k, v), delete: (k: string) => collections.delete(k) },
			}, 'some.id', false, [['V', {}]], []);
			return (collections.get('some.id') as { remoteAuthority: unknown }).remoteAuthority;
		};
		assert.equal(owner(sources(true)), null);
		// The mutant without the window-host exception keeps the tab's entry: the case can fail.
		assert.equal(owner(sources(true, mutant(OURS[1], '+		if (seclabEntry && this._extHostContext.remoteAuthority !== null && seclabIsTabAuthority(', '+		if (seclabEntry && seclabIsTabAuthority('))), TAB);
	}],
	['a tab-owned automation profile still applies in a tab', async () => {
		const tabProfile = { path: '/bin/bash', args: ['-l'] };
		// A copy: upstream's resolver sets `icon` on the profile object it reads.
		SETTINGS['terminal.integrated.automationProfile.linux'].workspaceValue = structuredClone(tabProfile);
		try {
			const o = await observe(sources(true), TAB, remoteFile(TAB));
			assert.deepEqual({ path: (o.automation as { path: string }).path, args: (o.automation as { args: string[] }).args }, tabProfile);
		} finally {
			delete SETTINGS['terminal.integrated.automationProfile.linux'].workspaceValue;
		}
	}],
	['a non-tab remote window is unchanged by the patches', async () => {
		const other = 'ssh-remote+box';
		for (const kind of ['tab', 'hostFolder'] as const) {
			// 0058 escapes profile descriptions in every window by design; nothing else may change.
			const { descriptions, ...patched } = await observe(sources(true), other, hostFile, kind);
			const { descriptions: _d, ...baseline } = await observe(sources(false), other, hostFile, kind);
			assert.deepEqual(JSON.parse(JSON.stringify(patched)), JSON.parse(JSON.stringify(baseline)));
			assert.ok(descriptions.every(d => !/(^|[^\\])!\[/.test(d)));
			assert.ok(sees(patched.createProcess.configuration['terminal.integrated.env.linux']));
		}
	}],
	['each mutant of 0053 to 0058 is caught', async () => {
		const mutants: Array<[string, Record<string, string>, string]> = [
			['helper reads the local user layer', mutant(OURS[0], '+	const layers: unknown[] = [v.defaultValue, v.userRemoteValue,', '+	const layers: unknown[] = [v.defaultValue, v.userLocalValue, v.userRemoteValue,'), 'terminal.integrated.env.linux'],
			['helper reads the application layer', mutant(OURS[0], '+	const layers: unknown[] = [v.defaultValue, v.userRemoteValue,', '+	const layers: unknown[] = [v.defaultValue, v.applicationValue, v.userRemoteValue,'), 'terminal.integrated.env.osx'],
			['helper reads the policy layer', mutant(OURS[0], '+	const layers: unknown[] = [v.defaultValue, v.userRemoteValue,', '+	const layers: unknown[] = [v.defaultValue, v.policyValue, v.userRemoteValue,'), 'terminal.integrated.env.windows'],
			['helper trusts any workspace', mutant(OURS[0], '...(workspaceInTab ? [v.workspaceValue, v.workspaceFolderValue] : [])', 'v.workspaceValue, v.workspaceFolderValue'), 'hostFolder: workspace settings'],
			['createProcess keeps the host env', mutant(OURS[0], "+				'terminal.integrated.env.linux': tab<ICompleteTerminalConfiguration['terminal.integrated.env.linux']>('terminal.integrated.env.linux') ?? {},\n", ''), 'terminal.integrated.env.linux'],
			['getProfiles sends the host profiles', mutant(OURS[0], '+		return primaryBackend.getProfiles(this._seclabSetting(`${TerminalSettingPrefix.Profiles}${platform}`),', '+		return primaryBackend.getProfiles(this._configurationService.getValue(`${TerminalSettingPrefix.Profiles}${platform}`),'), 'getProfiles profiles'],
			['resolver reads the host automation profile', mutant(OURS[0], '? seclabTabSetting(this._configurationService, this._workspaceContextService.getWorkspace(), authority, key)', '? this._configurationService.getValue(key)'), 'automation profile'],
			['the host extension host gets the tab profile', mutant(OURS[0], '+		if (this._extHostContext.remoteAuthority === null && seclabIsTabAuthority(remoteAuthority)) {', '+		if (false) {'), 'tab profile to the host extension host'],
			['collections keep other origins', mutant(OURS[1], '&& originAuthority !== targetAuthority)', '&& originAuthority === undefined)'), 'host collection'],
			['a tab replaces a host collection', mutant(OURS[1], '+		if (seclabEntry && this._extHostContext.remoteAuthority !== null && seclabIsTabAuthority(', '+		if (false && seclabIsTabAuthority('), 'tab deletes a host collection'],
			['active file of any remote authority', mutant(OURS[2], '+			activeFileResource: own(activeFileResource) ? activeFileResource : undefined,', '+			activeFileResource,'), 'active file: host file'],
			['host folders sent', mutant(OURS[2], '+			workspaceFolders: ownFolders,', '+			workspaceFolders,'), 'hostFolder: folder paths or name'],
			['host workspace id sent', mutant(OURS[2], '+		if (!seclabIsTabWindow(this._remoteAuthority) || id !== workspace.id || seclabWorkspaceInTab(workspace, this._remoteAuthority)) {', '+		if (true) {'), 'hostFile: folder paths or name'],
			['host default profile name picks', mutant(OURS[0], '+			defaultProfileName = this._seclabSetting(`${TerminalSettingPrefix.DefaultProfile}${this._getOsKey(os)}`) as string | undefined;', '+			defaultProfileName = this._configurationService.getValue(`${TerminalSettingPrefix.DefaultProfile}${this._getOsKey(os)}`);'), 'host default profile picks a REH profile'],
			['contributed default from the host', mutant(OURS[0], '+			const defaultProfileName = this._seclabSetting(`${TerminalSettingPrefix.DefaultProfile}${key}`);', '+			const defaultProfileName = this._configurationService.getValue(`${TerminalSettingPrefix.DefaultProfile}${key}`);'), 'host default profile picks a contributed profile'],
			['tab authority from the connection only', mutant(OURS[0], 'this._seclabEnvironment?.remoteAuthority ?? this._remoteAgentService', 'this._remoteAgentService'), 'automation profile without a connection'],
			['tab collections to the host extension host', mutant(OURS[1], "+				.filter(([, c]) => !seclabIsTabAuthority(this._environmentService.remoteAuthority) || seclabOrigin(c as { remoteAuthority?: string | null }));", "+				.filter(() => true);"), 'tab collection to the host extension host'],
			['profile writes to the host', mutant(OURS[4], '+		return this._seclabTab() ? ConfigurationTarget.USER_REMOTE : ConfigurationTarget.USER;', '+		return ConfigurationTarget.USER;'), 'REH profile written to host settings'],
			['tab profile writes extend the host profiles', mutant(OURS[4], '+		if (!tab) {\n+			return this._configurationService.getValue(key);', '+		if (true) {\n+			return this._configurationService.getValue(key);'), 'host profiles copied into the tab'],
			['profile text as markdown', mutant(OURS[5], '+	return escapeUntrustedMarkdown(String(value));', '+	return String(value);'), 'markdown image in a profile description'],
			['profile text keeps links', mutant(OURS[5], '+	return escapeUntrustedMarkdown(String(value));', '+	return escapeMarkdownSyntaxTokens(String(value));'), 'link or forged line in a profile description'],
			['hover status as markdown', mutant(OURS[5], 'const text = (s: string) => seclabTab ? escapeUntrustedMarkdown(s) : s;', 'const text = (s: string) => s;'), 'markdown image in the terminal hover'],
			['inheritEnv from the host', mutant(OURS[0], '+			shellLaunchConfig.useShellEnvironment = this._seclabProfileSetting(TerminalSettingId.InheritEnv) as boolean | undefined;', '+			shellLaunchConfig.useShellEnvironment = this._configurationService.getValue(TerminalSettingId.InheritEnv) as boolean | undefined;'), 'host process switches'],
			['process switches from the host', mutant(OURS[0], "windowsUseConptyDll: tab<boolean>('terminal.integrated.windowsUseConptyDll') === true,", "windowsUseConptyDll: options.windowsUseConptyDll,"), 'host process switches'],
			['folder cwd from the host', mutant(OURS[0], "? seclabCwd.workspaceFolderValue ?? seclabCwd.userRemoteValue ?? seclabCwd.defaultValue", "? configurationService.getValue(TerminalSettingId.Cwd, { resource: folder.uri })"), 'host cwd in a folder\'s launch'],
			['contributed profile to host settings', mutant(OURS[4], '? ConfigurationTarget.USER_REMOTE : ConfigurationTarget.USER);', '? ConfigurationTarget.USER : ConfigurationTarget.USER);'), 'contributed profile written to host settings'],
			['hover title as markdown', mutant(OURS[5], '? escapeUntrustedMarkdown(instance.title) : instance.title', '? instance.title : instance.title'), 'markdown image in the terminal hover'],
			['link scheme to the host', mutant(OURS[4], '[...(Array.isArray(own) ? own : []), scheme], ConfigurationTarget.USER_REMOTE);', '[...(Array.isArray(own) ? own : []), scheme]);'), 'link scheme allowed in host settings'],
			['link schemes from the merged list', mutant(OURS[4], '+									if (tab && seclabIsTabWindow(tab)) {', '+									if (false) {'), 'host link schemes in the written list'],
			['detach with a foreign id', mutant(OURS[2], '+		if (seclabIsTabWindow(this._remoteAuthority) && workspaceId !== this._workspaceContextService.getWorkspace().id) {', '+		if (false) {'), 'foreign workspace id on detach'],
			['foreign icons kept', mutant(OURS[3], '+		const seclabOk = (u: URI | UriComponents) => !seclabTab || seclabUriInTab(u, seclabTab);', '+		const seclabOk = (_u: URI | UriComponents) => true;'), 'foreign profile icon'],
		];
		for (const [name, patches, leak] of mutants) {
			const found = await leaks(sources(true, patches), TAB);
			assert.ok(found.includes(leak), `mutant not caught by its own leak (${leak}): ${name}; found ${JSON.stringify(found)}`);
		}
		// R5-26: the resolution guard in another case lets a mixed-case tab's launch resolve host settings.
		const guard = mutant(OURS[0], 'if (!/^seclab\\+/i.test(this._remoteAuthority)) {', 'if (!/^seclab\\+/.test(this._remoteAuthority)) {');
		assert.ok((await leaks(sources(true, guard), TAB.replace('seclab', 'SecLab'))).includes('host settings resolved for the tab'), 'mutant not caught: a case-sensitive resolution guard');
		// R5-27: a contributed profile write starting from the merged profiles.
		const merged = mutant(OURS[4], "const profilesConfig = this._seclabSetting(`${TerminalSettingPrefix.Profiles}${platformKey}`) ?? {};", "const profilesConfig = this._configurationService.getValue(`${TerminalSettingPrefix.Profiles}${platformKey}`);");
		assert.ok((await leaks(sources(true, merged), TAB)).includes('host profiles copied into a contributed profile write'), 'mutant not caught: a contributed write from the merged profiles');
		// R5-29: the helper hands back a configuration model's own object.
		const live = mutant(OURS[0], '+	return copy(layers.filter(l => l !== undefined).reduce(merge, undefined)) as T | undefined;', '+	return layers.filter(l => l !== undefined).reduce(merge, undefined) as T | undefined;');
		assert.ok(Object.keys((await contributedOverLiveLayers(sources(true, live))).defaults as object).includes('p'), "mutant not caught: the helper returns a model's own object");
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
