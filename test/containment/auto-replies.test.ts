// Patch 0061 (review R5-32): a tab window installs no terminal auto reply on the local pty host.
// Every window registers the local backend, and the local pty host behind it is one per app: it
// applies each reply to every terminal it runs, in every window. A tab window's settings include
// the remote user settings the tab's server serves, so a tab could name a match and a reply,
// carriage return included, that the pty host typed into a normal window's shell. 0061 makes the
// local backend's installAutoReply a no-op in a tab window, whoever calls it (R5-32). The other
// way, the window installed the host user's pairs on the tab's own backend, whose server reads
// them; 0061 sends a tab's backend only pairs from the tab's own settings (R5-31).
// The suite runs upstream's TerminalAutoRepliesContribution._installListenersOnBackend against a
// local backend and the tab's own, each running this tree's installAutoReply (series applied), at
// start and on a settings change, with a host user's pair and a tab's. On a tree without 0061 (main before it)
// the tab case fails. Each mutant of 0061 must bring the leak back.
//
//   ./seclab test auto-replies   (SECLAB_UPSTREAM_SRC = the pinned src/vs, read-only)

import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SRC = process.env.SECLAB_UPSTREAM_SRC;
if (!SRC) {
	console.error('auto-replies: set SECLAB_UPSTREAM_SRC to the pinned src/vs (./seclab test auto-replies does)');
	process.exit(1);
}
const CONTRIB = 'workbench/contrib/terminalContrib/autoReplies/browser/terminal.autoReplies.contribution.ts';
const REL = 'workbench/contrib/terminal/electron-browser/localTerminalBackend.ts';
const REMOTE = 'workbench/contrib/terminal/browser/remoteTerminalBackend.ts';
const SETTINGS = 'workbench/services/configuration/common/seclabTabSettings.ts';
const P0061 = '0061-seclab-no-tab-auto-replies-on-the-local-pty-host.patch';
const SERIES = readFileSync(join(REPO, 'patches', 'series'), 'utf8').split('\n').map(l => l.trim()).filter(l => l.endsWith('.patch'));
const patchFile = (name: string) => {
	const p = join(REPO, 'patches', name);
	return existsSync(p) ? readFileSync(p, 'utf8') : '';
};

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

/** `rel` with every series patch that touches it applied, 0061 replaced by `p0061`. */
function applied(rel: string, p0061: string | undefined): string {
	let text = readFileSync(join(SRC!, rel), 'utf8');
	for (const name of SERIES) {
		const patch = name === P0061 ? p0061 : patchFile(name);
		if (patch) {
			text = apply(text, patch, rel);
		}
	}
	return text;
}
const fn = (source: string, name: string, deps: Record<string, unknown>) => new Function(...Object.keys(deps),
	`return ${stripTypeScriptTypes(`(${method(source, name)})`, { mode: 'transform' }).trim().replace(/;$/, '')};`)(...Object.values(deps));

/** The method at `head`, brace-matched, as a function. */
function method(source: string, name: string): string {
	const m = new RegExp(`\\n\\t(?:private |public )?${name}\\(`).exec(source);
	assert.ok(m, `${name} not found`);
	let i = m.index + m[0].length;
	for (let depth = 1; depth > 0; i++) {
		depth += source[i] === '(' ? 1 : source[i] === ')' ? -1 : 0;
	}
	let j = source.indexOf('{', i) + 1;
	for (let depth = 1; depth > 0; j++) {
		depth += source[j] === '{' ? 1 : source[j] === '}' ? -1 : 0;
	}
	return source.slice(m.index, j).trim().replace(/^(?:(?:private|public) )?/, 'function ');
}

// The filter module's own tab test, from this tree.
const SECLAB_AUTHORITY = new Function(`return ${/\nconst SECLAB_AUTHORITY = (\/.*\/\w*);/.exec(readFileSync(join(REPO, 'rpc-filter', 'patch-src', 'seclabRpcFilter.ts'), 'utf8'))![1]};`)() as RegExp;
const seclabIsTabAuthority = (a: unknown) => typeof a === 'string' && SECLAB_AUTHORITY.test(a);

// The host user's pair, and the tab's from its server's remote user settings.
const LAYERS = { defaultValue: {}, userLocalValue: { seclabcanary_hostmatch_ar1: 'seclabcanary_hostreply_ar1', unset: null }, userRemoteValue: { seclabcanary_tabmatch_ar1: 'seclabcanary_tabreply_ar1' } };
const MERGED = { ...LAYERS.defaultValue, ...LAYERS.userLocalValue, ...LAYERS.userRemoteValue };
/** 0060's helper module (on every tree this suite runs on), evaluated over stubs. */
function helpers(): { seclabOnTab: unknown; seclabTabOwnValue: unknown } {
	const sec = section(patchFile('0060-seclab-no-host-search-excludes-in-tabs.patch'), SETTINGS);
	assert.ok(sec, '0060 creates the tab settings helper');
	const body = sec.split('\n').filter(l => l.startsWith('+') && !l.startsWith('+++')).map(l => l.slice(1)).join('\n').replace(/^import .*$/mg, '').replace(/^export /mg, '');
	const js = stripTypeScriptTypes(`(function () {\n${body}\nreturn { seclabOnTab, seclabTabOwnValue };\n})`, { mode: 'transform' }).trim().replace(/;$/, '');
	return new Function('Schemas', 'seclabIsTabAuthority', `return ${js}();`)({ vscodeRemote: 'vscode-remote' }, seclabIsTabAuthority);
}
const LOCAL = '(local pty host)';

/**
 * Which backends got which replies when a window with `window` as its authority runs upstream's
 * contribution: the local backend runs the tree's LocalTerminalBackend.installAutoReply over a
 * recording pty host, any other backend records what it is given.
 */
async function installs(p0061: string | undefined, window: string | undefined, backends: Array<string | undefined>): Promise<Record<string, string[]>> {
	const install = fn(applied(CONTRIB, p0061), '_installListenersOnBackend', {
		seclabIsTabAuthority, TERMINAL_CONFIG_SECTION: 'terminal.integrated', TerminalAutoRepliesSettingId: { AutoReplies: 'terminal.integrated.autoReplies' }, localize: (_k: string, m: string) => m,
	});
	const localInstall = fn(applied(REL, p0061), 'installAutoReply', { seclabIsTabAuthority });
	const remoteInstall = fn(applied(REMOTE, p0061), 'installAutoReply', { seclabIsTabAuthority, ...helpers(), URI: { from: (u: object) => u }, Schemas: { vscodeRemote: 'vscode-remote' }, MERGED_FOR_MUTANT: MERGED });
	const got: Record<string, string[]> = {};
	const listeners: Array<(e: unknown) => Promise<void> | void> = [];
	const self = {
		_ownerId: 'owner',
		_seclabEnvironment: { remoteAuthority: window },
		_configurationService: {
			getValue: (k: string) => k === 'terminal.integrated' ? { autoReplies: { ...MERGED } } : undefined,
			onDidChangeConfiguration: (l: (e: unknown) => void) => { listeners.push(l); return { dispose() { } }; },
		},
		_register: <T>(d: T) => d,
		_lifecycleService: { onWillShutdown: () => ({ dispose() { } }) },
	};
	for (const authority of backends) {
		const key = authority ?? LOCAL;
		got[key] = [];
		const record = (match: string, reply: string) => { got[key].push(`${match}=${reply}`); return Promise.resolve(); };
		const local = { _environmentService: { remoteAuthority: window }, _proxy: { installAutoReply: record } };
		const remote = {
			remoteAuthority: authority, _remoteTerminalChannel: { installAutoReply: record },
			_workspaceContextService: { getWorkspace: () => ({ folders: [{ uri: { scheme: 'vscode-remote', authority, path: '/w' } }] }) },
			_configurationService: { inspect: (k: string) => k === 'terminal.integrated.autoReplies' ? structuredClone(LAYERS) : {} },
		};
		install.call(self, {
			remoteAuthority: authority,
			installAutoReply: (m: string, r: string, o: string) => authority === undefined ? localInstall.call(local, m, r, o) : remoteInstall.call(remote, m, r, o),
			uninstallAllAutoReplies: async () => { got[key].push('uninstall'); },
		});
	}
	// And when the setting changes.
	for (const l of listeners) {
		await l({ affectsConfiguration: (k: string) => k === 'terminal.integrated.autoReplies' });
	}
	return got;
}

const TAB = 'seclab+tab1';
const BACKENDS = [undefined, TAB];
const HOST = 'seclabcanary_hostmatch_ar1=seclabcanary_hostreply_ar1';
const TABR = 'seclabcanary_tabmatch_ar1=seclabcanary_tabreply_ar1';
const P = patchFile(P0061);

const tests: Array<[string, () => Promise<void>]> = [
	['0061 ships, and gates the local backend\'s installAutoReply', async () => {
		assert.ok(SERIES.includes(P0061), '0061 is not in patches/series');
		assert.ok(section(P, REL), '0061 does not touch the local backend');
		assert.match(method(applied(REL, P), 'installAutoReply'), /seclabIsTabAuthority\(this\._environmentService\.remoteAuthority\)/);
	}],
	['baseline: a tab window installs replies on the shared local pty host', async () => {
		const got = await installs(undefined, TAB, BACKENDS);
		assert.deepEqual(got[LOCAL], [HOST, TABR, 'uninstall', HOST, TABR]);
		// And the host user's pair went to the tab's server (R5-31).
		assert.deepEqual(got[TAB], [HOST, TABR, 'uninstall', HOST, TABR]);
	}],
	['a tab window installs no auto reply on the shared local pty host', async () => {
		for (const window of [TAB, 'SecLab+Tab1']) {
			const got = await installs(P, window, BACKENDS);
			assert.deepEqual(got[LOCAL], ['uninstall'], `${window}: the local pty host got replies`);
			// The tab's own backend gets the tab's pair, never the host user's, at start and on a change.
			assert.deepEqual(got[TAB], [TABR, 'uninstall', TABR], `${window}: the tab's own backend`);
		}
	}],
	['a window that is not a tab installs on every backend, as upstream', async () => {
		for (const window of [undefined, 'ssh-remote+box', 'seclab-tab1', 'xseclab+tab1']) {
			const backends = [undefined, window ?? 'ssh-remote+other'];
			assert.deepEqual(await installs(P, window, backends), await installs(undefined, window, backends), `window ${window}`);
		}
	}],
	['each mutant of 0061 is caught', async () => {
		const mutants: Array<[string, string, string]> = [
			['no gate', '+			return Promise.resolve();\n', '+\n'],
			['the gate tests nothing', '+		if (seclabIsTabAuthority(this._environmentService.remoteAuthority)) {', '+		if (false) {'],
			['the gate tests another authority', '+		if (seclabIsTabAuthority(this._environmentService.remoteAuthority)) {', '+		if (seclabIsTabAuthority(this.remoteAuthority)) {'],
		];
		for (const [name, from, to] of mutants) {
			assert.equal(P.split(from).length - 1, 1, `mutant text not found once: ${name}`);
			const got = await installs(P.replace(from, () => to), TAB, BACKENDS);
			assert.ok(got[LOCAL].some(x => x !== 'uninstall'), `mutant not caught: ${name}`);
		}
		const remoteMutants: Array<[string, string, string]> = [
			['no tab-pair check', '+		if (seclabIsTabAuthority(this.remoteAuthority)) {', '+		if (false) {'],
			['no membership check', "if (!own || typeof own !== 'object' || !Object.prototype.hasOwnProperty.call(own, match) || own[match] !== reply) {", "if (!own) {"],
			['the host layers read', "seclabTabOwnValue<Record<string, unknown>>(this._configurationService, 'terminal.integrated.autoReplies',", "((_c: unknown, _k: unknown, _r: unknown) => MERGED_FOR_MUTANT)(this._configurationService, 'terminal.integrated.autoReplies',"],
		];
		for (const [name, from, to] of remoteMutants) {
			assert.equal(P.split(from).length - 1, 1, `mutant text not found once: ${name}`);
			const got = await installs(P.replace(from, () => to), TAB, BACKENDS);
			assert.ok(got[TAB].includes(HOST), `mutant not caught: ${name}`);
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
