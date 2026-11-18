/**
 * The SHIPPED filter module, imported and run: the rewrite ladder, the tab identity, the
 * fail-closed attachment, the route patch 0008 takes, and the push refusals' decision path.
 *
 * Run: node --experimental-transform-types test/containment/filter-module.test.ts
 *      (or ./seclab test filter-module)
 *
 * `rpc-filter/patch-src/seclabRpcFilter.ts` imports four upstream modules; a resolve hook
 * redirects only those to the stand-ins in test/containment/filter-stubs/ (see its README). The
 * policy data and validators are the real ones. Each rule is also shown failing: a case that
 * would pass with the fix reverted pins nothing (the mutants at the bottom).
 *
 * Findings this pins (docs/security-reviews/FINDINGS.md): rpc-filter-patches #1 (rewrite
 * permitted with no rewriting), #4 (tab identity), #5 (0008 routing).
 */

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, cpSync, rmSync } from 'node:fs';
import { registerHooks } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..', '..');
const SRC_DIR = process.env.SECLAB_FILTER_SRC_DIR ?? join(REPO, 'rpc-filter', 'patch-src');
const STUBS: Record<string, string> = {
	'base/parts/ipc/common/ipc.js': 'ipc.mjs',
	'base/common/uri.js': 'uri.mjs',
	'platform/commands/common/commands.js': 'commands.mjs',
	'platform/contextkey/common/contextkey.js': 'contextkey.mjs',
};
registerHooks({
	resolve(specifier, context, next) {
		for (const [suffix, stub] of Object.entries(STUBS)) {
			if (specifier.endsWith(suffix)) {
				return { url: pathToFileURL(join(HERE, 'filter-stubs', stub)).href, shortCircuit: true };
			}
		}
		// The patch-src files import each other as `.js`, the form upstream's build resolves.
		if (/^\.\/seclab\w+\.js$/.test(specifier)) {
			return { url: pathToFileURL(join(SRC_DIR, specifier.slice(2).replace(/\.js$/, '.ts'))).href, shortCircuit: true };
		}
		return next(specifier, context);
	},
});

const F = await import(pathToFileURL(join(SRC_DIR, 'seclabRpcFilter.ts')).href);
const PD = await import(pathToFileURL(join(SRC_DIR, 'seclabPolicyData.ts')).href);
const ipc = await import(pathToFileURL(join(HERE, 'filter-stubs', 'ipc.mjs')).href);
const commands = await import(pathToFileURL(join(HERE, 'filter-stubs', 'commands.mjs')).href);

const TAB = 't-aaaaaaaaaaaaaaaaaaaaaaaaaa';
const AUTH = `seclab+${TAB}`;

const tests: Array<[string, () => void | Promise<void>]> = [];
const test = (name: string, fn: () => void | Promise<void>) => tests.push([name, fn]);

// Runs first: nothing has subscribed yet, which is the window before its decision log installs.
test('a push refusal made before the log installs is held, then delivered with its fixed reason', () => {
	F.seclabRefusePush(AUTH, 'push:remoteterminal:$onExecuteCommand');
	const seen: Array<Record<string, unknown>> = [];
	const sub = F.seclabOnDecision((d: Record<string, unknown>) => seen.push(d));
	sub.dispose();
	const d = seen.find(x => x.ref === 'push:remoteterminal:$onExecuteCommand');
	assert.ok(d, 'the early refusal was dropped');
	assert.equal(d.surface, 'push');
	assert.equal(d.verdict, 'deny');
	assert.equal(d.tabId, TAB);
	assert.equal(d.reason, 'server-initiated push refused in a tab window');
});

test('identity: the tab id comes from the authority, and nothing else parses', () => {
	assert.equal(F.seclabResolveTabId(AUTH), TAB);
	for (const bad of ['seclab+', 'seclab+a/b', 'seclab+a b', 'seclab+a:1', 'ssh-remote+x', '', 'x seclab+a', 'seclab+a\n']) {
		assert.equal(F.seclabResolveTabId(bad), undefined, JSON.stringify(bad));
	}
});

test('attachment fails closed: unparseable tab throws, unknown remote is deny-all, local is unfiltered', () => {
	assert.equal(F.seclabFilterFor(null), undefined);
	assert.equal(F.seclabFilterFor(AUTH).tabId, TAB);
	assert.throws(() => F.seclabFilterFor('seclab+a/b'), /cannot derive a tab id/);
	const unknown = F.seclabFilterFor('ssh-remote+host');
	assert.equal(unknown.tabId, 'unknown');
	assert.ok(unknown.checkRpc('MainThreadSecretState', '$getPassword', ['x.y', 'k']) instanceof Error);
	assert.equal(F.seclabPartitionOf(null), undefined);
	assert.equal(F.seclabPartitionOf(AUTH), TAB);
	assert.throws(() => F.seclabPartitionOf('seclab+a/b'));
	assert.equal(F.seclabIsTabAuthority(AUTH), true);
	assert.equal(F.seclabIsTabAuthority('ssh-remote+x'), false);
	assert.equal(F.seclabIsTabAuthority(undefined), false);
});

test('rewrite ladder: an unimplemented rewrite is denied, and says so', () => {
	const f = F.seclabFilterFor(AUTH);
	assert.ok(f.checkRpc('MainThreadAuthentication', '$getSession', ['github', ['repo'], {}]) instanceof Error);
	assert.equal(f.denials.at(-1).reason, 'rewrite not implemented; failing closed');
	assert.ok(f.checkRpc('MainThreadSecretState', '$getPassword', ['pub.ext', 'key']) instanceof Error);
	assert.equal(f.denials.at(-1).reason, 'rewrite not implemented; failing closed');
});

test('rewrite ladder: a registered rewrite runs its validator, then permits', () => {
	F.seclabRegisterRewrite('MainThreadSecretState', '$getPassword');
	const f = F.seclabFilterFor(AUTH);
	assert.equal(f.checkRpc('MainThreadSecretState', '$getPassword', ['pub.ext', 'key']), undefined);
	assert.ok(f.checkRpc('MainThreadSecretState', '$getPassword', ['pub.ext']) instanceof Error, 'wrong arity must be refused');
	assert.notEqual(f.denials.at(-1).reason, 'rewrite not implemented; failing closed');
	// Registering one method registers nothing else.
	assert.ok(f.checkRpc('MainThreadSecretState', '$deletePassword', ['pub.ext', 'key']) instanceof Error);
	assert.equal(f.denials.at(-1).reason, 'rewrite not implemented; failing closed');
});

test('a prompt verdict is denied until prompting is wired', () => {
	const f = F.seclabFilterFor(AUTH);
	assert.ok(f.checkRpc('MainThreadWindow', '$openUri', [{ scheme: 'https', authority: 'example.test', path: '/' }, undefined, {}]) instanceof Error);
	assert.equal(f.denials.at(-1).reason, 'prompt not yet wired; failing closed');
});

test('channels: only allow passes; deny, prompt, rewrite and allow_with_constraint are refused', () => {
	const f = F.seclabFilterFor(AUTH);
	for (const verdict of ['deny', 'prompt', 'rewrite', 'allow_with_constraint']) {
		PD.SECLAB_CHANNELS.set('seclabTestChannel', { verdict, ref: 'chan:seclabTestChannel' });
		assert.ok(f.checkChannel('seclabTestChannel', 'call') instanceof Error, verdict);
	}
	assert.equal(f.denials.at(-2).reason, 'rewrite is not defined for a channel; failing closed');
	PD.SECLAB_CHANNELS.set('seclabTestChannel', { verdict: 'allow', ref: 'chan:seclabTestChannel' });
	assert.equal(f.checkChannel('seclabTestChannel', 'call'), undefined);
	PD.SECLAB_CHANNELS.delete('seclabTestChannel');
	assert.ok(f.checkChannel('seclabNoSuchChannel', 'call') instanceof Error, 'an unknown channel takes the default deny');
});

test('the installed channel guard refuses for a tab context and ignores a trusted one', () => {
	assert.equal(typeof ipc.installedGuard, 'function');
	assert.ok(ipc.installedGuard({ remoteAuthority: AUTH }, 'seclabNoSuchChannel', 'call') instanceof Error);
	assert.equal(ipc.installedGuard({ remoteAuthority: 'ssh-remote+x' }, 'seclabNoSuchChannel', 'call'), undefined);
	assert.equal(ipc.installedGuard(undefined, 'seclabNoSuchChannel', 'call'), undefined);
});

test('0008 route: a tab command goes to the tainted path with its origin, and fails closed without it', async () => {
	const origin = F.seclabOriginFor(AUTH);
	assert.ok(origin, 'a tab authority has an origin');
	assert.equal(F.seclabOriginFor(null), undefined);
	assert.equal(F.seclabOriginFor('ssh-remote+x'), undefined);
	const calls: unknown[][] = [];
	const tainted = { seclabExecuteFromTab: async (id: string, args: unknown[], o: unknown) => { calls.push([id, args, o]); return 'ran'; } };
	assert.equal(await F.seclabExecuteCommandFromTab(tainted, 'x.y', [1], origin), 'ran');
	assert.deepEqual(calls, [['x.y', [1], origin]]);
	await assert.rejects(F.seclabExecuteCommandFromTab({ executeCommand: async () => 'untainted' }, 'x.y', [], origin), /Unsupported operation/);
});

// ---- the response side (ADR 20261116-response-side-control)

/** The command a token link or a rewritten command names, and its token. */
function tokenOf(link: string): string {
	const m = link.match(/^command:_seclab\.tabCommand\?(.+)$/);
	assert.ok(m, `not a token link: ${link}`);
	const args = JSON.parse(decodeURIComponent(m[1]));
	assert.ok(Array.isArray(args) && args.length === 1 && /^[0-9a-f]{32}$/.test(args[0]));
	return args[0];
}
const run = (token: unknown, cs: unknown = {}) => commands.handlers.get(F.SECLAB_TAB_COMMAND)({ get: () => cs }, token);

test('response: a trusted host gets no sanitiser; a tab and an unknown remote do', () => {
	assert.equal(F.seclabFromTab(null, async () => undefined), undefined);
	assert.ok(F.seclabFromTab(AUTH, async () => undefined));
	assert.ok(F.seclabFromTab('ssh-remote+x', async () => undefined));
});

test('response: tab markdown loses command links, HTML and remote images', () => {
	const s = F.seclabFromTab(AUTH, async () => undefined);
	const md = s.markdown({
		value: 'a [run](command:workbench.action.terminal.newLocal) b ![x](https://example.test/p.png) ![y](data:image/png;base64,AAAA) ![z][ref] [ref]: https://example.test/q.png <img src="https://example.test/r.png">',
		isTrusted: true, supportHtml: true, baseUri: { scheme: 'https', authority: 'example.test', path: '/' },
	});
	assert.deepEqual(md.isTrusted, { enabledCommands: [F.SECLAB_TAB_COMMAND] });
	assert.equal(md.supportHtml, false);
	assert.equal('baseUri' in md, false);
	assert.doesNotMatch(md.value, /command:workbench/);
	const link = md.value.match(/\((command:[^)]+)\)/)![1];
	tokenOf(link);
	assert.equal(s.markdown('plain').value, 'plain');
	assert.equal(s.markdown(undefined).value, '');
});

test('response: a tab command link keeps arguments with quotes and parentheses (review on #48)', async () => {
	const ran: unknown[] = [];
	const s = F.seclabFromTab(AUTH, async (id: string, args: unknown[]) => { ran.push([id, args]); return 'ok'; });
	const forms: Array<[string, unknown[], string]> = [
		['[run](command:pub.ext.own?%5B%22don\'t%22%5D)', ['don\'t'], ''],
		['[run](command:pub.ext.own?%5B%22a(b)c%22%5D)', ['a(b)c'], ''],
		['(see [run](command:pub.ext.own?%5B1%5D))', [1], ')'],
	];
	for (const [value, args, after] of forms) {
		const out = s.markdown({ value }).value;
		const m = out.match(/\((command:_seclab\.tabCommand\?[^)\s]+)\)(.*)$/);
		assert.ok(m, `no token link in ${out}`);
		assert.equal(m[2], after, `text after the link changed: ${out}`);
		ran.length = 0;
		await run(tokenOf(m[1]));
		assert.deepEqual(ran, [['pub.ext.own', args]], value);
	}
});

/** Markup that could open an image or a tag: an unescaped `![`, or `<` before a tag character. */
const OPENS_IMAGE_OR_TAG = /(?<!\\)!\[|<(?=[A-Za-z/!?])/;

test('response: no image or HTML form survives in tab markdown (review RSC-2)', () => {
	const s = F.seclabFromTab(AUTH, async () => undefined);
	const forms = [
		'![x](https://example.test/a.png)',
		'![x![]y](https://example.test/nested.png)',
		'![x![]y][1]\n\n[1]: https://example.test/ref.png',
		'<span x>\n<img src="https://example.test/block.png">\n',
		'<span class="a"><img src="https://example.test/inline.png"></span>',
		'\\<img src="https://example.test/escaped-backslash.png">',
		'\\![x](https://example.test/escaped-backslash.png)',
		'<!-- c --><?x?></a>',
		'![y](data:image/png;base64,AAAA)',
	];
	for (const form of forms) {
		const out = s.markdown({ value: form, isTrusted: true }).value;
		assert.doesNotMatch(out, OPENS_IMAGE_OR_TAG, form);
	}
	// Ordinary text is untouched: a comparison and a plain link.
	assert.equal(s.markdown('a < b and [docs](https://example.test/)').value, 'a < b and [docs](https://example.test/)');
});

test('response: a tab snippet that reads the clipboard is refused (review RSC-1)', () => {
	const s = F.seclabFromTab(AUTH, async () => undefined);
	for (const t of ['${CLIPBOARD}', '$CLIPBOARD', 'x ${CLIPBOARD:default} y', '${ CLIPBOARD}', '${1:${CLIPBOARD}}']) {
		assert.equal(s.snippetAllowed(t), false, t);
	}
	for (const t of ['${1:name}', '$TM_FILENAME', 'CLIPBOARD', '${TM_SELECTED_TEXT}']) {
		assert.equal(s.snippetAllowed(t), true, t);
	}
	assert.equal(s.snippetAllowed(undefined as unknown as string), false);
});

test('response: a tab command becomes the token command', () => {
	const s = F.seclabFromTab(AUTH, async () => undefined);
	const c = s.command({ id: 'workbench.action.terminal.newLocal', title: 't', arguments: [1] });
	assert.equal(c.id, F.SECLAB_TAB_COMMAND);
	assert.equal(c.arguments.length, 1);
	assert.match(c.arguments[0], /^[0-9a-f]{32}$/);
	assert.equal(s.command(undefined), undefined);
});

test('response: a denied command runs in the tab, never on the trusted side, and is logged when the tab lacks it', async () => {
	const seen: Array<Record<string, unknown>> = [];
	const sub = F.seclabOnDecision((d: Record<string, unknown>) => seen.push(d));
	try {
		const ranInTab: unknown[][] = [];
		const s = F.seclabFromTab(AUTH, async (id: string, args: unknown[]) => { ranInTab.push([id, args]); throw new Error('not found'); });
		const trusted = { seclabExecuteFromTab: async () => { throw new Error('must not run on the trusted side'); } };
		const token = s.command({ id: 'workbench.action.terminal.newLocal', title: 't', arguments: [1] }).arguments[0];
		await assert.rejects(run(token, trusted), /Unsupported operation/);
		assert.deepEqual(ranInTab, [['workbench.action.terminal.newLocal', [1]]]);
		assert.ok(seen.some(d => d.ref === 'cmd:workbench.action.terminal.newLocal' && d.verdict === 'deny'), 'the refusal was not logged');
		const link = s.markdown({ value: '[x](command:workbench.action.terminal.sendSequence?%7B%22text%22%3A%22x%22%7D)' }).value.match(/\((command:[^)]+)\)/)![1];
		await assert.rejects(run(tokenOf(link), trusted), /Unsupported operation/);
		assert.deepEqual(ranInTab[1], ['workbench.action.terminal.sendSequence', [{ text: 'x' }]]);
	} finally {
		sub.dispose();
	}
});

test('response: the tab\'s own command runs in the tab; an unknown token is refused', async () => {
	const s = F.seclabFromTab(AUTH, async (id: string) => `ran ${id}`);
	const token = s.command({ id: 'pub.ext.own', title: 't' }).arguments[0];
	assert.equal(await run(token), 'ran pub.ext.own');
	await assert.rejects(run('0'.repeat(32)), /Unsupported operation/);
	await assert.rejects(run(undefined), /Unsupported operation/);
});

test('response: a command the policy allows outright runs on the trusted side, under the tab origin', async () => {
	PD.SECLAB_COMMANDS.set('seclabTest.allowed', { verdict: 'allow', ref: 'cmd:seclabTest.allowed' });
	try {
		const calls: unknown[][] = [];
		const trusted = { seclabExecuteFromTab: async (id: string, args: unknown[], origin: unknown) => { calls.push([id, args, origin]); return 'trusted'; } };
		const s = F.seclabFromTab(AUTH, async () => { throw new Error('must not run in the tab'); });
		assert.equal(await run(s.command({ id: 'seclabTest.allowed', title: 't', arguments: [2] }).arguments[0], trusted), 'trusted');
		assert.equal(calls.length, 1);
		assert.equal((calls[0][2] as { tabId: string }).tabId, TAB);
	} finally {
		PD.SECLAB_COMMANDS.delete('seclabTest.allowed');
	}
});

test('0008 patch: $executeCommand routes a tab origin, captured from the connection, before the plain path', () => {
	const patch = readFileSync(join(REPO, 'patches', '0008-seclab-route-tab-commands.patch'), 'utf8');
	assert.deepEqual(routeProblems(patch), []);
});

/** What is wrong with patch 0008's routing, or nothing. */
function routeProblems(patch: string): string[] {
	const added = patch.split('\n').filter(l => l.startsWith('+') && !l.startsWith('+++')).map(l => l.slice(1));
	const code = added.filter(l => !/^\s*(\/\/|\*|\/\*\*)/.test(l)).join('\n');
	const problems: string[] = [];
	if (!/this\._seclabOrigin = seclabOriginFor\(extHostContext\.remoteAuthority\);/.test(code)) {
		problems.push('the origin is not taken from the connection');
	}
	if (!/if \(this\._seclabOrigin\) \{\s*return seclabExecuteCommandFromTab<T>\(this\._commandService, id, args, this\._seclabOrigin\);/.test(code)) {
		problems.push('a tab origin does not route to seclabExecuteCommandFromTab');
	}
	// The route must come before upstream's plain call, which is context in the hunk.
	const route = patch.indexOf('return seclabExecuteCommandFromTab<T>');
	const plain = patch.indexOf(' \t\treturn this._commandService.executeCommand<T>(id, ...args);');
	if (route < 0 || plain < 0 || route > plain) {
		problems.push('the route is not ahead of the plain executeCommand');
	}
	return problems;
}

test('0008 patch checker rejects each mutant of the real patch', () => {
	const patch = readFileSync(join(REPO, 'patches', '0008-seclab-route-tab-commands.patch'), 'utf8');
	const mutants: Array<[string, string, string]> = [
		['origin from an argument', 'seclabOriginFor(extHostContext.remoteAuthority)', 'seclabOriginFor(id)'],
		['routing removed', 'return seclabExecuteCommandFromTab<T>(this._commandService, id, args, this._seclabOrigin);', 'return this._commandService.executeCommand<T>(id, ...args);'],
		['origin dropped from the route', 'id, args, this._seclabOrigin);', 'id, args, undefined);'],
	];
	for (const [name, from, to] of mutants) {
		assert.ok(patch.includes(from), `mutant "${name}" no longer applies; update it`);
		assert.notDeepEqual(routeProblems(patch.replace(from, to)), [], name);
	}
});

let failed = 0;
for (const [name, fn] of tests) {
	try {
		await fn();
		console.log(`ok   ${name}`);
	} catch (err) {
		failed++;
		console.log(`FAIL ${name}\n     ${(err as Error).message.split('\n')[0]}`);
	}
}

// Mutants of the shipped module: each fix reverted in a copy of patch-src must fail a case
// above. Run as a child over the copy, so this process's module state is not shared.
if (!process.env.SECLAB_FILTER_SRC_DIR) {
	const MUTANTS: Array<[string, string, string]> = [
		['an unregistered rewrite is permitted', "if (!seclabRewrites.has(`${sid}.${method}`)) {", 'if (false) {'],
		['a channel rewrite is permitted', "return this._deny(ref, 'rewrite is not defined for a channel; failing closed');", 'return this._permit(ref, verdict);'],
		['an unparseable tab gets a filter', "throw new Error(`seclab: cannot derive a tab id from authority ${remoteAuthority}`);\n\t}\n\treturn new SeclabFilter(tabId,", "}\n\treturn new SeclabFilter(tabId ?? 'unparsed',"],
		['the tab id accepts any characters', "authority.match(/^seclab\\+([\\w.-]+)$/)", "authority.match(/^seclab\\+(.+)$/)"],
		['the route falls back to the plain path', "return Promise.reject(new Error('Unsupported operation'));\n\t}\n\treturn tainted.seclabExecuteFromTab", "return (commandService as any).executeCommand(id, ...args);\n\t}\n\treturn tainted.seclabExecuteFromTab"],
		['early decisions are dropped', 'if (seclabEarly.length < SECLAB_EARLY_MAX) {', 'if (false) {'],
		['a denied data command runs on the trusted side', "if (entry.filter.commandVerdict(entry.id) === 'allow') {", 'if (true) {'],
		['markdown keeps full trust', 'isTrusted: { enabledCommands: [SECLAB_TAB_COMMAND] },', 'isTrusted: true,'],
		['images are kept', ".replace(SECLAB_IMAGE_OPEN, '!\\\\[')", ".replace(SECLAB_IMAGE_OPEN, '![')"],
		['HTML is kept', ".replace(SECLAB_HTML_OPEN, '&lt;')", ".replace(SECLAB_HTML_OPEN, '<')"],
		['HTML is escaped with a backslash', ".replace(SECLAB_HTML_OPEN, '&lt;')", ".replace(SECLAB_HTML_OPEN, '\\\\<')"],
		['the clipboard snippet is allowed', 'return typeof insertText === \'string\' && !SECLAB_SNIPPET_CLIPBOARD.test(insertText);', 'return typeof insertText === \'string\';'],
		['command links are kept', 'out += value.slice(last, m.index) + rewrite(m[1], query);', 'out += value.slice(last, end);'],
		['the query stops at an apostrophe', 'if (/[\\s"<>\\]`]/.test(c)) {', 'if (/[\\s"\'<>\\]`]/.test(c)) {'],
		['the query stops at the first parenthesis', 'if (depth === 0) {\n\t\t\t\t\t\tbreak;', 'if (true) {\n\t\t\t\t\t\tbreak;'],
		['an unknown token runs', "if (!entry) {\n\t\tthrow denied();", "if (!entry) {\n\t\treturn undefined;"],
	];
	const src = readFileSync(join(SRC_DIR, 'seclabRpcFilter.ts'), 'utf8');
	const scratch = mkdtempSync(join(process.env.SECLAB_SCRATCH ?? tmpdir(), 'seclab-filter-mutants-'));
	// Control: the same child over an unchanged copy passes, so a caught mutant is the mutant.
	cpSync(SRC_DIR, join(scratch, 'control'), { recursive: true });
	const control = spawnSync(process.execPath, [...process.execArgv, fileURLToPath(import.meta.url)], { env: { ...process.env, SECLAB_FILTER_SRC_DIR: join(scratch, 'control') }, encoding: 'utf8' });
	if (control.status !== 0) {
		failed++;
		console.log(`FAIL control: the unchanged copy fails in the child, so no mutant result means anything\n${control.stdout}`);
	} else {
		console.log('ok   control: the unchanged copy passes in the child');
	}
	for (const [name, from, to] of MUTANTS) {
		if (!src.includes(from)) {
			failed++;
			console.log(`FAIL mutant "${name}": its target is gone from seclabRpcFilter.ts; update the mutant`);
			continue;
		}
		const dir = join(scratch, String(MUTANTS.findIndex(m => m[0] === name)));
		cpSync(SRC_DIR, dir, { recursive: true });
		writeFileSync(join(dir, 'seclabRpcFilter.ts'), src.replace(from, to));
		const r = spawnSync(process.execPath, [...process.execArgv, fileURLToPath(import.meta.url)], { env: { ...process.env, SECLAB_FILTER_SRC_DIR: dir }, encoding: 'utf8' });
		if (r.status === 0) {
			failed++;
			console.log(`FAIL mutant survived: ${name}`);
		} else {
			console.log(`ok   mutant caught: ${name}`);
		}
	}
	rmSync(scratch, { recursive: true, force: true });
}
console.log(failed ? `\n${failed} failed` : '\nall passed');
process.exit(failed ? 1 : 0);
