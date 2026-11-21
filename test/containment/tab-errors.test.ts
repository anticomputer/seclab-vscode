// Review AIP-4: an error that crosses from the trusted window to a tab carries no host stack, and a
// policy refusal reads as an unsupported operation. Before patch 0062 the RPC filter's denial error
// reached the tab with the window's stack: the app's install path (under the host user's home) and
// the `_deny`/`checkRpc` frames that tell a refusal apart from an ordinary failure.
//
// The suite runs upstream's real RPCProtocol, ChannelServer and ChannelClient, with every series
// patch applied, from a virtual install path holding a canary user name, so any host frame that
// crosses names the canary. One side is the window (the filter attached, a tab's context), the
// other the tab. For each way an error reaches a tab it asserts what the tab gets:
//   - the RPC filter's denial (checkRpc), the command taint's (seclabTaintInFlight), the
//     fail-closed route (seclabExecuteCommandFromTab), patch 0009's throw and an ordinary upstream
//     failure, each through the RPC reply;
//   - the channel guard's denial (checkChannel), the unguarded refusal and an ordinary channel
//     failure, each through the IPC reply;
//   - patch 0030's and the agent-host gate's (0015) answers, against upstream's own text for the
//     same unsupported request.
// The tab must get the name and message (the ordinary failure is the control: it still arrives),
// a stack that is that one line, the same acknowledged reply an ordinary failure gets, and no
// canary, install path, filter frame or `seclab` text. The series without 0062 (main's) and each
// mutant of 0062 must fail.
//
//   ./seclab test tab-errors   (SECLAB_UPSTREAM_SRC = the pinned src/vs, read-only)

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { registerHooks } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as vm from 'node:vm';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SRC = process.env.SECLAB_UPSTREAM_SRC;
if (!SRC) {
	console.error('tab-errors: set SECLAB_UPSTREAM_SRC to the pinned src/vs (./seclab test tab-errors does)');
	process.exit(1);
}
const P0062 = '0062-seclab-tab-errors-carry-no-host-stack.patch';
const SERIES = readFileSync(join(REPO, 'patches', 'series'), 'utf8').split('\n').map(l => l.replace(/#.*/, '').trim()).filter(l => l.endsWith('.patch'));
const patchText = (name: string) => readFileSync(join(REPO, 'patches', name), 'utf8');

// The host user, as a stack would name them: a canary, so a match can only be a leak.
const CANARY = `seclabcanary_${randomBytes(6).toString('hex')}`;
const INSTALL = `/Users/${CANARY}/Applications/seclab-vscode.app/Contents/Resources/app/out/vs/`;
const TAB = 't-aaaaaaaaaaaaaaaaaaaaaaaaaa';
const AUTH = `seclab+${TAB}`;
// Patch 0009's refusals reach a tab only as RPC replies; its one message is read from the patch.
const P0009_THROWS = [...patchText('0009-seclab-no-builtin-chat-in-tabs.patch').matchAll(/^\+.*\bthrow new Error\((.*)\);\s*$/gm)].map(m => m[1]);
assert.ok(P0009_THROWS.length > 0 && P0009_THROWS.every(t => t === P0009_THROWS[0]), 'patch 0009 throws more than one message');
const P0009_THROW = JSON.parse(P0009_THROWS[0].replace(/^'(.*)'$/, '"$1"')) as string;

/** One file's section of a patch (`diff -ruN` or `diff --git`). */
const section = (patch: string, rel: string) => patch.split(/^(?=diff (?:-ruN|--git) )/m).find(p => p.split('\n')[0].includes(`/src/vs/${rel} `));

/** The content of a new file a patch creates, or undefined. */
function created(patch: string, rel: string): string | undefined {
	const sec = section(patch, rel);
	if (!sec || !/^@@ -0,0 /m.test(sec)) {
		return undefined;
	}
	const body = sec.slice(sec.indexOf('\n@@') + 1).split('\n').slice(1);
	const noEol = body.includes('\\ No newline at end of file');
	const lines = body.filter(l => l.startsWith('+')).map(l => l.slice(1));
	return lines.join('\n') + (noEol ? '' : '\n');
}

/** Apply one file's hunks to `source`, each exactly once. */
function apply(source: string, patch: string, rel: string): string {
	const sec = section(patch, rel);
	if (!sec || /^@@ -0,0 /m.test(sec)) {
		return source;
	}
	let out = source;
	for (const hunk of sec.split(/\n(?=@@ )/).slice(1)) {
		const lines = hunk.split('\n').slice(1).filter(l => l.length > 0 && l[0] !== '\\');
		const old = lines.filter(l => l[0] === ' ' || l[0] === '-').map(l => l.slice(1)).join('\n');
		const neu = lines.filter(l => l[0] === ' ' || l[0] === '+').map(l => l.slice(1)).join('\n');
		assert.equal(out.split(old).length - 1, 1, `a hunk no longer applies once to ${rel}`);
		out = out.replace(old, () => neu);
	}
	return out;
}

/** Variants of the tree: each is the series with 0062 replaced (undefined: left out). */
const VARIANTS = new Map<string, string | undefined>();
const ROOTS = new Map<string, string>();
function variant(name: string, p0062: string | undefined): string {
	VARIANTS.set(name, p0062);
	const root = `file://${INSTALL.replace('/out/vs/', `/out-${name}/vs/`)}`;
	ROOTS.set(root, name);
	return root;
}

function sourceOf(variantName: string, rel: string): string {
	const p0062 = VARIANTS.get(variantName);
	const patches = SERIES.map(n => n === P0062 ? p0062 : patchText(n)).filter((p): p is string => p !== undefined);
	let text: string | undefined;
	const real = join(SRC!, rel);
	if (existsSync(real)) {
		text = readFileSync(real, 'utf8');
	} else {
		for (const p of patches) {
			text ??= created(p, rel);
		}
	}
	assert.ok(text !== undefined, `no source for ${rel}`);
	for (const p of patches) {
		text = apply(text, p, rel);
	}
	// Node strips types but runs no decorators; upstream's memoize decorator only caches a getter.
	return text.replace(/^\s*[@]memoize\s*$/gm, '');
}

// Node strips types without eliding imports (verbatim module syntax), and upstream imports
// interfaces by name. So, as tsc does, an imported or re-exported name is kept only when the
// module it comes from exports it as a value.
const exists = (variantName: string, rel: string) => existsSync(join(SRC!, rel))
	|| SERIES.some(n => { const p = n === P0062 ? VARIANTS.get(variantName) : patchText(n); return p !== undefined && created(p, rel) !== undefined; });
function targetRel(variantName: string, from: string, spec: string): string | undefined {
	if (!spec.startsWith('.')) {
		return undefined;
	}
	const rel = new URL(spec, `file:///v/${from}`).pathname.slice('/v/'.length);
	if (rel.endsWith('.js')) {
		for (const alt of [rel.slice(0, -3) + '.ts', rel, rel.slice(0, -3) + '.d.ts']) {
			if (exists(variantName, alt)) {
				return alt;
			}
		}
	}
	return rel;
}
const valueCache = new Map<string, Set<string>>();
function valueExports(variantName: string, rel: string): Set<string> {
	const key = `${variantName}:${rel}`;
	const hit = valueCache.get(key);
	if (hit) {
		return hit;
	}
	const names = new Set<string>();
	valueCache.set(key, names);
	if (rel.endsWith('.d.ts') || !/\.[mc]?[jt]s$/.test(rel)) {
		return names;
	}
	const src = sourceOf(variantName, rel);
	for (const m of src.matchAll(/^export\s+(declare\s+)?(?:default\s+)?(?:async\s+)?(?:abstract\s+)?(const\s+enum|const|let|var|function\*?|class|enum|namespace|interface|type)\s+([A-Za-z_$][\w$]*)/gm)) {
		if (!m[1] && m[2] !== 'interface' && m[2] !== 'type') {
			names.add(m[3]);
		}
	}
	for (const m of src.matchAll(/^export\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from/gm)) {
		names.add(m[1]);
	}
	for (const m of src.matchAll(/^export\s+\*\s+from\s*['"]([^'"]+)['"]/gm)) {
		const t = targetRel(variantName, rel, m[1]);
		if (t) {
			valueExports(variantName, t).forEach(n => names.add(n));
		}
	}
	for (const m of src.matchAll(/^export\s+(type\s+)?\{([^}]*)\}(?:\s*from\s*['"]([^'"]+)['"])?/gm)) {
		if (m[1]) {
			continue;
		}
		const from = m[3] ? targetRel(variantName, rel, m[3]) : undefined;
		for (const item of m[2].split(',').map(s => s.trim()).filter(Boolean)) {
			if (item.startsWith('type ')) {
				continue;
			}
			const [local, as = local] = item.split(/\s+as\s+/);
			const value = m[3] ? (from ? valueExports(variantName, from).has(local) : true)
				: new RegExp(`(?:const|let|var|function\\*?|class|enum)\\s+${local.replace(/\$/g, '\\$')}\\b|import\\s[^;]*\\b${local.replace(/\$/g, '\\$')}\\b`).test(src);
			if (value) {
				names.add(as);
			}
		}
	}
	return names;
}
/** `rel`'s source with every import and re-export of a type-only name removed. */
function elided(variantName: string, rel: string): string {
	const src = sourceOf(variantName, rel);
	const keep = (spec: string, items: string): string[] => {
		const t = targetRel(variantName, rel, spec);
		const values = t ? valueExports(variantName, t) : undefined;
		return items.split(',').map(s => s.trim()).filter(Boolean).filter(item => {
			if (item.startsWith('type ')) {
				return false;
			}
			const name = item.split(/\s+as\s+/)[0];
			return !values || values.has(name);
		});
	};
	return src
		.replace(/^import\s+(?!type\b)(?:([A-Za-z_$][\w$]*)\s*,\s*)?\{([^}]*)\}\s*from\s*(['"])([^'"]+)\3;?/gm, (_all, def: string | undefined, items: string, q: string, spec: string) => {
			const kept = keep(spec, items);
			if (!def && kept.length === 0) {
				return '';
			}
			return `import ${def ? def + (kept.length ? ', ' : ' ') : ''}${kept.length ? `{ ${kept.join(', ')} } ` : ''}from ${q}${spec}${q};`;
		})
		.replace(/^export\s+(?!type\b)\{([^}]*)\}\s*from\s*(['"])([^'"]+)\2;?/gm, (_all, items: string, q: string, spec: string) => {
			const kept = keep(spec, items);
			return kept.length ? `export { ${kept.join(', ')} } from ${q}${spec}${q};` : '';
		});
}

const rootOf = (url: string) => [...ROOTS.keys()].find(r => url.startsWith(r));
registerHooks({
	resolve(specifier, context, next) {
		if (rootOf(specifier)) {
			return { url: specifier, shortCircuit: true };
		}
		const root = context.parentURL && rootOf(context.parentURL);
		if (root && (specifier.startsWith('./') || specifier.startsWith('../'))) {
			const url = new URL(specifier, context.parentURL).href;
			const rel = url.slice(root.length);
			return { url: root + targetRel(ROOTS.get(root)!, '', `./${rel}`)!, shortCircuit: true };
		}
		return next(specifier, context);
	},
	load(url, context, next) {
		const root = rootOf(url);
		if (root) {
			const rel = url.slice(root.length);
			return { format: rel.endsWith('.ts') ? 'module-typescript' : 'module', source: rel.endsWith('.ts') ? elided(ROOTS.get(root)!, rel) : sourceOf(ROOTS.get(root)!, rel), shortCircuit: true };
		}
		return next(url, context);
	},
});

/** Two in-memory ends of a message-passing protocol; `sent` records what the window sent. */
function pipe() {
	type L = (b: unknown) => void;
	const toWindow: L[] = [];
	const toTab: L[] = [];
	const sent: Uint8Array[] = [];
	const end = (mine: L[], theirs: L[], record: boolean) => ({
		onMessage: (l: L) => { mine.push(l); return { dispose() { mine.splice(mine.indexOf(l), 1); } }; },
		send: (b: { buffer: Uint8Array }) => {
			if (record) {
				sent.push(b.buffer.slice());
			}
			queueMicrotask(() => theirs.forEach(f => f(b)));
		},
	});
	return { window: end(toWindow, toTab, true), tab: end(toTab, toWindow, false), sent };
}

/** What a tab gets for one failing call: the error its side builds, and the window's raw bytes. */
interface Seen { name: string; message: string; stack: string | undefined; acked: boolean; wire: string }

const NONCE = randomBytes(6).toString('hex');
const ORDINARY = `ordinary failure ${NONCE}`;

/** What the tab sees of each failing call, in one variant of the tree. */
async function observe(variantName: string, p0062: string | undefined): Promise<Record<string, Seen>> {
	const root = variant(variantName, p0062);
	const rpc = await import(`${root}workbench/services/extensions/common/rpcProtocol.ts`);
	const ids = await import(`${root}workbench/services/extensions/common/proxyIdentifier.ts`);
	const F = await import(`${root}workbench/services/extensions/common/seclabRpcFilter.ts`);
	const ipc = await import(`${root}base/parts/ipc/common/ipc.ts`);
	const filter = F.seclabFilterFor(AUTH);
	assert.equal(filter.tabId, TAB);
	const seen: Record<string, Seen> = {};
	const record = (e: unknown, sent: Uint8Array[], acked: boolean): Seen => {
		const x = e as { name: string; message: string; stack?: string };
		return { name: x.name, message: x.message, stack: x.stack, acked, wire: sent.map(b => Buffer.from(b).toString('latin1')).join('\n') };
	};
	// Made on the window side, as an upstream handler's failure is: a code, a cause, a full stack.
	const ordinary = () => {
		const err = new Error(ORDINARY, { cause: new Error(`the cause ${NONCE}`) });
		(err as { code?: string }).code = 'ENOENT';
		return err;
	};

	// ---- RPC: the window's protocol carries the filter, as extensionHostManager builds it.
	const p = pipe();
	const windowSide = new rpc.RPCProtocol(p.window, null, null, filter);
	const tabSide = new rpc.RPCProtocol(p.tab);
	const clipboard = ids.createProxyIdentifier('MainThreadClipboard');
	const extService = ids.createProxyIdentifier('MainThreadExtensionService');
	windowSide.set(clipboard, { $readText: () => Promise.resolve('host clipboard') });
	// `$onWillActivateExtension` is allowed by policy; here it stands for a handler that fails
	// with each path's error, as MainThreadCommands does with the taint's or the route's.
	const cases: Record<string, () => unknown> = {
		ordinary,
		taint: () => F.seclabTaintInFlight('workbench.action.restartExtensionHost', filter),
		route: () => F.seclabExecuteCommandFromTab({}, 'x', [], filter),
		'0009': () => new Error(P0009_THROW),
	};
	windowSide.set(extService, {
		$onWillActivateExtension: (which: string) => {
			const v = cases[which]();
			if (v instanceof Promise) {
				return v;
			}
			throw v;
		},
	});
	const call = async (name: string, f: () => Promise<unknown>) => {
		const before = p.sent.length;
		try {
			await f();
			assert.fail(`${name}: the call succeeded`);
		} catch (e) {
			const sent = p.sent.slice(before);
			// Message type 5 is upstream's Acknowledged: an ordinary failure is acknowledged first.
			seen[name] = record(e, sent, sent.length > 1 && sent[0][0] === 5);
		}
	};
	await call('rpc-deny', () => tabSide.getProxy(clipboard).$readText());
	for (const name of Object.keys(cases)) {
		await call(`rpc-${name}`, () => tabSide.getProxy(extService).$onWillActivateExtension(name));
	}
	// Rejections that aren't plain errors (review TE-1, TE-2): a plain object carrying stacks at
	// depth, an error-like object from another realm, and an error whose message can't be read.
	const hostStack = new Error('host').stack!;
	const odd: Record<string, () => unknown> = {
		plain: () => ({ data: { stack: hostStack, detail: `kept ${NONCE}` }, list: [{ stacktrace: hostStack }] }),
		errorlike: () => vm.runInNewContext(`new Error(${JSON.stringify(`like ${NONCE}`)})`),
		unreadable: () => Object.defineProperty(new Error('x'), 'message', { get() { throw new Error('unreadable'); } }),
		// TE-9: an instance of another class carrying a stack below it; TE-13: a cycle, and a chain
		// deeper than the bound with a stack at its end.
		foreign: () => new (class Wrapped { kept = `foreign ${NONCE}`; detail = { stack: hostStack }; })(),
		// TE-15: a toJSON that returns its own object (URI's shape): its fields, not undefined.
		selfjson: () => new (class SelfJson { kept = `selfjson ${NONCE}`; detail = { stack: hostStack }; toJSON() { return this; } })(),
		// PR review on #78: binary data with properties of its own, and a toJSON whose result has one.
		binary: () => Object.assign(new Uint8Array([1, 2]), { detail: { stack: hostStack } }),
		json2: () => ({ toJSON: () => ({ kept: `json2 ${NONCE}`, toJSON: () => ({ stack: hostStack }) }) }),
		cyclic: () => {
			const a: Record<string, unknown> = { kept: `cyclic ${NONCE}` };
			a.self = a;
			let deep: Record<string, unknown> = { stack: hostStack };
			for (let i = 0; i < 10; i++) {
				deep = { deeper: deep };
			}
			a.deep = deep;
			return a;
		},
	};
	const errorsId = ids.createProxyIdentifier('MainThreadErrors');
	windowSide.set(errorsId, {
		$onUnexpectedError: (which: string) => Promise.reject(odd[which]()),
	});
	for (const name of Object.keys(odd)) {
		const before = p.sent.length;
		const settled = await Promise.race([
			tabSide.getProxy(errorsId).$onUnexpectedError(name).then(() => ({ how: 'resolved', message: '' }), (e: { message?: unknown } | undefined) => ({ how: 'rejected', message: String(e?.message ?? '') })),
			new Promise<{ how: string; message: string }>(r => setTimeout(() => r({ how: 'no reply', message: '' }), 2000)),
		]);
		const sent = p.sent.slice(before);
		seen[`rpc-odd-${name}`] = { name: settled.how, message: settled.message, stack: undefined, acked: sent.length > 1 && sent[0][0] === 5, wire: sent.map(b => Buffer.from(b).toString('latin1')).join('\n') };
	}

	// ---- IPC: the channels a tab's server calls on the window, with the tab's connection context.
	const ctx = { remoteAuthority: AUTH, clientId: 'c' };
	const ch = pipe();
	const server = new ipc.ChannelServer(ch.window, ctx);
	const client = new ipc.ChannelClient(ch.tab);
	server.registerChannel('download', { call: () => Promise.resolve('host file'), listen: () => () => ({ dispose() { } }) });
	server.registerChannel('remoteFilesystem', { call: () => Promise.reject(ordinary()), listen: () => () => ({ dispose() { } }) });
	const ipcCall = async (name: string, channel: string) => {
		const before = ch.sent.length;
		try {
			await client.getChannel(channel).call('readFile', []);
			assert.fail(`${name}: the call succeeded`);
		} catch (e) {
			// IPC has no acknowledgement; every reply is one message.
			seen[name] = record(e, ch.sent.slice(before), true);
		}
	};
	ipc.setSeclabChannelGuard(undefined);
	await ipcCall('ipc-unguarded', 'download');
	ipc.setSeclabChannelGuard((_c: unknown, channel: string, method: string) => filter.checkChannel(channel, method));
	await ipcCall('ipc-deny', 'download');
	ipc.setSeclabChannelGuard((_c: unknown, channel: string, method: string) => channel === 'remoteFilesystem' ? undefined : filter.checkChannel(channel, method));
	await ipcCall('ipc-ordinary', 'remoteFilesystem');
	ipc.setSeclabChannelGuard(undefined);
	windowSide.dispose();
	tabSide.dispose();
	server.dispose();
	client.dispose();
	return seen;
}

/** Host detail in what the window sent: the canary user, an install path, a frame, the filter. */
const LEAK = new RegExp([CANARY, '/Users/', '/repo/', 'Contents/Resources/app', 'file://', '    at ', '_deny', 'checkRpc', 'checkChannel', 'seclab']
	.map(s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'), 'i');

/** Problems with what the tab saw, or an empty list. */
function judge(seen: Record<string, Seen>): string[] {
	const problems: string[] = [];
	for (const [name, s] of Object.entries(seen)) {
		const leak = s.wire.match(LEAK);
		if (name.startsWith('rpc-odd-')) {
			// What arrives is upstream's business; that something does, and carries no host detail, is ours.
			if (leak) {
				problems.push(`${name}: the window sent ${leak[0]}`);
			}
			if (s.name !== 'rejected') {
				problems.push(`${name}: the tab got no reply (${s.name})`);
			}
			if (name === 'rpc-odd-plain' && !s.wire.includes(`kept ${NONCE}`)) {
				problems.push(`${name}: the object's other fields were not sent`);
			}
			for (const kept of ['foreign', 'cyclic', 'selfjson', 'json2']) {
				if (name === `rpc-odd-${kept}` && !s.wire.includes(`${kept} ${NONCE}`)) {
					problems.push(`${name}: the object's other fields were not sent`);
				}
			}
			// An error of another realm (instanceof misses it) still reaches the tab as an error.
			if (name === 'rpc-odd-errorlike' && s.message !== `like ${NONCE}`) {
				problems.push(`${name}: the error's message did not arrive`);
			}
			if (s.wire.length > 65536) {
				problems.push(`${name}: the reply is unbounded (${s.wire.length} bytes)`);
			}
			continue;
		}
		const header = s.message ? `${s.name}: ${s.message}` : s.name;
		if (s.stack !== header) {
			problems.push(`${name}: the stack is not its one header line`);
		}
		if (leak) {
			problems.push(`${name}: the window sent ${leak[0]}`);
		}
		if (!s.acked) {
			problems.push(`${name}: not acknowledged before its answer, unlike an ordinary failure`);
		}
		if (name.endsWith('-ordinary')) {
			// The control: an ordinary failure still reaches the tab whole.
			if (s.name !== 'Error' || s.message !== ORDINARY) {
				problems.push(`${name}: the ordinary failure did not arrive whole`);
			}
			if (name.startsWith('rpc-') && (!s.wire.includes(`the cause ${NONCE}`) || !s.wire.includes('ENOENT'))) {
				problems.push(`${name}: the cause or code was not sent`);
			}
		} else if (s.name !== 'Error' || s.message !== 'Unsupported operation') {
			problems.push(`${name}: a refusal is not "Error: Unsupported operation"`);
		}
	}
	return problems;
}

const tests: Array<[string, () => void | Promise<void>]> = [];
const test = (name: string, fn: () => void | Promise<void>) => tests.push([name, fn]);
// On a tree without 0062 (main before it) the "patched" case runs that tree's own series, and fails.
const p0062 = existsSync(join(REPO, 'patches', P0062)) ? patchText(P0062) : undefined;
const CALLS = ['ipc-deny', 'ipc-ordinary', 'ipc-unguarded', 'rpc-0009', 'rpc-deny', 'rpc-odd-binary', 'rpc-odd-cyclic', 'rpc-odd-errorlike', 'rpc-odd-foreign', 'rpc-odd-json2', 'rpc-odd-plain', 'rpc-odd-selfjson', 'rpc-odd-unreadable', 'rpc-ordinary', 'rpc-route', 'rpc-taint'];
// Main's window can fail to answer (an unreadable error throws inside upstream's reply); that is a
// result here, not a crash of the suite.
let unanswered = 0;
process.on('unhandledRejection', () => { unanswered++; });

test('patched: every refusal and the ordinary failure reach the tab with no host stack (AIP-4)', async () => {
	const seen = await observe('patched', p0062);
	assert.deepEqual(Object.keys(seen).sort(), CALLS);
	const problems = judge(seen);
	assert.deepEqual(problems, [], problems.join('; '));
});

test('main (the series without 0062): a refusal reaches the tab with the install path and the filter frames', async () => {
	const seen = await observe('main', undefined);
	assert.deepEqual(Object.keys(seen).sort(), CALLS);
	assert.ok(seen['rpc-deny'].stack!.includes(CANARY) && seen['rpc-deny'].wire.includes(CANARY), 'the canary install path did not reach the tab');
	assert.match(seen['rpc-deny'].stack!, /_deny|checkRpc/, 'no filter frame reached the tab');
	const problems = judge(seen);
	for (const name of CALLS.filter(n => !n.startsWith('rpc-odd-') || n === 'rpc-odd-plain')) {
		assert.ok(problems.some(p => p.startsWith(`${name}: the window sent`)), `${name} leaked nothing on main`);
	}
	assert.ok(problems.includes('rpc-deny: not acknowledged before its answer, unlike an ordinary failure'));
	assert.ok(problems.some(p => p.startsWith('rpc-odd-unreadable: the tab got no reply')) && unanswered > 0, 'an unreadable error was answered on main');
});

// Each mutant of 0062 must bring a named problem back.
const mutants: Array<[string, (p: string) => string, RegExp]> = [
	['the RPC reply keeps the stack', p => p.replace('this._seclabFilter ? errors.seclabErrorForTab(err) : err', 'err'), /^rpc-deny: the window sent/],
	['a refusal answers at once, unacknowledged', p => p.replace('+\t\t\tpromise = Promise.reject(refused);', '+\t\t\tthis._protocol.send(MessageIO.serializeReplyErr(req, errors.seclabErrorForTab(refused))); return;'), /^rpc-deny: not acknowledged/],
	['the IPC reply keeps the stack', p => p.replace('+\t\t\t\terr = seclabErrorForTab(err);', '+\t\t\t\terr = err;'), /^ipc-deny: the window sent/],
	['the clean error keeps the stack', p => p.replace('{ name, stack: message ? `${name}: ${message}` : name }', '{ name, stack: (error as Error).stack }'), /^rpc-taint: the window sent/],
	['the cause is passed on as it is', p => p.replace('+\t\t\t\tclean.cause = seclabErrorForTab(e!.cause, depth + 1);', '+\t\t\t\tclean.cause = e!.cause;'), /^rpc-ordinary: the window sent/],
	['the cause is dropped', p => p.replace('+\t\t\t\tclean.cause = seclabErrorForTab(e!.cause, depth + 1);', '+\t\t\t\tvoid 0;'), /^rpc-ordinary: the cause or code was not sent/],
	['only a tab context is not checked', p => p.replace('+\t\t\tif (seclabIsTabContext(this.ctx)) {', '+\t\t\tif (seclabIsTabContext(undefined)) {'), /^ipc-ordinary: the window sent/],
	['nested stacks are kept', p => p.replace(".filter(([k]) => k !== 'stack' && k !== 'stacktrace' && k !== 'toJSON')", ".filter(([k]) => k !== 'toJSON')"), /^rpc-odd-plain: the window sent/],
	['an error-like object is passed as data', p => p.replace(" || (e && typeof e === 'object' && typeof e.stack === 'string' && 'message' in e)", ''), /^rpc-odd-errorlike: the error's message did not arrive/],
	['an unreadable error is not caught', p => p.replace('+\t} catch {\n+\t\treturn bare(', '+\t} finally {\n+\t\tvoid bare(').replace("bare('Error', 'Unsupported operation');", "bare('Error', 'Unsupported operation'), 0;"), /^rpc-odd-unreadable: the tab got no reply/],
	['only plain objects are walked', p => p.replace("+\t\tif (e && typeof e === 'object') {", "+\t\tif (e && typeof e === 'object' && [Object.prototype, null].includes(Object.getPrototypeOf(e))) {"), /^rpc-odd-foreign: the window sent/],
	// The bound shows as an unbounded reply, or, should serialising that fail, as lost fields (review TE-14).
	['the depth is not bounded', p => p.replace('+\t\t\tif (depth >= 8) {\n+\t\t\t\treturn undefined;\n+\t\t\t}\n', ''), /^rpc-odd-cyclic: (the reply is unbounded|the object's other fields were not sent|the tab got no reply)/],
	['toJSON is asked again', p => p.replace("+\t\t\tif (!v || typeof v !== 'object') {", "+\t\t\tif (v !== e || typeof (e as { toJSON?: unknown }).toJSON === 'function') {\n+\t\t\t\treturn seclabErrorForTab(v, depth + 1);\n+\t\t\t}\n+\t\t\tif (!v || typeof v !== 'object') {"), /^rpc-odd-selfjson: the object's other fields were not sent/],
	['binary data passes as it is', p => p.replace('+\t\t\t\treturn new Uint8Array(e.buffer, e.byteOffset, e.byteLength).slice();', '+\t\t\t\treturn e;'), /^rpc-odd-binary: the window sent/],
	['a toJSON is copied', p => p.replace(" && k !== 'toJSON'", ''), /^rpc-odd-json2: the window sent/],
];
mutants.forEach(([name, mutate, expected], i) => {
	test(`rejects the mutant "${name}"`, async () => {
		assert.ok(p0062, `${P0062} is missing`);
		const m = mutate(p0062);
		assert.notEqual(m, p0062, `mutant "${name}" changed nothing: the prover is broken, not the gate`);
		const problems = judge(await observe(`m${i}`, m));
		assert.ok(problems.some(p => expected.test(p)), `not caught: ${problems.join('; ') || 'no problem found'}`);
	});
});

// Patch 0030 and the agent-host gate (0015) answer a tab's request themselves. Each answer is the
// one upstream gives the same request when it has no handler, read from the pinned source.
test('0030 answers a refused remote CLI command as upstream answers an unknown one', () => {
	const up = readFileSync(join(SRC!, 'workbench/contrib/terminal/browser/remoteTerminalBackend.ts'), 'utf8');
	assert.match(up, /this\._remoteTerminalChannel\.sendCommandResult\(reqId, true, 'Invalid remote cli command: ' \+ commandId\);/);
	const ours = sourceOf('patched', 'workbench/contrib/terminal/browser/remoteTerminalBackend.ts');
	const refusal = ours.slice(ours.indexOf('if (seclabTab) {'), ours.indexOf('if (!seclabTab) {'));
	assert.match(refusal, /sendCommandResult\(e\.reqId, true, 'Invalid remote cli command: ' \+ e\.commandId\);/);
	assert.doesNotMatch(refusal.split('\n').filter(l => /sendCommandResult/.test(l)).join('\n'), /seclab/i);
});

test('0015 answers a refused agent-host request as upstream answers an unknown method', async () => {
	const up = readFileSync(join(SRC!, 'platform/agentHost/browser/agentHostProtocolClient.ts'), 'utf8');
	assert.match(up, /throw new Error\(`Unknown method: \$\{method\}`\);/);
	assert.match(up, /let code = -32000;/);
	const root = variant('patched', p0062);
	const G = await import(`${root}platform/agentHost/common/seclabAhpPolicy.ts`);
	const D = await import(`${root}platform/agentHost/common/seclabAhpPolicyData.ts`);
	const tables = Object.values(D).find(v => v && typeof v === 'object' && 'clientRequests' in (v as object));
	assert.ok(tables, 'no verdict tables in seclabAhpPolicyData');
	const f = new G.SeclabAhpFilter(tables, 1, () => { });
	for (const method of ['resourceRead', '_vscode/resolveClientProxy']) {
		const out = f.fromUpstream(JSON.stringify({ jsonrpc: '2.0', id: 7, method, params: {} }));
		assert.deepEqual(JSON.parse(out.toUpstream[0]), { jsonrpc: '2.0', id: 7, error: { code: -32000, message: `Unknown method: ${method}` } });
	}
});

let failed = 0;
for (const [name, fn] of tests) {
	try {
		await fn();
		console.log(`PASS  ${name}`);
	} catch (err) {
		failed++;
		console.log(`FAIL  ${name}\n      ${(err as Error).message.split('\n').slice(0, 4).join('\n      ')}`);
	}
}
console.log(`\n${tests.length - failed}/${tests.length} passed`);
process.exit(failed ? 1 : 0);

