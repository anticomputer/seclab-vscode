// Bundles the spike runner with the REAL upstream modules from the pinned Code-OSS
// source. Runs inside the node container (see run.sh); esbuild comes read-only from
// the shared builder volume's build/node_modules, so nothing is installed.
//
//   MODE=baseline  pristine upstream, byte for byte
//   MODE=gated     pristine upstream plus the prototype patches below, applied to the
//                  in-memory copy at bundle time (never to the source tree)
import * as esbuild from '/shared/vscode/build/node_modules/esbuild/lib/main.js';
import * as fs from 'node:fs';

const MODE = process.env.MODE;
if (MODE !== 'baseline' && MODE !== 'gated') { throw new Error('MODE must be baseline or gated'); }
const SRC = '/src/src/vs';

// agentHostAuth.ts imports one constant (CHAT_SETUP_ACTION_ID, used only by interactive
// sign-in) from chatActions.ts, which drags the chat actions UI into the bundle. Replace
// that one module with its constant, read from the real file.
const chatActionsStub = {
	name: 'chat-actions-stub',
	setup(build) {
		build.onResolve({ filter: /actions\/chatActions\.js$/ }, args => ({ path: args.path, namespace: 'stub' }));
		build.onLoad({ filter: /.*/, namespace: 'stub' }, () => {
			const real = fs.readFileSync(`${SRC}/workbench/contrib/chat/browser/actions/chatActions.ts`, 'utf8');
			const m = /export const CHAT_SETUP_ACTION_ID = ('[^']+')/.exec(real);
			if (!m) { throw new Error('CHAT_SETUP_ACTION_ID not found upstream'); }
			return { contents: `export const CHAT_SETUP_ACTION_ID = ${m[1]};`, loader: 'js' };
		});
	},
};

// Prototype of the plan §10 "client-tool execution" patch: in a seclab+ window the
// session handler refuses every client-tool execution the agent host asks for. The real
// patch reads IWorkbenchEnvironmentService.remoteAuthority (as patch 0009 does); the
// prototype reads the same value from a test global the runner sets.
const PROTOTYPE_PATCHES = [{
	file: `${SRC}/workbench/contrib/chat/browser/agentSessions/agentHost/agentHostSessionHandler.ts`,
	anchor: 'private async _executeClientTool(request: ClientToolExecutionRequest, backendSession: URI, sessionResource: URI, contextSessionResource: URI | undefined, token: CancellationToken, isCurrent: () => boolean, markInvocationStarted: () => void): Promise<void> {',
	insert: "\n\t\tif (String((globalThis as { __seclabRemoteAuthority?: string }).__seclabRemoteAuthority ?? '').startsWith('seclab+')) { this._logService.warn('[seclab-gate] deny client-tool ' + request.toolCall.toolName); return; }",
}];
const prototypePatches = {
	name: 'prototype-patches',
	setup(build) {
		for (const p of PROTOTYPE_PATCHES) {
			build.onLoad({ filter: new RegExp(p.file.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$') }, () => {
				const text = fs.readFileSync(p.file, 'utf8');
				const at = text.indexOf(p.anchor);
				if (at < 0 || text.indexOf(p.anchor, at + 1) >= 0) { throw new Error(`prototype anchor not found exactly once in ${p.file}`); }
				return { contents: text.slice(0, at + p.anchor.length) + p.insert + text.slice(at + p.anchor.length), loader: 'ts' };
			});
		}
	},
};

// Browser-layer modules touch DOM globals at load. No DOM behaviour is under test (these
// probes exercise protocol, file, configuration, auth and tool-dispatch logic only), so
// inert placeholders are enough for the modules to load.
const DOM_NAMES = ['HTMLElement', 'UIEvent', 'Event', 'KeyboardEvent', 'MouseEvent', 'CustomEvent', 'Element', 'Node', 'HTMLDivElement', 'HTMLInputElement', 'HTMLCanvasElement', 'HTMLIFrameElement', 'DocumentFragment', 'ShadowRoot', 'MutationObserver', 'ResizeObserver', 'IntersectionObserver', 'DOMParser', 'Range', 'Selection', 'DragEvent', 'FocusEvent', 'PointerEvent', 'WheelEvent', 'ClipboardEvent', 'InputEvent', 'StorageEvent', 'MessageEvent', 'Image', 'HTMLImageElement', 'SVGElement', 'HTMLAnchorElement', 'HTMLStyleElement', 'CSSStyleSheet'];
const banner = [
	"import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);",
	'globalThis.window ??= globalThis; globalThis.addEventListener ??= () => {}; globalThis.removeEventListener ??= () => {};',
	"globalThis.navigator ??= { userAgent: 'node', language: 'en' }; globalThis.location ??= { href: 'http://localhost/', protocol: 'http:' };",
	`for (const n of ${JSON.stringify(DOM_NAMES)}) globalThis[n] ??= class {};`,
	'globalThis.customElements ??= { define() {}, get() {} };',
	"const __el = () => new Proxy(function () {}, { get: (t, k) => k === Symbol.toPrimitive ? () => '' : k === 'then' ? undefined : __el(), apply: () => __el(), construct: () => __el() }); globalThis.document ??= __el();",
	'globalThis.matchMedia ??= () => ({ matches: false, addEventListener() {}, removeEventListener() {} }); globalThis.requestAnimationFrame ??= f => setTimeout(f, 0);',
].join('\n');

const r = await esbuild.build({
	entryPoints: [process.env.ENTRY ?? '/harness/runner.ts'],
	bundle: true, platform: 'node', format: 'esm', target: 'node22',
	outfile: process.env.OUT ?? `/run/bundle-${MODE}.mjs`, logLevel: 'error', metafile: true,
	alias: { vs: SRC },
	resolveExtensions: ['.ts', '.js', '.mjs'],
	tsconfigRaw: { compilerOptions: { experimentalDecorators: true, useDefineForClassFields: false } },
	loader: { '.css': 'empty', '.svg': 'empty', '.png': 'empty', '.ttf': 'empty' },
	nodePaths: ['/shared/vscode/node_modules'],
	external: ['electron'],
	plugins: MODE === 'gated' ? [chatActionsStub, prototypePatches] : [chatActionsStub],
	banner: { js: banner },
});
const upstream = Object.keys(r.metafile.inputs).filter(p => p.includes('src/vs/')).length;
console.log(`bundle ${MODE}: ${upstream} upstream modules${MODE === 'gated' ? `, ${PROTOTYPE_PATCHES.length} prototype patch(es)` : ''}`);
