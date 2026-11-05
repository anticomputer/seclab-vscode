// Bundles the spike runner with the REAL upstream modules from the pinned Code-OSS
// source. Runs inside the node container (see run.sh); esbuild comes read-only from
// the shared builder volume's build/node_modules, so nothing is installed.
import * as esbuild from '/shared/vscode/build/node_modules/esbuild/lib/main.js';
import * as fs from 'node:fs';

// agentHostAuth.ts imports one constant (CHAT_SETUP_ACTION_ID, used only by interactive
// sign-in) from chatActions.ts, which drags the whole chat UI and the DOM into the
// bundle. Replace that one module with its constant, read from the real file, so the
// code under test is byte-for-byte upstream and nothing else changes.
const chatActionsStub = {
	name: 'chat-actions-stub',
	setup(build) {
		build.onResolve({ filter: /actions\/chatActions\.js$/ }, args => ({ path: args.path, namespace: 'stub' }));
		build.onLoad({ filter: /.*/, namespace: 'stub' }, () => {
			const real = fs.readFileSync('/src/src/vs/workbench/contrib/chat/browser/actions/chatActions.ts', 'utf8');
			const m = /export const CHAT_SETUP_ACTION_ID = ('[^']+')/.exec(real);
			if (!m) { throw new Error('CHAT_SETUP_ACTION_ID not found upstream'); }
			return { contents: `export const CHAT_SETUP_ACTION_ID = ${m[1]};`, loader: 'js' };
		});
	},
};

const r = await esbuild.build({
	entryPoints: ['/harness/runner.ts'],
	bundle: true, platform: 'node', format: 'esm', target: 'node22',
	outfile: '/run/bundle.mjs', logLevel: 'error', metafile: true,
	alias: { vs: '/src/src/vs' },
	resolveExtensions: ['.ts', '.js', '.mjs'],
	tsconfigRaw: { compilerOptions: { experimentalDecorators: true, useDefineForClassFields: false } },
	loader: { '.css': 'empty', '.svg': 'empty', '.png': 'empty' },
	nodePaths: ['/shared/vscode/node_modules'],
	external: ['electron'],
	plugins: [chatActionsStub],
	// Browser-layer modules read a few globals at load. No DOM behaviour is under test:
	// these probes exercise protocol, file, configuration and auth logic only.
	banner: { js: "import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url); globalThis.window ??= globalThis; globalThis.addEventListener ??= () => {}; globalThis.removeEventListener ??= () => {}; globalThis.navigator ??= { userAgent: 'node', language: 'en' };" },
});
const upstream = Object.keys(r.metafile.inputs).filter(p => p.includes('src/vs/')).length;
console.log(`bundle: ${upstream} upstream modules`);
