/*---------------------------------------------------------------------------------------------
 *  seclab Tab Manager build (upstream extension esbuild convention).
 *--------------------------------------------------------------------------------------------*/
import * as path from 'node:path';
import { run } from '../esbuild-extension-common.mts';

const srcDir = path.join(import.meta.dirname, 'src');
const outDir = path.join(import.meta.dirname, 'dist');

run({
	platform: 'node',
	entryPoints: {
		'extension': path.join(srcDir, 'extension.ts'),
		// The supervisor ships inside the extension and runs on the editor's own Node
		// (ELECTRON_RUN_AS_NODE); see docs/edr/20261104-tabd-implementation-language.md.
		'tabd': path.join(import.meta.dirname, 'tabd-src', 'main.ts'),
	},
	srcDir,
	outdir: outDir,
}, process.argv);
