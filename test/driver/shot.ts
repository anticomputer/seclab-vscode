// Screenshot of a real editor window from its own renderer (headless driver; no OS capture, no
// Screen Recording). Launches, waits for the workbench, captures, quits. Replaces window.ts shot.
//   node test/driver/shot.ts --app APP --profile DIR --out OUT.png [--folder-uri URI] [--settle-ms N]

import * as path from 'node:path';
import { DrivenEditor } from './editor.ts';

const argv = process.argv.slice(2);
const opt = (k: string) => (argv.indexOf(k) >= 0 ? argv[argv.indexOf(k) + 1] : undefined);
const app = opt('--app');
const profile = opt('--profile');
const out = opt('--out');
const settle = Number(opt('--settle-ms') ?? 5000);
if (!app || !profile || !out || !(settle >= 0)) {
	console.error('usage: shot.ts --app APP --profile DIR --out OUT.png [--folder-uri URI] [--settle-ms N]');
	process.exit(2);
}
const ed = await DrivenEditor.launch({ app, userData: profile, folderUri: opt('--folder-uri') });
try {
	await ed.waitFor(`document.querySelector('.monaco-workbench')`, 60_000);
	await new Promise(r => setTimeout(r, settle));
	const bytes = await ed.screenshot(path.resolve(out));
	console.log(`screenshot from the renderer (${bytes} bytes) -> ${out}`);
} finally {
	await ed.close();
}
