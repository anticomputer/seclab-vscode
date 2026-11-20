// The fake-model hook patch (test/builds/variants.json, hook `fake-model`) is generated from the
// extension's sources here, so what the containment variant builds is exactly what is reviewed
// and unit tested:
//   node test/containment/fake-model/hook.ts --write   regenerate fake-model-hook.patch
//   node test/containment/fake-model/hook.ts --check   fail when the patch is stale

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
export const HOOK = join(HERE, 'fake-model-hook.patch');
/** Where the extension lands in the upstream tree: a built-in, packaged with the others. */
export const TARGET_DIR = 'extensions/seclab-test-fake-model';
const FILES = ['extension.js', 'package.json'];
const SRC = join(HERE, 'extension');

export function hookText(): string {
	let out = '';
	for (const f of FILES) {
		const text = readFileSync(join(SRC, f), 'utf8');
		if (!text.endsWith('\n') || text.includes('\r')) {
			throw new Error(`${f}: must end with a newline and hold no CR`);
		}
		const lines = text.slice(0, -1).split('\n');
		const p = `${TARGET_DIR}/${f}`;
		out += `diff --git a/${p} b/${p}\nnew file mode 100644\n--- /dev/null\n+++ b/${p}\n@@ -0,0 +1,${lines.length} @@\n${lines.map(l => `+${l}`).join('\n')}\n`;
	}
	return out;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
	const mode = process.argv[2];
	if (mode === '--write') {
		writeFileSync(HOOK, hookText());
		console.log(`fake-model hook: wrote ${HOOK}`);
	} else if (mode === '--check') {
		let current = '';
		try {
			current = readFileSync(HOOK, 'utf8');
		} catch { /* missing */ }
		if (current !== hookText()) {
			console.error('fake-model hook: fake-model-hook.patch is stale; run node test/containment/fake-model/hook.ts --write');
			process.exit(1);
		}
		console.log('fake-model hook: in sync');
	} else {
		console.error('usage: hook.ts --write|--check');
		process.exit(2);
	}
}
