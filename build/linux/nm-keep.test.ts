// EDR local-install-cache: a failed `npm ci` must leave the previous install exactly as it was.
// Drives build/linux/nm-keep.sh (sourced by build/linux/build.sh) on a scratch tree.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { test } from 'node:test';

const lib = path.join(import.meta.dirname, 'nm-keep.sh');
const scratch = path.join(import.meta.dirname, '..', '..', '.work', 'test-scratch', `nm-keep-${process.pid}`);
const src = path.join(scratch, 'vscode');
const keep = path.join(scratch, '.nm-prev');
const sh = (script: string) => execFileSync('bash', ['-euo', 'pipefail', '-c', `. "${lib}"; ${script}`, 'x', src, keep], { encoding: 'utf8' });
const tree = (root: string) => fs.existsSync(root)
	? (fs.readdirSync(root, { recursive: true }) as string[]).filter(p => fs.statSync(path.join(root, p)).isFile()).sort().map(p => `${p}=${fs.readFileSync(path.join(root, p), 'utf8')}`)
	: [];
const put = (rel: string, text: string) => {
	fs.mkdirSync(path.dirname(path.join(src, rel)), { recursive: true });
	fs.writeFileSync(path.join(src, rel), text);
};

test('nm-keep: a failed install is rolled back to the previous node_modules, everywhere', () => {
	fs.rmSync(scratch, { recursive: true, force: true });
	try {
		put('package.json', '{}');
		put('src/vs/a.ts', 'a');
		put('node_modules/.seclab-stamp', 'old');
		put('node_modules/pkg/index.js', 'v1');
		put('node_modules/pkg/node_modules/inner/index.js', 'inner');
		put('build/node_modules/b/index.js', 'b1');
		put('extensions/git/node_modules/c/index.js', 'c1');
		put('extensions/git/package.json', '{}');
		const before = tree(src);

		sh('nm_keep_aside "$1" "$2"');
		assert.ok(!fs.existsSync(path.join(src, 'node_modules')), 'root node_modules moved aside');
		assert.ok(!fs.existsSync(path.join(src, 'extensions/git/node_modules')), 'nested node_modules moved aside');
		assert.ok(fs.existsSync(path.join(keep, 'extensions/git/node_modules/c/index.js')));

		// A failed install leaves partial trees behind.
		put('node_modules/pkg/index.js', 'partial');
		put('node_modules/half/index.js', 'half');
		put('remote/node_modules/r/index.js', 'partial');

		sh('nm_restore "$1" "$2"');
		assert.deepEqual(tree(src), before, 'the tree is exactly as before the install');
		assert.ok(!fs.existsSync(keep), 'the kept copy is consumed');
	} finally {
		fs.rmSync(scratch, { recursive: true, force: true });
	}
});
