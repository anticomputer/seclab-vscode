// lock-fill.mjs --verify (review YY-5): a filled lockfile may differ from upstream only by
// sha512 `integrity` and the canonical `resolved` added to registry entries that lacked them.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { test } from 'node:test';

const scratch = path.join(import.meta.dirname, '..', '..', '.work', 'test-scratch', `lock-fill-${process.pid}`);
const sha = 'sha512-' + 'A'.repeat(86) + '==';
const upstream = { name: 'x', lockfileVersion: 3, packages: {
	'': { name: 'x' },
	'node_modules/a': { version: '1.0.0', resolved: 'https://registry.npmjs.org/a/-/a-1.0.0.tgz', integrity: sha },
	'node_modules/@s/b': { version: '2.0.0', dev: true },
	'packageMocks/keytar': { version: '7.9.0' },
} };
const verify = (filled: unknown) => {
	fs.mkdirSync(scratch, { recursive: true });
	fs.writeFileSync(path.join(scratch, 'up.json'), JSON.stringify(upstream));
	fs.writeFileSync(path.join(scratch, 'filled.json'), JSON.stringify(filled));
	return spawnSync(process.execPath, [path.join(import.meta.dirname, 'lock-fill.mjs'), '--verify', path.join(scratch, 'up.json'), path.join(scratch, 'filled.json')], { encoding: 'utf8' });
};
const fill = (mut: (p: Record<string, Record<string, unknown>>) => void) => {
	const f = JSON.parse(JSON.stringify(upstream));
	mut(f.packages);
	return f;
};

test('lock-fill --verify: only integrity and the canonical resolved may be added', () => {
	try {
		assert.equal(verify(upstream).status, 0, 'unchanged passes');
		assert.equal(verify(fill(p => { p['node_modules/@s/b'].integrity = sha; p['node_modules/@s/b'].resolved = 'https://registry.npmjs.org/@s/b/-/b-2.0.0.tgz'; })).status, 0, 'a proper fill passes');
		assert.equal(verify(fill(p => { p['node_modules/@s/b'].integrity = 'sha1-abc'; })).status, 1, 'non-sha512 refused');
		assert.equal(verify(fill(p => { p['node_modules/@s/b'].integrity = sha; p['node_modules/@s/b'].resolved = 'https://evil.example.test/b.tgz'; })).status, 1, 'non-canonical resolved refused');
		assert.equal(verify(fill(p => { p['node_modules/a'].integrity = 'sha512-' + 'B'.repeat(86) + '=='; })).status, 1, 'an existing hash may not change');
		assert.equal(verify(fill(p => { p['node_modules/a'].version = '1.0.1'; })).status, 1, 'versions may not change');
		assert.equal(verify(fill(p => { p['node_modules/c'] = { version: '1.0.0', integrity: sha }; })).status, 1, 'no new packages');
		assert.equal(verify(fill(p => { p['packageMocks/keytar'].integrity = sha; })).status, 1, 'local entries are never filled');
	} finally {
		fs.rmSync(scratch, { recursive: true, force: true });
	}
});
