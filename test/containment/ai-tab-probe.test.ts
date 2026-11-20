// The tab-side tool call probe's target comes from its packaged run record, never the workspace
// (review AIP-2).   node --test test/containment/ai-tab-probe.test.ts   (in ./seclab test unit)

import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { test } from 'node:test';

const { tabToolUrl } = createRequire(import.meta.url)('./ai-tab-probe/target.js');
const NONCE = 'c'.repeat(32);
const run = { nonce: NONCE, port: 43210 };

test('the target is the packaged beacon port, confirmed by the workspace nonce', () => {
	assert.equal(tabToolUrl(run, { arm: NONCE }), `http://127.0.0.1:43210/ai-tabtool-${NONCE}`);
	// The workspace can't name another port: its targets file has no say in it.
	assert.equal(tabToolUrl(run, { arm: NONCE, tabtoolPort: '22' }), `http://127.0.0.1:43210/ai-tabtool-${NONCE}`);
});

test('a workspace or run record that does not agree arms nothing', () => {
	assert.equal(tabToolUrl(run, { arm: 'd'.repeat(32) }), undefined);
	assert.equal(tabToolUrl(run, {}), undefined);
	assert.equal(tabToolUrl(run, undefined), undefined);
	assert.equal(tabToolUrl(undefined, { arm: NONCE }), undefined);
	assert.equal(tabToolUrl({ nonce: 'x', port: 43210 }, { arm: 'x' }), undefined);
	for (const port of [22, 1023, 65536, '43210', 4.5, undefined]) {
		assert.equal(tabToolUrl({ nonce: NONCE, port }, { arm: NONCE }), undefined, String(port));
	}
});
