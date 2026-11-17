// tabExec (test/harness.ts) stays bounded whatever the tab put at the path it reads (review SQ-6).
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { test } from 'node:test';
import { tabExec } from '../harness.ts';

const dir = fs.mkdtempSync(path.join(process.env.SECLAB_SCRATCH ?? os.tmpdir(), 'tab-exec-'));
// Stands in for `sbx exec -u agent <sandbox> CMD...`: drops the first four arguments and runs CMD.
const fakeSbx = path.join(dir, 'sbx');
fs.writeFileSync(fakeSbx, '#!/bin/sh\nshift 4\nexec "$@"\n', { mode: 0o755 });

test('a FIFO with no writer at the read path times out to no data (SQ-6)', () => {
	const fifo = path.join(dir, 'report.json');
	execFileSync('mkfifo', [fifo]);
	const t0 = Date.now();
	assert.equal(tabExec('seclab-x', ['cat', fifo], { bin: fakeSbx, timeoutMs: 1000 }), undefined);
	assert.ok(Date.now() - t0 < 10_000);
});

test('control: a regular file is read through the tab', () => {
	const file = path.join(dir, 'ok.json');
	fs.writeFileSync(file, '{"ok":true}');
	assert.equal(tabExec('seclab-x', ['cat', file], { bin: fakeSbx }), '{"ok":true}');
});

test('a failing command is no data', () => {
	assert.equal(tabExec('seclab-x', ['cat', path.join(dir, 'missing')], { bin: fakeSbx }), undefined);
});
