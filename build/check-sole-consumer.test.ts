// Regressions for the sole-consumer invariants (build/check-sole-consumer.ts), including review
// 20261106-rpc-core-landing-v2 round 13 #4: patch 0006's channel-guard setter is a last-writer-wins
// API, so a third caller must fail the patch-build check.

import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { test } from 'node:test';
import { soleConsumerProblems } from './check-sole-consumer.ts';

const scratch = path.join(path.dirname(new URL(import.meta.url).pathname), '..', '.work', 'test-scratch');

function tree(files: Record<string, string>): { src: string; config: string } {
	fs.mkdirSync(scratch, { recursive: true });
	const src = fs.mkdtempSync(path.join(scratch, 'sole-consumer-'));
	for (const [rel, text] of Object.entries(files)) {
		fs.mkdirSync(path.dirname(path.join(src, rel)), { recursive: true });
		fs.writeFileSync(path.join(src, rel), text);
	}
	const config = path.join(src, 'sole-consumer.json');
	fs.writeFileSync(config, JSON.stringify({
		setSeclabChannelGuard: {
			why: 'last writer wins',
			files: {
				'src/vs/base/parts/ipc/common/ipc.ts': 'export function setSeclabChannelGuard(guard',
				'src/vs/workbench/services/extensions/common/seclabRpcFilter.ts': '',
			},
		},
	}));
	return { src, config };
}

const allowed = {
	'src/vs/base/parts/ipc/common/ipc.ts': 'export function setSeclabChannelGuard(guard: G) {}\n',
	'src/vs/workbench/services/extensions/common/seclabRpcFilter.ts': 'setSeclabChannelGuard(real);\n',
};

test('control: only the listed consumers, each on its required line', () => {
	const { src, config } = tree(allowed);
	try {
		assert.deepEqual(soleConsumerProblems(src, config), []);
	} finally {
		fs.rmSync(src, { recursive: true, force: true });
	}
});

test('a third caller of the channel-guard setter fails as an unexpected consumer', () => {
	const { src, config } = tree({ ...allowed, 'src/vs/workbench/contrib/x/browser/x.ts': 'setSeclabChannelGuard(() => true);\n' });
	try {
		const p = soleConsumerProblems(src, config);
		assert.equal(p.length, 1);
		assert.match(p[0], /setSeclabChannelGuard: unexpected consumer src\/vs\/workbench\/contrib\/x\/browser\/x\.ts \(last writer wins\)/);
	} finally {
		fs.rmSync(src, { recursive: true, force: true });
	}
});

test('a listed file mentioning the symbol off its required line fails', () => {
	const { src, config } = tree({ ...allowed, 'src/vs/base/parts/ipc/common/ipc.ts': allowed['src/vs/base/parts/ipc/common/ipc.ts'] + 'setSeclabChannelGuard(() => true);\n' });
	try {
		assert.match(soleConsumerProblems(src, config).join('\n'), /ipc\.ts mentions it outside/);
	} finally {
		fs.rmSync(src, { recursive: true, force: true });
	}
});

test('a listed file that no longer mentions the symbol is a stale invariant', () => {
	const { src, config } = tree({ 'src/vs/base/parts/ipc/common/ipc.ts': allowed['src/vs/base/parts/ipc/common/ipc.ts'] });
	try {
		assert.match(soleConsumerProblems(src, config).join('\n'), /seclabRpcFilter\.ts no longer mentions it/);
	} finally {
		fs.rmSync(src, { recursive: true, force: true });
	}
});

test('upstream test directories are not consumers', () => {
	const { src, config } = tree({ ...allowed, 'src/vs/base/test/common/ipc.test.ts': 'setSeclabChannelGuard(() => true);\n' });
	try {
		assert.deepEqual(soleConsumerProblems(src, config), []);
	} finally {
		fs.rmSync(src, { recursive: true, force: true });
	}
});
