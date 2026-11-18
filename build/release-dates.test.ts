import assert from 'node:assert/strict';
import { test } from 'node:test';
import { imageDate } from './release-dates.ts';

const d = (c: string) => `sha256:${c.repeat(64)}`;
const PIN = `example.test/img:1@${d('0')}`;

function registry(entries: Record<string, unknown>) {
	return async (_kind: 'manifests' | 'blobs', digest: string) => {
		if (!(digest in entries)) {
			throw new Error(`unexpected fetch ${digest}`);
		}
		return JSON.stringify(entries[digest]);
	};
}

test('BMP-1: an index is dated by the newest platform we run, not by linux/amd64 alone', async () => {
	const get = registry({
		[d('0')]: {
			manifests: [
				{ digest: d('1'), platform: { os: 'linux', architecture: 'amd64' } },
				{ digest: d('2'), platform: { os: 'linux', architecture: 'arm64', variant: 'v8' } },
				{ digest: d('3'), platform: { os: 'unknown', architecture: 'unknown' }, annotations: { 'vnd.docker.reference.type': 'attestation-manifest' } },
			],
		},
		[d('1')]: { config: { digest: d('a') } },
		[d('2')]: { config: { digest: d('b') } },
		[d('a')]: { created: '2026-11-05T18:00:00Z' },
		[d('b')]: { created: '2026-11-13T07:53:10Z' },
	});
	assert.equal(await imageDate(PIN, get), '2026-11-13T07:53:10Z');
});

test('BMP-1: a platform we never pull neither dates the index nor is fetched', async () => {
	const get = registry({
		[d('0')]: {
			manifests: [
				{ digest: d('1'), platform: { os: 'linux', architecture: 'amd64' } },
				{ digest: d('2'), platform: { os: 'linux', architecture: 'arm64', variant: 'v8' } },
				{ digest: d('4'), platform: { os: 'linux', architecture: 'riscv64' } },
			],
		},
		[d('1')]: { config: { digest: d('a') } },
		[d('2')]: { config: { digest: d('b') } },
		[d('a')]: { created: '2026-11-05T18:00:00Z' },
		[d('b')]: { created: '2026-11-05T20:11:38Z' },
	});
	assert.equal(await imageDate(PIN, get), '2026-11-05T20:11:38Z');
});

test('BMP-1: a single-image manifest is dated by its config', async () => {
	const get = registry({ [d('0')]: { config: { digest: d('a') } }, [d('a')]: { created: '2026-11-01T00:00:00Z' } });
	assert.equal(await imageDate(PIN, get), '2026-11-01T00:00:00Z');
});

test('BMP-1: an image with no parseable created date fails rather than being skipped', async () => {
	const get = registry({
		[d('0')]: { manifests: [{ digest: d('1'), platform: { os: 'linux', architecture: 'amd64' } }, { digest: d('2'), platform: { os: 'linux', architecture: 'arm64' } }] },
		[d('1')]: { config: { digest: d('a') } },
		[d('2')]: { config: { digest: d('b') } },
		[d('a')]: { created: '2026-11-01T00:00:00Z' },
		[d('b')]: { created: 'not a date' },
	});
	await assert.rejects(imageDate(PIN, get), /no created date/);
});
