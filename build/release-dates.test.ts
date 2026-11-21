import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ageDays, ageExemptPins, ageExemptReason, COOLDOWN_DAYS, imageDate, imagePinsToJudge } from './release-dates.ts';

const d = (c: string) => `sha256:${c.repeat(64)}`;
const NOW = Date.parse('2026-11-20T23:00:00Z');
// The case that made publication dates the rule (review of PR 74): the golang 1.27.4-trixie index
// was first pushed on 2026-11-10, then re-pushed on 2026-11-16 when riscv64 was added. Docker
// Official Images keep `created` across rebuilds, and the first index's images carry 11-10 build
// times, yet only the tag's current digest has a publication record.
const REPUSHED = d('f');
const FIRST = d('e');
// Built from parts: a literal image reference here would read as an unpinned image to check-pins.
const GOLANG = (digest: string) => `${['golang', '1.27.4-trixie'].join(':')}@${digest}`;

const hub = (rec: { digest?: string; tag_last_pushed?: string }) => async () => rec;
const hubDown = async () => {
	throw new Error('hub unavailable');
};

test('publication date: a Docker Hub pin that is the current digest of its tag is dated by the last push of the tag', async () => {
	const date = await imageDate(GOLANG(REPUSHED), { hub: hub({ digest: REPUSHED, tag_last_pushed: '2026-11-16T07:23:55Z' }) });
	assert.equal(date, '2026-11-16T07:23:55Z');
	assert.ok(ageDays(date, NOW) < COOLDOWN_DAYS, 'the re-pushed digest is inside the hold');
});

test('publication date: a re-indexed digest of old images is undated, so it fails', async () => {
	// Injected case: an index of 11-10 images that is not what Docker Hub records for its tag. No
	// evidence about the images dates when this index was published.
	await assert.rejects(imageDate(GOLANG(FIRST), { hub: hub({ digest: REPUSHED, tag_last_pushed: '2026-11-16T07:23:55Z' }) }), /not the current digest/);
});

test('publication date: an old tag paired with a new digest is not dated by the tag', async () => {
	// tag@digest pulls the digest whatever the tag says: the old tag record proves nothing about it.
	await assert.rejects(imageDate(GOLANG(REPUSHED), { hub: hub({ digest: FIRST, tag_last_pushed: '2026-10-01T00:00:00Z' }) }), /not the current digest/);
});

test('publication date: with Docker Hub down, a digest is undated, never dated by the image', async () => {
	await assert.rejects(imageDate(GOLANG(REPUSHED), { hub: hubDown }), /lookup failed/);
	await assert.rejects(imageDate(GOLANG(REPUSHED), { hub: hub({ digest: REPUSHED }) }), /no push date/);
});

test('publication date: another registry, or an untagged pin, has no publication date and needs an exemption', async () => {
	const never = async () => assert.fail('Docker Hub consulted for a pin it does not hold');
	await assert.rejects(imageDate(`example.test/img:1@${REPUSHED}`, { hub: never }), /ageExempt/);
	await assert.rejects(imageDate(`golang@${REPUSHED}`, { hub: never }), /untagged/);
});

test('changed pins: only image pins the base register lacks are judged', () => {
	const kept = GOLANG(FIRST), bumped = GOLANG(REPUSHED);
	const base = { deps: [{ pins: [kept, 'tool:gitleaks:arm64@' + d('1')] }] };
	const r = imagePinsToJudge([kept, bumped, 'tool:gitleaks:arm64@' + d('2'), 'deb:x@' + d('3')], base);
	assert.deepEqual(r, { judge: [bumped], unchanged: [kept] });
	assert.throws(() => imagePinsToJudge([bumped], {} as { deps: [] }), /no deps array/);
});

test('ageExempt: an exemption without a reason is refused', () => {
	for (const x of [{}, { reason: '' }, { reason: '   ' }, { reason: 'because' }, { reason: 42 }, null]) {
		assert.throws(() => ageExemptReason(x), /must record its reason/);
	}
	assert.equal(ageExemptReason({ reason: ' Host-dictated: must match the installed release. ' }), 'Host-dictated: must match the installed release.');
});

test('ageExempt: an exemption covers only the exact pins it lists, so a bump falls outside it (IMB-9)', () => {
	const old = GOLANG(FIRST), bumped = GOLANG(REPUSHED);
	const why = 'Host-dictated: must match the installed release.';
	assert.deepEqual([...ageExemptPins({ pins: [old], ageExempt: { reason: why, pins: [old] } })], [old]);
	assert.equal(ageExemptPins({ pins: [old] }).size, 0);
	// The entry was bumped and the exemption left naming the old pin: it no longer covers anything.
	assert.throws(() => ageExemptPins({ pins: [bumped], ageExempt: { reason: why, pins: [old] } }), /no longer holds/);
	for (const pins of [undefined, [], [42]]) {
		assert.throws(() => ageExemptPins({ pins: [old], ageExempt: { reason: why, pins } }), /exact pins/);
	}
	assert.throws(() => ageExemptPins({ pins: [old], ageExempt: { reason: 'r', pins: [old] } }), /must record its reason/);
});

test('changed pins: a pin the base exempted was never judged, so dropping its exemption has it judged', () => {
	const kit = `${['example', 'kit'].join('/')}@${REPUSHED}`, other = GOLANG(FIRST);
	const why = 'Host-dictated: must match the installed release.';
	// main's exemptions have no pin list (they covered the whole entry); scoped ones cover their pins.
	for (const ageExempt of [{ reason: why }, { reason: why, pins: [kit] }]) {
		const base = { deps: [{ pins: [kit, other], ageExempt }] };
		assert.deepEqual(imagePinsToJudge([kit, other], base), { judge: ageExempt.pins ? [kit] : [kit, other], unchanged: ageExempt.pins ? [other] : [] });
	}
});
