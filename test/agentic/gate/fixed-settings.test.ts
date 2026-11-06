// Patch 0017: the values a tab window fixes, and the ways a reader could get around them.
//
// These run against the patch's own source under agentic/patch-src, which sync-patch keeps
// byte-identical to what the patch ships, so a test here is a test of the shipped code.
//   node --test test/agentic/gate/fixed-settings.test.ts

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
	SECLAB_FIXED_TAB_SETTINGS,
	isSeclabTabAuthority,
	seclabFixedSetting,
	seclabScrubFixedSettings,
	SECLAB_TAB_AUTHORITY_PREFIX,
} from '../../../agentic/patch-src/src/vs/workbench/services/configuration/common/seclabFixedSettings.ts';
import { SECLAB_AUTHORITY_PREFIX } from '../../../agentic/patch-src/src/vs/platform/agentHost/common/seclabAhpGateCheck.ts';

const TAB = 'seclab+t-abc';

test('a tab window fixes exactly the declared keys, and nothing else', () => {
	// The keys are asserted literally, not by looping over the map against itself, which
	// would have been tautological (security review round 6).
	assert.deepEqual([...SECLAB_FIXED_TAB_SETTINGS.entries()].sort(), [
		['chat.automations.cloud.enabled', false],
		['chat.automations.enabled', false],
	]);
	for (const [key, value] of SECLAB_FIXED_TAB_SETTINGS) {
		assert.equal(seclabFixedSetting(TAB, key)?.value, value, key);
	}
	assert.equal(seclabFixedSetting(TAB, 'chat.automations.enabledX'), undefined);
	assert.equal(seclabFixedSetting(TAB, 'editor.fontSize'), undefined);
	// Round 6 removed this one: forcing it false sends the browser tools' model-chosen URL
	// to the HOST network, which leaving it alone does not. It returns with its own measurement.
	assert.equal(SECLAB_FIXED_TAB_SETTINGS.has('workbench.browser.enableRemoteProxy'), false);
});

// The two call sites the patch edits, modelled exactly as upstream shapes them. Round 6
// found a real break in `inspect` that the helper-only tests could not see.
test('inspect keeps its per-layer getters when it reports a fixed value', () => {
	// Upstream returns a class instance whose layer fields are PROTOTYPE getters; spreading
	// it drops all of them and exposes the raw configuration models instead.
	// No parameter property: `node --test` runs this file with type stripping only (AGENTS.md).
	class InspectValue {
		readonly _layers: Record<string, unknown>;
		constructor(layers: Record<string, unknown>) { this._layers = layers; }
		get value() { return this._layers.value; }
		get defaultValue() { return this._layers.defaultValue; }
		get policyValue() { return this._layers.policyValue; }
		get userRemoteValue() { return this._layers.userRemoteValue; }
	}
	const result = new InspectValue({ value: true, defaultValue: false, policyValue: undefined, userRemoteValue: true });
	const fixed = seclabFixedSetting(TAB, 'chat.automations.enabled')!;
	const out = Object.create(result as object, { value: { value: fixed.value, enumerable: true } }) as InspectValue;
	assert.equal(out.value, false, 'the fixed value is reported');
	assert.equal(out.defaultValue, false, 'defaultValue survives');
	assert.equal(out.userRemoteValue, true, 'the layer a tab wrote is still visible');
	assert.equal(out.policyValue, undefined);
	// The shape the patch must not use, kept here so the regression is named.
	assert.equal(({ ...result } as InspectValue).defaultValue, undefined, 'spread drops getters');
});

test('the extension-host snapshot is scrubbed layer by layer', () => {
	// `getConfigurationData().<layer>.contents` is what ExtHostConfiguration answers reads
	// from; it never goes through getValue, so round 6 required scrubbing it too.
	const layer = { contents: { chat: { automations: { enabled: true, cloud: { enabled: true } } }, editor: { fontSize: 12 } } };
	layer.contents = seclabScrubFixedSettings(TAB, undefined, layer.contents) as typeof layer.contents;
	assert.equal(layer.contents.chat.automations.enabled, false);
	assert.equal(layer.contents.chat.automations.cloud.enabled, false);
	assert.equal(layer.contents.editor.fontSize, 12);
});

test('an ordinary window is untouched', () => {
	for (const authority of [undefined, '', 'ssh-remote+box', 'wsl+ubuntu', 'not-seclab+x']) {
		for (const key of SECLAB_FIXED_TAB_SETTINGS.keys()) {
			assert.equal(seclabFixedSetting(authority, key), undefined, `${authority} ${key}`);
		}
		assert.deepEqual(
			seclabScrubFixedSettings(authority, 'chat.automations', { enabled: true }),
			{ enabled: true },
			String(authority),
		);
	}
});

test('reading a prefix cannot route around the exact-key override', () => {
	// `getValue('chat.automations')` returns an object; without scrubbing it would carry the
	// tab's value while `getValue('chat.automations.enabled')` returned false.
	const scrubbed = seclabScrubFixedSettings(TAB, 'chat.automations', { enabled: true, cloud: { enabled: true }, other: 1 }) as Record<string, unknown>;
	assert.equal(scrubbed.enabled, false);
	assert.equal((scrubbed.cloud as Record<string, unknown>).enabled, false);
	assert.equal(scrubbed.other, 1);
});

test('reading the whole configuration cannot route around it either', () => {
	const whole = {
		chat: { automations: { enabled: true, cloud: { enabled: true } } },
		editor: { fontSize: 12 },
	};
	const out = seclabScrubFixedSettings(TAB, undefined, whole) as typeof whole;
	assert.equal(out.chat.automations.enabled, false);
	assert.equal(out.chat.automations.cloud.enabled, false);
	assert.equal(out.editor.fontSize, 12);
});

test('the caller\'s object is never mutated (the configuration model is shared)', () => {
	const whole = { chat: { automations: { enabled: true, cloud: { enabled: true } } } };
	const out = seclabScrubFixedSettings(TAB, undefined, whole) as typeof whole;
	assert.equal(whole.chat.automations.enabled, true, 'input mutated');
	assert.equal(out.chat.automations.enabled, false);
	assert.notEqual(out.chat, whole.chat, 'descended objects must be copied');
});

test('a key the configuration does not carry is not invented', () => {
	// Scrubbing must not add a key that was absent: a reader distinguishes "absent" from
	// "false" (observableConfigValue falls back to its own default on undefined).
	const out = seclabScrubFixedSettings(TAB, undefined, { editor: { fontSize: 12 } }) as Record<string, unknown>;
	assert.deepEqual(out, { editor: { fontSize: 12 } });
});

test('non-objects and arrays pass through untouched', () => {
	for (const v of [undefined, null, 1, 'x', true, [1, 2]]) {
		assert.deepEqual(seclabScrubFixedSettings(TAB, undefined, v), v, String(v));
	}
});

test('a non-object on the path is left alone rather than rewritten', () => {
	// `chat.automations` being a scalar is nonsense, but it must not throw or be replaced.
	const out = seclabScrubFixedSettings(TAB, undefined, { chat: { automations: 5 } }) as Record<string, unknown>;
	assert.deepEqual(out, { chat: { automations: 5 } });
});

test('0017 and 0015 decide "is this a tab window" from the same prefix', () => {
	// Two copies of the prefix would let a change to one unfix these settings in tab windows
	// while the gate still applied, so the drift is asserted rather than assumed (round 6).
	assert.equal(SECLAB_TAB_AUTHORITY_PREFIX, SECLAB_AUTHORITY_PREFIX);
});

test('isSeclabTabAuthority matches the prefix and nothing adjacent to it', () => {
	assert.ok(isSeclabTabAuthority('seclab+t-abc'));
	assert.ok(!isSeclabTabAuthority('xseclab+t-abc'));
	assert.ok(!isSeclabTabAuthority('seclab'));
	assert.ok(!isSeclabTabAuthority(undefined));
});
