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
} from '../../../agentic/patch-src/src/vs/workbench/services/configuration/common/seclabFixedSettings.ts';

const TAB = 'seclab+t-abc';

test('a tab window fixes exactly the declared keys, and nothing else', () => {
	for (const [key, value] of SECLAB_FIXED_TAB_SETTINGS) {
		assert.equal(seclabFixedSetting(TAB, key)?.value, value, key);
	}
	assert.equal(seclabFixedSetting(TAB, 'workbench.browser.enableRemoteProxyX'), undefined);
	assert.equal(seclabFixedSetting(TAB, 'editor.fontSize'), undefined);
	// The value that matters: upstream refuses to open an embedded page when this is off,
	// rather than falling back to the host network.
	assert.equal(SECLAB_FIXED_TAB_SETTINGS.get('workbench.browser.enableRemoteProxy'), false);
});

test('an ordinary window is untouched', () => {
	for (const authority of [undefined, '', 'ssh-remote+box', 'wsl+ubuntu', 'not-seclab+x']) {
		for (const key of SECLAB_FIXED_TAB_SETTINGS.keys()) {
			assert.equal(seclabFixedSetting(authority, key), undefined, `${authority} ${key}`);
		}
		assert.deepEqual(
			seclabScrubFixedSettings(authority, 'workbench.browser', { enableRemoteProxy: true }),
			{ enableRemoteProxy: true },
			String(authority),
		);
	}
});

test('reading a prefix cannot route around the exact-key override', () => {
	// `getValue('workbench.browser')` returns an object; without scrubbing it would carry the
	// tab's value while `getValue('workbench.browser.enableRemoteProxy')` returned false.
	const scrubbed = seclabScrubFixedSettings(TAB, 'workbench.browser', { enableRemoteProxy: true, other: 1 }) as Record<string, unknown>;
	assert.equal(scrubbed.enableRemoteProxy, false);
	assert.equal(scrubbed.other, 1);
});

test('reading the whole configuration cannot route around it either', () => {
	const whole = {
		workbench: { browser: { enableRemoteProxy: true } },
		chat: { automations: { enabled: true, cloud: { enabled: true } } },
		editor: { fontSize: 12 },
	};
	const out = seclabScrubFixedSettings(TAB, undefined, whole) as typeof whole;
	assert.equal(out.workbench.browser.enableRemoteProxy, false);
	assert.equal(out.chat.automations.enabled, false);
	assert.equal(out.chat.automations.cloud.enabled, false);
	assert.equal(out.editor.fontSize, 12);
});

test('the caller\'s object is never mutated (the configuration model is shared)', () => {
	const whole = { workbench: { browser: { enableRemoteProxy: true } } };
	const out = seclabScrubFixedSettings(TAB, undefined, whole) as typeof whole;
	assert.equal(whole.workbench.browser.enableRemoteProxy, true, 'input mutated');
	assert.equal(out.workbench.browser.enableRemoteProxy, false);
	assert.notEqual(out.workbench, whole.workbench, 'descended objects must be copied');
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
	// `workbench.browser` being a scalar is nonsense, but it must not throw or be replaced.
	const out = seclabScrubFixedSettings(TAB, undefined, { workbench: { browser: 5 } }) as Record<string, unknown>;
	assert.deepEqual(out, { workbench: { browser: 5 } });
});

test('isSeclabTabAuthority matches the prefix and nothing adjacent to it', () => {
	assert.ok(isSeclabTabAuthority('seclab+t-abc'));
	assert.ok(!isSeclabTabAuthority('xseclab+t-abc'));
	assert.ok(!isSeclabTabAuthority('seclab'));
	assert.ok(!isSeclabTabAuthority(undefined));
});
