/**
 * Differential test for the RPC filter's URI argument constraint.
 *
 * Run: node test/containment/uri-constraint.test.ts
 *
 * What it is for
 * --------------
 * The filter permits `$readFile`/`$writeFile` and friends only for this tab's
 * own remote filesystem. That constraint is the thing standing between a tab
 * and the host's disk, so the question is not "does the check look right" but
 * "does the check agree with the consumer".
 *
 * The consumer is `URI.revive(arg)` on a fixed argument position
 * (`mainThreadFileSystem.ts`), and `URI.revive` does **not** look for a `$mid`
 * marker -- given any truthy non-URI object it returns a URI built from
 * whatever `scheme`/`authority`/`path` fields are present
 * (`src/vs/base/common/uri.ts`). So the only sound check is positional.
 *
 * The earlier implementation searched the argument graph for URI-*shaped*
 * values, keyed on `$mid` being a number. `test_marker_less_components_*`
 * below is the exact payload that defeated it: plain components with no
 * marker, which the search ignored and the consumer happily revived into
 * `file:///…`. That case is kept as a permanent regression test rather than
 * deleted, because the bug was not a typo -- it was a design that could only
 * ever approximate the consumer.
 *
 * This test deliberately does not import the filter class, which would drag in
 * the whole workbench. It re-implements the two primitives under test --
 * position selection and the scheme/authority rule -- against the *real*
 * generated `SECLAB_URI_ARGS` table, so a drift in the generated positions
 * fails here. The filter's own use of those primitives is covered by the
 * probe suite against a running build.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..', '..');
const TAB_AUTHORITY = 'seclab+t-abc';
/**
 * A deliberately synthetic host path. The constraint turns on the *scheme*
 * leaving the tab's authority, not on which file is named, so there is no
 * reason for a unit test to carry a real secret path -- and `seclab lint
 * fixtures` is right to refuse one even in inert data it never opens.
 */
const HOST_PATH = '/seclab-canary/host-only-marker';

/** Parse the generated positions out of the emitted module. */
function loadUriArgs(): Map<string, number[]> {
	const text = readFileSync(
		join(REPO, 'rpc-filter', 'patch-src', 'seclabPolicyData.ts'), 'utf8');
	const block = text.split('SECLAB_URI_ARGS')[1];
	assert.ok(block, 'SECLAB_URI_ARGS is missing from the emitted policy module');
	const out = new Map<string, number[]>();
	for (const m of block.matchAll(/\['([^']+)',\s*\[([0-9,\s]*)\]\]/g)) {
		out.set(m[1], m[2].trim() ? m[2].split(',').map(s => Number(s.trim())) : []);
	}
	return out;
}

const URI_ARGS = loadUriArgs();

/**
 * What the consumer sees. Mirrors `URI.revive`: falsy passes through, anything
 * else becomes a URI from its own fields, with no regard for `$mid`.
 */
function consumerRevive(raw: any): { scheme: string; authority: string } | undefined {
	if (!raw) {
		return undefined;
	}
	return { scheme: String(raw.scheme ?? ''), authority: String(raw.authority ?? '') };
}

/** The filter's rule, positional. Returns a denial reason or undefined. */
function filterCheck(sid: string, method: string, args: readonly unknown[]): string | undefined {
	const positions = URI_ARGS.get(`${sid}.${method}`);
	if (!positions || positions.length === 0) {
		return undefined;
	}
	const components: any[] = [];
	for (const i of positions) {
		const value: any = args[i];
		if (value === undefined || value === null) {
			continue;
		}
		if (typeof value !== 'object') {
			return `argument ${i} is not URI components`;
		}
		if (Array.isArray(value)) {
			components.push(...value.filter(v => v !== undefined && v !== null));
			continue;
		}
		components.push(value);
	}
	for (const raw of components) {
		const uri = consumerRevive(raw)!;
		if (uri.scheme === 'untitled') {
			continue;
		}
		if (uri.scheme !== 'vscode-remote') {
			return `scheme ${uri.scheme} is not reachable from a tab`;
		}
		if (uri.authority !== TAB_AUTHORITY) {
			return `authority ${uri.authority} is not this tab`;
		}
	}
	return undefined;
}

/** The old, shape-based walker, kept only to prove the regression test bites. */
function legacyShapeWalk(args: readonly unknown[]): string | undefined {
	const visit = (o: any): string | undefined => {
		if (o.scheme === 'untitled') { return undefined; }
		if (o.scheme !== 'vscode-remote') { return `scheme ${o.scheme} refused`; }
		if (o.authority !== TAB_AUTHORITY) { return `authority ${o.authority} refused`; }
		return undefined;
	};
	const walk = (v: any, depth: number): string | undefined => {
		if (depth > 200 || !v || typeof v !== 'object') { return undefined; }
		if (typeof v['$mid'] === 'number' && typeof v['scheme'] === 'string') { return visit(v); }
		for (const k of Object.keys(v)) {
			const r = walk(v[k], depth + 1);
			if (r) { return r; }
		}
		return undefined;
	};
	return walk(args, 0);
}

const tests: Array<[string, () => void]> = [];
const test = (name: string, fn: () => void) => tests.push([name, fn]);

const MID_URI = 1;
const own = (path: string) =>
	({ $mid: MID_URI, scheme: 'vscode-remote', authority: TAB_AUTHORITY, path });

// -- the positions themselves ------------------------------------------------

test('positions are generated, not assumed', () => {
	assert.deepEqual(URI_ARGS.get('MainThreadFileSystem.$readFile'), [0]);
	assert.deepEqual(URI_ARGS.get('MainThreadFileSystem.$writeFile'), [0]);
	// Two URIs, and the second one matters: a copy to a host path is a write.
	assert.deepEqual(URI_ARGS.get('MainThreadFileSystem.$copy'), [0, 1]);
	assert.deepEqual(URI_ARGS.get('MainThreadFileSystem.$rename'), [0, 1]);
});

test('positions are not all zero, so the table is really positional', () => {
	// $startTextSearch takes its URI second and $updateWorkspaceFolders fourth.
	// If the generator silently defaulted to [0] these would be wrong.
	assert.deepEqual(URI_ARGS.get('MainThreadWorkspace.$startTextSearch'), [1]);
	assert.deepEqual(URI_ARGS.get('MainThreadWorkspace.$updateWorkspaceFolders'), [3]);
});

// -- the regression that motivated the rewrite -------------------------------

test('marker-less components are refused (the bypass)', () => {
	const payload = [{ scheme: 'file', path: HOST_PATH }];
	assert.ok(
		filterCheck('MainThreadFileSystem', '$readFile', payload),
		'plain components with no $mid must be refused');
});

test('marker-less components defeated the old shape walk', () => {
	// Negative control. Without this the test above could pass against an
	// implementation that was never broken, and would prove nothing.
	const payload = [{ scheme: 'file', path: HOST_PATH }];
	assert.equal(
		legacyShapeWalk(payload), undefined,
		'the old walker is expected to miss this; if it does not, this test is '
		+ 'no longer demonstrating the bug it exists to pin');
	assert.ok(filterCheck('MainThreadFileSystem', '$readFile', payload));
});

test('marker-less components are refused on every URI position', () => {
	// $copy's second argument is the destination: missing it means a tab can
	// write anywhere even if the source is checked.
	assert.ok(filterCheck('MainThreadFileSystem', '$copy',
		[own('/w/a'), { scheme: 'file', path: HOST_PATH }, {}]));
});

// -- agreement with the consumer, both directions ----------------------------

test('this tab is allowed, with and without a marker', () => {
	assert.equal(filterCheck('MainThreadFileSystem', '$readFile', [own('/w/f.ts')]), undefined);
	assert.equal(filterCheck('MainThreadFileSystem', '$readFile',
		[{ scheme: 'vscode-remote', authority: TAB_AUTHORITY, path: '/w/f.ts' }]), undefined);
});

test('another tab is refused', () => {
	assert.ok(filterCheck('MainThreadFileSystem', '$readFile',
		[{ scheme: 'vscode-remote', authority: 'seclab+t-other', path: '/w/f.ts' }]));
});

test('schemes that reach the host are refused', () => {
	for (const scheme of ['file', 'vscode-userdata', 'http', 'https', 'vscode-file']) {
		assert.ok(filterCheck('MainThreadFileSystem', '$readFile', [{ scheme, path: '/x' }]),
			`${scheme} must not be reachable from a tab`);
	}
});

test('a URI hidden in a non-URI position is ignored, as the consumer ignores it', () => {
	// $writeFile revives argument 0 only; argument 1 is content. A file: URI
	// sitting in the content is never revived, so refusing it would be a false
	// denial -- the over-strict direction the shape search also got wrong.
	assert.equal(filterCheck('MainThreadFileSystem', '$writeFile',
		[own('/w/f.ts'), { $mid: MID_URI, scheme: 'file', path: '/etc/passwd' }]),
		undefined);
});

test('methods with no URI parameters are not constrained', () => {
	assert.equal(filterCheck('MainThreadFileSystem', '$ensureActivation', ['file']), undefined);
});

// -- shapes that are not calls anyone makes ----------------------------------

test('a non-object in a URI position is refused rather than reasoned about', () => {
	for (const bad of ['/etc/passwd', 42, true]) {
		assert.ok(filterCheck('MainThreadFileSystem', '$readFile', [bad]),
			`${typeof bad} in a URI position must be refused`);
	}
});

test('null and undefined pass through, matching URI.revive', () => {
	assert.equal(filterCheck('MainThreadFileSystem', '$readFile', [null]), undefined);
	assert.equal(filterCheck('MainThreadFileSystem', '$readFile', [undefined]), undefined);
	assert.equal(consumerRevive(null), undefined);
});

test('a prototype-polluting key cannot smuggle a scheme', () => {
	// Object.create(null)-style payload: own scheme wins, inherited is ignored
	// by both sides, so the two agree.
	const payload: any = Object.create({ scheme: 'vscode-remote', authority: TAB_AUTHORITY });
	payload.scheme = 'file';
	payload.path = '/etc/passwd';
	assert.ok(filterCheck('MainThreadFileSystem', '$readFile', [payload]));
});

// -- differential sweep ------------------------------------------------------

test('filter and consumer agree over generated payloads', () => {
	const schemes = ['file', 'vscode-remote', 'vscode-userdata', 'untitled', 'https', ''];
	const authorities = [TAB_AUTHORITY, 'seclab+t-other', 'ssh-remote+x', ''];
	const markers: Array<Record<string, unknown>> = [{}, { $mid: MID_URI }, { $mid: 'x' }];
	let checked = 0;
	for (const scheme of schemes) {
		for (const authority of authorities) {
			for (const marker of markers) {
				const raw = { ...marker, scheme, authority, path: '/p' };
				const refused = filterCheck('MainThreadFileSystem', '$readFile', [raw]) !== undefined;
				const seen = consumerRevive(raw)!;
				// The consumer's view decides the expected verdict. The filter
				// must match it for every shape, marked or not.
				const shouldRefuse = !(seen.scheme === 'untitled'
					|| (seen.scheme === 'vscode-remote' && seen.authority === TAB_AUTHORITY));
				assert.equal(refused, shouldRefuse,
					`disagreement for ${JSON.stringify(raw)}: filter refused=${refused}, `
					+ `consumer sees ${seen.scheme}://${seen.authority}`);
				checked++;
			}
		}
	}
	assert.ok(checked >= 72, `expected a real sweep, only checked ${checked}`);
});

test('every method with declared URI positions is covered by the table', () => {
	// The filter constrains exactly the methods the generator found. If a
	// reachable method took a URI and were missing here, it would go
	// unconstrained, so assert the table is non-trivial and well formed.
	assert.ok(URI_ARGS.size >= 60, `expected the generated table, got ${URI_ARGS.size}`);
	for (const [key, positions] of URI_ARGS) {
		assert.match(key, /^MainThread[\w$.]+$/, `malformed key ${key}`);
		assert.ok(positions.length > 0, `${key} has no positions`);
		for (const p of positions) {
			assert.ok(Number.isInteger(p) && p >= 0, `${key} has a bad position ${p}`);
		}
	}
});

let failed = 0;
for (const [name, fn] of tests) {
	try {
		fn();
		console.log(`ok   ${name}`);
	} catch (err) {
		failed++;
		console.error(`FAIL ${name}\n     ${(err as Error).message}`);
	}
}
console.log(`\n${tests.length - failed}/${tests.length} passed`);
process.exit(failed ? 1 : 0);
