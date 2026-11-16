/**
 * Patch 0034 (review RFU-1): in a tab window the window resolves no host variables in the
 * terminal launch config the tab's REH supplies. Checked on the patch text, the artefact that
 * ships, with each rule shown failing on a mutant of the real patch.
 *
 * Run: node test/containment/terminal-variables.test.ts   (or ./seclab test terminal-variables)
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const PATCH = readFileSync(join(REPO, 'patches', '0034-seclab-no-host-variables-for-tab-terminals.patch'), 'utf8');

/** The added and context lines of one file's hunks, comments dropped, trimmed. */
function code(patch: string, file: string): string {
	const out: string[] = [];
	let inFile = false;
	for (const raw of patch.split('\n')) {
		if (raw.startsWith('diff ')) {
			inFile = raw.endsWith(`/${file}`);
			continue;
		}
		if (!inFile || raw.startsWith('---') || raw.startsWith('+++') || raw.startsWith('@@') || raw.startsWith('-')) {
			continue;
		}
		const line = raw.slice(1).trim();
		if (!line.startsWith('//')) {
			out.push(line);
		}
	}
	return out.join('\n');
}

function problems(patch: string): string[] {
	const p: string[] = [];
	const channel = code(patch, 'remoteTerminalChannel.ts');
	const guard = channel.indexOf('if (!/^seclab\\+/.test(this._remoteAuthority)) {');
	const resolve = channel.indexOf('await this._resolverService.resolveAsync(lastActiveWorkspace, expr);');
	const collect = channel.indexOf('resolvedVariables[inner] = resolved.value;');
	if (guard < 0 || resolve < guard || collect < resolve) {
		p.push('createProcess resolves or sends variables outside the tab guard');
	}
	const profile = code(patch, 'terminalProfileResolverService.ts');
	if (!profile.includes('const seclabTab = seclabIsTabAuthority(options.remoteAuthority);')) {
		p.push('the profile resolver does not key on the window authority');
	}
	if ((profile.match(/this\._resolveVariables\([^)]*, seclabTab\)/g) ?? []).length !== 3) {
		p.push('not every profile path and argument resolution passes the tab flag');
	}
	const branch = profile.match(/if \(seclabTab\) \{\n(.*)\n\}/);
	if (!branch || branch[1] !== "return value.replace(/\\$\\{env:([^}]+)\\}/g, (_m, name: string) => env[name] ?? '');") {
		p.push('a tab profile resolves more than ${env:} against the REH environment');
	}
	return p;
}

const tests: Array<[string, () => void]> = [
	['patch 0034 resolves no host variables for a tab terminal', () => assert.deepEqual(problems(PATCH), [])],
	['the tab branch resolves only env, from the REH environment', () => {
		const env: Record<string, string> = { HOME: '/home/agent' };
		const tab = (value: string) => value.replace(/\$\{env:([^}]+)\}/g, (_m, name: string) => env[name] ?? '');
		assert.equal(tab('/bin/sh${config:seclab.test.canary}'), '/bin/sh${config:seclab.test.canary}');
		assert.equal(tab('${userHome}/x ${env:HOME}/y ${env:MISSING}'), '${userHome}/x /home/agent/y ');
	}],
	['each rule fails on a mutant of the real patch', () => {
		const mutants: Array<[string, string, string]> = [
			['createProcess guard removed', '+\t\tif (!/^seclab\\+/.test(this._remoteAuthority)) {\n', '+\t\tif (true) {\n'],
			['profile flag from elsewhere', 'seclabIsTabAuthority(options.remoteAuthority)', 'seclabIsTabAuthority(undefined)'],
			['one call site without the flag', 'this._resolveVariables(profile.path, env, lastActiveWorkspace, seclabTab)', 'this._resolveVariables(profile.path, env, lastActiveWorkspace)'],
			['tab branch resolves config', "return value.replace(/\\$\\{env:([^}]+)\\}/g, (_m, name: string) => env[name] ?? '');", 'return this._configurationResolverService.resolveWithEnvironment(env, lastActiveWorkspace, value);'],
		];
		for (const [name, from, to] of mutants) {
			assert.ok(PATCH.includes(from), `mutant "${name}" no longer applies; update it`);
			assert.notDeepEqual(problems(PATCH.replace(from, to)), [], `mutant survived: ${name}`);
		}
	}],
];

let failed = 0;
for (const [name, fn] of tests) {
	try {
		fn();
		console.log(`ok   ${name}`);
	} catch (err) {
		failed++;
		console.log(`FAIL ${name}\n     ${(err as Error).message.split('\n')[0]}`);
	}
}
console.log(`\n${tests.length - failed}/${tests.length} passed`);
process.exit(failed ? 1 : 0);
