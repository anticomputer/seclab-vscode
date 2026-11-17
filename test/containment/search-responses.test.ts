/**
 * Patch 0051 (reviews SRCH-2, SRCH-3): in a tab window, what a tab's search provider returns
 * besides results goes through seclabFromTab, and the query sent to the tab carries no open
 * editor outside its own file system. Checked on the patch text, the artefact that ships, with
 * each rule shown failing on a mutant of the real patch.
 *
 * Run: node test/containment/search-responses.test.ts   (or ./seclab test search-responses)
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const PATCH = readFileSync(join(REPO, 'patches', '0051-seclab-sanitise-tab-search-responses.patch'), 'utf8');

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
	const c = code(patch, 'mainThreadSearch.ts');
	if (!c.includes('const fromTab = seclabFromTab(extHostContext.remoteAuthority,')) {
		p.push('MainThreadSearch builds no sanitiser for its host');
	}
	if ((c.match(/new RemoteSearchProvider\([^)]*, this\._proxy, this\._seclab\)\)/g) ?? []).length !== 3) {
		p.push('a search provider is built without the sanitiser');
	}
	if (!c.includes('messages: seclab ? seclab.fromTab.searchMessages(result.messages) as ITextSearchCompleteMessage[] : result.messages')) {
		p.push('a tab provider\'s completion messages reach the Search view unsanitised');
	}
	if (!c.includes("extraFileResources: query.extraFileResources.filter(r => r.scheme === 'vscode-remote' && r.authority.toLowerCase() === seclab.authority.toLowerCase())")) {
		p.push('the query sent to a tab carries editors outside its file system');
	}
	if (!c.includes('if (seclab && query.extraFileResources) {')) {
		p.push('the extra-resource filter does not apply to a tab');
	}
	return p;
}

const tests: Array<[string, () => void]> = [
	['patch 0051 sanitises tab search messages and the query sent to a tab', () => assert.deepEqual(problems(PATCH), [])],
	['each rule fails on a mutant of the real patch', () => {
		const mutants: Array<[string, string, string]> = [
			['no sanitiser', 'const fromTab = seclabFromTab(extHostContext.remoteAuthority,', 'const fromTab = undefined && seclabFromTab(extHostContext.remoteAuthority,'],
			['one provider without it', 'scheme, handle, this._proxy, this._seclab));', 'scheme, handle, this._proxy));'],
			['messages passed through', 'messages: seclab ? seclab.fromTab.searchMessages(result.messages) as ITextSearchCompleteMessage[] : result.messages', 'messages: result.messages'],
			['extra resources kept', "r.scheme === 'vscode-remote' && r.authority.toLowerCase() === seclab.authority.toLowerCase()", 'true'],
			['filter never applies', 'if (seclab && query.extraFileResources) {', 'if (false && query.extraFileResources) {'],
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
