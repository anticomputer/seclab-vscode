/**
 * Patch 0009: in a tab window the built-in chat registers no tools, runs none, and sends no
 * request. Checked on the patch text, the artefact that ships.
 *
 * Run: node test/containment/chat-gate.test.ts   (or ./seclab test chat-gate)
 *
 * For each guarded method, the FIRST thing its body does is an added
 * `if (seclabAiDisabled(<environment>.remoteAuthority))` block that logs the refusal under its own
 * key (`seclabRefuseAi`, into the window's decision log, so a run sees a refusal rather than only an
 * absence) and then returns `Disposable.None` (the two registration primitives that write the tool
 * map) or throws (invocation and the agent loop), ahead of every upstream line. registerToolData and registerToolImplementation are
 * guarded rather than the registerTool wrapper, because both are public and called directly
 * (agent-host-patches finding 2). Each rule is shown failing on a mutant of the real patch.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const PATCH = readFileSync(join(REPO, 'patches', '0009-seclab-no-builtin-chat-in-tabs.patch'), 'utf8');

interface Guard { title: string; file: string; signature: string; env: string; ref: string; outcome: RegExp }
const GUARDS: Guard[] = [
	{ title: 'registerToolData refuses first in a tab window', file: 'languageModelToolsService.ts', signature: 'registerToolData(toolData: IToolData): IDisposable {', env: 'this._seclabEnvironmentService', ref: 'ai:tools.registerToolData', outcome: /^return Disposable\.None;$/ },
	{ title: 'registerToolImplementation refuses first in a tab window', file: 'languageModelToolsService.ts', signature: 'registerToolImplementation(id: string, tool: IToolImpl): IDisposable {', env: 'this._seclabEnvironmentService', ref: 'ai:tools.registerToolImplementation', outcome: /^return Disposable\.None;$/ },
	{ title: 'invokeTool refuses first in a tab window', file: 'languageModelToolsService.ts', signature: 'async invokeTool(dto: IToolInvocation, countTokens: CountTokensCallback, token: CancellationToken): Promise<IToolResult> {', env: 'this._seclabEnvironmentService', ref: 'ai:tools.invokeTool', outcome: /^throw new Error\('Unsupported operation'\);$/ },
	{ title: 'sendRequest refuses first in a tab window', file: 'chatServiceImpl.ts', signature: 'async sendRequest(sessionResource: URI, request: string, options?: IChatSendRequestOptions): Promise<ChatSendResult> {', env: 'this.seclabEnvironmentService', ref: 'ai:chat.sendRequest', outcome: /^throw new Error\('Unsupported operation'\);$/ },
];

/** The file's hunk lines, `+` and context only, in order. */
function linesOf(patch: string, file: string): Array<{ kind: '+' | ' '; text: string }> {
	const out: Array<{ kind: '+' | ' '; text: string }> = [];
	let inFile = false;
	for (const raw of patch.split('\n')) {
		if (raw.startsWith('diff ')) {
			inFile = raw.endsWith(`/${file}`);
			continue;
		}
		if (!inFile || raw.startsWith('---') || raw.startsWith('+++') || raw.startsWith('@@')) {
			continue;
		}
		if (raw.startsWith('+')) {
			out.push({ kind: '+', text: raw.slice(1).trim() });
		} else if (raw.startsWith(' ')) {
			out.push({ kind: ' ', text: raw.slice(1).trim() });
		}
	}
	return out;
}

function problems(patch: string, g: Guard): string[] {
	const lines = linesOf(patch, g.file).filter(l => !l.text.startsWith('//'));
	const at = lines.findIndex(l => l.kind === ' ' && l.text === g.signature);
	if (at < 0) {
		return ['signature not found as context'];
	}
	const [open, log, act, close, next] = lines.slice(at + 1, at + 6);
	const out: string[] = [];
	if (!open || open.kind !== '+' || open.text !== `if (seclabAiDisabled(${g.env}.remoteAuthority)) {`) {
		out.push('the first statement is not the tab-window guard');
	}
	if (!log || log.kind !== '+' || log.text !== `seclabRefuseAi(${g.env}.remoteAuthority, '${g.ref}');`) {
		out.push('the guard does not log its refusal under its own key');
	}
	if (!act || act.kind !== '+' || !g.outcome.test(act.text)) {
		out.push('the guard does not refuse');
	}
	if (!close || close.kind !== '+' || close.text !== '}') {
		out.push('the guard does not close before upstream code');
	}
	if (!next || next.kind !== ' ') {
		out.push('upstream code does not follow the guard');
	}
	return out;
}

const tests: Array<[string, () => void]> = [];
for (const g of GUARDS) {
	tests.push([g.title, () => assert.deepEqual(problems(PATCH, g), [])]);
}
tests.push(['the injection is imported, from the filter module', () => {
	const imports = PATCH.split('\n').filter(l => l.startsWith('+import { seclabAiDisabled, seclabRefuseAi }'));
	assert.equal(imports.length, 2);
	for (const l of imports) {
		assert.match(l, /from '\.\.\/\.\.\/\.\.\/\.\.\/services\/extensions\/common\/seclabRpcFilter\.js';$/);
	}
}]);
tests.push(['each rule fails on a mutant of the real patch', () => {
	const mutants: Array<[string, (p: string) => string]> = [
		['the tool-data guard removed', p => p.replace(/\+\t\tif \(seclabAiDisabled\(this\._seclabEnvironmentService\.remoteAuthority\)\) \{\n(\+\t\t\t\/\/[^\n]*\n)*\+\t\t\tseclabRefuseAi\([^\n]*\n\+\t\t\treturn Disposable\.None;\n\+\t\t\}\n/, '')],
		['the sendRequest refusal not logged', p => p.replace(/\+\t\t\tseclabRefuseAi\(this\.seclabEnvironmentService\.remoteAuthority, 'ai:chat\.sendRequest'\);\n/, '')],
		['invokeTool logged under another key', p => p.replace("'ai:tools.invokeTool'", "'ai:tools.registerToolData'")],
		['the guard keyed on something else', p => p.replace('if (seclabAiDisabled(this._seclabEnvironmentService.remoteAuthority)) {', 'if (seclabAiDisabled(undefined)) {')],
		['invocation allowed through', p => p.replace("\t\t\tthrow new Error('Unsupported operation');", '\t\t\tconsole.log(1);')],
		['sendRequest guard on a different env', p => p.replace('if (seclabAiDisabled(this.seclabEnvironmentService.remoteAuthority)) {', 'if (seclabAiDisabled(this.otherService.remoteAuthority)) {')],
	];
	for (const [name, mutate] of mutants) {
		const m = mutate(PATCH);
		assert.notEqual(m, PATCH, `mutant "${name}" changed nothing: the prover is broken`);
		assert.ok(GUARDS.some(g => problems(m, g).length > 0), `mutant survived: ${name}`);
	}
}]);

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
