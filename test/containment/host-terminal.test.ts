/**
 * Patch 0050 (project owner decision 2026-11-16): a tab window opens no host terminal. Checked on
 * the patch text, the artefact that ships, with each rule shown failing on a mutant of the real
 * patch. The runtime proof is test/containment/host-terminal.ts.
 *
 * Run: node test/containment/host-terminal.test.ts   (or ./seclab test host-terminal)
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const PATCH = readFileSync(join(REPO, 'patches', '0050-seclab-no-host-terminal-in-tabs.patch'), 'utf8');

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

const NOT_TAB = "RemoteNameContext.notEqualsTo('seclab')";

function problems(patch: string): string[] {
	const p: string[] = [];
	const native = code(patch, 'terminalNativeContribution.ts');
	if (!native.includes('if (connection && connection.remoteAuthority && !seclabIsTabAuthority(connection.remoteAuthority)) {\nregisterRemoteContributions();')) {
		p.push('"Create New Integrated Terminal (Local)" is registered in a tab window');
	}
	const external = code(patch, 'externalTerminal.contribution.ts');
	if (!external.includes(`when: ContextKeyExpr.and(TerminalContextKeys.notFocus, IsSessionsWindowContext.negate(), ${NOT_TAB}),`)) {
		p.push('the external terminal keybinding is active in a tab window');
	}
	if (!external.includes('handler: async (accessor) => {\nif (seclabIsTabAuthority(accessor.get(IWorkbenchEnvironmentService).remoteAuthority)) {\nreturn;\n}')) {
		p.push('the external terminal handler runs in a tab window');
	}
	if (!external.includes(`title: nls.localize2('globalConsoleAction', "Open New External Terminal")\n},\nwhen: ${NOT_TAB}\n});`)) {
		p.push('the palette offers the external terminal in a tab window');
	}
	const manager = code(patch, 'terminalProcessManager.ts');
	const refuse = manager.indexOf('if (seclabIsTabAuthority(seclabWindow) && this.remoteAuthority?.toLowerCase() !== seclabWindow!.toLowerCase()) {\nreturn { message:');
	const backend = manager.indexOf('const backend = await this._terminalInstanceService.getBackend(this.remoteAuthority);');
	if (!manager.includes('const seclabWindow = this._workbenchEnvironmentService.remoteAuthority;') || refuse < 0 || backend < refuse) {
		p.push('a tab window can start a pty outside its own tab');
	}
	return p;
}

const tests: Array<[string, () => void]> = [
	['patch 0050 offers and starts no host terminal in a tab window', () => assert.deepEqual(problems(PATCH), [])],
	['each rule fails on a mutant of the real patch', () => {
		const mutants: Array<[string, string, string]> = [
			['local terminal registered anyway', ' && !seclabIsTabAuthority(connection.remoteAuthority)) {', ') {'],
			['keybinding when clause dropped', `IsSessionsWindowContext.negate(), ${NOT_TAB}),`, 'IsSessionsWindowContext.negate()),'],
			['handler refusal dropped', '+\t\tif (seclabIsTabAuthority(accessor.get(IWorkbenchEnvironmentService).remoteAuthority)) {\n+\t\t\treturn;', '+\t\tif (false) {\n+\t\t\treturn;'],
			['palette when clause dropped', `+\twhen: ${NOT_TAB}\n`, ''],
			['backend refusal allows any authority', 'this.remoteAuthority?.toLowerCase() !== seclabWindow!.toLowerCase()', 'this.remoteAuthority === undefined && false'],
			['backend refusal keyed on the terminal', 'const seclabWindow = this._workbenchEnvironmentService.remoteAuthority;', 'const seclabWindow = this.remoteAuthority;'],
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
