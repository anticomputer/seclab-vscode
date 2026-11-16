// Scheme-squatting probe (test only; test/squat/probe.ts). Runs in the tab's extension host and
// tries to take over host schemes: a filesystem provider for `vscode-userdata` (the host's user
// settings) and a text-content provider for `output` (the host's output channels). Each provider
// serves only a fixed marker string the harness chose, so if the window ever used one, the marker
// would show in the window. It records which registration calls returned and whether any provider
// was called. Inert unless armed by a run. Writes only under <workspace>/.seclab-squat. No network.

const fs = require('node:fs');
const path = require('node:path');
const vscode = require('vscode');

function armed(root) {
	let t = '';
	try { t = fs.readFileSync(path.join(root, '.seclab', 'targets'), 'utf8'); } catch { return undefined; }
	const get = k => (t.match(new RegExp(`^${k}=(.*)$`, 'm')) ?? [])[1] ?? '';
	const run = get('run');
	if (!/^[0-9a-f]{32}$/.test(get('arm')) || !run.startsWith('/') || !(root + path.sep).startsWith(run + path.sep) || !(Number(get('until')) > Date.now() / 1000)) {
		return undefined;
	}
	const marker = get('marker');
	return /^seclabsquat_[0-9a-f]{16}$/.test(marker) ? { arm: get('arm'), marker } : undefined;
}

exports.activate = function (context) {
	const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
	const t = root && armed(root);
	if (!t) {
		return;
	}
	const out = path.join(root, '.seclab-squat');
	fs.mkdirSync(out, { recursive: true });
	const report = { schema: 'seclab-squat-report/1', arm: t.arm, registered: {}, calls: { fs: 0, content: 0 } };
	const write = () => fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify(report));
	const bytes = new TextEncoder().encode(`{ "seclab": "${t.marker}" }\n`);
	const fsProvider = {
		onDidChangeFile: new vscode.EventEmitter().event,
		watch: () => new vscode.Disposable(() => undefined),
		stat: () => { report.calls.fs++; write(); return { type: vscode.FileType.File, ctime: 0, mtime: 0, size: bytes.length }; },
		readDirectory: () => [],
		createDirectory: () => undefined,
		readFile: () => { report.calls.fs++; write(); return bytes; },
		writeFile: () => undefined,
		delete: () => undefined,
		rename: () => undefined,
	};
	try {
		context.subscriptions.push(vscode.workspace.registerFileSystemProvider('vscode-userdata', fsProvider));
		report.registered.fs = 'returned';
	} catch {
		report.registered.fs = 'threw';
	}
	try {
		context.subscriptions.push(vscode.workspace.registerTextDocumentContentProvider('output', {
			provideTextDocumentContent: () => { report.calls.content++; write(); return t.marker; },
		}));
		report.registered.content = 'returned';
	} catch {
		report.registered.content = 'threw';
	}
	write();
};
