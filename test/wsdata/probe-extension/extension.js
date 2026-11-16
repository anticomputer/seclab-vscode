// Workspace-data probe (test only; test/wsdata/probe.ts). Runs in the tab's extension host and
// records what the window tells it about the workspace: folder and configuration URI schemes, the
// folder count, and SHA-256 hashes of every token of the folders' URIs and names, the workspace
// name and its configuration URI. Never the text. Inert unless armed by a run; stops when the
// harness writes <workspace>/.seclab/stop. Writes only under <workspace>/.seclab-wsdata. No network.

const crypto = require('node:crypto');
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
	return { arm: get('arm') };
}

const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const sleep = ms => new Promise(r => setTimeout(r, ms));

exports.activate = async function (context) {
	const first = vscode.workspace.workspaceFolders?.[0];
	const root = first?.uri.fsPath;
	const t = root && armed(root);
	if (!t) {
		return;
	}
	const out = path.join(root, '.seclab-wsdata');
	fs.mkdirSync(out, { recursive: true });
	const report = { schema: 'seclab-wsdata-report/1', arm: t.arm, done: false, maxFolders: 0, schemes: {}, tokens: [] };
	const seen = new Set();
	const tokens = (s, field) => {
		for (const tok of String(s).split(/[\/\\~\s?#&=:.-]+/)) {
			if (tok.length >= 4 && tok.length <= 120) {
				const h = sha(tok);
				if (!seen.has(`${field}|${h}`) && seen.size < 5000) {
					seen.add(`${field}|${h}`);
					report.tokens.push({ field, sha256: h });
				}
			}
		}
	};
	const scheme = (u, field) => {
		const k = `${field}:${u.scheme === 'file' && (u.fsPath + path.sep).startsWith(root + path.sep) ? 'file+own' : u.scheme}`;
		report.schemes[k] = (report.schemes[k] ?? 0) + 1;
	};
	const scan = () => {
		const folders = vscode.workspace.workspaceFolders ?? [];
		report.maxFolders = Math.max(report.maxFolders, folders.length);
		for (const f of folders) {
			scheme(f.uri, 'folder');
			tokens(f.uri.toString(true), 'folder');
			tokens(f.name, 'folderName');
		}
		tokens(vscode.workspace.name ?? '', 'name');
		const cfg = vscode.workspace.workspaceFile;
		if (cfg) {
			scheme(cfg, 'config');
			tokens(cfg.toString(true), 'config');
		}
	};
	const write = () => fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify(report));
	context.subscriptions.push(vscode.workspace.onDidChangeWorkspaceFolders(() => { scan(); write(); }));
	for (let i = 0; i < 240 && !fs.existsSync(path.join(root, '.seclab', 'stop')); i++) {
		scan();
		write();
		await sleep(1000);
	}
	scan();
	report.done = true;
	write();
};
