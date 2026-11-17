// Editor-tabs probe (test only; test/edtabs/probe.ts). Runs in the tab's extension host and records
// what the window's editor-tab model tells it about each open editor: the input kind, URI schemes
// (own tab authority or not), and SHA-256 hashes of every token of the tab's label and of every URI
// it carries. Never the text. Inert unless the workspace was armed by a run. Stops when the harness
// writes <workspace>/.seclab/stop. Writes only under <workspace>/.seclab-edtabs. No network.

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
const KINDS = ['TabInputText', 'TabInputTextDiff', 'TabInputCustom', 'TabInputNotebook', 'TabInputNotebookDiff', 'TabInputWebview', 'TabInputTerminal', 'TabInputTextMerge', 'TabInputInteractiveWindow', 'TabInputChat', 'TabInputTextMultiDiff'];

exports.activate = async function (context) {
	const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
	const t = root && armed(root);
	if (!t) {
		return;
	}
	const out = path.join(root, '.seclab-edtabs');
	fs.mkdirSync(out, { recursive: true });
	const report = { schema: 'seclab-edtabs-report/1', arm: t.arm, done: false, tabs: 0, untitledText: false, kinds: {}, schemes: {}, tokens: [] };
	const seen = new Set();
	const tokens = (s, field) => {
		for (const tok of String(s).split(/[\/\\~\s?#&=:.-]+/)) {
			if (tok.length >= 4 && tok.length <= 120) {
				const h = sha(tok);
				const k = `${field}|${h}`;
				if (!seen.has(k) && seen.size < 5000) {
					seen.add(k);
					report.tokens.push({ field, sha256: h });
				}
			}
		}
	};
	const uris = input => {
		if (!input || typeof input !== 'object') {
			return [];
		}
		const list = [];
		for (const k of ['uri', 'original', 'modified', 'base', 'input1', 'input2', 'result']) {
			if (input[k] instanceof vscode.Uri) {
				list.push(input[k]);
			}
		}
		for (const d of Array.isArray(input.textDiffs) ? input.textDiffs : []) {
			list.push(...[d.original, d.modified].filter(u => u instanceof vscode.Uri));
		}
		return list;
	};
	const scan = () => {
		report.tabs = Math.max(report.tabs, vscode.window.tabGroups.all.reduce((n, g) => n + g.tabs.length, 0));
		for (const g of vscode.window.tabGroups.all) {
			for (const tab of g.tabs) {
				if (tab.input instanceof vscode.TabInputText && tab.input.uri.scheme === 'untitled') {
					report.untitledText = true;
				}
				const kind = KINDS.find(k => vscode[k] && tab.input instanceof vscode[k]) ?? (tab.input === undefined ? 'unknown' : 'other');
				report.kinds[kind] = (report.kinds[kind] ?? 0) + 1;
				tokens(tab.label, 'label');
				for (const u of uris(tab.input)) {
					// The REH's URI transformer shows the tab's own vscode-remote files as file: here, and host files as vscode-local:.
					const key = u.scheme === 'file' && (u.fsPath + path.sep).startsWith(root + path.sep) ? 'file+own' : u.scheme;
					report.schemes[key] = (report.schemes[key] ?? 0) + 1;
					tokens(u.toString(true), 'uri');
				}
			}
		}
	};
	const write = () => fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify(report));
	context.subscriptions.push(vscode.window.tabGroups.onDidChangeTabs(e => {
		for (const tab of [...e.opened, ...e.changed]) {
			tokens(tab.label, 'label');
			for (const u of uris(tab.input)) {
				tokens(u.toString(true), 'uri');
			}
		}
	}));
	// Control: the tab's own file, opened by the tab.
	try {
		await vscode.window.showTextDocument(vscode.Uri.joinPath(vscode.workspace.workspaceFolders[0].uri, 'README.md'), { preview: false });
	} catch {
		// reported through the scan: no own-scheme tab
	}

	for (let i = 0; i < 240 && !fs.existsSync(path.join(root, '.seclab', 'stop')); i++) {
		await sleep(1000);
		scan();
		write();
	}
	scan();
	report.done = true;
	write();
};
