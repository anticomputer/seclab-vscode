// Notebook-sync probe (test only; test/nbsync/probe.ts). Runs in the tab's extension host and
// records which notebooks reach it, and through which channel: the notebook sync (notebook
// documents and their cells), cell text documents, and this extension's own serializer. It reports
// URI schemes and SHA-256 hashes of text lines, never the text. Inert unless the workspace was armed
// by a run. Writes only under <workspace>/.seclab-nbsync. Sends nothing over the network.

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
	const hostIpynb = get('hostipynb'), hostNb = get('hostnb');
	if (!hostIpynb.startsWith(run + '/host/') || !hostNb.startsWith(run + '/host/')) {
		return undefined;
	}
	return { arm: get('arm'), hostIpynb, hostNb };
}

const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const sleep = ms => new Promise(r => setTimeout(r, ms));
const TAB_CELL = 'nbsync tab-created cell';
const TAB_EDIT = 'nbsync tab edit';

exports.activate = async function (context) {
	const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
	const t = root && armed(root);
	if (!t) {
		return;
	}
	const own = vscode.workspace.workspaceFolders[0].uri.authority;
	const out = path.join(root, '.seclab-nbsync');
	fs.mkdirSync(out, { recursive: true });
	const report = {
		schema: 'seclab-nbsync-report/1', arm: t.arm, done: false, steps: {},
		schemes: {},            // "<channel>:<scheme>[+own|+other]" -> count
		hits: [],               // { channel, phase, sha256 } for every distinct line hash seen
		controls: { ownNotebook: false, tabUntitled: false, tabUntitledEdited: false },
	};
	let phase = 'start';
	const seenLines = new Set();
	const note = (channel, uri, text) => {
		const key = `${channel}:${uri.scheme}${uri.scheme === 'vscode-remote' ? (uri.authority === own ? '+own' : '+other') : ''}`;
		report.schemes[key] = (report.schemes[key] ?? 0) + 1;
		for (const line of String(text).split(/\r?\n/).slice(0, 400)) {
			const l = line.replace(/^[\s"#,]+|[\s",]+$/g, '');
			if (l.length >= 8 && l.length <= 200) {
				const h = sha(l);
				const k = `${channel}|${phase}|${h}`;
				if (!seenLines.has(k) && seenLines.size < 5000) {
					seenLines.add(k);
					report.hits.push({ channel, phase, sha256: h });
				}
			}
		}
	};
	const write = () => fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify(report));
	const scanNotebook = (nb, channel) => {
		note(channel, nb.uri, '');
		for (const c of nb.getCells()) {
			note(`${channel}-cell`, c.document.uri, c.document.getText());
		}
	};
	const scanAll = () => {
		for (const nb of vscode.workspace.notebookDocuments) {
			scanNotebook(nb, 'notebooks');
		}
		for (const d of vscode.workspace.textDocuments) {
			if (d.uri.scheme === 'vscode-notebook-cell') {
				note('celldocs', d.uri, d.getText());
			}
		}
	};
	context.subscriptions.push(
		vscode.workspace.onDidOpenNotebookDocument(nb => scanNotebook(nb, 'onopen')),
		vscode.workspace.onDidChangeNotebookDocument(e => scanNotebook(e.notebook, 'onchange')),
		vscode.workspace.onDidOpenTextDocument(d => { if (d.uri.scheme === 'vscode-notebook-cell') { note('celldocs', d.uri, d.getText()); } }),
		// The tab's own serializer: what the window hands it to deserialize (bytes of the file opened).
		vscode.workspace.registerNotebookSerializer('seclab-nbprobe', {
			deserializeNotebook(content) {
				note('serializer', vscode.Uri.from({ scheme: 'bytes' }), Buffer.from(content).toString('utf8'));
				return new vscode.NotebookData([new vscode.NotebookCellData(vscode.NotebookCellKind.Markup, 'probe notebook', 'markdown')]);
			},
			serializeNotebook() { return new Uint8Array(); },
		}),
	);

	const ownNb = vscode.Uri.joinPath(vscode.workspace.workspaceFolders[0].uri, 'nb.ipynb');
	const hostIpynb = vscode.Uri.from({ scheme: 'vscode-local', path: t.hostIpynb });
	const hostNb = vscode.Uri.from({ scheme: 'vscode-local', path: t.hostNb });
	const steps = [
		['own-notebook', async () => {
			const nb = await vscode.workspace.openNotebookDocument(ownNb);
			await vscode.window.showNotebookDocument(nb);
			report.controls.ownNotebook = vscode.workspace.notebookDocuments.some(n => n.uri.toString() === ownNb.toString());
		}],
		['tab-untitled', async () => {
			const nb = await vscode.workspace.openNotebookDocument('jupyter-notebook', new vscode.NotebookData([new vscode.NotebookCellData(vscode.NotebookCellKind.Markup, TAB_CELL, 'markdown')]));
			await vscode.window.showNotebookDocument(nb);
			report.controls.tabUntitled = vscode.workspace.notebookDocuments.some(n => n.uri.toString() === nb.uri.toString());
			const cell = nb.cellAt(0).document;
			const edit = new vscode.WorkspaceEdit();
			edit.insert(cell.uri, new vscode.Position(0, 0), TAB_EDIT + ' ');
			report.steps['tab-untitled-applied'] = String(await vscode.workspace.applyEdit(edit));
			await sleep(1000);
			report.controls.tabUntitledEdited = nb.cellAt(0).document.getText().startsWith(TAB_EDIT);
		}],
		// What a user does: open a host notebook in this window (File > Open, recent, drag-and-drop).
		['host-ipynb-open', async () => { await vscode.commands.executeCommand('vscode.open', hostIpynb); }],
		['host-nb-open', async () => { await vscode.commands.executeCommand('vscode.openWith', hostNb, 'seclab-nbprobe'); }],
		// The tab asks for a host notebook by URI itself.
		['tab-claims-host-ipynb', async () => { await vscode.workspace.openNotebookDocument(hostIpynb); }],
	];
	for (const [name, fn] of steps) {
		phase = name;
		try {
			await fn();
			report.steps[name] = 'ok';
		} catch (e) {
			report.steps[name] = `error: ${String(e && e.name || 'Error').slice(0, 40)}`;
		}
		await sleep(2500);
		scanAll();
		write();
	}
	phase = 'end';
	scanAll();
	report.done = true;
	write();
};
