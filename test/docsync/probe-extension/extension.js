// Document-sync probe (test only; test/docsync/probe.ts). Runs in the tab's extension host and
// records which documents the window hands it. It drives ordinary editor commands, two hijack
// attempts and some positive controls.
//
// The probe never learns a canary. It hashes every `seclabcanary_ds_…` match it sees, and the host
// harness compares the hashes with the canaries it seeded. The report holds scheme names, counts,
// hashes and booleans; URIs go only into this run's workspace under .work. No contents are written.
// It is inert unless the workspace was armed by a run: per-run nonce, workspace inside that run's
// dir, unexpired. It writes only under <workspace>/.seclab-docsync and to the tab file it edits.
// It sends nothing over the network.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const vscode = require('vscode');

const STEP_MS = 3000;
const SENTINEL = 'seclab docsync probe: tab-provided content\n';
const TYPED = 'typed-by-probe';
const TAB_UNTITLED = 'tab-untitled-by-probe';
const EDITED = 'edited-by-probe';
const CANARY = /seclabcanary_ds_[0-9a-f]{16,64}/g;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const clean = s => String(s && s.message || s).replace(/[^\x20-\x7e]/g, '?').slice(0, 200);

function armed(root) {
	let t = '';
	try { t = fs.readFileSync(path.join(root, '.seclab', 'targets'), 'utf8'); } catch { return undefined; }
	const get = k => (t.match(new RegExp(`^${k}=(.*)$`, 'm')) ?? [])[1] ?? '';
	const run = get('run');
	const until = Number(get('until'));
	if (!/^[0-9a-f]{32}$/.test(get('arm')) || !run.startsWith('/') || !(root + path.sep).startsWith(run + path.sep)
		|| !(until > Date.now() / 1000) || !get('hostfile').startsWith(run + path.sep)) {
		return undefined;
	}
	return { arm: get('arm'), hostfile: get('hostfile') };
}

exports.activate = async function () {
	const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
	const t = root && armed(root);
	if (!t) {
		return;
	}
	const out = path.join(root, '.seclab-docsync');
	fs.mkdirSync(out, { recursive: true });
	const tabUri = vscode.Uri.joinPath(vscode.workspace.workspaceFolders[0].uri, 'tracked.txt');
	const nbUri = vscode.Uri.joinPath(vscode.workspace.workspaceFolders[0].uri, 'nb.ipynb');
	const perfUri = vscode.Uri.from({ scheme: 'perf', path: 'Startup Performance' });
	const hostUri = vscode.Uri.from({ scheme: 'vscode-local', path: t.hostfile });
	const report = {
		schema: 'seclab-docsync-report/1', arm: t.arm, done: false, steps: [], schemes: {}, hits: [], uris: [],
		perf: { precreated: false, foreignSeen: false, servedToTab: 0, removedAt: '' },
		hijack: { providers: 0, fsUserdata: 'not tried', fsOutput: 'not tried', hostSchemeAsks: 0, untitledClaims: 0 },
		seeded: false, untitledForeign: false,
		controls: { editSaved: false, untitledTyped: false, tabUntitled: false, gitDoc: false, cellDoc: false },
	};
	let step = 'start';
	let perfAt = Date.now();
	const hits = new Set();
	const write = () => fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify(report, null, 1));
	const observe = (doc, kind) => {
		const s = doc.uri.scheme.slice(0, 64);
		const c = report.schemes[s] ??= { open: 0, change: 0, close: 0, snapshot: 0 };
		c[kind]++;
		const u = doc.uri.toString().slice(0, 300);
		if (report.uris.length < 300 && !report.uris.includes(u)) {
			report.uris.push(u);
		}
		if (kind === 'close') {
			if (doc.uri.toString() === perfUri.toString() && !report.perf.removedAt) {
				report.perf.removedAt = step;
			}
			return;
		}
		const text = doc.getText();
		for (const m of text.match(CANARY) ?? []) {
			const sha256 = crypto.createHash('sha256').update(m).digest('hex');
			if (!hits.has(`${s}|${sha256}`)) {
				hits.add(`${s}|${sha256}`);
				report.hits.push({ scheme: s, step, sha256 });
			}
		}
		if (doc.uri.toString() === perfUri.toString() && text !== SENTINEL) {
			report.perf.foreignSeen = true;
		}
		if (s === 'untitled' && text.includes(TYPED)) {
			report.controls.untitledTyped = true;
		}
		if (s === 'untitled' && text.includes(TAB_UNTITLED)) {
			report.controls.tabUntitled = true;
		}
		// Untitled text the probe neither typed nor created: host-seeded content.
		if (s === 'untitled' && text.trim() && !text.includes(TYPED) && !text.includes(TAB_UNTITLED)) {
			report.untitledForeign = true;
		}
		if (s === 'git') {
			report.controls.gitDoc = true;
		}
		if (s === 'vscode-notebook-cell') {
			report.controls.cellDoc = true;
		}
	};
	vscode.workspace.onDidOpenTextDocument(d => observe(d, 'open'));
	vscode.workspace.onDidChangeTextDocument(e => observe(e.document, 'change'));
	vscode.workspace.onDidCloseTextDocument(d => observe(d, 'close'));

	const steps = [
		['settle', async () => { await sleep(8000); }],
		// Sibling evidence only: a user setting's value through the configuration snapshot.
		['configuration-sibling', async () => {
			const v = String(vscode.workspace.getConfiguration().get('docsync.sibling') ?? '');
			report.configHashes = (v.match(CANARY) ?? []).map(m => crypto.createHash('sha256').update(m).digest('hex'));
		}],
		// Hijack 1: providers for host schemes. They decline every host request, so the host's own
		// provider makes the model; only the tab's own first perf request gets tab content.
		['register-host-scheme-providers', async () => {
			const decline = { provideTextDocumentContent() { report.hijack.hostSchemeAsks++; return undefined; } };
			// `file` isn't here: the ext host refuses it, since it's taken by its own filesystem.
			for (const scheme of ['output', 'vscode-userdata', 'vscode-local']) {
				try {
					vscode.workspace.registerTextDocumentContentProvider(scheme, decline);
					report.hijack.providers++;
				} catch { /* refused by the ext host itself */ }
			}
			vscode.workspace.registerTextDocumentContentProvider('perf', {
				provideTextDocumentContent(uri) {
					if (uri.toString() === perfUri.toString() && report.perf.servedToTab === 0) {
						report.perf.servedToTab++;
						return SENTINEL;
					}
					report.hijack.hostSchemeAsks++;
					return undefined;
				},
			});
			report.hijack.providers++;
			try {
				const e = new vscode.EventEmitter();
				vscode.workspace.registerFileSystemProvider('vscode-userdata', {
					onDidChangeFile: e.event, watch: () => new vscode.Disposable(() => { }),
					stat: () => { throw vscode.FileSystemError.FileNotFound(); }, readDirectory: () => [],
					createDirectory: () => { }, readFile: () => new Uint8Array(), writeFile: () => { },
					delete: () => { }, rename: () => { },
				});
				report.hijack.fsUserdata = 'registered';
			} catch (err) {
				report.hijack.fsUserdata = `refused: ${clean(err)}`;
			}
		}],
		// Hijack 2: pre-create a model at a host URI that host code reuses. The window keeps the
		// tab's reference for at most 3 minutes (BoundModelReferenceCollection), and the model
		// outlives it (TextResourceEditorModel never disposes a model it didn't create). The
		// next open then asks the perf provider, which reuses the model (`getModel() ||
		// createModel()`) and calls `setValue` with host data (perfviewEditor.ts).
		['precreate-perf', async () => {
			const doc = await vscode.workspace.openTextDocument(perfUri);
			report.perf.precreated = doc.getText() === SENTINEL;
			perfAt = Date.now();
		}],
		['open-user-settings', async () => { await vscode.commands.executeCommand('workbench.action.openSettingsJson'); }],
		['open-keybindings', async () => { await vscode.commands.executeCommand('workbench.action.openGlobalKeybindingsFile'); }],
		['show-window-log', async () => {
			fs.writeFileSync(path.join(out, 'ready-output'), '');
			for (let i = 0; i < 120 && !fs.existsSync(path.join(out, 'seeded')); i++) {
				await sleep(1000);
			}
			report.seeded = fs.existsSync(path.join(out, 'seeded'));
			await vscode.commands.executeCommand('workbench.action.showWindowLog');
		}],
		// Hijack 1b, after the host's output models exist: a filesystem provider for `output`, a host
		// scheme that has none. The window accepts the registration; host output must still not sync.
		['register-output-fs-provider', async () => {
			const e = new vscode.EventEmitter();
			vscode.workspace.registerFileSystemProvider('output', {
				onDidChangeFile: e.event, watch: () => new vscode.Disposable(() => { }),
				stat: () => { throw vscode.FileSystemError.FileNotFound(); }, readDirectory: () => [],
				createDirectory: () => { }, readFile: () => new Uint8Array(), writeFile: () => { },
				delete: () => { }, rename: () => { },
			});
			report.hijack.fsOutput = 'registered';
			await vscode.commands.executeCommand('workbench.action.showWindowLog');
		}],
		// A host file. In the tab's extension host, `file:` is the tab's own disk; the window's
		// `file:` (the host disk) is `vscode-local:` (base/common/uriTransformer.ts).
		['open-host-file', async () => { await vscode.commands.executeCommand('vscode.open', hostUri); }],
		['diff-host-file', async () => { await vscode.commands.executeCommand('vscode.diff', hostUri, tabUri, 'docsync diff'); }],
		['git-open-change', async () => { await vscode.commands.executeCommand('git.openChange', tabUri); await sleep(2000); }],
		['notebook', async () => {
			const nb = await vscode.workspace.openNotebookDocument(nbUri);
			await vscode.window.showNotebookDocument(nb);
		}],
		['untitled-typed', async () => {
			await vscode.commands.executeCommand('workbench.action.files.newUntitledFile');
			await sleep(1000);
			await vscode.commands.executeCommand('type', { text: TYPED });
			const ed = vscode.window.activeTextEditor;
			if (!report.controls.untitledTyped && ed && ed.document.uri.scheme === 'untitled' && !ed.document.getText().includes(TYPED)) {
				await ed.edit(b => b.insert(new vscode.Position(0, 0), TYPED));
			}
		}],
		['tab-untitled', async () => { await vscode.workspace.openTextDocument({ content: TAB_UNTITLED }); }],
		// A host-seeded untitled document (the keyboard-mapping dump), then the tab tries to claim
		// existing untitled models by URI.
		['host-seeded-untitled', async () => {
			await vscode.commands.executeCommand('workbench.action.inspectKeyMappingsJSON');
			await sleep(1500);
			for (let n = 1; n <= 6; n++) {
				try {
					await vscode.workspace.openTextDocument(vscode.Uri.parse(`untitled:Untitled-${n}`));
				} catch { /* refused */ }
				report.hijack.untitledClaims++;
			}
		}],
		['edit-and-save-tab-file', async () => {
			const edit = new vscode.WorkspaceEdit();
			edit.insert(tabUri, new vscode.Position(0, 0), `${EDITED}\n`);
			await vscode.workspace.applyEdit(edit);
			const doc = await vscode.workspace.openTextDocument(tabUri);
			await doc.save();
			report.controls.editSaved = doc.getText().startsWith(EDITED) && fs.readFileSync(tabUri.fsPath, 'utf8').startsWith(EDITED);
		}],
		['perfview-after-release', async () => {
			await sleep(Math.max(0, perfAt + 200_000 - Date.now()));
			await vscode.commands.executeCommand('perfview.show');
			await sleep(8000);
		}],
	];
	for (const [name, run] of steps) {
		step = name;
		const r = { name, ok: true };
		try {
			await run();
		} catch (err) {
			r.ok = false;
			r.error = clean(err);
		}
		await sleep(STEP_MS);
		for (const doc of vscode.workspace.textDocuments) {
			observe(doc, 'snapshot');
		}
		report.steps.push(r);
		write();
	}
	report.done = true;
	write();
};
