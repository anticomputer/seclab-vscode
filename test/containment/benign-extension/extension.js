// seclab positive control. The counterpart to the rogue extension: this one does only
// what an ordinary workspace extension does, and every step must SUCCEED in a tab window.
//
// Why it exists: the first patched build wrote no host marker and looked contained, but
// its extension host was dead -- the filter denied MainThreadErrors.$onUnexpectedError and
// the activation lifecycle, so nothing activated at all and the absent marker meant
// nothing (docs/edr/20261106-rpc-core-proof-run.md). A containment suite made only of
// "the bad thing did not happen" cannot tell containment from a broken editor. This is the
// check that fails when the filter breaks the product.
//
// Nothing here is hostile and nothing is armed: it touches only its own workspace folder,
// makes no network call, reads no host path, and runs in every build, patched or not.

const vscode = require('vscode');
const os = require('node:os');
const path = require('node:path');

/** Record a step's outcome without ever throwing out of activate(). */
async function step(results, name, fn) {
	try {
		results[name] = { ok: true, value: await fn() };
	} catch (e) {
		results[name] = { ok: false, error: String((e && e.message) || e) };
	}
}

async function activate(context) {
	const folder = (vscode.workspace.workspaceFolders || [])[0];
	if (!folder) {
		return;
	}
	const root = folder.uri;
	const results = {};
	const enc = new TextEncoder();
	const dec = new TextDecoder();

	// Where it ran. The positive control is only meaningful inside a tab.
	results.where = {
		remoteName: vscode.env.remoteName ?? null,
		hostname: os.hostname(),
		seclabTab: process.env.SECLAB_TAB ?? null,
	};

	// 1. Register a command and execute it. This is MainThreadCommands
	// $registerCommand + $executeCommand, the surface the taint guards: a tab's
	// own command must still round-trip, or no extension can function.
	let pinged = 0;
	context.subscriptions.push(
		vscode.commands.registerCommand('seclab-test.benign.ping', () => ++pinged));
	await step(results, 'ownCommandRoundTrip', async () => {
		const r = await vscode.commands.executeCommand('seclab-test.benign.ping');
		return { returned: r, pinged };
	});

	// 2. Read and write a file in its own workspace, through the editor's file
	// system API rather than node's: MainThreadFileSystem with the URI constraint.
	const scratch = vscode.Uri.joinPath(root, '.seclab-evidence', 'benign-scratch.txt');
	await step(results, 'workspaceFileWrite', async () => {
		await vscode.workspace.fs.writeFile(scratch, enc.encode('positive control\n'));
		return true;
	});
	await step(results, 'workspaceFileRead', async () =>
		dec.decode(await vscode.workspace.fs.readFile(scratch)) === 'positive control\n');

	// 3. Open a document and read its text: MainThreadDocuments.
	await step(results, 'openTextDocument', async () => {
		const doc = await vscode.workspace.openTextDocument(scratch);
		return doc.getText().startsWith('positive control');
	});

	// 4. Find files in the workspace: MainThreadWorkspace / the search provider.
	await step(results, 'findFiles', async () =>
		(await vscode.workspace.findFiles('**/*', undefined, 5)).length >= 0);

	// 5. Read configuration, the ordinary way an extension reads its settings.
	await step(results, 'getConfiguration', async () =>
		typeof vscode.workspace.getConfiguration('editor').get('tabSize') !== 'undefined');

	// 6. Log through an output channel: MainThreadOutputService.
	await step(results, 'outputChannel', async () => {
		const ch = vscode.window.createOutputChannel('seclab positive control');
		context.subscriptions.push(ch);
		ch.appendLine('ok');
		return true;
	});

	// 7. Workspace state, i.e. the extension's own storage.
	await step(results, 'workspaceState', async () => {
		await context.workspaceState.update('seclab-benign', 'v1');
		return context.workspaceState.get('seclab-benign') === 'v1';
	});

	// 8. A language feature: register a hover provider and invoke it. This is the
	// shape most real extensions take, and it exercises the provider registration
	// path rather than a one-shot call.
	await step(results, 'languageFeature', async () => {
		context.subscriptions.push(vscode.languages.registerHoverProvider(
			{ scheme: 'file' }, { provideHover: () => new vscode.Hover('seclab') }));
		const doc = await vscode.workspace.openTextDocument(scratch);
		const hovers = await vscode.commands.executeCommand(
			'vscode.executeHoverProvider', doc.uri, new vscode.Position(0, 0));
		return Array.isArray(hovers);
	});

	// 9. Global state: every activation already initialises it (the extension host
	// awaits both mementos before activate() runs), and most real extensions write it.
	await step(results, 'globalState', async () => {
		await context.globalState.update('seclab-benign', 'g1');
		context.globalState.setKeysForSync(['seclab-benign']);
		return context.globalState.get('seclab-benign') === 'g1';
	});

	// 10. A command declared in contributes.commands, run the way a menu or the
	// palette runs it.
	await step(results, 'contributedCommand', async () => {
		context.subscriptions.push(vscode.commands.registerCommand(
			'seclab-test.benign.contributed', () => 'contributed'));
		return await vscode.commands.executeCommand('seclab-test.benign.contributed') === 'contributed';
	});

	// 11. A second language feature with a different registration and invocation
	// path: completion items.
	await step(results, 'completionProvider', async () => {
		context.subscriptions.push(vscode.languages.registerCompletionItemProvider(
			{ scheme: 'vscode-remote' }, { provideCompletionItems: () => [new vscode.CompletionItem('seclab')] }));
		const doc = await vscode.workspace.openTextDocument(scratch);
		const list = await vscode.commands.executeCommand(
			'vscode.executeCompletionItemProvider', doc.uri, new vscode.Position(0, 0));
		return !!list && Array.isArray(list.items);
	});

	// 12. A status bar item, the commonest piece of extension UI.
	await step(results, 'statusBarItem', async () => {
		const item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left);
		context.subscriptions.push(item);
		item.text = 'seclab';
		item.show();
		return true;
	});

	// 13. The extension's own secret storage, with a fake value.
	await step(results, 'ownSecret', async () => {
		await context.secrets.store('seclab-benign', 'seclabcanary_benign_not_a_secret');
		return await context.secrets.get('seclab-benign') === 'seclabcanary_benign_not_a_secret';
	});

	// Measurement only (test/containment/rpc-trace.ts): when the workspace carries the
	// trace marker, also open ordinary files so the built-in language extensions activate
	// the way they do for a user, and reload once so a warm start is traced too. Never
	// present in a proof run's workspace.
	if (await exists(vscode.Uri.joinPath(root, '.seclab-trace-passes'))) {
		await step(results, 'tracePasses', async () => {
			const opened = [];
			for (const f of ['src/index.ts', 'README.md', 'data.json']) {
				const doc = await vscode.workspace.openTextDocument(vscode.Uri.joinPath(root, f));
				await vscode.window.showTextDocument(doc, { preview: false, preserveFocus: true });
				opened.push(doc.languageId);
			}
			await new Promise(r => setTimeout(r, 20000));
			if (!context.workspaceState.get('seclab-trace-reloaded')) {
				await context.workspaceState.update('seclab-trace-reloaded', true);
				await vscode.commands.executeCommand('workbench.action.reloadWindow');
			}
			return opened;
		});
	}

	const out = vscode.Uri.joinPath(root, '.seclab-evidence', 'benign.json');
	const failed = Object.entries(results)
		.filter(([k, v]) => k !== 'where' && !v.ok).map(([k]) => k);
	try {
		await vscode.workspace.fs.createDirectory(vscode.Uri.joinPath(root, '.seclab-evidence'));
		await vscode.workspace.fs.writeFile(out, enc.encode(JSON.stringify({
			activated: true, failed, results,
		}, null, 2)));
	} catch {
		// If even this cannot be written, the harness reads an absent file as
		// "the benign extension could not run", which is the correct verdict.
	}
}

async function exists(uri) {
	try {
		await vscode.workspace.fs.stat(uri);
		return true;
	} catch {
		return false;
	}
}

function deactivate() { }

module.exports = { activate, deactivate };
