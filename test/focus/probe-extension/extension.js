// Focus probe (test only; test/focus/probe.ts). Runs in the tab and drives, one at a time, the
// editor paths that could raise or activate a background window: a notification, a quick pick,
// focus commands, full screen, an extension host restart, a window reload, a new window, a modal
// dialog, and a forced loss of the server connection. Each step is timestamped in
// .seclab-focus/marks.log, so a recorded focus steal can be matched to the step before it.
// Progress lives in globalState, so the battery resumes after a restart, a reload or a reconnect.
// It reads and writes nothing outside the workspace and sends nothing over the network.

const vscode = require('vscode');
const fs = require('fs');
const path = require('path');

const STEP_MS = 6000;
const sleep = ms => new Promise(r => setTimeout(r, ms));

function mark(text) {
	const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
	if (!root) {
		return;
	}
	fs.mkdirSync(path.join(root, '.seclab-focus'), { recursive: true });
	fs.appendFileSync(path.join(root, '.seclab-focus', 'marks.log'), `${new Date().toISOString()} ${text}\n`);
}

const steps = [
	['settle', async () => { }],
	['notification', async () => { vscode.window.showInformationMessage('seclab focus probe: notification'); }],
	['quick-pick', async () => {
		vscode.window.showQuickPick(['a', 'b'], { placeHolder: 'seclab focus probe' });
		await sleep(2000);
		await vscode.commands.executeCommand('workbench.action.closeQuickOpen');
	}],
	['focus-commands', async () => {
		await vscode.commands.executeCommand('workbench.action.focusSideBar');
		await vscode.commands.executeCommand('workbench.action.focusActiveEditorGroup');
	}],
	['fullscreen', async () => {
		await vscode.commands.executeCommand('workbench.action.toggleFullScreen');
		await sleep(2000);
		await vscode.commands.executeCommand('workbench.action.toggleFullScreen');
	}],
	['modal-dialog', async () => { vscode.window.showWarningMessage('seclab focus probe: modal', { modal: true }, 'OK'); }],
	['new-window', async () => { await vscode.commands.executeCommand('workbench.action.newWindow'); }],
	['reload-window', async () => { await vscode.commands.executeCommand('workbench.action.reloadWindow'); }],
	// The extension host's parent is the server: killing it drops the connection, so the window
	// goes through its reconnect path (and, if that fails, its "reload" prompt).
	['server-connection-lost', async () => { process.kill(process.ppid, 'SIGKILL'); }],
	// Last: it restarts the local extension host too, and with it the Tab Manager's tabd.
	['restart-extension-host', async () => { await vscode.commands.executeCommand('workbench.action.restartExtensionHost'); }],
];

async function activate(context) {
	let i = context.globalState.get('seclab.focusProbe.step', 0);
	const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
	let skip = [];
	try {
		skip = fs.readFileSync(path.join(root, '.seclab-focus-skip'), 'utf8').split(/[\s,]+/).filter(Boolean);
	} catch { /* none */ }
	mark(`activate at step ${i}`);
	while (i < steps.length) {
		const [name, run] = steps[i];
		// Advance first: the step may restart this host, reload the window or kill the server.
		await context.globalState.update('seclab.focusProbe.step', i + 1);
		if (skip.includes(name)) {
			mark(`step ${i} ${name} skipped`);
			i++;
			continue;
		}
		mark(`step ${i} ${name}`);
		try {
			await run();
		} catch (e) {
			mark(`step ${i} ${name} error ${String(e && e.message || e).slice(0, 200)}`);
		}
		await sleep(STEP_MS);
		i++;
	}
	mark('done');
}

module.exports = { activate, deactivate() { } };
