// Window-log probe (EDR window-decision-logs): a tab extension that makes the RPC filter refuse
// something, so the window's seclabRpcFilter.log has a denial to forward. It asks for one
// seclab.* command that doesn't exist (inert either way) and records only whether the call threw,
// in the tab's own /tmp. Inert unless the run armed it (.seclab/rpc-prober-arm, unexpired).
'use strict';

const fs = require('fs');
const path = require('path');
const vscode = require('vscode');

const OUT = '/tmp/seclab-rpc-prober.json';
const COMMAND = 'seclab.windowLogProbe.doesNotExist';

function armed() {
	const folder = vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders[0];
	if (!folder) {
		return false;
	}
	try {
		const arm = fs.readFileSync(path.join(folder.uri.fsPath, '.seclab', 'rpc-prober-arm'), 'utf8');
		const until = Number(/^until=(\d+)$/m.exec(arm)?.[1]);
		return /^arm=[0-9a-f]{32}$/m.test(arm) && until > Date.now() / 1000;
	} catch {
		return false;
	}
}

async function activate() {
	if (!armed()) {
		return;
	}
	let refused = false;
	try {
		await vscode.commands.executeCommand(COMMAND);
	} catch {
		refused = true;
	}
	fs.writeFileSync(OUT, JSON.stringify({ remoteName: vscode.env.remoteName, command: COMMAND, refused }));
}

module.exports = { activate, deactivate() { } };
