// Settings-withheld probe (EDR settings-withheld-notice): a tab extension forging the call 0036
// makes. It only calls one command in the editor and records each call's outcome in the tab's
// own /tmp. Inert unless the run armed it (.seclab/withheld-arm in the workspace, unexpired).
'use strict';

const fs = require('fs');
const path = require('path');
const vscode = require('vscode');

const COMMAND = 'seclab.tabs.settingsWithheld';
const MARKER = 'seclabSettingsWithheld:v1';
const OUT = '/tmp/seclab-withheld-forger.json';

function armed() {
	const folder = vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders[0];
	if (!folder) {
		return false;
	}
	try {
		const arm = fs.readFileSync(path.join(folder.uri.fsPath, '.seclab', 'withheld-arm'), 'utf8');
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
	const own = vscode.workspace.workspaceFolders[0].uri.authority; // env.remoteAuthority is a proposed API
	const forged = {
		'not-in-host-settings': { v: MARKER, authority: own, settings: [{ key: 'seclabProbe.forgedToken', reason: 'credential-name' }] },
		'host-setting-not-a-credential': { v: MARKER, authority: own, settings: [{ key: 'workbench.startupEditor', reason: 'credential-name' }] },
		'another-tab': { v: MARKER, authority: 'seclab+t-zzzzzzzzzzzzzzzzzzzzzzzzzz', settings: [{ key: 'seclabProbe.apiToken', reason: 'credential-name' }] },
		'hostile-text': { v: MARKER, authority: own, settings: [{ key: 'seclab\u202eProbe[open](command:seclab.tabs.stop).token', reason: 'credential-name' }] },
		'flood': { v: MARKER, authority: own, settings: Array.from({ length: 64 }, (_, i) => ({ key: `seclabProbe.flood${i}.token`, reason: 'credential-name' })) },
	};
	const results = {};
	// Whether 0036 kept the canary out of this tab's configuration: a yes/no, never the value.
	const v = vscode.workspace.getConfiguration('seclabProbe').get('apiToken');
	const canaryVisible = typeof v === 'string' && v.startsWith('seclabcanary_');
	for (const [name, payload] of Object.entries(forged)) {
		try {
			const r = await vscode.commands.executeCommand(COMMAND, payload);
			results[name] = { sent: true, returned: r === undefined ? 'undefined' : typeof r };
		} catch (e) {
			results[name] = { sent: false, error: String(e && e.message || e).slice(0, 200) };
		}
	}
	fs.writeFileSync(OUT, JSON.stringify({ remoteName: vscode.env.remoteName, canaryVisible, results }));
}

module.exports = { activate, deactivate() { } };
