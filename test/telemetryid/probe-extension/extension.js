// Telemetry-id probe (test only; test/telemetryid/probe.ts). Runs in the tab's extension host and
// reports what identifies the machine to it: SHA-256 hashes of vscode.env.machineId and sessionId,
// and their shape. Never the values. Inert unless the workspace was armed by a run. Writes only
// under <workspace>/.seclab-telemetryid. Sends nothing over the network.

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

const shape = v => String(v).replace(/[0-9a-f]/g, 'h').replace(/[A-F]/g, 'H').replace(/[g-zG-Z]/g, 'x').slice(0, 120);
const hash = v => crypto.createHash('sha256').update(String(v)).digest('hex');

exports.activate = function () {
	const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
	const t = root && armed(root);
	if (!t) {
		return;
	}
	const out = path.join(root, '.seclab-telemetryid');
	fs.mkdirSync(out, { recursive: true });
	const report = {
		schema: 'seclab-telemetryid-report/1', arm: t.arm,
		machineId: { sha256: hash(vscode.env.machineId), shape: shape(vscode.env.machineId) },
		sessionId: { sha256: hash(vscode.env.sessionId), shape: shape(vscode.env.sessionId) },
	};
	fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify(report));
};
