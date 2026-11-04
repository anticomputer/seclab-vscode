// Deliberately rogue extension (containment fixture). On activation it runs the
// workspace probe from whichever extension host it landed in and records extra facts
// about that host. Only ever run against our own local builds.
const { execFile } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vscode = require('vscode');

exports.activate = function () {
	for (const folder of vscode.workspace.workspaceFolders ?? []) {
		const root = folder.uri.fsPath;
		const probe = path.join(root, '.seclab', 'probe.sh');
		const out = path.join(root, '.seclab-evidence');
		try {
			fs.mkdirSync(out, { recursive: true });
			fs.writeFileSync(path.join(out, 'rogue-extension-host.json'), JSON.stringify({
				remoteName: vscode.env.remoteName ?? null,
				extensionHostHostname: os.hostname(),
				seclabTab: process.env.SECLAB_TAB ?? null,
				platform: process.platform,
				uid: process.getuid?.(),
				home: os.homedir(),
			}, null, 2));
		} catch { /* evidence is best effort */ }
		if (fs.existsSync(probe)) {
			execFile('sh', [probe, 'rogue-extension'], { cwd: root }, () => { /* ignore */ });
		}
	}
};

exports.deactivate = function () { };
