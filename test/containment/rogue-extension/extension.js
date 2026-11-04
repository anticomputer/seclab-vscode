// Deliberately rogue extension (containment fixture). On activation it runs the
// workspace probe from whichever extension host it landed in and records extra facts
// about that host. Only ever run against our own local builds.
// Fixture safety (EDR fixture-safety): inert unless the workspace was armed by a harness
// run (per-run nonce in .seclab/targets, workspace inside that run's dir); reads only
// what the isolated test profile holds, and the clipboard only when the run opted in.
const { execFile } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vscode = require('vscode');

function armed(root) {
	let t = '';
	try { t = fs.readFileSync(path.join(root, '.seclab', 'targets'), 'utf8'); } catch { return undefined; }
	const get = k => (t.match(new RegExp(`^${k}=(.*)$`, 'm')) ?? [])[1] ?? '';
	const run = get('run');
	if (!/^[0-9a-f]{32}$/.test(get('arm')) || !run || !(root + path.sep).startsWith(run + path.sep)) {
		return undefined;
	}
	return { clipboard: get('clipboard') === '1' };
}

exports.activate = async function (context) {
	for (const folder of vscode.workspace.workspaceFolders ?? []) {
		const root = folder.uri.fsPath;
		const arm = armed(root);
		if (!arm) {
			continue;
		}
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
		// Everything this extension can observe through the API, for the canary harness.
		const observed = { env: process.env };
		const tryGet = async (k, f) => { try { observed[k] = await f(); } catch (e) { observed[k] = `error: ${e?.message ?? e}`; } };
		await tryGet('configuration', () => JSON.parse(JSON.stringify(vscode.workspace.getConfiguration())));
		if (arm.clipboard) {
			await tryGet('clipboard', () => vscode.env.clipboard.readText());
		}
		await tryGet('githubSession', () => vscode.authentication.getSession('github', ['repo'], { silent: true }));
		await tryGet('microsoftSession', () => vscode.authentication.getSession('microsoft', ['openid'], { silent: true }));
		await tryGet('ownSecret', () => context.secrets.get('anything'));
		await tryGet('shellEnv', () => vscode.env.shell);
		try {
			fs.writeFileSync(path.join(out, 'rogue-observed.json'), JSON.stringify(observed, null, 2));
		} catch { /* best effort */ }
	}
};

exports.deactivate = function () { };
