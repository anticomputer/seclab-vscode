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
	const until = Number(get('until'));
	if (!/^[0-9a-f]{32}$/.test(get('arm')) || !run.startsWith('/') || !(root + path.sep).startsWith(run + path.sep)
		|| !(until > Date.now() / 1000)) {
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
		// Values are recorded only when it really runs in a tab (clean env, isolated test
		// profile). If containment failed and it runs on the host, the env and settings are
		// the developer's real ones: record names/presence only, never values (FS-1).
		const inTab = vscode.env.remoteName === 'seclab' && process.env.SECLAB_TAB === '1';
		const observed = inTab ? { inTab, env: process.env } : { inTab, ranOnHost: true, envNames: Object.keys(process.env).sort() };
		const tryGet = async (k, f) => { try { observed[k] = await f(); } catch (e) { observed[k] = `error: ${e?.message ?? e}`; } };
		// Auth sessions: never a raw token, in or out of a tab; only whether one exists and
		// whether it carries a (fake) canary, raw or base64.
		const session = async (id, scopes) => {
			const s = await vscode.authentication.getSession(id, scopes, { silent: true });
			if (!s) {
				return null;
			}
			const t = String(s.accessToken ?? '');
			let decoded = '';
			try { decoded = Buffer.from(t, 'base64').toString('latin1'); } catch { /* not base64 */ }
			return { present: true, account: inTab ? s.account?.label : undefined, tokenLength: t.length, carriesCanary: /seclabcanary_/.test(t) || /seclabcanary_/.test(decoded) };
		};
		if (inTab) {
			await tryGet('configuration', () => JSON.parse(JSON.stringify(vscode.workspace.getConfiguration())));
			if (arm.clipboard) {
				await tryGet('clipboard', () => vscode.env.clipboard.readText());
			}
			await tryGet('ownSecret', () => context.secrets.get('anything'));
		}
		if (inTab) {
			await tryGet('githubSession', () => session('github', ['repo']));
			await tryGet('microsoftSession', () => session('microsoft', ['openid']));
		}
		await tryGet('shellEnv', () => vscode.env.shell);
		try {
			fs.writeFileSync(path.join(out, 'rogue-observed.json'), JSON.stringify(observed, null, 2));
		} catch { /* best effort */ }

		// RPC escape probes. Separate file and separate evidence, because these
		// have a per-build expected outcome (succeed unpatched, denied patched)
		// rather than a fixed assertion.
		try {
			const targets = {};
			for (const line of fs.readFileSync(path.join(root, '.seclab', 'targets'), 'utf8').split('\n')) {
				const i = line.indexOf('=');
				if (i > 0) { targets[line.slice(0, i)] = line.slice(i + 1); }
			}
			const { runProbes } = require('./rpc-probes.js');
			const results = await runProbes(vscode, context, targets);
			fs.writeFileSync(path.join(out, 'rpc-probes.json'), JSON.stringify({
				tab: process.env.SECLAB_TAB_ID ?? process.env.SECLAB_TAB ?? null,
				remoteName: vscode.env.remoteName ?? null,
				results,
			}, null, 2));
		} catch (e) {
			try {
				fs.writeFileSync(path.join(out, 'rpc-probes-error.txt'), String(e?.stack ?? e));
			} catch { /* best effort */ }
		}
	}
};

exports.deactivate = function () { };
