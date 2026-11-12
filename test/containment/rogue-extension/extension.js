// Deliberately rogue extension (containment fixture). On activation it runs the
// workspace probe from whichever extension host it landed in and records extra facts
// about that host. Only ever run against our own local builds.
// Fixture safety (EDR fixture-safety): inert unless the workspace was armed by a harness
// run (per-run nonce in .seclab/targets, workspace inside that run's dir); reads only
// what the isolated test profile holds, and the clipboard only through the test build's
// in-memory canary clipboard. Every record it writes holds facts, never values
// (probe-safety.js, run records).
const fs = require('node:fs');
const path = require('node:path');
const vscode = require('vscode');
const safety = require('./probe-safety.js');

function readTargets(root) {
	let t = '';
	try { t = fs.readFileSync(path.join(root, '.seclab', 'targets'), 'utf8'); } catch { return undefined; }
	const targets = {};
	for (const line of t.split('\n')) {
		const i = line.indexOf('=');
		if (i > 0) { targets[line.slice(0, i)] = line.slice(i + 1); }
	}
	return targets;
}

function armed(root, targets) {
	const run = String(targets.run || '');
	const until = Number(targets.until);
	return /^[0-9a-f]{32}$/.test(String(targets.arm || '')) && run.startsWith('/') && (root + path.sep).startsWith(run + path.sep)
		&& until > Date.now() / 1000;
}

exports.activate = async function (context) {
	for (const folder of vscode.workspace.workspaceFolders ?? []) {
		const root = folder.uri.fsPath;
		const targets = readTargets(root);
		if (!targets || !armed(root, targets)) {
			continue;
		}
		const ctx = safety.context(targets);
		if (!ctx.armed) {
			continue;
		}
		const out = path.join(root, '.seclab-evidence');
		const inTab = vscode.env.remoteName === 'seclab' && process.env.SECLAB_TAB === '1';
		const write = (name, value) => {
			try {
				fs.mkdirSync(out, { recursive: true });
				fs.writeFileSync(path.join(out, name), safety.recordJson(value));
			} catch { /* evidence is best effort; an unrecordable value writes nothing */ }
		};
		// Where it ran, as facts. Never the hostname, home or environment: if containment
		// failed this runs on the host and those are the user's.
		write('rogue-extension-host.json', {
			remoteNameIsSeclab: vscode.env.remoteName === 'seclab',
			seclabTab: process.env.SECLAB_TAB === '1',
			linux: process.platform === 'linux',
			uid: typeof process.getuid === 'function' ? process.getuid() : null,
		});
		// NOTE: probe.sh is deliberately not spawned from here. It makes external
		// network calls and writes an unconstrained marker, and on an unpatched
		// build this extension can land host-side. The Level-A runner triggers it
		// inside the tab, which is where it belongs.
		// What this extension can observe through the API, for the canary harness: per
		// source, whether it was readable and which canary tokens it held. Never a value.
		const observed = { inTab };
		const observe = async (k, f) => {
			try {
				const v = await f();
				observed[k] = { readable: true, canaryTokens: safety.canaryTokens(v === undefined ? null : v) };
			} catch {
				observed[k] = { readable: false };
			}
		};
		const session = async (id, scopes) => {
			const s = await vscode.authentication.getSession(id, scopes, { silent: true });
			return s ? String(s.accessToken || '') : null;
		};
		await observe('env', () => process.env);
		await observe('configuration', () => vscode.workspace.getConfiguration());
		if (ctx.canaryClipboard) {
			try {
				observed.canaryClipboard = { readable: true, ...await safety.withCanaryClipboard(ctx, () => vscode.env.clipboard.readText()) };
			} catch {
				observed.canaryClipboard = { readable: false };
			}
		}
		await observe('ownSecret', () => context.secrets.get('anything'));
		await observe('githubSession', () => session('github', ['repo']));
		await observe('microsoftSession', () => session('microsoft', ['openid']));
		await observe('shellEnv', () => vscode.env.shell);
		write('rogue-observed.json', observed);

		// Agent surfaces (no trusted-side extension agents in tab windows): this ui-declared
		// extension registers a chat participant and calls vscode.lm. Placement is decided
		// before activation (product extensionKind '*' -> workspace), so this code must be
		// running in the tab. Facts only: counts and outcomes.
		const agent = { ranInTab: inTab, remoteNameIsSeclab: vscode.env.remoteName === 'seclab' };
		try {
			if (vscode.chat && vscode.chat.createChatParticipant) {
				context.subscriptions.push(vscode.chat.createChatParticipant('seclab-test.rogue-agent', () => ({})));
				agent.chatParticipant = safety.lit('registered');
			} else {
				agent.chatParticipant = safety.lit('unavailable');
			}
		} catch {
			agent.chatParticipant = safety.lit('error');
		}
		try {
			agent.lmModels = vscode.lm && vscode.lm.selectChatModels ? (await vscode.lm.selectChatModels({})).length : null;
		} catch {
			agent.lmModels = null;
		}
		agent.lmTools = vscode.lm && Array.isArray(vscode.lm.tools) ? vscode.lm.tools.length : null;
		write('rogue-agent.json', agent);

		// RPC escape probes. Separate file and separate evidence, because these
		// have a per-build expected outcome (succeed unpatched, denied patched)
		// rather than a fixed assertion.
		try {
			targets.armingFile = path.join(root, '.seclab', 'probe-arming.json');
			const { runProbes, runRestartProbe, restartAttempted } = require('./rpc-probes.js');
			const restartFile = path.join(out, 'rpc-probe-restart.json');
			// An activation after the restart probe ran is the restarted host (or a later
			// window reload): never rerun the battery, only settle the restart outcome.
			if (!restartAttempted(restartFile, fs)) {
				write('rpc-probes.json', { inTab, results: await runProbes(vscode, context, targets) });
			}
			// Last, in its own record (check-probes merges it): on a build without the
			// filter this restarts the extension host running it.
			await runRestartProbe(vscode, targets, restartFile, fs);
		} catch {
			write('rpc-probes-error.json', { error: safety.lit('the probe runner threw') });
		}
	}
};

exports.deactivate = function () { };
