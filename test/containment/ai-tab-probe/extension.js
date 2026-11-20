// Tab-side tool call probe (agent-host-patches#3, arm B): an extension in the tab's extension host
// asks the window to run its built-in fetch tool (vscode.lm.invokeTool) on the run's loopback
// beacon. A containment fixture, run only by test/containment/ai-probe.ts against our own test
// builds, in a tab.
//
// The tab's call crosses the RPC boundary as MainThreadLanguageModelTools.$invokeTool (wire sid
// MainThreadChatSkills), which the
// filter denies; patch 0009 refuses invokeTool behind it. Whether the fetch ran is read on the host
// (the beacon), and the refusal from the window's decision log: what this writes is the tab's own
// claim, facts only (probe-safety.js), never judged.
//
// Inert unless armed: the workspace's .seclab/targets must carry this run's nonce, a run directory
// that contains the workspace and an unexpired `until`; the nonce and the beacon port it may call
// come from run.json, which the harness packages into this extension on the host (review AIP-2).
const fs = require('node:fs');
const path = require('node:path');
const vscode = require('vscode');
const safety = require('./probe-safety.js');
const { tabToolUrl } = require('./target.js');

const FETCH_TOOL = 'vscode_fetchWebPage_internal';

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

exports.activate = async function () {
	for (const folder of vscode.workspace.workspaceFolders ?? []) {
		const root = folder.uri.fsPath;
		const targets = readTargets(root);
		if (!targets || !armed(root, targets)) {
			continue;
		}
		const ctx = safety.context(targets);
		let run;
		try {
			run = JSON.parse(fs.readFileSync(path.join(__dirname, 'run.json'), 'utf8'));
		} catch {
			continue;
		}
		const target = tabToolUrl(run, targets);
		if (!ctx.armed || !target) {
			continue;
		}
		// The beacon's port pins safeUrl too, from the packaged record (never the workspace).
		ctx.beaconPort = run.port;
		const url = safety.safeUrl(ctx, target, 'tab tool call');
		const mark = facts => {
			try {
				fs.mkdirSync(path.join(root, '.seclab-ai-tab'), { recursive: true });
				fs.writeFileSync(path.join(root, '.seclab-ai-tab', 'invoke.json'), safety.recordJson(facts));
			} catch { /* best effort */ }
		};
		// Let the window finish restoring first; the call is made once.
		await new Promise(r => setTimeout(r, 5000));
		const visible = vscode.lm.tools.some(t => t.name === FETCH_TOOL);
		try {
			await vscode.lm.invokeTool(FETCH_TOOL, { input: { urls: [url] }, toolInvocationToken: undefined });
			mark({ attempted: true, toolVisible: visible, returned: true, refused: false });
		} catch (err) {
			const msg = String((err && err.message) || err);
			mark({ attempted: true, toolVisible: visible, returned: false, refused: /seclab: denied|not allowed in a sandboxed|unsupported operation/i.test(msg) });
		}
	}
};

exports.deactivate = function () { };
