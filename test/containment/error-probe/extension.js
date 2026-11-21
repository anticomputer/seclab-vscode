// Error probe (review AIP-4). A containment fixture, run only by test/containment/error-probe.ts
// against our own test builds, in a tab.
//
// It makes three calls the trusted window answers with an error: one the RPC filter refuses
// outright (`commands.getCommands`, $getCommands), one it refuses by command verdict (an
// unregistered command through $executeCommand), and an ordinary failure upstream raises for an
// allowed call (opening a missing file of the tab's own workspace, $tryOpenDocument), the control.
// Each error's stack, as the tab received it, goes to this extension's own log, the tab's log the
// harness reads, as an extension logging its failures would. The marker records facts only:
// whether each call failed, whether a refusal says "Unsupported operation", whether the control's
// message names its file, whether the stack is one line, and the canary tokens in it (the harness
// puts one in the host app's install path).
//
// Inert unless armed: the workspace's .seclab/targets must carry this run's nonce, a run
// directory that contains the workspace, and an unexpired `until`. It writes only its marker in
// its own workspace; nothing it calls changes anything.
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

exports.activate = async function () {
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
		const id = String(targets.arm).slice(0, 12);
		const log = vscode.window.createOutputChannel('seclab error probe', { log: true });
		const bounded = (p) => Promise.race([Promise.resolve(p).then(() => ({ ok: true }), e => ({ ok: false, e })), new Promise(resolve => setTimeout(() => resolve({ ok: true, timedOut: true }), 30000))]);
		const facts = {};
		const observe = async (key, call) => {
			const r = await bounded(call());
			const e = r.e;
			const stack = String(e && e.stack);
			const message = String(e && e.message);
			if (!r.ok) {
				log.error(`${key} failed; the stack the tab received:\n${stack}`);
			}
			facts[key] = {
				failed: !r.ok,
				timedOut: r.timedOut === true,
				unsupported: message === 'Unsupported operation',
				namesItsFile: message.includes(`missing-${id}.txt`),
				oneLineStack: !r.ok && stack === `${e.name}: ${message}`,
				stackLines: !r.ok ? stack.split('\n').length : 0,
				stackCanaries: safety.canaryTokens(stack),
			};
		};
		await observe('denyRpc', () => vscode.commands.getCommands());
		await observe('denyCommand', () => vscode.commands.executeCommand(`seclab-error-probe.none-${id}`));
		await observe('control', () => vscode.workspace.openTextDocument(folder.uri.with({ path: `${folder.uri.path}/missing-${id}.txt` })));
		try {
			const out = path.join(root, '.seclab-errors');
			fs.mkdirSync(out, { recursive: true });
			fs.writeFileSync(path.join(out, 'facts'), safety.recordJson(facts));
		} catch { /* best effort */ }
	}
};

exports.deactivate = function () { };
