// The takeover's host inside the tab. It exists so that the REH starts it, not the harness:
// the tab is restarted during a run, and every host-side way of restarting the takeover was
// worse (an `sbx exec` loop during the editor's tab startup makes `tab.ensureRunning` fail
// with "collector: workspace overlay not mounted", and a workspace heartbeat is invisible to
// the host because the tab's workspace is an overlay). An extension is restarted by the REH
// automatically, so no host polling and no liveness signal are needed at all.
//
// Inert by construction (EDR fixture safety): it does nothing unless the harness wrote this
// run's config, with a nonce that also reaches it out of band, and it touches only paths
// inside the run directory.

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { fork } = require('node:child_process');

/** The run config the harness drops next to the extension when it packages it. */
function readConfig(extensionPath) {
	const p = path.join(extensionPath, 'mitm.json');
	return fs.existsSync(p) ? { path: p, cfg: JSON.parse(fs.readFileSync(p, 'utf8')) } : undefined;
}

function activate(context) {
	const found = readConfig(context.extensionPath);
	if (!found) {
		return; // not a probe run: do nothing at all
	}
	const { cfg } = found;
	// The agent host runs under the REH's own node, which is also what runs this extension
	// host, so `process.execPath` is the right interpreter and needs no path of its own.
	const child = fork(path.join(context.extensionPath, 'mitm.js'), [found.path, cfg.arm], {
		detached: false,
		stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
	});
	context.subscriptions.push({ dispose: () => child.kill() });
}

function deactivate() { }

module.exports = { activate, deactivate };
