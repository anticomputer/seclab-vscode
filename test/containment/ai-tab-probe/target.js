// The tab-side probe's one target (review AIP-2). It comes from the run record the harness packaged
// into this extension on the host (run.json), never from the workspace: the workspace's targets
// file is tab-writable, so it may only confirm the run (its nonce must match), not name the port.
'use strict';

function tabToolUrl(run, targets) {
	if (!run || typeof run !== 'object' || !/^[0-9a-f]{32}$/.test(String(run.nonce ?? '')) || !targets || targets.arm !== run.nonce) {
		return undefined;
	}
	const port = run.port;
	if (!Number.isSafeInteger(port) || port < 1024 || port > 65535) {
		return undefined;
	}
	return `http://127.0.0.1:${port}/ai-tabtool-${run.nonce}`;
}

module.exports = { tabToolUrl };
