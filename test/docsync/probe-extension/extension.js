// Document-sync probe (test only; test/docsync/probe.ts). Runs in the tab's extension host and
// records which documents the window hands it, while the harness drives host-side actions from the
// trusted window (headless driver). The tab itself only does what a tab may still do: show its own
// file, and attempt the two hijacks (a provider for a host scheme, a model pre-created at a host
// URI), which the RPC filter refuses.
//
// The probe never learns a canary. It hashes every `seclabcanary_ds_…` match it sees, and the
// harness compares the hashes with the canaries it seeded. The report holds scheme names, counts,
// hashes and fixed strings; no contents and no URIs. It is inert unless the workspace was armed by
// a run: per-run nonce, workspace inside that run's dir, unexpired. It writes only under
// <workspace>/.seclab-docsync. It sends nothing over the network.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const vscode = require('vscode');

const TYPED = 'typed-in-window-by-harness';
const EDITED = 'edited-in-window-by-harness';
const CANARY = /seclabcanary_ds_[0-9a-f]{16,64}/g;
const sleep = ms => new Promise(r => setTimeout(r, ms));

function armed(root) {
	let t = '';
	try { t = fs.readFileSync(path.join(root, '.seclab', 'targets'), 'utf8'); } catch { return undefined; }
	const get = k => (t.match(new RegExp(`^${k}=(.*)$`, 'm')) ?? [])[1] ?? '';
	const run = get('run');
	const until = Number(get('until'));
	if (!/^[0-9a-f]{32}$/.test(get('arm')) || !run.startsWith('/') || !(root + path.sep).startsWith(run + path.sep)
		|| !(until > Date.now() / 1000) || !get('hostfile').startsWith(run + path.sep)) {
		return undefined;
	}
	return { arm: get('arm'), hostfile: get('hostfile') };
}

exports.activate = async function () {
	const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
	const t = root && armed(root);
	if (!t) {
		return;
	}
	const out = path.join(root, '.seclab-docsync');
	const ctl = path.join(root, '.seclab');
	fs.mkdirSync(out, { recursive: true });
	const own = vscode.Uri.joinPath(vscode.workspace.workspaceFolders[0].uri, 'tracked.txt');
	const perfUri = vscode.Uri.from({ scheme: 'perf', path: 'Startup Performance' });
	const hostUri = vscode.Uri.from({ scheme: 'vscode-local', path: t.hostfile });
	const report = {
		schema: 'seclab-docsync-report/2', arm: t.arm, done: false, schemes: {}, hits: [], untitledForeign: false,
		hijack: { textProviders: '', fsProviders: '', precreatePerf: '', openHostFile: '', untitledClaims: 0 },
		controls: { ownShown: false, editSeen: false, untitledTyped: false },
	};
	const hits = new Set();
	const write = () => fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify(report));
	const observe = (doc, kind) => {
		const s = doc.uri.scheme.slice(0, 64);
		const c = report.schemes[s] ??= { open: 0, change: 0, close: 0, snapshot: 0 };
		c[kind]++;
		if (kind === 'close') {
			return;
		}
		const text = doc.getText();
		for (const m of text.match(CANARY) ?? []) {
			const sha256 = crypto.createHash('sha256').update(m).digest('hex');
			if (!hits.has(`${s}|${sha256}`)) {
				hits.add(`${s}|${sha256}`);
				report.hits.push({ scheme: s, sha256 });
			}
		}
		if (doc.uri.toString() === own.toString() && text.includes(EDITED)) {
			report.controls.editSeen = true;
		}
		if (s === 'untitled' && text.includes(TYPED)) {
			report.controls.untitledTyped = true;
		}
		// Untitled text the harness didn't type in the window (all of it or, mid-typing, part of it):
		// host-seeded content.
		if (s === 'untitled' && text.trim() && !text.includes(TYPED) && !TYPED.includes(text.trim())) {
			report.untitledForeign = true;
		}
	};
	vscode.workspace.onDidOpenTextDocument(d => observe(d, 'open'));
	vscode.workspace.onDidChangeTextDocument(e => observe(e.document, 'change'));
	vscode.workspace.onDidCloseTextDocument(d => observe(d, 'close'));
	// Bounded: a refused call may never settle.
	const settled = p => Promise.race([Promise.resolve(p).then(() => 'returned', () => 'threw'), sleep(10_000).then(() => 'timeout')]);
	write();

	// Hijack 1: providers for host schemes. The extension host registers them locally and asks the
	// window; the RPC filter refuses the window side (decision log). They serve nothing.
	const decline = { provideTextDocumentContent() { return undefined; } };
	const tried = [];
	for (const scheme of ['output', 'vscode-userdata', 'vscode-local', 'perf']) {
		try { vscode.workspace.registerTextDocumentContentProvider(scheme, decline); tried.push('r'); } catch { tried.push('t'); }
	}
	report.hijack.textProviders = tried.join('');
	const fsTried = [];
	for (const scheme of ['vscode-userdata', 'output']) {
		try {
			const e = new vscode.EventEmitter();
			vscode.workspace.registerFileSystemProvider(scheme, {
				onDidChangeFile: e.event, watch: () => new vscode.Disposable(() => { }),
				stat: () => { throw vscode.FileSystemError.FileNotFound(); }, readDirectory: () => [],
				createDirectory: () => { }, readFile: () => new Uint8Array(), writeFile: () => { },
				delete: () => { }, rename: () => { },
			});
			fsTried.push('r');
		} catch {
			fsTried.push('t');
		}
	}
	report.hijack.fsProviders = fsTried.join('');
	// Hijack 2: a model at a host URI, which host code would reuse (perf:), and a host file by its
	// window URI. Both are window-side opens, which the filter limits to the tab's own resources.
	report.hijack.precreatePerf = await settled(vscode.workspace.openTextDocument(perfUri));
	report.hijack.openHostFile = await settled(vscode.workspace.openTextDocument(hostUri));
	// Its own file, shown in the window: the harness types into it there and saves (control).
	try {
		await vscode.window.showTextDocument(own, { preview: false });
		report.controls.ownShown = true;
	} catch { /* reported as a failed control */ }
	write();
	fs.writeFileSync(path.join(out, 'ready'), '');

	let claimed = false;
	for (let i = 0; i < 900 && !fs.existsSync(path.join(ctl, 'stop')); i++) {
		// After the window opened a host-seeded untitled document: try to claim untitled models by URI.
		if (!claimed && fs.existsSync(path.join(ctl, 'claim'))) {
			claimed = true;
			for (let n = 1; n <= 6; n++) {
				await settled(vscode.workspace.openTextDocument(vscode.Uri.from({ scheme: 'untitled', path: `Untitled-${n}` })));
				report.hijack.untitledClaims++;
			}
		}
		await sleep(500);
		if (i % 4 === 0) {
			for (const doc of vscode.workspace.textDocuments) {
				observe(doc, 'snapshot');
			}
			write();
		}
	}
	for (const doc of vscode.workspace.textDocuments) {
		observe(doc, 'snapshot');
	}
	report.done = true;
	write();
};
