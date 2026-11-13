// Configuration-snapshot probe (test only; test/configsync/probe.ts). Runs in the tab's extension
// host and records what host settings it can see through the configuration API: the whole
// snapshot, `inspect()` of the keys the harness seeded, and again after a host settings change
// (the `$acceptConfigurationChanged` path). It never learns a canary: it reports hashes of every
// `seclabcanary_cf_…` it finds, in raw, URL-decoded or base64-decoded text, plus setting names (never
// values) of the snapshot it received. Inert unless the workspace was armed by a run. Writes only
// under <workspace>/.seclab-configsync. Sends nothing over the network.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const vscode = require('vscode');

const CANARY = /seclabcanary_cf_[0-9a-f]{16,64}/g;
const KEYS = ['seclabProbe.undeclared', 'http.proxyAuthorization', 'seclabProbe.password', 'seclabProbe.endpointValue', 'seclabProbe.color', 'editor.tabSize', 'seclabProbe.detect', 'seclabProbe.toolsEnv', 'remote', 'seclabProbe.label'];
const sleep = ms => new Promise(r => setTimeout(r, ms));

function armed(root) {
	let t = '';
	try { t = fs.readFileSync(path.join(root, '.seclab', 'targets'), 'utf8'); } catch { return undefined; }
	const get = k => (t.match(new RegExp(`^${k}=(.*)$`, 'm')) ?? [])[1] ?? '';
	const run = get('run');
	if (!/^[0-9a-f]{32}$/.test(get('arm')) || !run.startsWith('/') || !(root + path.sep).startsWith(run + path.sep) || !(Number(get('until')) > Date.now() / 1000)) {
		return undefined;
	}
	return { arm: get('arm') };
}

function leafNames(value, prefix, out) {
	if (value && typeof value === 'object' && !Array.isArray(value)) {
		for (const [k, v] of Object.entries(value)) {
			if (typeof v !== 'function') {
				leafNames(v, prefix ? `${prefix}.${k}` : k, out);
			}
		}
	} else if (prefix) {
		out.add(prefix);
	}
}

function decodings(text) {
	const out = [text];
	try { out.push(decodeURIComponent(text)); } catch { /* not encoded */ }
	for (const m of text.match(/[A-Za-z0-9+/]{24,}={0,2}/g) ?? []) {
		try { out.push(Buffer.from(m, 'base64').toString('latin1')); } catch { /* not base64 */ }
	}
	return out;
}

exports.activate = async function () {
	const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
	const t = root && armed(root);
	if (!t) {
		return;
	}
	const out = path.join(root, '.seclab-configsync');
	fs.mkdirSync(out, { recursive: true });
	const report = { schema: 'seclab-configsync-report/1', arm: t.arm, done: false, hits: [], keys: [], controls: { tabSizeInitial: false, colorInitial: false, changeSeen: false } };
	const seen = new Set();
	const scan = phase => {
		const config = vscode.workspace.getConfiguration();
		const parts = [JSON.stringify(config)];
		for (const k of KEYS) {
			parts.push(JSON.stringify(config.inspect(k) ?? null));
			parts.push(JSON.stringify(config.get(k) ?? null));
		}
		for (const text of decodings(parts.join('\n'))) {
			for (const m of text.match(CANARY) ?? []) {
				const sha256 = crypto.createHash('sha256').update(m).digest('hex');
				if (!seen.has(`${phase}|${sha256}`)) {
					seen.add(`${phase}|${sha256}`);
					report.hits.push({ phase, sha256 });
				}
			}
		}
		return config;
	};
	const write = () => fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify(report));

	// Scan at once (a start-up leak can be replaced quickly) and on every change from the start.
	scan('initial');
	let resolveChanged;
	const changed = new Promise(resolve => { resolveChanged = resolve; });
	vscode.workspace.onDidChangeConfiguration(() => {
		const c = scan(fs.existsSync(path.join(out, 'ready-change')) ? 'after-change' : 'initial');
		if (c.get('editor.tabSize') === 9) {
			report.controls.changeSeen = true;
			resolveChanged();
		}
	});
	for (let i = 0; i < 12; i++) {
		await sleep(500);
		scan('initial');
	}
	const initial = scan('initial');
	report.controls.tabSizeInitial = initial.get('editor.tabSize') === 7;
	report.controls.colorInitial = initial.get('seclabProbe.color') === 'teal';
	const names = new Set();
	leafNames(JSON.parse(JSON.stringify(initial)), '', names);
	report.keys = [...names].sort().slice(0, 20000);
	write();

	// The host changes its settings now (harness `seed`).
	fs.writeFileSync(path.join(out, 'ready-change'), '');
	await Promise.race([changed, sleep(120000)]);
	await sleep(5000);
	scan('after-change');
	report.done = true;
	write();
};
