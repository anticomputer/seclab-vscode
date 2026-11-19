// Search probe (RPC-LOCKDOWN 7.1, the search restoration). A containment fixture, run only by
// test/containment/search-probe.ts against our own test builds, in a tab.
//
// It calls workspace.findFiles for the run's needle file and records facts only: whether the
// call returned within the bound, how many results, and whether every result is on this
// workspace folder's own scheme and authority, under its path. For patch 0060 (SRCH-3) it also
// records, as booleans, whether this tab sees the host user's canary exclude patterns in its
// configuration, the tab's own workspace exclude (the control), and which of the run's excluded
// files findFiles returns. Without the search restoration the tab's
// search provider registration is denied and the call never returns, which the bound turns
// into a fact. The only file it writes is its marker in its own workspace.
//
// Inert unless armed: the workspace's .seclab/targets must carry this run's nonce, a run
// directory that contains the workspace, and an unexpired `until`.
const fs = require('node:fs');
const path = require('node:path');
const vscode = require('vscode');
const safety = require('./probe-safety.js');

function readTargets(root) {
	let t = '';
	try { t = fs.readFileSync(path.join(root, '.seclab', 'targets'), 'utf8'); } catch { return undefined; }
	const targets = {};
	for (const line of t.split('\n')) {
		const i = line.indexOf('=');
		if (i > 0) { targets[line.slice(0, i)] = line.slice(i + 1); }
	}
	return targets;
}

function armed(root, targets) {
	const run = String(targets.run || '');
	const until = Number(targets.until);
	return /^[0-9a-f]{32}$/.test(String(targets.arm || '')) && run.startsWith('/') && (root + path.sep).startsWith(run + path.sep)
		&& until > Date.now() / 1000;
}

exports.activate = async function () {
	for (const folder of vscode.workspace.workspaceFolders ?? []) {
		const root = folder.uri.fsPath;
		const targets = readTargets(root);
		if (!targets || !armed(root, targets)) {
			continue;
		}
		const ctx = safety.context(targets);
		if (!ctx.armed) {
			continue;
		}
		const out = path.join(root, '.seclab-search');
		const started = Date.now();
		const timeout = new Promise(resolve => setTimeout(() => resolve(undefined), 30000));
		const found = await Promise.race([vscode.workspace.findFiles('**/seclab-needle-*.txt', undefined, 10).then(r => r, () => null), timeout]);
		const facts = {
			returned: Array.isArray(found),
			count: Array.isArray(found) ? found.length : 0,
			// The tab's extension host sees its workspace through the remote URI transformer, so its
			// own results share the folder's scheme and authority and sit under its path.
			ownAuthority: Array.isArray(found) && found.every(u => u.scheme === folder.uri.scheme && u.authority === folder.uri.authority
				&& (u.path + '/').startsWith(folder.uri.path.replace(/\/?$/, '/'))),
			ms: Date.now() - started,
		};
		// Patch 0060 (SRCH-3): the run's file names carry its id, the first 12 hex of the nonce.
		const id = String(targets.arm).slice(0, 12);
		const keys = (section) => Object.keys(vscode.workspace.getConfiguration(section, folder.uri).get('exclude') || {});
		facts.configHostFilesExclude = keys('files').some(k => k.includes(`seclabcanary_hx${id}`));
		facts.configHostSearchExclude = keys('search').some(k => k.includes(`seclabcanary_hs${id}`));
		facts.configTabExclude = keys('files').some(k => k.includes(`seclab-tabexcl-${id}`));
		const others = await Promise.race([vscode.workspace.findFiles(`**/*${id}*`, undefined, 20).then(r => r, () => null), new Promise(resolve => setTimeout(() => resolve(undefined), 30000))]);
		const names = Array.isArray(others) ? others.map(u => path.posix.basename(u.path)) : [];
		facts.excludesReturned = Array.isArray(others);
		facts.foundHostFilesExcluded = names.includes(`seclabcanary_hx${id}.txt`);
		facts.foundTabExcluded = names.includes(`seclab-tabexcl-${id}.txt`);
		try {
			fs.mkdirSync(out, { recursive: true });
			fs.writeFileSync(path.join(out, 'findfiles'), safety.recordJson(facts));
		} catch { /* best effort */ }
	}
};

exports.deactivate = function () { };
