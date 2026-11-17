// Response-side probe (ADR 20261116-response-side-control). A containment fixture, run only by
// test/containment/response-probe.ts against our own test builds, in a tab.
//
// It returns data, never calls anything: a completion item whose command, and a hover whose
// `command:` link, name `workbench.action.terminal.newLocal` (a host shell when the trusted side
// runs it), and the same pair naming this extension's own command (the positive control, which
// must run in the tab). Whether anything runs is decided by the window when the harness accepts
// the item or clicks the link. The only file it writes is a marker in its own workspace when its
// own command runs, holding facts only (probe-safety.js).
//
// Two more vectors (review RSC-1, RSC-2), each needing only data:
// - a completion item inserted as a snippet naming the CLIPBOARD variable, offered only when the
//   harness verified the app's in-memory canary store (the system one is never read). After the
//   item is accepted, the text the window inserted is read back through
//   safety.withCanaryClipboard, which records only whether a canary token is in it;
// - hover images in three forms (plain, nested, inside a <span> HTML block), each naming its own
//   loopback port from the targets file. The harness counts TCP connections on each.
//
// Inert unless armed: the workspace's .seclab/targets must carry this run's nonce, a run
// directory that contains the workspace, and an unexpired `until`.
const fs = require('node:fs');
const path = require('node:path');
const vscode = require('vscode');
const safety = require('./probe-safety.js');

const HOST_COMMAND = 'workbench.action.terminal.newLocal';
const OWN_COMMAND = 'seclab-test.responseProbe.own';

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

exports.activate = async function (context) {
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
		const out = path.join(root, '.seclab-response');
		const mark = (name, facts) => {
			try {
				fs.mkdirSync(out, { recursive: true });
				fs.writeFileSync(path.join(out, name), safety.recordJson(facts));
			} catch { /* best effort */ }
		};
		context.subscriptions.push(vscode.commands.registerCommand(OWN_COMMAND, (via) => {
			mark(via === 'hover' ? 'own-hover' : 'own-completion', { ran: true, inTab: process.env.SECLAB_TAB === '1' });
		}));
		const selector = { language: 'plaintext' };
		const ports = ['img1', 'img2', 'img3'].map(k => Number(targets[k])).filter(p => Number.isSafeInteger(p) && p > 1024 && p < 65536);
		const images = ports.length === 3 ? [
			`![a](https://127.0.0.1:${ports[0]}/a.png)`,
			`![x![]y](https://127.0.0.1:${ports[1]}/b.png)`,
			`<span x>\n<img src="https://127.0.0.1:${ports[2]}/c.png">\n</span>`,
		].join('\n\n') : '';
		const SNIPPET_LABEL = 'seclabSnippetCommand';
		if (ctx.canaryClipboard) {
			context.subscriptions.push(vscode.languages.registerCompletionItemProvider(selector, {
				provideCompletionItems() {
					const item = new vscode.CompletionItem(SNIPPET_LABEL, vscode.CompletionItemKind.Snippet);
					item.insertText = new vscode.SnippetString('<${CLIPBOARD}>');
					item.preselect = true;
					return [item];
				},
			}, '%'));
			context.subscriptions.push(vscode.workspace.onDidChangeTextDocument(async e => {
				if (!e.document.uri.path.endsWith('/probe.txt') || !e.contentChanges.some(c => c.text.startsWith('<') && c.text.endsWith('>'))) {
					return;
				}
				const inserted = e.contentChanges.map(c => c.text).join('');
				const seen = await safety.withCanaryClipboard(ctx, async () => inserted);
				mark('snippet', { sawCanary: seen.sawCanary, literalVariable: inserted.includes('${CLIPBOARD}') });
			}));
		}
		context.subscriptions.push(vscode.languages.registerCompletionItemProvider(selector, {
			provideCompletionItems(_doc, _pos, _token, completion) {
				const own = completion.triggerCharacter === '#';
				const item = new vscode.CompletionItem(own ? 'seclabOwnCommand' : 'seclabHostCommand', vscode.CompletionItemKind.Text);
				item.insertText = '';
				item.preselect = true;
				item.command = own ? { command: OWN_COMMAND, title: 'own', arguments: ['completion'] } : { command: HOST_COMMAND, title: 'host' };
				return [item];
			},
		}, '@', '#'));
		context.subscriptions.push(vscode.languages.registerHoverProvider(selector, {
			provideHover() {
				const md = new vscode.MarkdownString(`seclab-response-probe [hostlink](command:${HOST_COMMAND}) [ownlink](command:${OWN_COMMAND}?${encodeURIComponent(JSON.stringify(['hover']))})\n\n${images}`);
				md.isTrusted = true;
				return new vscode.Hover(md);
			},
		}));
		const doc = vscode.Uri.joinPath(folder.uri, 'probe.txt');
		await vscode.window.showTextDocument(doc).then(undefined, () => undefined);
		mark('ready', { ready: true });
	}
};

exports.deactivate = function () { };
