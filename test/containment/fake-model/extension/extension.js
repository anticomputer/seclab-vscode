// SECLAB_TEST_ONLY:fake-model
//
// A scripted language model and default chat participant: the window's stand-in for an agent such
// as Copilot Chat, which this build doesn't ship. Built only into the `containment` test variant
// (test/builds/variants.json, hook `fake-model`); check-release refuses any artifact carrying the
// marker above, and the release product.json grants no extension the defaultChatParticipant
// proposal.
//
// What it does, and only when a harness run has armed it:
//   - the participant reads the instruction files core attached to the request (references) as
//     DATA, and only those in a seclab tab's workspace or the test profile (never the user's real
//     home). A file "matches" only if it holds, as a whole line, one of the exact canary lines the
//     run armed, each carrying the run's nonce. Nothing in the text is followed: the matched line
//     only selects one of the actions the run armed, and the action's URL comes from the arming
//     record, never from the text;
//   - the action is one call of the built-in fetch tool, on the run's loopback beacon
//     (http://127.0.0.1:<port>/ai-<window>-<nonce>);
//   - a trigger file the harness writes makes the window open chat with a fixed query, so the
//     harness decides which window asks and when.
// It writes facts (booleans and counts) to its own storage in the test profile. The model never
// contacts anything: its reply is a fixed string. Unarmed (no arming record, a malformed or
// expired one, or a profile outside ~/.seclab-test or .work), it registers and does nothing else.

'use strict';

const fs = require('fs');
const path = require('path');

const MARKER = 'SECLAB_TEST_ONLY:fake-model';
const FETCH_TOOL = 'vscode_fetchWebPage_internal';
const NONCE = /^[0-9a-f]{32}$/;
const KINDS = ['ordinary', 'tab'];
const MAX_TEXT = 64 * 1024;
const MAX_ARM_SECONDS = 3600;
/** The settings a tab writes to switch the built-in chat back on (ai-settings-reenable). */
const REENABLE_KEYS = ['chat.agent.enabled', 'chat.disableAIFeatures', 'chat.extensionTools.enabled', 'chat.tools.global.autoApprove'];

/** A harness-made test profile: never arm in a real one. */
function isTestProfile(dir) {
	return typeof dir === 'string' && path.isAbsolute(dir) && /\/(\.seclab-test|\.work)\//.test(dir + '/') && !dir.includes('..');
}

/**
 * The arming record, validated: `{ nonce, until, actions: [{ window, line, url }] }`, or
 * `{ reason }` when it can't arm. Every action's URL is the run's loopback beacon, on a path that
 * names the window and the nonce; every line carries the nonce.
 */
function parseArm(text, nowSec) {
	let a;
	try {
		a = JSON.parse(text);
	} catch {
		return { reason: 'not JSON' };
	}
	if (!a || typeof a !== 'object' || !NONCE.test(a.nonce ?? '')) {
		return { reason: 'no nonce' };
	}
	if (typeof a.until !== 'number' || !(a.until > nowSec) || a.until > nowSec + MAX_ARM_SECONDS) {
		return { reason: 'expired or unbounded' };
	}
	if (!Array.isArray(a.actions) || a.actions.length < 1 || a.actions.length > 4) {
		return { reason: 'no actions' };
	}
	const actions = [];
	for (const x of a.actions) {
		if (!x || !KINDS.includes(x.window)) {
			return { reason: 'bad window' };
		}
		if (typeof x.line !== 'string' || x.line.length > 200 || /[\r\n]/.test(x.line) || !x.line.includes(a.nonce) || x.line.trim() !== x.line) {
			return { reason: 'bad line' };
		}
		const m = typeof x.url === 'string' ? x.url.match(/^http:\/\/127\.0\.0\.1:(\d{4,5})\/ai-([a-z]+)-([0-9a-f]{32})$/) : null;
		if (!m || Number(m[1]) < 1024 || Number(m[1]) > 65535 || m[3] !== a.nonce || m[2] !== (x.window === 'ordinary' ? 'ord' : 'tab')) {
			return { reason: 'bad url' };
		}
		actions.push({ window: x.window, line: x.line, url: x.url });
	}
	return { nonce: a.nonce, until: a.until, actions };
}

/** A trigger's sequence number: `<nonce> <n>` for this run's nonce and 1 <= n <= 1000, else 0. */
function triggerSeq(text, nonce) {
	const m = typeof text === 'string' ? text.match(/^([0-9a-f]{32}) ([1-9][0-9]{0,2}|1000)$/) : null;
	return m && m[1] === nonce ? Number(m[2]) : 0;
}

/** Which kind of window this extension host serves: a seclab tab window, an ordinary one, or neither. */
function windowKind(remoteName) {
	if (remoteName === undefined || remoteName === null || remoteName === '') {
		return 'ordinary';
	}
	return remoteName === 'seclab' ? 'tab' : null;
}

/**
 * Whether a referenced file may be read: one in a seclab tab's workspace, or one under the test
 * profile's User directory. Anything else (instructions in the user's real home, such as
 * ~/.copilot/instructions, which core also attaches) is never opened.
 */
function mayRead(uri, userDir) {
	if (!uri || typeof uri.scheme !== 'string') {
		return false;
	}
	if (uri.scheme === 'vscode-remote') {
		return typeof uri.authority === 'string' && uri.authority.startsWith('seclab+');
	}
	if (uri.scheme === 'file' || uri.scheme === 'vscode-userdata') {
		const p = path.posix.normalize(uri.path ?? '');
		return isTestProfile(userDir) && p.startsWith(userDir + '/') && !p.includes('/../');
	}
	return false;
}

/** The armed action for this window whose exact line one of the texts holds as a whole line. */
function selectAction(arm, kind, texts) {
	for (const action of arm.actions) {
		if (action.window !== kind) {
			continue;
		}
		for (const t of texts) {
			if (typeof t === 'string' && t.split('\n').some(l => l.replace(/\r$/, '').trim() === action.line)) {
				return action;
			}
		}
	}
	return undefined;
}

function activate(context) {
	const vscode = require('vscode');
	const dir = context.globalStorageUri.fsPath;
	// globalStorage/<extension id> is under the profile's User directory.
	const userDir = path.resolve(dir, '..', '..');
	const kind = windowKind(vscode.env.remoteName);
	const facts = { marker: MARKER, kind: kind ?? 'other', armed: false, triggered: 0, triggerFailed: false, requests: 0, references: 0, referencesRead: 0, referencesSkipped: 0, matched: false, fetchToolVisible: false, invoked: false, invokeOk: false, invokeRefused: false, invokeOtherError: false, modelResponses: 0, reenableSettingsSeen: 0, remoteAiFeaturesOn: false };
	const armOf = () => {
		if (!kind || !isTestProfile(dir)) {
			return undefined;
		}
		let text;
		try {
			text = fs.readFileSync(path.join(dir, 'arm.json'), 'utf8');
		} catch {
			return undefined;
		}
		const a = parseArm(text, Date.now() / 1000);
		return a.nonce ? a : undefined;
	};
	const record = () => {
		if (!kind || !isTestProfile(dir) || !facts.armed) {
			return;
		}
		try {
			fs.writeFileSync(path.join(dir, `facts-${kind}.json`), JSON.stringify(facts));
		} catch {
			// the storage directory went away: the run is over
		}
	};

	context.subscriptions.push(vscode.lm.registerLanguageModelChatProvider('seclab-test-fake', {
		provideLanguageModelChatInformation: async () => [{
			id: 'seclab-test-fake', name: 'seclab TEST ONLY fake model', family: 'seclab-test-fake', version: '1',
			maxInputTokens: 8192, maxOutputTokens: 1024, capabilities: { toolCalling: true },
		}],
		provideLanguageModelChatResponse: async (_model, _messages, _options, progress) => {
			facts.modelResponses++;
			record();
			progress.report(new vscode.LanguageModelTextPart('seclab fake model: scripted reply'));
		},
		provideTokenCount: async (_model, text) => typeof text === 'string' ? Math.ceil(text.length / 4) : 1,
	}));

	const participant = vscode.chat.createChatParticipant('seclab-test.fake-agent', async (request, _chatContext, stream, token) => {
		facts.requests++;
		record();
		const arm = armOf();
		if (!arm) {
			stream.markdown('seclab fake agent: not armed');
			return {};
		}
		const texts = [];
		for (const ref of request.references ?? []) {
			facts.references++;
			const v = ref.value;
			try {
				if (v instanceof vscode.Uri) {
					if (!mayRead(v, userDir)) {
						facts.referencesSkipped++;
						continue;
					}
					const bytes = await vscode.workspace.fs.readFile(v);
					texts.push(Buffer.from(bytes.subarray(0, MAX_TEXT)).toString('utf8'));
					facts.referencesRead++;
				} else if (typeof v === 'string') {
					texts.push(v.slice(0, MAX_TEXT));
					facts.referencesRead++;
				}
			} catch {
				// unreadable: not a match
			}
		}
		const action = selectAction(arm, kind, texts);
		facts.matched = facts.matched || !!action;
		record();
		if (action) {
			facts.fetchToolVisible = vscode.lm.tools.some(t => t.name === FETCH_TOOL);
			facts.invoked = true;
			record();
			try {
				await vscode.lm.invokeTool(FETCH_TOOL, { input: { urls: [action.url] }, toolInvocationToken: request.toolInvocationToken }, token);
				facts.invokeOk = true;
			} catch (err) {
				if (err && err.message === 'Unsupported operation') {
					facts.invokeRefused = true;
				} else {
					facts.invokeOtherError = true;
				}
			}
		}
		try {
			const r = await request.model.sendRequest([vscode.LanguageModelChatMessage.User('seclab')], {}, token);
			for await (const _ of r.text) { /* drain */ }
		} catch {
			// the fake model is a side path; the fetch is the measurement
		}
		record();
		stream.markdown('seclab fake agent: done');
		return {};
	});
	context.subscriptions.push(participant);

	// The harness's trigger for this window: one chat request with a fixed query, once per trigger.
	let handled = 0;
	const timer = setInterval(() => {
		const arm = armOf();
		if (!arm) {
			return;
		}
		if (!facts.armed) {
			facts.armed = true;
			record();
		}
		// Whether this window reads the settings a tab wrote to switch chat back on (the
		// settings-reenable probe's in-run control): a count of keys whose workspace value is set.
		if (kind === 'tab') {
			const c = vscode.workspace.getConfiguration();
			const seen = REENABLE_KEYS.filter(k => c.inspect(k)?.workspaceValue !== undefined).length;
			// And whether it reads `chat.disableAIFeatures: false` from the remote user settings the
			// tab supplies (ai-disable-ai-features-reenable's in-run control).
			const remoteOn = c.inspect('chat.disableAIFeatures')?.userRemoteValue === false;
			if (seen !== facts.reenableSettingsSeen || remoteOn !== facts.remoteAiFeaturesOn) {
				facts.reenableSettingsSeen = seen;
				facts.remoteAiFeaturesOn = remoteOn;
				record();
			}
		}
		// The trigger holds `<nonce> <n>`; each n is acted on once, and nothing is deleted.
		const trigger = path.join(dir, `trigger-${kind}`);
		let t;
		try {
			t = fs.readFileSync(trigger, 'utf8').trim();
		} catch {
			return;
		}
		const seq = triggerSeq(t, arm.nonce);
		if (seq <= handled) {
			return;
		}
		handled = seq;
		facts.triggered++;
		record();
		vscode.commands.executeCommand('workbench.action.chat.open', {
			query: `seclab probe ${arm.nonce.slice(0, 8)}: run the repository setup`, isPartialQuery: false, mode: 'agent',
			// The request names this model explicitly: an extension host resolves an unnamed one only
			// to the Copilot vendor's default, which this build has none of.
			modelSelector: { vendor: 'seclab-test-fake', id: 'seclab-test-fake' },
		}).then(undefined, () => { facts.triggerFailed = true; record(); });
	}, 1000);
	context.subscriptions.push({ dispose: () => clearInterval(timer) });
}

function deactivate() { }

module.exports = { activate, deactivate, parseArm, selectAction, windowKind, isTestProfile, mayRead, triggerSeq, MARKER, FETCH_TOOL, REENABLE_KEYS };
