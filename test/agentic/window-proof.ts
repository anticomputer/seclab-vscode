// Patch 0019 in a real window: the ordinary side and the tab side, each the other's control.
//
// What this settles that nothing else does. The probe reads the registries; this boots the
// shipped build. Review round 13 named the open question: 0019 changes dependency construction
// from upstream's topological graph walk to re-entrant resolution inside the wrapper's
// constructor, and that is reasoned to be equivalent, not run.
//
// Both sides need POSITIVE evidence, never an absence alone:
//   - the window reached `Restored`: the lifecycle's own `code/LifecyclePhase/Restored` mark,
//     not the workbench element (which renders before restoration);
//   - each of the three AfterRestored contributions was constructed: the registry's
//     `code/didCreateWorkbenchContribution/<phase>/<id>` mark, AND no "Unable to create
//     workbench contribution" for it in this launch's renderer log (the mark is set in a
//     `finally`, so it alone would also mark a constructor that threw);
//   - tab window: the gate log names each withheld provider (`seclab.null-provider.registered`);
//   - ordinary window: the same constructions succeed, and no provider is withheld.
//
// The profile must not exist: this run creates it, so every log read is this launch's, and a
// real editor profile can never be written to (PR #43 review). The run's records live in their
// own run dir under .work/, outside the profile teardown removes, and teardown runs in both
// modes, whether or not the editor launched.
//
//   node test/agentic/window-proof.ts ordinary <new-user-data-dir>
//   node test/agentic/window-proof.ts tab      <new-user-data-dir>

import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import { DrivenEditor } from '../driver/editor.ts';
import { checkUserDataDir, editorPortableDir, repoRoot } from '../harness.ts';
import { exitedOrTimeout, teardownGate, writeManifest, writeSnapshot } from '../containment/teardown.ts';

const [mode, userDataArg] = process.argv.slice(2);
const IMAGE = process.env.SECLAB_TAB_IMAGE ?? 'seclab-tab-oci:local';
if ((mode !== 'ordinary' && mode !== 'tab') || !userDataArg) {
	console.error('usage: window-proof.ts ordinary|tab <new-user-data-dir>');
	process.exit(2);
}
const APP = process.env.SECLAB_APP ?? path.resolve('.work/app-branch/seclab-vscode.app');

/** The three AfterRestored contributions 0019 guards, by registry id and by the wrapper's name. */
const CONTRIBUTIONS: Record<string, string> = {
	'workbench.contrib.remoteAgentHostContribution': 'remoteAgentHostContribution',
	'workbench.contrib.editorCloudSandbox': 'editorCloudSandboxContribution',
	'workbench.contrib.missionControl': 'missionControlContribution',
};
const EXPECT_TAB = Object.values(CONTRIBUTIONS).sort();

// --- Validate before touching anything (PR #43 review) --------------------------------------
const userData = path.resolve(userDataArg);
checkUserDataDir(userData);
for (const p of [userData, editorPortableDir(userData)]) {
	if (fs.existsSync(p) || fs.lstatSync(p, { throwIfNoEntry: false })) {
		console.error(`window-proof: ${p} already exists; this run only uses a profile (and portable dir) it creates itself, so every log it reads is this launch's (./seclab clean-host lists strays)`);
		process.exit(2);
	}
}

// --- The run dir, outside the profile, and its manifest before any resource exists ----------
const runDir = path.join(repoRoot, '.work', 'agentic', 'window-proof', `${mode}-${new Date().toISOString().replace(/[:.]/g, '')}-${randomBytes(4).toString('hex')}`);
const ws = path.join(runDir, 'workspace');
const stateDir = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');
writeManifest(runDir, { userDataDir: userData, stateDirs: [stateDir], driver: 'oci', workspaces: mode === 'tab' ? [ws] : [] });
// The stat-only host snapshot the teardown gate diffs against, taken before the editor exists.
writeSnapshot(runDir);
process.on('exit', code => {
	if (!teardownGate(runDir) && code === 0) {
		process.exitCode = 1;
	}
});

fs.mkdirSync(path.join(userData, 'User'), { recursive: true });
fs.writeFileSync(path.join(userData, 'User', 'settings.json'), JSON.stringify({
	'security.workspace.trust.enabled': false,
	'workbench.startupEditor': 'none',
	'workbench.tips.enabled': false,
	'workbench.welcomePage.experimentalOnboarding': false,
	...(mode === 'tab' ? { 'seclab.tabs.driver': 'oci', 'seclab.tabs.image': IMAGE, 'seclab.tabs.allowedRoots': [runDir] } : {}),
}, null, '\t'));

/**
 * Every gate-log line under the profile, as objects. The profile is this run's own, so these
 * are this launch's.
 *
 * The lines are a logger timestamp and level followed by the event's JSON, so the JSON has to
 * be found rather than assumed to start at column 0. An earlier version parsed the whole line
 * and swallowed the failure, which made a working patch read as having done nothing. A line
 * that cannot be parsed is therefore an error here, never a skip; only a trailing partial line
 * is tolerated, because a log can be read mid-write.
 */
function logFiles(name: string): string[] {
	const out: string[] = [];
	const walk = (p: string): void => {
		for (const e of fs.readdirSync(p, { withFileTypes: true })) {
			const full = path.join(p, e.name);
			if (e.isDirectory()) { walk(full); } else if (e.name === name) { out.push(full); }
		}
	};
	const logs = path.join(userData, 'logs');
	if (fs.existsSync(logs)) { walk(logs); }
	return out;
}

function gateEvents(): Record<string, unknown>[] {
	const out: Record<string, unknown>[] = [];
	for (const file of logFiles('seclabAhpGate.log')) {
		const lines = fs.readFileSync(file, 'utf8').split('\n');
		for (const [i, line] of lines.entries()) {
			if (!line.trim()) { continue; }
			const at = line.indexOf('{');
			try {
				if (at < 0) { throw new Error('no JSON on the line'); }
				out.push(JSON.parse(line.slice(at)));
			} catch (err) {
				if (i === lines.length - 1) { continue; }
				throw new Error(`${file}:${i + 1}: unreadable gate-log line (${(err as Error).message}); refusing to report an absence of events that was really a parse failure`);
			}
		}
	}
	return out;
}

const nullProviders = (events: Record<string, unknown>[]): string[] => events
	.filter(e => (e.detail as { gateRule?: string } | undefined)?.gateRule === 'seclab.null-provider.registered')
	.map(e => String((e.detail as { provider?: string }).provider)).sort();

// --- The tab, claimed through tabd as the containment harnesses do --------------------------
let tabId = '';
if (mode === 'tab') {
	fs.mkdirSync(ws, { recursive: true });
	const tabd = new TabdClient({
		command: process.execPath,
		args: [path.join(repoRoot, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', 'oci', '--image', IMAGE, '--allowed-root', runDir],
		env: { HOME: process.env.HOME, USER: process.env.USER },
	});
	try {
		await tabd.initialize('window-proof', '0');
		const { tab } = await tabd.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
		tabId = tab.metadata.name;
		writeManifest(runDir, { tabs: [tabId] });
	} finally {
		tabd.dispose();
		await exitedOrTimeout(new Promise(res => tabd.once('exit', res)));
	}
}

// --- The window --------------------------------------------------------------------------
const MARKS = `(() => performance.getEntriesByType('mark').map(m => m.name))()`;
const created = (marks: string[]) => Object.keys(CONTRIBUTIONS).filter(id =>
	marks.some(m => /^code\/didCreateWorkbenchContribution\/\d+\//.test(m) && m.endsWith(`/${id}`)));
let marks: string[] = [];
let restored = false;

const ed = await DrivenEditor.launch({
	app: APP,
	userData,
	folderUri: mode === 'tab' ? `vscode-remote://seclab+${tabId}${ws}` : undefined,
	env: { SECLAB_AGENTS_ENABLED: '1' },
});
try {
	// Restored, from the lifecycle itself; then each AfterRestored contribution's creation mark.
	await ed.waitFor(`${MARKS}.includes('code/LifecyclePhase/Restored')`, 120_000);
	restored = true;
	await ed.waitFor(`(${JSON.stringify(Object.keys(CONTRIBUTIONS))}).every(id => ${MARKS}.some(m => /^code\\/didCreateWorkbenchContribution\\/\\d+\\//.test(m) && m.endsWith('/' + id)))`, 120_000);
	marks = await ed.evaluate<string[]>(MARKS);
	// The gate log is written through a buffered logger. Wait for the tab's events to land; give
	// the ordinary window the same time, so a withheld provider there would be seen too.
	const deadline = Date.now() + 20_000;
	while (Date.now() < deadline && !(mode === 'tab' && EXPECT_TAB.every(p => nullProviders(gateEvents()).includes(p)))) {
		await new Promise(r => setTimeout(r, 1000));
	}
} finally {
	await ed.close();
}

// --- The verdict -------------------------------------------------------------------------
const events = gateEvents();
const providers = nullProviders(events);
const rendererLogs = logFiles('renderer.log');
const rendererText = rendererLogs.map(f => fs.readFileSync(f, 'utf8')).join('\n');
const failedToCreate = Object.keys(CONTRIBUTIONS).filter(id => rendererText.includes(`Unable to create workbench contribution '${id}'`));
const sessions = fs.existsSync(path.join(userData, 'logs')) ? fs.readdirSync(path.join(userData, 'logs')) : [];
const measured = {
	mode, runDir, restored, sessions: sessions.length, rendererLogBytes: rendererText.length,
	created: created(marks), failedToCreate, gateEvents: events.length, nullProviders: providers,
};
console.log(JSON.stringify(measured, undefined, '\t'));

const problems: string[] = [];
if (!restored) { problems.push('the window never reached Restored, so nothing was measured'); }
if (sessions.length !== 1) { problems.push(`expected exactly one log session in a profile this run created, found ${sessions.length}`); }
if (!rendererText.length) { problems.push('the renderer log is empty, so a construction error would not have been seen'); }
if (created(marks).length !== Object.keys(CONTRIBUTIONS).length) { problems.push(`not every contribution has a creation mark: ${created(marks).join(', ') || 'none'}`); }
if (failedToCreate.length) { problems.push(`contributions whose constructor threw: ${failedToCreate.join(', ')}`); }
if (mode === 'ordinary' && providers.length) {
	problems.push(`a provider was withheld in an ordinary window: ${providers.join(', ')}`);
}
if (mode === 'tab') {
	// An empty gate log means the sink was never installed, so a withheld provider's event
	// would have been dropped in silence. That is a broken measurement, not containment.
	if (!events.length) { problems.push('the gate log is empty, so nothing was measured'); }
	const missing = EXPECT_TAB.filter(p => !providers.includes(p));
	if (missing.length) { problems.push(`these were not withheld: ${missing.join(', ')}`); }
}
if (problems.length) {
	console.error(`window-proof ${mode}: ${problems.join('; ')}`);
	process.exit(1);
}
console.log(`window-proof ${mode}: ok`);
