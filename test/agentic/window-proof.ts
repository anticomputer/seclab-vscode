// Patch 0019 in a real window: the ordinary side and the tab side, each the other's control.
//
// What this settles that nothing else does. The probe reads the registries; this boots the
// shipped build. Review round 13 named the open question: 0019 changes dependency construction
// from upstream's topological graph walk to re-entrant resolution inside the wrapper's
// constructor, and that is reasoned to be equivalent, not run.
//
// The measurement is differential on purpose. In a tab window the three withheld contributions
// emit `seclab.null-provider.registered`; in an ordinary window they construct the real classes
// and emit nothing. Taken alone the tab side is an absence, and absence is not containment, so
// the ordinary side is what gives it meaning — and the tab side is what stops the ordinary side
// being read as "the patch does nothing".
//
// Both constructions happen at `AfterRestored` with nothing having to drive them, so neither
// side depends on a step that could silently not run. The run fails if a window never reaches
// that phase, rather than reporting a quiet pass.
//
//   node test/agentic/window-proof.ts ordinary <user-data-dir>
//   node test/agentic/window-proof.ts tab      <user-data-dir> <tabId>

import * as fs from 'node:fs';
import * as path from 'node:path';
import { TabdClient } from '../../tabd/src/client.ts';
import { DrivenEditor } from '../driver/editor.ts';
import { repoRoot } from '../harness.ts';
import { teardownGate, writeManifest, writeSnapshot } from '../containment/teardown.ts';

const [mode, userData] = process.argv.slice(2);
const IMAGE = process.env.SECLAB_TAB_IMAGE ?? 'seclab-tab-oci:local';
if (mode !== 'ordinary' && mode !== 'tab') {
	console.error('usage: window-proof.ts ordinary|tab <user-data-dir> [tabId]');
	process.exit(2);
}
const APP = process.env.SECLAB_APP ?? path.resolve('.work/app-branch/seclab-vscode.app');

/**
 * Every gate-log line this window wrote, as objects.
 *
 * The lines are a logger timestamp and level followed by the event's JSON, so the JSON has to
 * be found rather than assumed to start at column 0. The first version of this function parsed
 * the whole line and swallowed the failure, which made a patch that was working perfectly read
 * as having done nothing at all: every event was dropped, the run reported no null providers,
 * and that is indistinguishable from a patch that never ran. A line that cannot be parsed is
 * therefore an error here, never a skip. Only a trailing partial line is tolerated, and only
 * because a log can be read mid-write.
 */
function gateEvents(dir: string): Record<string, unknown>[] {
	const out: Record<string, unknown>[] = [];
	const walk = (p: string): void => {
		for (const e of fs.readdirSync(p, { withFileTypes: true })) {
			const full = path.join(p, e.name);
			if (e.isDirectory()) { walk(full); continue; }
			if (e.name !== 'seclabAhpGate.log') { continue; }
			const lines = fs.readFileSync(full, 'utf8').split('\n');
			for (const [i, line] of lines.entries()) {
				if (!line.trim()) { continue; }
				const at = line.indexOf('{');
				try {
					if (at < 0) { throw new Error('no JSON on the line'); }
					out.push(JSON.parse(line.slice(at)));
				} catch (err) {
					if (i === lines.length - 1) { continue; }   // a partial final line
					throw new Error(`${full}:${i + 1}: unreadable gate-log line (${(err as Error).message}); refusing to report an absence of events that was really a parse failure`);
				}
			}
		}
	};
	const logs = path.join(dir, 'logs');
	if (fs.existsSync(logs)) { walk(logs); }
	return out;
}

const nullProviders = (events: Record<string, unknown>[]): string[] => events
	.filter(e => (e.detail as { gateRule?: string } | undefined)?.gateRule === 'seclab.null-provider.registered')
	.map(e => String((e.detail as { provider?: string }).provider));

const base = path.join(userData, 'run');
const ws = path.join(base, 'workspace');
fs.mkdirSync(ws, { recursive: true });
fs.mkdirSync(path.join(userData, 'User'), { recursive: true });
const stateDir = path.join(userData, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd');
fs.writeFileSync(path.join(userData, 'User', 'settings.json'), JSON.stringify({
	'security.workspace.trust.enabled': false,
	'workbench.startupEditor': 'none',
	'workbench.tips.enabled': false,
	'workbench.welcomePage.experimentalOnboarding': false,
	...(mode === 'tab' ? { 'seclab.tabs.driver': 'oci', 'seclab.tabs.image': IMAGE, 'seclab.tabs.allowedRoots': [base] } : {}),
}, null, '\t'));

// The tab is claimed in the editor's own tabd state, exactly as the containment harnesses do,
// so the window attaches to a real tab rather than to a remote authority that resolves to
// nothing. A window that never connects would never reach AfterRestored, and this run would
// report that it measured nothing rather than quietly passing.
let tabId = '';
if (mode === 'tab') {
	const tabd = new TabdClient({
		command: process.execPath,
		args: [path.join(repoRoot, 'tabd/src/main.ts'), '--state-dir', stateDir, '--driver', 'oci', '--image', IMAGE, '--allowed-root', base],
		env: { HOME: process.env.HOME, USER: process.env.USER },
	});
	await tabd.initialize('window-proof', '0');
	const { tab } = await tabd.request<{ tab: { metadata: { name: string } } }>('tab.claim', { workspace: { hostPath: ws } });
	tabId = tab.metadata.name;
	writeManifest(base, { tabs: [tabId] });
	// The stat-only host snapshot the teardown gate diffs against. Taken before the editor
	// exists, or the gate can only report that it could not check.
	writeSnapshot(base);
	tabd.dispose();
	await new Promise(res => tabd.once('exit', res));
}

process.on('exit', code => {
	if (mode === 'tab' && !teardownGate(base) && code === 0) {
		process.exitCode = 1;
	}
});

const ed = await DrivenEditor.launch({
	app: APP,
	userData,
	folderUri: mode === 'tab' ? `vscode-remote://seclab+${tabId}${ws}` : undefined,
	env: { SECLAB_AGENTS_ENABLED: '1' },
});

let reachedRestored = false;
try {
	// `AfterRestored` is the phase the three contributions are registered for. The workbench
	// element only exists once the window has restored, so this is the phase gate, not a sleep.
	await ed.waitFor('!!document.querySelector(".monaco-workbench")', 120_000);
	reachedRestored = true;
	// Give the AfterRestored contributions their turn to construct before reading the log.
	await ed.evaluate('new Promise(r => setTimeout(r, 8000))', 30_000);
} finally {
	await ed.close();
}

const events = gateEvents(userData);
const providers = nullProviders(events);
const result = { mode, reachedRestored, gateEvents: events.length, nullProviders: providers.sort() };
console.log(JSON.stringify(result, undefined, '\t'));

if (!reachedRestored) {
	console.error(`window-proof ${mode}: the window never restored, so nothing was measured`);
	process.exit(1);
}
// The ordinary window must construct the real providers; the tab window must withhold all three.
const EXPECT_TAB = ['editorCloudSandboxContribution', 'missionControlContribution', 'remoteAgentHostContribution'];
if (mode === 'ordinary' && providers.length) {
	console.error(`window-proof ordinary: a null provider in an ordinary window: ${providers.join(', ')}`);
	process.exit(1);
}
if (mode === 'tab') {
	// If the gate's own events are absent the sink was never installed, and a null-provider
	// event would have been dropped in silence rather than withheld. Read that as a broken
	// measurement, not as containment.
	if (!events.length) {
		console.error('window-proof tab: the gate log is empty, so nothing was measured');
		process.exit(1);
	}
	const missing = EXPECT_TAB.filter(p => !providers.includes(p));
	if (missing.length) {
		console.error(`window-proof tab: these were not withheld: ${missing.join(', ')}`);
		process.exit(1);
	}
}
console.log(`window-proof ${mode}: ok`);
