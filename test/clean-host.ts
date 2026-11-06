// clean-host: list (default) or remove every seclab-vscode resource on this machine.
//   ./seclab clean-host                      dry run: list what would be removed
//   ./seclab clean-host --apply              remove stopped test tabs and leftovers, kill stray test processes
//   ./seclab clean-host --apply --running    also remove RUNNING test tabs
//   ./seclab clean-host --apply --all-tabs   also the real editor's tabs and tabs of unknown owner
//   ./seclab clean-host --apply --caches     also remove build caches and live local images
//   ./seclab clean-host --superseded-images  only superseded images (builds run this after tagging)
// Images: --apply removes superseded ones (no worktree's build references them); live ones only
// with --caches.
// Scope: this project's exact resource name patterns (OURS below: tab sandboxes and pods,
// harness helpers, broker test pods, our images and volumes), the test profiles under
// ~/.seclab-test and the demo folders under /Users/Shared/seclab-demo. Nothing else: the
// user's own sandboxes (e.g. `copilot-*`) and other projects' `seclab-*` images are not
// matched. Tabs are classified by the tabd state that owns them: only test tabs (state in
// ~/.seclab-test or a worktree's .work/) are removed by default; the user's real editor tabs
// hold their installed extensions. Processes are matched on option values: editors only
// with a test --user-data-dir, tabd only when orphaned with a test --state-dir. Stale fixture
// copies (workspaces with our .seclab/ dir, or an AV loader shape) under every worktree's .work/
// are removed too: they are what endpoint protection flags (EDR fixture-safety).
// Exit 0; with --apply, 1 if something could not be removed.

import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { treeTexts } from './containment/teardown.ts';
import { avFindings } from './safety/av-shape.ts';

const args = new Set(process.argv.slice(2));
for (const a of args) {
	if (!['--apply', '--running', '--caches', '--all-tabs', '--self-test', '--superseded-images'].includes(a)) {
		console.error(`unknown option ${a}\nusage: clean-host [--apply] [--running] [--caches] [--all-tabs] | --superseded-images`);
		process.exit(2);
	}
}
const apply = args.has('--apply');
const SBX = fs.existsSync('/opt/homebrew/bin/sbx') ? '/opt/homebrew/bin/sbx' : 'sbx';
// Exactly this project's names. A bare `seclab-` prefix is NOT ours alone: other projects
// on the same machine use it (e.g. seclab-example-a, seclab-example-b, seclab-example-kit-* images).
const TAB = 't-[a-z2-7]{26}';
const OURS = {
	// tabs, early spikes, broker sbx validation (brkval-<hex6>)
	sandbox: new RegExp(`^seclab-(${TAB}|spike-[a-z0-9-]+|brkval-[0-9a-f]{6})$`),
	// tab pod, harness helpers, broker integration pods and sbx validation
	container: new RegExp(`^seclab-(${TAB}(-broker)?|containment-hostsvc-(sbx|oci)-[0-9a-f]{8}|spike-[a-z0-9-]+|it-[0-9a-f]{6}-[a-z0-9-]+|brkval-[0-9a-f]{6}-[a-z0-9]+)$`),
	network: new RegExp(`^seclab-(${TAB}-(net|egress)|it-[0-9a-f]{6}-[a-z0-9-]+|brkval-[0-9a-f]{6}-[a-z0-9]+|spike-[a-z0-9-]+)$`),
	volume: new RegExp(`^seclab-${TAB}-home$`),
	image: /^seclab-(tab|tab-oci|builder|broker|broker-placeholder|broker-unit|broker-it-[a-z]+|broker-spike-[0-9a-f]{16}|template-builder|npm-cache|vsce|attest|tool-[a-z]+):[A-Za-z0-9._-]+$/,
};
const tabIdOf = (name: string) => new RegExp(`^seclab-(${TAB})(-broker|-net|-egress|-home)?$`).exec(name)?.[1];
if (args.has('--self-test')) {
	// Names seen on a real host: ours must match, other projects' and the user's must not.
	const yes: Array<[keyof typeof OURS, string]> = [['sandbox', 'seclab-t-dyhhlwazovvh3p7sk4el4vbjeq'], ['sandbox', 'seclab-spike-a'],
		['container', 'seclab-t-lih2z3i4s2dizitdpovzfpyi7y-broker'], ['container', 'seclab-spike-proxy'], ['container', 'seclab-containment-hostsvc-sbx-1a2b3c4d'],
		['container', 'seclab-it-4af231-broker'], ['network', 'seclab-t-lih2z3i4s2dizitdpovzfpyi7y-net'], ['network', 'seclab-t-lih2z3i4s2dizitdpovzfpyi7y-egress'], ['volume', 'seclab-t-lih2z3i4s2dizitdpovzfpyi7y-home'],
		['image', 'seclab-tab-oci:local'], ['image', 'seclab-broker-it-harness:test'], ['image', 'seclab-broker-spike-0123456789abcdef:local'],
		['image', 'seclab-tool-gitleaks:8.30.1-e3e2f34c682a'], ['image', 'seclab-attest:local']];
	const no: Array<[keyof typeof OURS, string]> = [['sandbox', 'copilot-bla'], ['sandbox', 'seclab-example-kit-base'], ['image', 'seclab-example-a:test-caching'],
		['image', 'seclab-example-b:local'], ['image', 'seclab-example-kit-sast:latest'], ['image', 'seclab-example-kit-base:latest'], ['volume', 'seclab-vscode-work'],
		['container', 'seclab-example-a-runner'], ['network', 'seclab-example-b-net']];
	const bad = [...yes.filter(([k, n]) => !OURS[k].test(n)).map(([k, n]) => `should match ${k} ${n}`),
		...no.filter(([k, n]) => OURS[k].test(n)).map(([k, n]) => `must not match ${k} ${n}`),
		// Every per-tab resource maps to its tab, so a real tab's is never removed as a test's.
		...yes.filter(([, n]) => n.startsWith('seclab-t-') && tabIdOf(n) !== n.slice('seclab-'.length, 'seclab-t-'.length + 26)).map(([k, n]) => `${k} ${n} does not map to its tab`)];
	console.log(bad.length ? bad.join('\n') : `clean-host patterns: ${yes.length + no.length} cases OK`);
	process.exit(bad.length ? 1 : 0);
}
const CACHE_VOLUMES = new Set(['seclab-vscode-work', 'seclab-lychee-cache', 'seclab-test-scratch']);
// Test build variants' build volumes (EDR test-build-variants): build caches too.
const isCacheVolume = (n: string) => CACHE_VOLUMES.has(n) || /^seclab-test-[a-z][a-z0-9-]{0,31}$/.test(n);

interface Item { kind: string; name: string; state: string; remove: boolean; why: string; del: () => boolean }
const items: Item[] = [];

const run = (cmd: string, a: string[]) => spawnSync(cmd, a, { encoding: 'utf8' });
const ok = (cmd: string, a: string[]) => {
	const r = run(cmd, a);
	return !r.error && r.status === 0;
};
const lines = (cmd: string, a: string[]) => {
	const r = run(cmd, a);
	return r.error || r.status !== 0 ? [] : r.stdout.split('\n').map(s => s.trim()).filter(Boolean);
};

// ---- ownership: test vs the user's real editor (T-3) -------------------------------------
// A tab is a test tab if a test profile or a worktree's .work/ holds its tabd state (or, for
// sbx, its workspace is under one); the user's real editor tabs are in the real profile.
// Only test tabs are removed unless --all-tabs: the real ones hold installed extensions.
const home = os.homedir();
const repo = path.resolve(import.meta.dirname, '..');
const worktrees = new Set([repo, ...lines('git', ['-C', repo, 'worktree', 'list', '--porcelain'])
	.filter(l => l.startsWith('worktree ')).map(l => l.slice('worktree '.length))]);
const testRoots = [path.join(home, '.seclab-test'), '/Users/Shared/seclab-demo', ...[...worktrees].map(w => path.join(w, '.work'))];
const underTest = (p: string) => testRoots.some(r => p === r || p.startsWith(r + path.sep));
const realProfiles = [path.join(home, 'Library', 'Application Support', 'seclab-vscode'), path.join(home, '.config', 'seclab-vscode')];
const owner = new Map<string, 'test' | 'real'>();
const readTabs = (stateDir: string, kind: 'test' | 'real') => {
	let entries: string[] = [];
	try {
		entries = fs.readdirSync(path.join(stateDir, 'tabs'));
	} catch { /* none */ }
	for (const e of entries) {
		const id = /^(t-[a-z2-7]{26})\.json$/.exec(e)?.[1];
		if (id && owner.get(id) !== 'real') {
			owner.set(id, kind);
		}
	}
};
for (const p of realProfiles) {
	readTabs(path.join(p, 'User', 'globalStorage', 'seclab.tab-manager', 'tabd'), 'real');
}
for (const root of testRoots) {
	// tabd state dirs are `.../tabd` (editor profiles) or `.../state` (harness runs); bounded walk.
	const walk = (dir: string, depth: number) => {
		let entries: fs.Dirent[] = [];
		try {
			entries = fs.readdirSync(dir, { withFileTypes: true });
		} catch {
			return;
		}
		if (entries.length > 2000) {
			return;
		}
		for (const e of entries) {
			if (!e.isDirectory() || e.isSymbolicLink()) {
				continue;
			}
			const p = path.join(dir, e.name);
			if (e.name === 'tabs') {
				readTabs(dir, 'test');
			} else if (depth < 6 && !['node_modules', 'vscode', 'out', 'app', '.git'].includes(e.name)) {
				walk(p, depth + 1);
			}
		}
	};
	walk(root, 0);
}
/** Removal policy for a project resource: test resources go; real or unknown tabs stay unless --all-tabs. */
const tabPolicy = (name: string, hint?: 'test'): { remove: boolean; why: string; owner: string } => {
	const id = tabIdOf(name);
	if (!id) {
		return { remove: true, why: '', owner: 'test' }; // spikes, broker test pods, harness helpers
	}
	const o = owner.get(id) ?? hint;
	if (o === 'test' || args.has('--all-tabs')) {
		return { remove: true, why: '', owner: o ?? 'unknown' };
	}
	return { remove: false, why: o === 'real' ? 'your editor\'s tab (use --all-tabs)' : 'owner unknown (use --all-tabs)', owner: o ?? 'unknown' };
};

// ---- processes ---------------------------------------------------------------------------
// Editors only when running a test profile; tabd only when orphaned AND its state is a test
// location (T-6). Matched on option values, never on loose substrings.
const procs = lines('ps', ['-axo', 'pid=,ppid=,args=']).map(l => /^(\d+)\s+(\d+)\s+(.*)$/.exec(l)).filter((m): m is RegExpExecArray => !!m)
	.map(m => ({ pid: Number(m[1]), ppid: Number(m[2]), args: m[3] }));
const optValue = (args: string, opt: string) => new RegExp(`(?:^|\\s)--${opt}(?:=|\\s+)(\\S+)`).exec(args)?.[1];
for (const p of procs) {
	if (p.pid === process.pid || p.pid === process.ppid) {
		continue;
	}
	const udd = optValue(p.args, 'user-data-dir');
	const sd = optValue(p.args, 'state-dir');
	const editor = /seclab-vscode\.app\/|\/seclab-vscode(\s|$)/.test(p.args) && !!udd;
	const tabd = /(^|\/)(tabd\/src\/main\.ts|dist\/tabd\.js)(\s|$)/.test(p.args) && !!sd;
	if (!editor && !tabd) {
		continue;
	}
	const stray = editor ? underTest(path.resolve(udd!)) : p.ppid === 1 && underTest(path.resolve(sd!));
	items.push({
		kind: editor ? 'editor process' : 'tabd process', name: `${p.pid} ${p.args.slice(0, 100)}`, state: 'running',
		remove: stray, why: stray ? '' : editor ? 'not a test profile' : 'has a live parent or real state',
		del: () => {
			try {
				process.kill(p.pid, 'SIGTERM');
			} catch { /* gone */ }
			for (let i = 0; i < 20 && ok('kill', ['-0', String(p.pid)]); i++) {
				spawnSync('sleep', ['0.5']);
			}
			try {
				process.kill(p.pid, 'SIGKILL');
			} catch { /* gone */ }
			return true;
		},
	});
}

// ---- sbx sandboxes -----------------------------------------------------------------------
const sbx = run(SBX, ['ls', '--json']);
// Workspace paths mounted by sandboxes that stay (a fixture copy they mount is in use).
const keptMounts: string[] = [];
if (!sbx.error && sbx.status === 0) {
	for (const s of JSON.parse(sbx.stdout) as Array<{ name: string; status: string; workspaces?: string[] }>) {
		if (!OURS.sandbox.test(s.name)) {
			keptMounts.push(...(s.workspaces ?? []));
			continue;
		}
		const running = s.status !== 'stopped';
		const ws = s.workspaces ?? [];
		const pol = tabPolicy(s.name, ws.length && ws.every(w => underTest(w)) ? 'test' : undefined);
		const remove = pol.remove && (!running || args.has('--running'));
		if (!remove) {
			keptMounts.push(...ws);
		}
		items.push({
			kind: 'sbx sandbox', name: `${s.name} (${pol.owner})`, state: s.status, remove,
			why: !pol.remove ? pol.why : running && !args.has('--running') ? 'running (use --running)' : '', del: () => ok(SBX, ['rm', '--force', s.name]),
		});
	}
}

// ---- docker ------------------------------------------------------------------------------
/** Image names and IDs a current build in any worktree uses (see the image loop below). */
function liveImages(): { names: Set<string>; ids: Set<string> } {
	const names = new Set<string>();
	const ids = new Set<string>();
	const tag = /seclab-[a-z][a-z0-9-]*:[A-Za-z0-9._-]+(?![A-Za-z0-9._${}-])/g;
	for (const w of worktrees) {
		for (const f of lines('git', ['-C', w, 'ls-files']).filter(f => !/\.(png|jpe?g|gif|patch)$/.test(f))) {
			try {
				const text = fs.readFileSync(path.join(w, f), 'utf8');
				for (const m of text.matchAll(tag)) {
					names.add(m[0]);
				}
			} catch { /* deleted or unreadable */ }
		}
		// Tool images by their pinned version (build/tools/tool.sh tags NAME:VERSION and NAME:VERSION-HASH).
		try {
			const tools = JSON.parse(fs.readFileSync(path.join(w, 'build/tools/tools.json'), 'utf8')) as Record<string, { version?: string }>;
			for (const [n, t] of Object.entries(tools)) {
				if (!n.startsWith('$') && t.version) {
					names.add(`seclab-tool-${n}:${t.version}`);
				}
			}
		} catch { /* no tools lock */ }
		// The npm cache for this worktree's current lock set (seclab npm_fetch_cfs).
		const locks = path.join(w, '.work', 'npm-locks');
		if (fs.existsSync(locks)) {
			const key = run('sh', ['-c', 'cd "$1" && find . -type f | LC_ALL=C sort | xargs shasum -a 256 | shasum -a 256 | cut -c1-16', 'sh', locks]).stdout.trim();
			if (/^[0-9a-f]{16}$/.test(key)) {
				names.add(`seclab-npm-cache:${key}`);
			}
		}
	}
	// The gitleaks image the shared pre-push hook has baked in, by ID.
	const common = run('git', ['-C', repo, 'rev-parse', '--git-common-dir']).stdout.trim();
	try {
		for (const m of fs.readFileSync(path.resolve(repo, common, 'seclab-hooks', 'pre-push'), 'utf8').matchAll(/sha256:[0-9a-f]{64}/g)) {
			ids.add(m[0]);
		}
	} catch { /* no hook installed */ }
	// Tags sharing a live name's image are the same image.
	for (const n of names) {
		const id = run('docker', ['image', 'inspect', '--format', '{{.Id}}', '--', n]).stdout.trim();
		if (/^sha256:[0-9a-f]{64}$/.test(id)) {
			ids.add(id);
		}
	}
	return { names, ids };
}
const containers = new Map<string, string>();
for (const l of [...lines('docker', ['ps', '-a', '--filter', 'label=seclab.tab', '--format', '{{.Names}}\t{{.State}}']),
	...lines('docker', ['ps', '-a', '--filter', 'name=seclab-', '--format', '{{.Names}}\t{{.State}}'])]) {
	const [n, st] = l.split('\t');
	containers.set(n, st);
}
for (const [n, st] of containers) {
	if (!OURS.container.test(n)) {
		continue;
	}
	const running = st === 'running';
	const pol = tabPolicy(n);
	items.push({
		kind: 'container', name: `${n} (${pol.owner})`, state: st, remove: pol.remove && (!running || args.has('--running')),
		why: !pol.remove ? pol.why : running && !args.has('--running') ? 'running (use --running)' : '', del: () => ok('docker', ['rm', '-f', n]),
	});
}
for (const n of lines('docker', ['network', 'ls', '--filter', 'name=seclab-', '--format', '{{.Name}}']).filter(n => OURS.network.test(n))) {
	const pol = tabPolicy(n);
	items.push({ kind: 'network', name: `${n} (${pol.owner})`, state: '', remove: pol.remove, why: pol.why, del: () => ok('docker', ['network', 'rm', n]) });
}
for (const n of lines('docker', ['volume', 'ls', '--filter', 'name=seclab-', '--format', '{{.Name}}']).filter(n => OURS.volume.test(n) || isCacheVolume(n))) {
	const cache = isCacheVolume(n);
	const pol = cache ? { remove: args.has('--caches'), why: 'build cache (use --caches)', owner: 'cache' } : tabPolicy(n);
	items.push({
		kind: cache ? 'cache volume' : 'volume', name: `${n} (${pol.owner})`, state: '', remove: pol.remove,
		why: pol.remove ? '' : pol.why, del: () => ok('docker', ['volume', 'rm', n]),
	});
}
// Images: superseded ones go with --apply; live ones only with --caches. Live means named
// literally in any worktree's tracked files (other sessions' branches included), the current
// tool images (and tags sharing their image), the npm cache for the current lock set, the
// gitleaks image the pre-push hook has baked in, or built in the last hour (a build or test may
// be using it right now).
const live = liveImages();
const imageIds = new Map(lines('docker', ['image', 'ls', '--no-trunc', '--format', '{{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.CreatedAt}}']).map(l => {
	const [n, id, created] = l.split('\t');
	const m = /^(\S+) (\S+) ([+-]\d\d)(\d\d)/.exec(created ?? '');
	return [n, { id, created: m ? Date.parse(`${m[1]}T${m[2]}${m[3]}:${m[4]}`) : NaN }] as const;
}));
for (const n of [...imageIds.keys()].filter(n => OURS.image.test(n))) {
	const img = imageIds.get(n)!;
	const isLive = live.names.has(n) || live.ids.has(img.id) || !(Date.now() - img.created > 3_600_000);
	const remove = isLive ? args.has('--caches') : true;
	items.push({
		kind: 'image', name: `${n}${isLive ? '' : ' (superseded)'}`, state: '', remove, why: remove ? '' : 'in use by a current build (use --caches)',
		del: () => ok('docker', ['image', 'rm', n]),
	});
}
// Containers not named seclab-* but created from an image in the dependency register or one of
// our own images: possibly an ad-hoc command's leftover (AGENTS.md naming rule). Reported only,
// never removed: whoever created it must verify.
const registerRepos = new Set<string>();
try {
	const reg = JSON.parse(fs.readFileSync(path.join(import.meta.dirname, '..', 'deps', 'registry.json'), 'utf8')) as { deps?: Array<{ kind?: string; pins?: string[] }> };
	for (const e of reg.deps ?? []) {
		for (const p of e.kind === 'oci-image' ? e.pins ?? [] : []) {
			registerRepos.add(p.replace(/@.*$/, '').replace(/:[^/:]*$/, ''));
		}
	}
} catch { /* no register: only our own images are matched */ }
const repoOf = (img: string) => img.replace(/@.*$/, '').replace(/:[^/:]*$/, '');
const imageNames = new Map<string, string[]>();
for (const l of lines('docker', ['image', 'ls', '--no-trunc', '--format', '{{.ID}}\t{{.Repository}}:{{.Tag}}'])) {
	const [id, name] = l.split('\t');
	imageNames.set(id, [...imageNames.get(id) ?? [], name]);
}
for (const l of lines('docker', ['ps', '-a', '--no-trunc', '--format', '{{.Names}}\t{{.State}}\t{{.Image}}'])) {
	const [n, st, img] = l.split('\t');
	if (!n || n.startsWith('seclab-') || containers.has(n)) {
		continue;
	}
	const names = img?.startsWith('sha256:') ? imageNames.get(img) ?? [] : [img ?? ''];
	const hit = names.find(x => OURS.image.test(x) || registerRepos.has(repoOf(x)) || registerRepos.has(`docker.io/library/${repoOf(x)}`));
	if (hit) {
		items.push({ kind: 'container?', name: `${n} (image ${hit})`, state: st, remove: false, why: 'possibly ours, verify: not named seclab-*', del: () => false });
	}
}

// ---- host directories --------------------------------------------------------------------
for (const dir of [path.join(home, '.seclab-test'), '/Users/Shared/seclab-demo']) {
	let entries: string[] = [];
	try {
		entries = fs.readdirSync(dir);
	} catch { /* absent */ }
	for (const e of entries) {
		const p = path.join(dir, e);
		const inUse = procs.some(x => x.args.includes(p));
		items.push({
			kind: 'directory', name: p, state: inUse ? 'in use' : '', remove: !inUse, why: inUse ? 'a running process uses it' : '',
			del: () => {
				fs.rmSync(p, { recursive: true, force: true });
				return !fs.existsSync(p);
			},
		});
	}
}

// ---- stale fixture copies in every worktree's .work/ (EDR fixture-safety) ---------------------
// Hostile fixtures materialised on the host are what endpoint protection flags. Removed only
// when provably a harness copy (SS-1): it carries materialiseFixture's marker, a run.json lists
// it under `workspaces`, or it sits at an exact legacy harness path. Other `.seclab/` dirs and
// AV-shaped trees are reported, never deleted. Never descends into a checkout (a `.git` entry:
// e.g. a nested worktree's tracked fixtures) or follows symlinks; depth 0-1 is never a root.
const PRUNE = new Set(['node_modules', 'out', 'out-build', '.build', 'vscode', 'vscode-reh', 'src', 'deps-verified', 'attestations']);
const LEGACY = /^(containment\/(sbx|oci)\/tabs\/[^/]+|containment-editor\/ws-[^/]+|observability\/(sbx|oci)\/tabs\/[^/]+|obs-demo\/tabs\/[^/]+)$/;
const fixtureRoots = new Map<string, { remove: boolean; why: string }>();
const listed = new Set<string>();
const scanWork = (work: string, dir: string, depth: number): void => {
	if (depth > 8) {
		return;
	}
	let ents: fs.Dirent[] = [];
	try {
		ents = fs.readdirSync(dir, { withFileTypes: true });
	} catch {
		return;
	}
	const names = new Set(ents.map(e => e.name));
	if (depth > 0 && names.has('.git')) {
		return; // a checkout: its fixtures are tracked files, not copies
	}
	if (names.has('run.json')) {
		try {
			for (const w of (JSON.parse(fs.readFileSync(path.join(dir, 'run.json'), 'utf8')) as { workspaces?: unknown }).workspaces as string[] ?? []) {
				if (typeof w === 'string' && path.resolve(w).startsWith(dir + path.sep)) {
					listed.add(path.resolve(w));
				}
			}
		} catch { /* not a run manifest */ }
	}
	const hasDir = (n: string) => ents.some(e => e.name === n && e.isDirectory());
	if (depth >= 2 && (hasDir('.seclab') || names.has('.seclab-materialised'))) {
		const rel = path.relative(work, dir).split(path.sep).join('/');
		const ours = names.has('.seclab-materialised') || LEGACY.test(rel);
		fixtureRoots.set(dir, { remove: ours, why: ours ? '' : 'has a .seclab/ dir but is not a recognised harness copy: review it' });
		return;
	}
	if (depth >= 2 && hasDir('.vscode') && names.size < 400) {
		let first: string | undefined;
		try {
			first = avFindings(treeTexts(dir, 400))[0];
		} catch { /* unreadable: not ours to judge */ }
		if (first) {
			fixtureRoots.set(dir, { remove: false, why: `not a seclab fixture; has an AV loader shape, review it: ${first.slice(0, 140)}` });
			return;
		}
	}
	for (const e of ents) {
		if (e.isDirectory() && !PRUNE.has(e.name)) {
			scanWork(work, path.join(dir, e.name), depth + 1);
		}
	}
};
for (const w of worktrees) {
	const work = path.join(w, '.work');
	scanWork(work, work, 0);
}
for (const p of listed) {
	if (fs.existsSync(p)) {
		fixtureRoots.set(p, { remove: true, why: '' });
	}
}
for (const [p, f] of fixtureRoots) {
	const inUse = procs.some(x => x.args.includes(p)) || keptMounts.some(m => m === p || m.startsWith(p + path.sep) || p.startsWith(m + path.sep));
	items.push({
		kind: 'fixture copy', name: p, state: inUse ? 'in use' : '', remove: f.remove && !inUse, why: f.why || (inUse ? 'a running process or a kept sandbox uses it' : ''),
		del: () => {
			fs.rmSync(p, { recursive: true, force: true });
			return !fs.existsSync(p);
		},
	});
}

// ---- report / apply ------------------------------------------------------------------------
// --superseded-images (builds call it after tagging): remove only superseded images, nothing else.
if (args.has('--superseded-images')) {
	const gone = items.filter(i => i.kind === 'image' && i.name.endsWith(' (superseded)'));
	for (const it of gone) {
		console.log(`${it.del() ? 'removed' : 'FAILED '} image ${it.name}`);
	}
	process.exit(0);
}
// Processes first (they hold sandboxes and dirs), then sandboxes and containers, then the rest.
const order = ['editor process', 'tabd process', 'sbx sandbox', 'container', 'network', 'volume', 'cache volume', 'image', 'directory', 'fixture copy'];
items.sort((a, b) => order.indexOf(a.kind) - order.indexOf(b.kind));
let failed = 0;
for (const it of items) {
	const label = `${it.kind.padEnd(14)} ${it.name}${it.state ? ` [${it.state}]` : ''}`;
	if (!it.remove) {
		console.log(`keep    ${label}  (${it.why})`);
	} else if (!apply) {
		console.log(`would remove  ${label}`);
	} else if (it.del()) {
		console.log(`removed ${label}`);
	} else {
		failed++;
		console.log(`FAILED  ${label}`);
	}
}
if (!items.length) {
	console.log('no seclab resources on this host');
} else if (!apply) {
	console.log(`\ndry run: ${items.filter(i => i.remove).length} to remove, ${items.filter(i => !i.remove).length} kept. Re-run with --apply.`);
}
process.exit(failed ? 1 : 0);
