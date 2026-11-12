// Patch reachability (EDR patch-build gate): every source file a shipped patch touches must be
// reachable from what we ship (the desktop build or the REH), not only from web. A patch placed
// in a web-only file (`workbench.web.main.ts`) applies cleanly and type-checks, yet never runs.
//   node build/check-patch-reach.ts SRC     (SRC = the patched upstream tree)
// Entry points are read from upstream's own bundler (build/next/index.ts, build/lib/esbuild.ts),
// so they follow upstream; a list that can't be parsed fails closed. The graph follows static
// and literal dynamic imports. patches/reach.json may require specific targets per patch, e.g.
//   { "0012-background-windows-env.patch": ["desktop"] }  (every touched file must reach these).
import * as fs from 'node:fs';
import * as path from 'node:path';
import { patchedFiles, runtimeSpecs } from './patch-reach-imports.ts';
import { soleConsumerProblems } from './check-sole-consumer.ts';

const repo = path.resolve(import.meta.dirname, '..');
// `--patches DIR` (self-test only) reads series, reach.json and the patches from DIR.
const pi = process.argv.indexOf('--patches');
const patchesDir = pi > 0 ? path.resolve(process.argv.splice(pi, 2)[1] ?? '') : path.join(repo, 'patches');
const src = path.resolve(process.argv[2] ?? '');
if (!process.argv[2] || !fs.existsSync(path.join(src, 'src', 'vs'))) {
	console.error('usage: check-patch-reach.ts PATCHED_UPSTREAM_TREE');
	process.exit(2);
}
const fail = (m: string): never => {
	console.error(`check-patch-reach: ${m}`);
	process.exit(1);
};

// ---- entry points, from upstream's bundler ---------------------------------------------------
const nextIndex = fs.readFileSync(path.join(src, 'build', 'next', 'index.ts'), 'utf8');
const list = (name: string): string[] => {
	const m = new RegExp(`const ${name} = \\[([^\\]]*)\\]`).exec(nextIndex) ?? fail(`can't read ${name} from build/next/index.ts`);
	return [...m[1].matchAll(/'([^']+)'/g)].map(x => x[1]);
};
const esbuild = fs.readFileSync(path.join(src, 'build', 'lib', 'esbuild.ts'), 'utf8');
const boot = (target: string): string[] => {
	const m = new RegExp(`case '${target}':[^\\[]*return \\[([^\\]]*)\\]`).exec(esbuild) ?? fail(`can't read ${target} bootstrap entries from build/lib/esbuild.ts`);
	return [...m[1].matchAll(/'([^']+)'/g)].map(x => x[1]);
};
const targets: Record<string, string[]> = {
	desktop: [...boot('desktop'), ...list('workerEntryPoints'), ...list('desktopWorkerEntryPoints'), ...list('desktopEntryPoints'), ...list('codeEntryPoints')],
	server: [...boot('server'), ...list('serverEntryPoints')],
	web: [...list('workerEntryPoints'), ...list('webOnlyEntryPoints'), 'vs/workbench/workbench.web.main.internal'],
};
for (const [t, eps] of Object.entries(targets)) {
	if (eps.length < 3) {
		fail(`only ${eps.length} ${t} entry points parsed; refusing to judge reachability`);
	}
}

// ---- import graph ------------------------------------------------------------------------------
// Runtime edges only: see patch-reach-imports.ts.
const resolveFrom = (file: string, spec: string): string | undefined => {
	if (!spec.startsWith('.')) {
		return undefined; // packages and node: builtins
	}
	const base = path.resolve(path.dirname(file), spec);
	for (const c of [base.replace(/\.js$/, '.ts'), base, `${base}.ts`, path.join(base, 'index.ts')]) {
		if (c.startsWith(path.join(src, 'src')) && fs.existsSync(c) && fs.statSync(c).isFile()) {
			return c;
		}
	}
	return undefined;
};
const edges = new Map<string, string[]>();
const importsOf = (file: string): string[] => {
	let e = edges.get(file);
	if (!e) {
		e = runtimeSpecs(fs.readFileSync(file, 'utf8')).map(s => resolveFrom(file, s)).filter((x): x is string => !!x);
		edges.set(file, e);
	}
	return e;
};
const entryFile = (ep: string): string => {
	const f = path.join(src, 'src', `${ep}.ts`);
	return fs.existsSync(f) ? f : fail(`entry point ${ep} has no src/${ep}.ts`);
};
const reached: Record<string, Set<string>> = {};
for (const [t, eps] of Object.entries(targets)) {
	const seen = new Set<string>();
	const stack = eps.map(entryFile);
	while (stack.length) {
		const f = stack.pop()!;
		if (!seen.has(f)) {
			seen.add(f);
			stack.push(...importsOf(f));
		}
	}
	reached[t] = seen;
}

// ---- patches ---------------------------------------------------------------------------------
// `--file REL...` reports which targets reach the given source files (for patch authors).
if (process.argv[3] === '--file') {
	for (const rel of process.argv.slice(4)) {
		const f = path.join(src, rel);
		console.log(`${rel} -> ${Object.keys(targets).filter(t => reached[t].has(f)).join(', ') || 'nothing'}`);
	}
	process.exit(0);
}
const series = fs.readFileSync(path.join(patchesDir, 'series'), 'utf8').split('\n').map(l => l.replace(/#.*/, '').trim()).filter(Boolean);
// The policy files are required (GATE-2, GATE-3): a missing, unreadable or empty one would
// silently switch a security invariant off, so each fails the gate instead.
function readPolicy<T>(name: string): Record<string, T> {
	const file = path.join(patchesDir, name);
	let v: unknown;
	try {
		v = JSON.parse(fs.readFileSync(file, 'utf8'));
	} catch (e) {
		return fail(`patches/${name} is required and could not be read: ${(e as Error).message}`);
	}
	if (!v || typeof v !== 'object' || Array.isArray(v) || Object.keys(v).length === 0) {
		return fail(`patches/${name} must be a non-empty JSON object`);
	}
	return v as Record<string, T>;
}
const required = readPolicy<string[]>('reach.json');
for (const p of Object.keys(required)) {
	if (!series.includes(p)) {
		fail(`patches/reach.json names ${p}, which is not in patches/series`);
	}
	// An emptied entry would drop that patch's requirement silently (review SSS-3).
	const ts = required[p];
	if (!Array.isArray(ts) || ts.length === 0 || ts.some(t => !reached[t])) {
		fail(`patches/reach.json: ${p} must list one or more known targets (${Object.keys(reached).join(', ')}), got ${JSON.stringify(ts)}`);
	}
}
const problems: string[] = [];
let checked = 0;
for (const p of series) {
	let touched: string[];
	try {
		touched = patchedFiles(fs.readFileSync(path.join(patchesDir, p), 'utf8'));
	} catch (e) {
		fail(`${p}: ${(e as Error).message}`);
	}
	const files = touched!.filter(f => /^src\/.+\.ts$/.test(f)).map(f => path.join(src, f));
	console.log(`${p}: ${touched!.length} file(s), ${files.length} under src/**/*.ts`);
	if (required[p] && !files.length) {
		problems.push(`${p}: named in patches/reach.json but touches no src/**/*.ts file, so nothing was checked`);
	}
	for (const f of files) {
		checked++;
		const rel = path.relative(src, f);
		if (!fs.existsSync(f)) {
			console.log(`${p}: ${rel} deleted`);
			continue;
		}
		const into = Object.keys(targets).filter(t => reached[t].has(f));
		const shipped = into.filter(t => t !== 'web');
		const need = required[p] ?? [];
		if (!shipped.length) {
			problems.push(`${p}: ${rel} is not reachable from the desktop build or the REH (reached from: ${into.join(', ') || 'nothing'})`);
		} else if (need.some(t => !into.includes(t))) {
			problems.push(`${p}: ${rel} must be reachable from ${need.join(' and ')} (patches/reach.json); reached from ${into.join(', ')}`);
		} else {
			console.log(`${p}: ${rel} -> ${into.join(', ')}`);
		}
	}
}
// patches/unreachable.json: { "<target>": { "deny": [...], "except": [...] } } (I8: no agent-host
// process code in the desktop app). A `deny` entry ending in `/` covers every module under it
// (review WW-6), so a new agent module is covered without anyone listing it; `except` names the
// few under a denied prefix the target may reach. A listed file or directory that no longer
// exists fails too, so an upstream rename can't silently retire the rule.
const forbidden = readPolicy<{ deny: string[]; except?: string[] }>('unreachable.json');
// I8 is about the desktop app: it must deny something there.
if (!Array.isArray(forbidden.desktop?.deny) || forbidden.desktop.deny.length === 0) {
	fail('patches/unreachable.json must deny at least one module for desktop (invariant I8)');
}
let forbiddenChecked = 0;
for (const [t, rule] of Object.entries(forbidden)) {
	if (!reached[t] || !Array.isArray(rule?.deny)) {
		fail(`patches/unreachable.json: bad entry for ${t} (want { "deny": [...], "except": [...] } for a known target)`);
	}
	const except = new Set((rule.except ?? []).map(rel => path.join(src, rel)));
	for (const f of except) {
		if (!fs.existsSync(f)) {
			problems.push(`patches/unreachable.json: except ${path.relative(src, f)} does not exist in the patched tree`);
		}
	}
	for (const rel of rule.deny) {
		const f = path.join(src, rel);
		forbiddenChecked++;
		if (!fs.existsSync(f)) {
			problems.push(`patches/unreachable.json: ${rel} does not exist in the patched tree (renamed upstream? update the list)`);
			continue;
		}
		const hits = rel.endsWith('/')
			? [...reached[t]].filter(m => m.startsWith(f) && !except.has(m))
			: reached[t].has(f) ? [f] : [];
		for (const h of hits) {
			problems.push(`patches/unreachable.json: ${path.relative(src, h)} must not be reachable from ${t}, but is`);
		}
	}
}
// Sole-consumer invariants: a patch that gates a capability at one call site is only sound
// while that site is the only one. Checked here so it runs wherever reachability does.
const soleProblems = soleConsumerProblems(src, path.join(patchesDir, 'sole-consumer.json'));
problems.push(...soleProblems);
for (const pr of problems) {
	console.error(pr);
}
console.log(problems.length ? `check-patch-reach: ${problems.length} problem(s)` : `check-patch-reach: ok (${checked} patched files, ${forbiddenChecked} forbidden; ${reached.desktop.size} desktop, ${reached.server.size} server modules; sole-consumer invariants ok)`);
process.exit(problems.length ? 1 : 0);
