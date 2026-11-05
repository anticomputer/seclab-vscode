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
import { runtimeSpecs } from './patch-reach-imports.ts';

const repo = path.resolve(import.meta.dirname, '..');
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
const series = fs.readFileSync(path.join(repo, 'patches', 'series'), 'utf8').split('\n').map(l => l.replace(/#.*/, '').trim()).filter(Boolean);
const reachFile = path.join(repo, 'patches', 'reach.json');
const required: Record<string, string[]> = fs.existsSync(reachFile) ? JSON.parse(fs.readFileSync(reachFile, 'utf8')) : {};
for (const p of Object.keys(required)) {
	if (!series.includes(p)) {
		fail(`patches/reach.json names ${p}, which is not in patches/series`);
	}
}
const problems: string[] = [];
let checked = 0;
for (const p of series) {
	const files = [...fs.readFileSync(path.join(repo, 'patches', p), 'utf8').matchAll(/^\+\+\+ b\/(src\/\S+\.ts)$/gm)].map(m => path.join(src, m[1]));
	if (required[p] && !files.length) {
		problems.push(`${p}: named in patches/reach.json but touches no src/**/*.ts file, so nothing was checked`);
	}
	for (const f of files) {
		checked++;
		const rel = path.relative(src, f);
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
for (const pr of problems) {
	console.error(pr);
}
console.log(problems.length ? `check-patch-reach: ${problems.length} problem(s)` : `check-patch-reach: ok (${checked} patched files; ${reached.desktop.size} desktop, ${reached.server.size} server modules)`);
process.exit(problems.length ? 1 : 0);
