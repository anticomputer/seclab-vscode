// Import closure of a TS entry point (relative specifiers only), checked against the files a
// command mounts into its container. Commands that mount single files, to keep repo content out
// of a networked container (reviews DD-4, EE-2), break at run time when a new import is not
// mounted: deps-updates failed that way on its first scheduled run (ERR_MODULE_NOT_FOUND). The
// mounted code must equal the closure, so the lint also catches a widened mount (JJJ-1).
// Known misses (JJJ-4): template-literal dynamic imports. A miss fails at run time, closed.
// Usage: node build/import-closure.ts ENTRY -- MOUNTED...   (paths relative to the repo root)
//        node build/import-closure.ts --self-test

import * as fs from 'node:fs';
import * as path from 'node:path';

const SPEC = /(?:^|[\s;}])(?:import|export)\s[^'"`;]*?\bfrom\s*['"]([^'"]+)['"]|(?:^|[\s;(=[,!?:&|])import\s*\(\s*['"]([^'"]+)['"]\s*\)|(?:^|[\s;])import\s+['"]([^'"]+)['"]/g;

export function closure(root: string, entry: string): string[] {
	const seen = new Set<string>();
	const todo = [path.normalize(entry)];
	while (todo.length) {
		const rel = todo.pop()!;
		if (seen.has(rel)) {
			continue;
		}
		seen.add(rel);
		const src = fs.readFileSync(path.join(root, rel), 'utf8');
		for (const m of src.matchAll(SPEC)) {
			const s = m[1] ?? m[2] ?? m[3];
			if (s.startsWith('./') || s.startsWith('../')) {
				const next = path.normalize(path.join(path.dirname(rel), s));
				if (next.startsWith('..')) {
					throw new Error(`${rel}: import ${s} leaves the repo`);
				}
				todo.push(next);
			}
		}
	}
	return [...seen].sort();
}

export function missing(root: string, entry: string, mounted: string[]): string[] {
	const have = new Set(mounted.map(f => path.normalize(f)));
	return closure(root, entry).filter(f => !have.has(f));
}

/** Mounted code the entry never imports: a widened mount (JJJ-1). */
export function extra(root: string, entry: string, mounted: string[]): string[] {
	const need = new Set(closure(root, entry));
	return mounted.map(f => path.normalize(f)).filter(f => !need.has(f));
}

function selfTest(): void {
	const dir = fs.mkdtempSync(path.join(process.env.SECLAB_SCRATCH ?? path.resolve(import.meta.dirname, '../.work'), 'import-closure-'));
	try {
		fs.mkdirSync(path.join(dir, 'b'));
		fs.writeFileSync(path.join(dir, 'b/main.ts'), "import { a } from './a.ts';\nimport * as fs from 'node:fs';\nexport { c } from './c.ts';\nconst d = await import('./d.ts');\nexport const all = [import('./e.ts'),import('./f.ts')];\n");
		fs.writeFileSync(path.join(dir, 'b/a.ts'), "import './side.ts';\nexport const a = 1;\n");
		fs.writeFileSync(path.join(dir, 'b/c.ts'), 'export const c = 1;\n');
		fs.writeFileSync(path.join(dir, 'b/d.ts'), 'export {};\n');
		fs.writeFileSync(path.join(dir, 'b/e.ts'), 'export {};\n');
		fs.writeFileSync(path.join(dir, 'b/f.ts'), 'export {};\n');
		fs.writeFileSync(path.join(dir, 'b/side.ts'), 'export {};\n');
		fs.writeFileSync(path.join(dir, 'b/other.ts'), 'export {};\n');
		const all = ['b/a.ts', 'b/c.ts', 'b/d.ts', 'b/e.ts', 'b/f.ts', 'b/main.ts', 'b/side.ts'];
		const got = closure(dir, 'b/main.ts');
		if (JSON.stringify(got) !== JSON.stringify(all)) {
			throw new Error(`closure: got ${got.join(' ')}`);
		}
		if (missing(dir, 'b/main.ts', all).length || extra(dir, 'b/main.ts', all).length) {
			throw new Error('a complete mount list was rejected');
		}
		// Injected defects: one transitive import left out (the deps-updates failure), and a
		// mount the entry never imports (a widened container).
		const m = missing(dir, 'b/main.ts', all.filter(f => f !== 'b/side.ts'));
		if (JSON.stringify(m) !== '["b/side.ts"]') {
			throw new Error(`omission not caught: ${JSON.stringify(m)}`);
		}
		const x = extra(dir, 'b/main.ts', [...all, 'b/other.ts']);
		if (JSON.stringify(x) !== '["b/other.ts"]') {
			throw new Error(`extra mount not caught: ${JSON.stringify(x)}`);
		}
	} finally {
		fs.rmSync(dir, { recursive: true, force: true });
	}
	console.log('import-closure self-test: ok');
}

if (import.meta.main) {
	const args = process.argv.slice(2);
	if (args[0] === '--self-test') {
		selfTest();
	} else {
		const sep = args.indexOf('--');
		if (sep !== 1) {
			console.error('usage: import-closure.ts ENTRY -- MOUNTED... | --self-test');
			process.exit(2);
		}
		const m = missing(process.cwd(), args[0], args.slice(2));
		const x = extra(process.cwd(), args[0], args.slice(2));
		if (m.length || x.length) {
			if (m.length) {
				console.error(`import-closure: ${args[0]} imports files its container does not mount: ${m.join(' ')}`);
			}
			if (x.length) {
				console.error(`import-closure: ${args[0]}'s container mounts code it never imports: ${x.join(' ')}`);
			}
			process.exit(1);
		}
		console.log(`import-closure: ${args[0]}: ok (${closure(process.cwd(), args[0]).length} files)`);
	}
}
