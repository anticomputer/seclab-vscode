// Test build variants (EDR test-build-variants): before any probe that needs a test-only hook
// runs, check that the artifact under test is that test build and actually carries the hook.
// A probe run against a build without its hook proves nothing (the rogue-REH probes never ran
// for that reason), so this refuses instead of letting the run look clean.
//   node test/builds/require-hooks.ts --variant V --hook ID [--hook ID ...] (--image IMAGE | --dir REH_DIR)
//   node test/builds/require-hooks.ts --self-test
// Exit 0 and one line on stdout when every hook is present; otherwise exit 1 with the reasons.

import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

const repo = path.resolve(import.meta.dirname, '../..');
const MANIFEST = path.join(repo, 'test/builds/variants.json');

interface Hook { id: string; patch: string; target: 'desktop' | 'reh'; marker: string }
interface TestBuild { variant?: unknown; target?: unknown; hooks?: Array<{ id?: unknown }> }

/** The manifest's hooks for a variant and target (the reviewed list). */
export function manifestHooks(variant: string, target: 'desktop' | 'reh', manifestFile = MANIFEST): Hook[] {
	const m = JSON.parse(fs.readFileSync(manifestFile, 'utf8')) as Record<string, { hooks?: Hook[] }>;
	if (!/^[a-z][a-z0-9-]{0,31}$/.test(variant) || !Object.hasOwn(m, variant)) {
		throw new Error(`unknown test variant ${JSON.stringify(variant)}`);
	}
	return (m[variant].hooks ?? []).filter(h => h.target === target);
}

/**
 * Problems with a REH as the artifact for these hooks: its product.json must record this
 * variant and each hook, and each hook's marker must be in its code. An empty list means usable.
 * `product` is the REH's product.json text; `hasMarker` searches its code.
 */
export function rehProblems(variant: string, wanted: string[], product: string | undefined, hasMarker: (marker: string) => boolean, manifestFile = MANIFEST): string[] {
	const problems: string[] = [];
	const hooks = manifestHooks(variant, 'reh', manifestFile);
	if (!wanted.length) {
		problems.push('no hook requested');
	}
	let tb: TestBuild | undefined;
	try {
		tb = product === undefined ? undefined : (JSON.parse(product) as { seclabTestBuild?: TestBuild }).seclabTestBuild;
	} catch {
		problems.push('product.json is not JSON');
	}
	if (!tb) {
		problems.push('not a test build (no seclabTestBuild in product.json): a release REH has no hooks');
	} else if (tb.variant !== variant || tb.target !== 'reh') {
		problems.push(`a test build of ${JSON.stringify(tb.variant)}/${JSON.stringify(tb.target)}, not ${variant}/reh`);
	}
	const recorded = new Set((tb?.hooks ?? []).map(h => h.id));
	for (const id of wanted) {
		const h = hooks.find(x => x.id === id);
		if (!h) {
			problems.push(`hook ${JSON.stringify(id)} is not a reh hook of ${variant} in test/builds/variants.json`);
			continue;
		}
		if (tb && !recorded.has(id)) {
			problems.push(`hook ${id} is not recorded in the REH's seclabTestBuild`);
		}
		if (!hasMarker(h.marker)) {
			problems.push(`hook ${id}: marker ${h.marker} is not in the REH's code (the hook is absent)`);
		}
	}
	return problems;
}

function grepTree(dir: string, marker: string): boolean {
	for (const e of fs.readdirSync(dir, { withFileTypes: true, recursive: true })) {
		if (e.isFile() && /\.(c|m)?js$/.test(e.name) && fs.readFileSync(path.join(e.parentPath, e.name)).includes(marker)) {
			return true;
		}
	}
	return false;
}

function check(variant: string, wanted: string[], where: { image?: string; dir?: string }): string[] {
	if (where.dir) {
		const p = path.join(where.dir, 'product.json');
		return rehProblems(variant, wanted, fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : undefined, m => grepTree(path.join(where.dir!, 'out'), m));
	}
	const image = where.image!;
	if (!/^[a-z0-9][a-z0-9._/-]*(:[A-Za-z0-9._-]+)?(@sha256:[0-9a-f]{64})?$/.test(image)) {
		return [`bad image reference ${JSON.stringify(image)}`];
	}
	// Read-only, no network, no tab code run: cat and grep in the image's own filesystem.
	const inImage = (script: string, ...args: string[]) => execFileSync('docker', ['run', '--rm', '--network', 'none', '--entrypoint', 'sh', '--', image, '-c', script, 'sh', ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
	let product: string | undefined;
	try {
		product = inImage('cat /opt/seclab-reh/product.json');
	} catch {
		product = undefined;
	}
	return rehProblems(variant, wanted, product, m => {
		try {
			return inImage('grep -rlaF -- "$1" /opt/seclab-reh/out | head -1', m).trim() !== '';
		} catch {
			return false;
		}
	});
}

function selfTest(): void {
	const assert = (c: boolean, msg: string) => {
		if (!c) {
			throw new Error(`self-test: ${msg}`);
		}
	};
	const dir = fs.mkdtempSync(path.join(repo, '.work', 'require-hooks-'));
	try {
		const mf = path.join(dir, 'variants.json');
		fs.writeFileSync(mf, JSON.stringify({ v: { hooks: [{ id: 'h', patch: 'test/x.patch', target: 'reh', marker: 'SECLAB_TEST_ONLY:h' }, { id: 'd', patch: 'test/d.patch', target: 'desktop', marker: 'SECLAB_TEST_ONLY:d' }] } }));
		const prod = (tb: unknown) => JSON.stringify({ nameShort: 'x', ...(tb ? { seclabTestBuild: tb } : {}) });
		const good = { variant: 'v', target: 'reh', hooks: [{ id: 'h' }] };
		assert(rehProblems('v', ['h'], prod(good), () => true, mf).length === 0, 'a test REH with its hook passes');
		assert(rehProblems('v', ['h'], prod(undefined), () => false, mf).some(p => p.includes('not a test build')), 'a release REH is refused');
		assert(rehProblems('v', ['h'], prod(good), () => false, mf).some(p => p.includes('hook is absent')), 'a recorded hook whose code is missing is refused');
		assert(rehProblems('v', ['h'], prod({ ...good, hooks: [] }), () => true, mf).some(p => p.includes('not recorded')), 'an unrecorded hook is refused');
		assert(rehProblems('v', ['h'], prod({ ...good, variant: 'w' }), () => true, mf).some(p => p.includes('not v/reh')), 'another variant is refused');
		assert(rehProblems('v', ['d'], prod(good), () => true, mf).some(p => p.includes('not a reh hook')), 'a desktop hook is not a REH hook');
		assert(rehProblems('v', [], prod(good), () => true, mf).length > 0, 'asking for no hook is refused');
		assert(rehProblems('v', ['h'], undefined, () => true, mf).some(p => p.includes('not a test build')), 'no product.json is refused');
		// The real manifest: the containment variant's rogue-REH hook is a REH hook.
		assert(manifestHooks('containment', 'reh').some(h => h.id === 'rogue-reh'), 'containment lists rogue-reh');
		// A REH directory on disk, end to end.
		const reh = path.join(dir, 'reh');
		fs.mkdirSync(path.join(reh, 'out', 'vs'), { recursive: true });
		fs.writeFileSync(path.join(reh, 'product.json'), prod({ variant: 'containment', target: 'reh', hooks: [{ id: 'rogue-reh' }] }));
		fs.writeFileSync(path.join(reh, 'out', 'vs', 'server.js'), 'x');
		assert(check('containment', ['rogue-reh'], { dir: reh }).some(p => p.includes('hook is absent')), 'dir without the marker is refused');
		fs.writeFileSync(path.join(reh, 'out', 'vs', 'server.js'), 'const h="[SECLAB_TEST_ONLY:rogue-reh-hook]";');
		assert(check('containment', ['rogue-reh'], { dir: reh }).length === 0, 'dir with the marker passes');
	} finally {
		fs.rmSync(dir, { recursive: true, force: true });
	}
	console.log('require-hooks self-test: ok');
}

if (import.meta.main) {
	const a = process.argv.slice(2);
	if (a[0] === '--self-test') {
		selfTest();
	} else {
		let variant = '';
		const hooks: string[] = [];
		const where: { image?: string; dir?: string } = {};
		for (let i = 0; i < a.length; i += 2) {
			const [k, v] = [a[i], a[i + 1] ?? ''];
			if (k === '--variant') { variant = v; } else if (k === '--hook') { hooks.push(v); } else if (k === '--image') { where.image = v; } else if (k === '--dir') { where.dir = v; } else {
				console.error(`unknown argument ${k}`);
				process.exit(2);
			}
		}
		if (!variant || !!where.image === !!where.dir) {
			console.error('usage: require-hooks.ts --variant V --hook ID... (--image IMAGE | --dir REH_DIR)');
			process.exit(2);
		}
		const problems = check(variant, hooks, where);
		if (problems.length) {
			console.error(`refusing: ${where.image ?? where.dir} cannot run ${variant} probes:\n  ${problems.join('\n  ')}`);
			process.exit(1);
		}
		console.log(`${where.image ?? where.dir}: ${variant} test build with ${hooks.join(', ')}`);
	}
}
