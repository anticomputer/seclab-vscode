// Differential test: our port of gitleaks' rule decision (seclabSecretScan.ts, patch 0036) against
// the pinned gitleaks binary, on the same lines. sample.ts builds the lines at run time from each
// rule's own pattern, as settings-shaped `"key": "value"` lines, plus negatives. Nothing generated
// is committed: the corpus lives in a .work dir for the run only and is deleted afterwards. Both
// sides run in containers with --network none.
//   node build/secret-rules/differential.ts DIR   # DIR holds the patch's seclabSecretScan.ts and seclabSecretRules.ts
// Exit 0 when every line gets the same verdict (hit or no hit); prints disagreements otherwise.

import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

const repo = path.resolve(import.meta.dirname, '../..');
const src = path.resolve(process.argv[2] ?? '.');
const NODE_IMAGE = 'node:24.22.1-trixie@sha256:f1e034976f948cf212ef1f659c12e5dd58ac7eab947831813e81a62401ca38be';
fs.mkdirSync(path.join(repo, '.work'), { recursive: true });
const work = fs.mkdtempSync(path.join(repo, '.work', 'secret-diff-'));
const user = `${process.getuid!()}:${process.getgid!()}`;
try {
	for (const f of ['seclabSecretScan.ts', 'seclabSecretRules.ts']) {
		fs.writeFileSync(path.join(work, f), fs.readFileSync(path.join(src, f), 'utf8').replaceAll("from './seclabSecretRules.js'", "from './seclabSecretRules.ts'"));
	}
	fs.copyFileSync(path.join(import.meta.dirname, 'sample.ts'), path.join(work, 'sample.ts'));
	execFileSync('docker', ['run', '--rm', '--network', 'none', '--user', user, '-v', `${work}:/w`, '-w', '/w', NODE_IMAGE, 'node', 'sample.ts'], { stdio: 'inherit' });
	const gitleaks = execFileSync(path.join(repo, 'seclab'), ['tool', 'gitleaks'], { encoding: 'utf8' }).trim().split('\n').pop()!;
	try {
		// Decoding off: the port doesn't decode base64/hex/percent segments (EDR, residuals).
		execFileSync('docker', ['run', '--rm', '--network', 'none', '--user', user, '-v', `${work}:/w`, gitleaks,
			'dir', '/w/corpus.txt', '--no-banner', '--no-color', '--redact=100', '--max-decode-depth', '0', '--report-format', 'json', '--report-path', '/w/theirs.json'], { stdio: 'ignore' });
	} catch { /* exit 1 = leaks found */ }
	const lines = fs.readFileSync(path.join(work, 'corpus.txt'), 'utf8').split('\n').filter(Boolean);
	const ours: Array<string | null> = JSON.parse(fs.readFileSync(path.join(work, 'ours.json'), 'utf8'));
	const theirs = new Map<number, string>();
	for (const f of JSON.parse(fs.readFileSync(path.join(work, 'theirs.json'), 'utf8')) as Array<{ StartLine: number; RuleID: string }>) {
		theirs.set(f.StartLine, f.RuleID);
	}
	const diff: string[] = [];
	lines.forEach((l, n) => {
		const a = ours[n];
		const b = theirs.get(n + 1) ?? null;
		if (!!a !== !!b) {
			diff.push(`line ${n + 1} (${l.slice(1, l.indexOf('"', 1))}): ours=${a} gitleaks=${b}`);
		}
	});
	console.log(`${lines.length} lines; ours hit ${ours.filter(Boolean).length}, gitleaks hit ${theirs.size}; ${diff.length} disagree`);
	if (diff.length) {
		console.log(diff.slice(0, 60).join('\n'));
	}
	process.exitCode = diff.length ? 1 : 0;
} finally {
	fs.rmSync(work, { recursive: true, force: true });
}
