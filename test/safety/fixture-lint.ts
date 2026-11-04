// Fixture-safety lint (EDR fixture-safety). Scans test fixtures, probes and harness code
// for things a payload must never do even if containment fails:
//   - read real host secrets/profiles (~/.ssh, ~/.aws, keychain, browser/editor profiles)
//   - talk to non-test hosts (only loopback, our broker, RFC 5737/private test nets,
//     reserved *.test / *.invalid / *.example / *.localhost names)
//   - persist, delete broadly, download-and-execute or change host settings
//   - carry token-shaped literals (real credential formats)
// Usage: node test/safety/fixture-lint.ts [PATH...]    (default: test sandbox broker/tests)
// Exit 0 clean, 1 violations ("file:line: rule: ..."), 2 an explicit PATH does not exist
// (so a typo or a tree without that dir can never report "clean"). A line may opt out of one rule
// with a reason:   fixture-lint: allow <rule> -- <reason>

import * as fs from 'node:fs';
import * as net from 'node:net';
import * as path from 'node:path';

const repo = path.resolve(import.meta.dirname, '../..');
const selfTest = process.argv[2] === '--self-test';
const args = selfTest ? [] : process.argv.slice(2);
const roots: string[] = [];
for (const p of args.length ? args : ['test', 'sandbox', 'broker/tests']) {
	const abs = path.resolve(repo, p);
	if (fs.existsSync(abs)) {
		roots.push(abs);
	} else if (args.length) {
		console.error(`fixture-lint: no such path: ${p}`);
		process.exit(2);
	} else {
		console.log(`fixture-lint: default root absent, skipped: ${p}`);
	}
}
let scanned = 0;
const SKIP_DIRS = new Set(['node_modules', '.git', '.work', '__pycache__', '.venv']);
const TEXT = /\.(ts|js|mjs|cjs|json|jsonc|sh|py|toml|ya?ml|md|txt|env|cfg|ini|conf)$|(^|\/)(probe\.sh|fake-python|Dockerfile[^/]*)$/;

interface Rule { id: string; re: RegExp; why: string }
const RULES: Rule[] = [
	{ id: 'host-secret-path', why: 'reads real host secrets/profiles',
		re: /(~|\$HOME|\$\{HOME\}|homedir\(\)|\/Users\/[^/\s'"]+|\/home\/[^/\s'"]+)[^\n]{0,8}\/\.(ssh|aws|gnupg|kube|netrc|npmrc|pypirc|git-credentials)\b|(homedir\(\)|process\.env\.HOME|env\.HOME)[^\n]*['"`]\.(ssh|aws|gnupg|kube|netrc|npmrc|pypirc|git-credentials|docker)['"`/]|Library\/Keychains|login\.keychain|\bsecurity\s+(find|dump|export)-|Library\/Application Support\/(Code|Cursor|Google|Chrome|Firefox|BraveSoftware|Microsoft Edge|GitHub Copilot)|Library\/Cookies/ },
	{ id: 'persistence', why: 'persists or changes host settings',
		re: /\blaunchctl\b|LaunchAgents\/|LaunchDaemons|\bcrontab\b|\bdefaults\s+write\b|\bosascript\b|>>?\s*\S*\/\.(zshrc|bashrc|bash_profile|profile|zprofile)\b|\bsystemctl\s+(enable|start)\b|\bcsrutil\b/ },
	{ id: 'destructive', why: 'broad delete outside the run dir',
		re: /\brm\s+-[a-z]*r[a-z]*\s+(\/|~|\$HOME|\/Users|\/home)(\s|$|\/\s)|rmSync\(\s*(os\.homedir\(\)|process\.env\.HOME|['"`]\/['"`])/ },
	{ id: 'token-literal', why: 'token-shaped literal (real credential format)',
		re: /\b(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,}|AKIA[0-9A-Z]{16}|xox[abposr]-[A-Za-z0-9-]{10,}|sk-(proj-|ant-)?[A-Za-z0-9_-]{32,}|AIza[0-9A-Za-z_-]{35}|glpat-[A-Za-z0-9_-]{20})\b/ },
	{ id: 'download-exec', why: 'download-and-execute',
		re: /\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh|python3?|node)\b|<\(\s*(curl|wget)\b|\b(sh|bash|zsh)\s+-c\s+["'`]?\$\(\s*(curl|wget)\b/ },
];

// Network: every URL host must be a test-owned target. IPs are validated as literal IPs
// (no prefix tricks like 127.evil.example.com), and only loopback, RFC 5737 and the
// broker's own test net count; general LAN ranges are the developer's real network.
const URL_RE = /\b(?:https?|wss?|ftp):\/\/(?:[^@\s/]*@)?(\[[0-9a-f:]+\]|[A-Za-z0-9.-]+|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?)/gi;
// Scheme-less hosts handed to curl/wget (e.g. `curl evil.example.com/x`).
const BARE_RE = /\b(?:curl|wget)\b[^\n|;&]*?\s((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})(?=[/:\s'"`]|$)/g;
function allowedHost(h: string): boolean {
	const host = h.toLowerCase().replace(/^\[|\]$/g, '');
	if (host.startsWith('$')) {
		return true; // a variable: the target is configured by the harness
	}
	if (['localhost', 'broker', 'host.docker.internal', 'gateway.docker.internal'].includes(host)) {
		return true;
	}
	const ipv = net.isIP(host);
	if (ipv === 4) {
		return /^127\./.test(host) || /^(192\.0\.2|198\.51\.100|203\.0\.113|11\.250)\./.test(host) || host === '0.0.0.0';
	}
	if (ipv === 6) {
		return host === '::1';
	}
	return /(^|\.)(test|invalid|example|localhost)$/.test(host); // RFC 2606 reserved names
}

// Per-line opt-outs only count if also listed (file:rule) in this reviewed file.
const ALLOWLIST = (() => {
	try {
		return new Set(fs.readFileSync(path.join(import.meta.dirname, 'allowlist.txt'), 'utf8').split('\n').map(l => l.replace(/#.*/, '').trim()).filter(Boolean));
	} catch {
		return new Set<string>();
	}
})();

const violations: string[] = [];
function lintLine(rel: string, line: string, n: number): string[] {
	const out: string[] = [];
	const optOut = /fixture-lint: allow ([a-z-]+) -- \S/.exec(line)?.[1];
	const allow = optOut && ALLOWLIST.has(`${rel}:${optOut}`) ? optOut : undefined;
	for (const r of RULES) {
		if (allow !== r.id && r.re.test(line)) {
			out.push(`${rel}:${n}: ${r.id}: ${r.why}: ${line.trim().slice(0, 120)}`);
		}
	}
	// Template segments that are part of a hostname (`d{i}.x.example.test`,
	// `${sub}.evil.com`) become a placeholder label, so the real suffix is checked; one
	// that only trails a hostname (`api.example.test{path}`) is a path. A standalone
	// `${HOST}` stays a variable (configured by the harness).
	const hosty = line.replace(/\$?\{[^{}\s]*\}(?=[A-Za-z0-9.-])/g, 'x').replace(/(?<=[A-Za-z0-9.-])\$?\{[^{}\s]*\}/g, '/');
	for (const m of [...hosty.matchAll(URL_RE), ...hosty.matchAll(BARE_RE)]) {
		if (allow !== 'non-test-host' && !allowedHost(m[1])) {
			out.push(`${rel}:${n}: non-test-host: ${m[1]}: ${line.trim().slice(0, 120)}`);
		}
	}
	return out;
}
function lintFile(file: string): void {
	const rel = path.relative(repo, file);
	if (rel === path.join('test', 'safety', 'fixture-lint.ts')) {
		return; // the rules themselves
	}
	scanned++;
	fs.readFileSync(file, 'utf8').split('\n').forEach((line, i) => violations.push(...lintLine(rel, line, i + 1)));
}
if (selfTest) {
	// Hosts in templates (broker report): the real suffix is what counts.
	const cases: Array<[string, number]> = [
		['u = f"https://d{i}.x.example.test"', 0], ['w = `https://${HOST}/ok`', 0], ['q = "https://{host}/p"', 0],
		['p = f"https://api.example.test{path}"', 0], ['h = "http://x/"', 1], ['v = `https://${sub}.evil.com/x`', 1],
		['z = f"https://evil{n}.com"', 1], ['e = f"https://evil.com{path}"', 1], ['curl evil.example.test/x', 0], ['curl evil.example.com/x', 1],
	];
	const bad = cases.filter(([l, n]) => lintLine('self-test', l, 1).length !== n).map(([l, n]) => `expected ${n}: ${l} -> ${JSON.stringify(lintLine('self-test', l, 1))}`);
	console.log(bad.length ? bad.join('\n') : `fixture-lint self-test: ${cases.length} cases OK`);
	process.exit(bad.length ? 1 : 0);
}
const FIXTURE_DIR = path.join(repo, 'test', 'containment', 'fixtures');
function walk(p: string): void {
	let st: fs.Stats;
	try {
		st = fs.lstatSync(p);
	} catch {
		return;
	}
	const inFixtures = p.startsWith(FIXTURE_DIR + path.sep);
	if (st.isDirectory()) {
		// Fixture trees are linted whole: a payload can hide in any file name.
		if (inFixtures || !SKIP_DIRS.has(path.basename(p))) {
			for (const e of fs.readdirSync(p)) {
				walk(path.join(p, e));
			}
		}
	} else if (st.isFile() && st.size < 2 << 20 && (inFixtures || TEXT.test(p))) {
		lintFile(p);
	}
}
for (const r of roots) {
	walk(r);
}
for (const v of violations) {
	console.log(v);
}
console.log(violations.length ? `fixture-lint: ${violations.length} violation(s) in ${scanned} file(s)` : `fixture-lint: clean (${scanned} file(s))`);
process.exit(violations.length ? 1 : 0);
