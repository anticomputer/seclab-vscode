// Fixture-safety lint (EDR fixture-safety). Scans test fixtures, probes and harness code
// for things a payload must never do even if containment fails:
//   - read real host secrets/profiles (~/.ssh, ~/.aws, keychain, browser/editor profiles)
//   - talk to non-test hosts (only loopback, our broker, RFC 5737/private test nets,
//     reserved *.test / *.invalid / *.example / *.localhost names)
//   - persist, delete broadly, download-and-execute or change host settings
//   - carry token-shaped literals (real credential formats)
// Usage: node test/safety/fixture-lint.ts [PATH...]    (default: test sandbox broker/tests)
// Exit 0 clean, 1 violations ("file:line: rule: ..."). A line may opt out of one rule
// with a reason:   fixture-lint: allow <rule> -- <reason>

import * as fs from 'node:fs';
import * as path from 'node:path';

const repo = path.resolve(import.meta.dirname, '../..');
const args = process.argv.slice(2);
const roots = (args.length ? args : ['test', 'sandbox', 'broker/tests']).map(p => path.resolve(repo, p));
const SKIP_DIRS = new Set(['node_modules', '.git', '.work', '__pycache__', '.venv']);
const TEXT = /\.(ts|js|mjs|cjs|json|jsonc|sh|py|toml|ya?ml|md|txt|env|cfg|ini|conf)$|(^|\/)(probe\.sh|fake-python|Dockerfile[^/]*)$/;

interface Rule { id: string; re: RegExp; why: string }
const RULES: Rule[] = [
	{ id: 'host-secret-path', why: 'reads real host secrets/profiles',
		re: /(~|\$HOME|\$\{HOME\}|homedir\(\)|\/Users\/[^/\s'"]+|\/home\/[^/\s'"]+)[^\n]{0,8}\/\.(ssh|aws|gnupg|kube|netrc|npmrc|pypirc|git-credentials)\b|Library\/Keychains|login\.keychain|\bsecurity\s+(find|dump|export)-|Library\/Application Support\/(Code|Cursor|Google|Chrome|Firefox|BraveSoftware|Microsoft Edge|GitHub Copilot)|Library\/Cookies/ },
	{ id: 'persistence', why: 'persists or changes host settings',
		re: /\blaunchctl\b|LaunchAgents\/|LaunchDaemons|\bcrontab\b|\bdefaults\s+write\b|\bosascript\b|>>?\s*\S*\/\.(zshrc|bashrc|bash_profile|profile|zprofile)\b|\bsystemctl\s+(enable|start)\b|\bcsrutil\b/ },
	{ id: 'destructive', why: 'broad delete outside the run dir',
		re: /\brm\s+-[a-z]*r[a-z]*\s+(\/|~|\$HOME|\/Users|\/home)(\s|$|\/\s)|rmSync\(\s*(os\.homedir\(\)|process\.env\.HOME|['"`]\/['"`])/ },
	{ id: 'token-literal', why: 'token-shaped literal (real credential format)',
		re: /\b(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,}|AKIA[0-9A-Z]{16}|xox[abposr]-[A-Za-z0-9-]{10,}|sk-(proj-|ant-)?[A-Za-z0-9_-]{32,}|AIza[0-9A-Za-z_-]{35}|glpat-[A-Za-z0-9_-]{20})\b/ },
	{ id: 'download-exec', why: 'download-and-execute',
		re: /\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh|python3?|node)\b/ },
];

// Network: every URL host must be a test-owned target.
const URL_RE = /\b(?:https?|wss?|ftp):\/\/(?:[^@\s/]*@)?(\[[0-9a-f:]+\]|[A-Za-z0-9.-]+|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?)/gi;
function allowedHost(h: string): boolean {
	const host = h.toLowerCase().replace(/^\[|\]$/g, '');
	if (host.startsWith('$')) {
		return true; // a variable: the target is configured by the harness
	}
	if (['localhost', 'broker', 'host.docker.internal', 'gateway.docker.internal', '::1', '0.0.0.0'].includes(host)) {
		return true;
	}
	return /^127\./.test(host)
		|| /^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d+$/.test(host) // RFC 5737
		|| /^(10|172\.(1[6-9]|2\d|3[01])|192\.168|11\.250)\./.test(host) // private / broker test nets
		|| /(^|\.)(test|invalid|example|localhost)$/.test(host); // RFC 2606 reserved names
}

const violations: string[] = [];
function lintFile(file: string): void {
	const rel = path.relative(repo, file);
	if (rel === path.join('test', 'safety', 'fixture-lint.ts')) {
		return; // the rules themselves
	}
	fs.readFileSync(file, 'utf8').split('\n').forEach((line, i) => {
		const allow = /fixture-lint: allow ([a-z-]+) -- \S/.exec(line)?.[1];
		for (const r of RULES) {
			if (allow !== r.id && r.re.test(line)) {
				violations.push(`${rel}:${i + 1}: ${r.id}: ${r.why}: ${line.trim().slice(0, 120)}`);
			}
		}
		for (const m of line.matchAll(URL_RE)) {
			if (allow !== 'non-test-host' && !allowedHost(m[1])) {
				violations.push(`${rel}:${i + 1}: non-test-host: ${m[1]}: ${line.trim().slice(0, 120)}`);
			}
		}
	});
}
function walk(p: string): void {
	let st: fs.Stats;
	try {
		st = fs.lstatSync(p);
	} catch {
		return;
	}
	if (st.isDirectory()) {
		if (!SKIP_DIRS.has(path.basename(p))) {
			for (const e of fs.readdirSync(p)) {
				walk(path.join(p, e));
			}
		}
	} else if (st.isFile() && st.size < 2 << 20 && TEXT.test(p)) {
		lintFile(p);
	}
}
for (const r of roots) {
	walk(r);
}
for (const v of violations) {
	console.log(v);
}
console.log(violations.length ? `fixture-lint: ${violations.length} violation(s)` : 'fixture-lint: clean');
process.exit(violations.length ? 1 : 0);
