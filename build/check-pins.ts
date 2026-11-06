// Pin check (EDR ci-hardening): every third-party container image and GitHub Action the
// repo runs is pinned by digest, so a moved tag can't change what CI or a developer runs.
//   node build/check-pins.ts            (via ./seclab lint pins; exit 0 clean, 1 findings)
// Checks tracked text files for:
//   - Dockerfile `FROM` without @sha256 (stage names and `scratch` excepted);
//   - workflow `uses:` not pinned to a 40-hex commit (local ./ actions excepted), and
//     `docker://` uses, `container:`/`image:` keys without @sha256;
//   - external image references (`repo:tag`) anywhere in code without @sha256. External =
//     a registry host, or a Docker Hub library/org image we know of. Locally built images
//     (seclab-*:local etc.) are built from pinned bases and are allowed;
//   - URLs to public package registries this Mac blocks (npm, Yarn, PyPI files) in code:
//     local installs and lookups go through CFS, so each must be marked as a non-fetch.
// The sbx `shell` kit is pinned by the sbx version, not here (sbx manages it).

import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

const repo = path.resolve(import.meta.dirname, '..');
// File list (argv[2]): NUL-separated paths from `git ls-files -z`, passed as a file because
// the container may not see the git dir of a worktree; else git directly.

const DIGEST = /@sha256:[0-9a-f]{64}/;
const HUB = 'node|alpine|nginx|debian|ubuntu|python|busybox|golang|rust|buildpack-deps|docker|mitmproxy/mitmproxy|lycheeverse/lychee|rhysd/actionlint|koalaman/shellcheck|hadolint/hadolint';
// `repo:tag` where repo is a registry path or a known Docker Hub image; node:<builtin> is not an image.
const IMAGE = new RegExp(`(?<![\\w./-])((?:(?:ghcr\\.io|docker\\.io|quay\\.io|mcr\\.microsoft\\.com|gcr\\.io|public\\.ecr\\.aws|registry\\.[a-z0-9.-]+)/[a-z0-9._/-]+|(?:${HUB}))):([A-Za-z0-9][A-Za-z0-9._-]*)(@sha256:[0-9a-f]{64})?`, 'g');
// Images we build locally from pinned bases (and runtime-provided template names).
const LOCAL_IMAGE = /^seclab-[a-z0-9-]+(:[A-Za-z0-9._-]+)?$/;
// docker run/create/pull options that take a separate value.
const OPTS_WITH_VALUE = new Set(['-v', '--volume', '-e', '--env', '--env-file', '-w', '--workdir', '-p', '--publish', '--name', '--network', '--net',
	'-u', '--user', '--mount', '--entrypoint', '-l', '--label', '--tmpfs', '--platform', '--cap-add', '--cap-drop', '--security-opt', '-m', '--memory',
	'--pids-limit', '--runtime', '-h', '--hostname', '--network-alias', '--add-host', '--cpus', '--ulimit', '--device', '--group-add', '--ipc', '--pid',
	'--restart', '--shm-size', '--stop-signal', '--stop-timeout', '--log-driver', '--log-opt', '--dns', '--expose', '--cidfile', '--init-path', '--userns', '--uts',
	'--pull', '--gpus', '-a', '--attach', '--volumes-from', '--link', '--sysctl', '--cpuset-cpus', '--health-cmd', '--health-interval', '--cgroupns',
	'--storage-opt', '--tmpfs', '--mac-address', '--ip', '--ip6', '--isolation', '--kernel-memory', '--memory-swap', '--oom-score-adj']);
function checkText(f: string, text: string): string[] {
	const findings = new Set<string>();
	const isDockerfile = /(^|\/)Dockerfile[^/]*$/.test(f);
	const isWorkflow = /(^|\/)\.github\/(workflows|actions)\/.*\.ya?ml$/.test(f);
	const stages = new Set<string>();
	// Logical lines: backslash continuations are joined (multi-line `docker run \`), reported
	// at their first line.
	const logical: Array<[number, string]> = [];
	const raw = text.split('\n');
	for (let i = 0; i < raw.length; i++) {
		let l = raw[i];
		const start = i;
		while (/\\\s*$/.test(l) && i + 1 < raw.length && !/\.(ts|js|mjs|cjs)$/.test(f)) {
			l = l.replace(/\\\s*$/, ' ') + raw[++i];
		}
		logical.push([start, l]);
	}
	logical.forEach(([i, line]) => {
		const at = `${f}:${i + 1}`;
		const code = line.replace(/^\s*#.*$/, '');
		if (isDockerfile) {
			const m = /^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?/i.exec(code);
			if (m) {
				if (!DIGEST.test(m[1]) && m[1] !== 'scratch' && !stages.has(m[1].toLowerCase())) {
					findings.add(`${at}: FROM ${m[1]} is not pinned by digest`);
				}
				if (m[2]) {
					stages.add(m[2].toLowerCase());
				}
				return;
			}
		}
		if (isWorkflow) {
			const u = /^\s*-?\s*uses:\s*['"]?([^'"\s#]+)/.exec(code);
			if (u && !u[1].startsWith('./')) {
				if (u[1].startsWith('docker://') ? !DIGEST.test(u[1]) : !/@[0-9a-f]{40}$/.test(u[1])) {
					findings.add(`${at}: uses ${u[1]} is not pinned to a commit SHA / digest`);
				}
				return;
			}
			const img = /^\s*(?:image|container):\s*['"]?([^'"\s#]+)/.exec(code);
			if (img && !DIGEST.test(img[1])) {
				findings.add(`${at}: ${img[1]} is not pinned by digest${img[1].includes('${{') ? ' (expression-valued image keys are not allowed)' : ''}`);
				return;
			}
		}
		// Shell-style `docker run|create|pull … IMAGE`: the first non-option argument is the
		// image, tagged or not, from any registry (CI-2b). Variables ("$IMG", $(node_image))
		// are resolved where they are defined, which this check covers too.
		if (!/\.(ts|js|mjs|cjs)$/.test(f)) {
			for (const dm of code.matchAll(/\bdocker\s+(?:container\s+)?(?:run|create|pull)\b([^;&|`]*)/g)) {
				const toks = dm[1].trim().split(/\s+/).filter(Boolean);
				let image: string | undefined;
				for (let k = 0; k < toks.length; k++) {
					const t = toks[k];
					if (t === '\\' || t === '--') {
						continue;
					}
					if (t.startsWith('-')) {
						if (!t.includes('=') && OPTS_WITH_VALUE.has(t)) {
							k++;
						}
						continue;
					}
					image = t.replace(/^['"]|['"]$/g, '');
					break;
				}
				if (image && !/^\$/.test(image) && !DIGEST.test(image) && !LOCAL_IMAGE.test(image)) {
					findings.add(`${at}: docker image ${image} is not pinned by digest`);
				}
			}
		}
		for (const m of code.matchAll(IMAGE)) {
			if (!m[3] && !(m[1] === 'node' && !/^\d/.test(m[2])) && ![...findings].some(x => x.startsWith(`${at}: docker image ${m[1]}:${m[2]} `))) {
				findings.add(`${at}: image ${m[1]}:${m[2]} is not pinned by digest`);
			}
		}
	});
	// Public package registries this Mac blocks (AGENTS.md: local npm/pip go through CFS, never
	// around it). A URL to one in code is a potential direct fetch; each must state why it isn't
	// one (a comparison, a canonical `resolved` rewritten at fetch time, a CI-only path) with
	// `public-registry: <reason>` on its line. Lockfiles and prose are out of scope.
	if (!/(^|\/)(package-lock\.json|[^/]*\.lock|[^/]*\.md)$/.test(f) && !PUBLIC_REGISTRY_FILES.has(f)) {
		raw.forEach((line, i) => {
			if (PUBLIC_REGISTRY.test(line) && !/public-registry: \S/.test(line) && !PUBLIC_REGISTRY_COMPARE.test(line)) {
				findings.add(`${f}:${i + 1}: URL to a public package registry (local installs and lookups go through CFS; mark a non-fetch use with "public-registry: <reason>")`);
			}
		});
	}
	return [...findings];
}
const PUBLIC_REGISTRY = /https?:\/\/(registry\.npmjs\.org|registry\.yarnpkg\.com|files\.pythonhosted\.org)\b/;
// A prefix comparison of a lockfile's `resolved` (an origin check, not a fetch).
const PUBLIC_REGISTRY_COMPARE = /startsWith\(\s*["'`]https?:\/\/(registry\.npmjs\.org|registry\.yarnpkg\.com|files\.pythonhosted\.org)\//;
// Writes the canonical `resolved` URL into lockfiles, rewritten to CFS at fetch time
// (EDR cfs-local-builds); its bytes key the npm cache, so it carries no inline markers.
const PUBLIC_REGISTRY_FILES = new Set(['build/linux/lock-fill.mjs']);

/** Markdown: only the blocks CI executes (`<!-- ci: run -->` fenced shell), line numbers kept. */
function ciRunBlocks(text: string): string {
	const keep = new Set<number>();
	const lines = text.split('\n');
	for (let i = 0; i < lines.length; i++) {
		if (/<!-- ci: run -->/.test(lines[i]) && /^```(sh|bash|shell)\s*$/.test(lines[i + 1] ?? '')) {
			for (let j = i + 2; j < lines.length && !/^```\s*$/.test(lines[j]); j++) {
				keep.add(j);
			}
		}
	}
	return lines.map((l, i) => keep.has(i) ? l : '').join('\n');
}

if (process.argv[2] === '--self-test') {
	const pin = `@sha256:${'0'.repeat(64)}`;
	const cases: Array<[string, string, number]> = [
		['Dockerfile', `FROM alpine:3.22\nFROM x${pin} AS base\nFROM base\nFROM scratch\n`, 1],
		['.github/workflows/x.yml', `steps:\n  - uses: actions/checkout@v4\n  - uses: actions/checkout@${'a'.repeat(40)} # v4\n  - uses: docker://alpine:3\n    container: node:22\n  - uses: ./local\n`, 3],
		['x.ts', `run(["nginx:alpine", "ghcr.io/a/b:1", "node:24${pin}", "seclab-tab:local"]); import "node:fs";\n`, 2],
		['x.sh', `docker run --rm debian:trixie-slim true # node:22 in a comment line still counts\n`, 2],
		// CI-2: untagged, unlisted Docker Hub, multi-line, variables and local images
		['y.sh', `docker run --rm alpine sh\ndocker run -d -v a:/b --name x postgres:16\ndocker pull curlimages/curl:8\ndocker run --rm \\\n  -e X=1 \\\n  redis:7 true\ndocker run --rm "$IMG" x\ndocker run --rm seclab-tab-oci:local x\ndocker run --rm alpine${pin} x\n`, 4],
		['.github/workflows/y.yml', `jobs:\n  a:\n    container: \${{ matrix.img }}\n    services:\n      db:\n        image: postgres\n`, 2],
		['AGENTS.md', 'prose mentions alpine:3.22 freely\n<!-- ci: run -->\n```sh\ndocker run --rm alpine:3 true\n```\n', 1],
		// Direct public-registry URLs: a fetch fails; a marked line, a prefix comparison, a lockfile and prose pass.
		['z.ts', 'await fetch(`https://registry.npmjs.org/${n}`);\nfetch("https://files.pythonhosted.org/x");\nconst u = "https://registry.yarnpkg.com/a"; // public-registry: fixture\nif (r.startsWith("https://registry.npmjs.org/")) {}\n', 2],
		['package-lock.json', '"resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz"\n', 0],
		['NOTES.md', 'see https://registry.npmjs.org/\n', 0],
	];
	const bad = cases.filter(([f, t, n]) => checkText(f, f.endsWith('.md') ? ciRunBlocks(t) : t).length !== n)
		.map(([f, t, n]) => `${f}: expected ${n}, got ${JSON.stringify(checkText(f, f.endsWith('.md') ? ciRunBlocks(t) : t))}`);
	console.log(bad.length ? bad.join('\n') : `check-pins self-test: ${cases.length} cases OK`);
	process.exit(bad.length ? 1 : 0);
}

// Everything tracked except binaries and generated patches; Markdown contributes only the
// blocks CI executes (CI-2a). Fixture workspaces are hostile payloads (fixture-lint's job).
const files = (process.argv[2] ? fs.readFileSync(process.argv[2] === '-' ? 0 : process.argv[2], 'utf8') : execFileSync('git', ['-C', repo, 'ls-files', '-z'], { encoding: 'utf8' }))
	.split('\0').filter(Boolean)
	.filter(f => !/\.(png|jpe?g|gif|svg|lock|patch)$/.test(f) && !f.includes('/fixtures/') && !['build/check-pins.ts', 'build/deps.ts', 'deps/registry.json', 'broker/tools/supplychain.py'].includes(f)); // rules and their samples (incl. the broker's supply-chain self-test), and the register's names (its pins are checked by build/deps.ts)
const findings: string[] = [];
// The broker's supply-chain checker is skipped as samples; it must stay a pure parser (GG-1):
// if it ever executes anything, its image references need this check again.
try {
	if (/subprocess|\bos\.(system|exec\w*|popen|spawn\w*)\b|\bfrom\s+os\s+import\b|__import__|\bimportlib\b|\bpty\b|\bctypes\b/.test(fs.readFileSync(path.join(repo, 'broker/tools/supplychain.py'), 'utf8'))) {
		findings.push('broker/tools/supplychain.py: executes processes, so it can no longer be skipped as samples (narrow the skip)');
	}
} catch { /* absent */ }
for (const f of files) {
	let text: string;
	try {
		text = fs.readFileSync(path.join(repo, f), 'utf8');
	} catch {
		continue;
	}
	if (!text.includes('\0')) {
		findings.push(...checkText(f, f.endsWith('.md') ? ciRunBlocks(text) : text));
	}
}
for (const x of findings) {
	console.log(x);
}
console.log(findings.length ? `check-pins: ${findings.length} unpinned reference(s)` : `check-pins: clean (${files.length} files)`);
process.exit(findings.length ? 1 : 0);
