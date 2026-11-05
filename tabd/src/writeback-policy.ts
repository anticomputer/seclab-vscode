// Write-back gate policy (ADR 20261104-write-back-gate). Reviewed DATA: a change here needs a
// security-review round. Paths are workspace-relative and posix-style. `held`, `tabLocal` and
// `neverAlways` patterns match at ANY directory depth (review Z-2: `.claude/**` also matches
// `pkg/x/.claude/settings.json`), after Unicode folding and lowercasing (APFS is
// case-insensitive and normalising, so `.Git/hooks` and `.VSCODE/` must hold too); `gitAuto`
// must match exactly, at the root.
// Glob: `*` matches within one segment, `**` any number of segments.

/**
 * Files that steer host-side coding agents and IDEs: instructions are prompt injection; hooks,
 * skills, settings and MCP servers are commands the agent runs with host shell access (review
 * X-1, Y-1: Copilot loads `.github/hooks/*.json` and `.github/skills/**`). Held, and "Always
 * allow" is never offered for them (Y-6: one list, so held and neverAlways can't drift).
 */
const AGENT_AND_IDE = [
	'**/agents.md', '**/agent.md', '**/claude.md', '**/gemini.md', '.github/**', '.agents/**',
	'.cursorrules', '.windsurfrules', '.cursor/**', '.claude/**', '.mcp.json', '**/.mcp.json',
	'.gemini/**', '.codex/**', '.copilot/**', '.aider*', '.continue/**', '.roo/**', '.clinerules', '.clinerules/**', '.kiro/**', '.amazonq/**',
	'opencode.json', 'opencode.jsonc', '.opencode/**', '.junie/**', '.goosehints',
	'.vscode/**', '*.code-workspace', '.devcontainer/**', '.devcontainer.json', '.envrc', '**/.envrc',
	'.idea/**', '.fleet/**', '.zed/**', '.vs/**', '.theia/**',
];

export const WRITEBACK_POLICY = {
	version: 4,
	/**
	 * Under the ROOT .git/ only these are copied back automatically (exact match; review
	 * W-8: no objects/info, alternates). Everything else in any .git is held, as is the .git
	 * entry itself (a gitfile) and any nested .git (review W-1).
	 */
	gitAuto: ['.git/refs/**', '.git/packed-refs', '.git/HEAD', '.git/logs/**', '.git/FETCH_HEAD', '.git/ORIG_HEAD'],
	/** Loose object / pack file names that may be auto-applied (others under objects/ are held). */
	gitObjectName: /^\.git\/objects\/(?:[0-9a-f]{2}\/[0-9a-f]{38,62}|pack\/pack-[0-9a-f]{40,64}\.(?:pack|idx|rev|keep|mtimes))$/,
	/** Code-running config: held for approval. */
	held: [
		'.git/**', '.gitattributes', '.gitmodules', '.gitignore', 'sitecustomize.py', 'usercustomize.py',
		...AGENT_AND_IDE,
		'**/.env', '.env', '.env.*', '**/.env.*', '.tool-versions', '.npmrc', '**/.npmrc', '.yarnrc', '.yarnrc.*', '.pnpmfile.cjs',
		'.nvmrc', '.node-version', '.python-version',
		'makefile', 'gnumakefile', 'justfile', '*.sh', 'taskfile.yml', 'taskfile.yaml',
		'pyproject.toml', 'setup.py', 'setup.cfg', 'conftest.py', '**/conftest.py', 'tox.ini', 'noxfile.py', '.pre-commit-config.yaml',
		'gradlew', 'gradlew.bat', 'mvnw', 'mvnw.cmd', 'build.gradle', 'build.gradle.kts', 'settings.gradle', 'settings.gradle.kts', '.mvn/**',
		'cargo.toml', 'build.rs', '**/build.rs', '.cargo/**',
		'.husky/**', 'lefthook.yml', 'lefthook.yaml', '.lefthook.yml', '.lefthook/**', '.githooks/**',
		'node_modules/.bin/**', '**/node_modules/.bin/**',
		'.direnv/**', 'flake.nix', 'shell.nix', 'default.nix', 'devbox.json', 'mise.toml', '.mise.toml',
		// Review W-2: code host tools run without being asked.
		'.venv/**', '**/.venv/**', 'venv/**', '**/site-packages/**', '**/*.pth',
		'.yarn/**', '.pnp.cjs', '.pnp.js', '.pnp.loader.mjs',
		// Review Y-3: vendored dependency trees run on the host's next build or interpreter start
		// (Composer vendor/autoload.php, Go vendoring, Bundler config, Gradle caches/init scripts).
		'vendor/**', '**/vendor/**', '.bundle/**', '**/.bundle/**', '.gradle/**', '**/.gradle/**',
		'*.config.js', '*.config.cjs', '*.config.mjs', '*.config.ts', '*.config.cts', '*.config.mts', '**/*.config.js', '**/*.config.cjs', '**/*.config.mjs', '**/*.config.ts',
		'.eslintrc', '.eslintrc.*', '**/.eslintrc.*', '.prettierrc', '.prettierrc.*', '.babelrc', '.babelrc.*', '.swcrc', '.mocharc.*', '.lintstagedrc*',
		'bunfig.toml', 'deno.json', 'deno.jsonc', 'gemfile', 'gemfile.lock', '*.gemspec', 'rakefile', '.rspec', 'composer.json',
		'.exrc', '.nvim.lua', '.nvimrc', '.vimrc', '.pdbrc', '.pythonrc', 'pytest.ini', 'requirements*.txt', 'pipfile', 'poetry.lock', 'uv.lock',
		'go.mod', 'go.work', '.cargo/config.toml', 'rust-toolchain', 'rust-toolchain.toml', 'dockerfile', 'compose.yaml', 'compose.yml', 'docker-compose.yml', 'docker-compose.yaml',
		// Review X-1/Y-1: agent and IDE config is in AGENT_AND_IDE above.
		// Review X-2: npm-family lockfiles (a `resolved` URL can point at any tarball).
		'package-lock.json', '**/package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', '**/yarn.lock', 'pnpm-lock.yaml', 'pnpm-workspace.yaml', 'bun.lock', 'bun.lockb',
		// Review X-3: build definitions and IDE project config that run code.
		'pom.xml', '**/pom.xml', 'cmakelists.txt', '**/cmakelists.txt', '*.cmake', '**/*.cmake', 'cmakepresets.json', 'meson.build', '**/meson.build', 'build.xml',
		'build', 'build.bazel', '**/build', '**/build.bazel', 'workspace', 'workspace.bazel', 'module.bazel', '*.bzl', '**/*.bzl', '.bazelrc',
		'*.csproj', '**/*.csproj', '*.fsproj', '**/*.fsproj', '*.vbproj', 'directory.build.props', 'directory.build.targets', '**/directory.build.props', '**/directory.build.targets', 'nuget.config',
		'procfile', '.gitlab-ci.yml', 'jenkinsfile', '.circleci/**', 'azure-pipelines.yml', '.buildkite/**', 'tiltfile', 'skaffold.yaml',
		'*.sln',
	],
	/**
	 * Tab-local: generated or installed artifacts that are never written back (review Y-2/Y-3).
	 * Bytecode caches run with no visible source change (the pyc header's mtime/size are
	 * forgeable from the lower layer); installed trees are gitignored, so a review would never
	 * see them. The host regenerates both from sources and the (held) manifests and lockfiles.
	 */
	tabLocal: ['**/__pycache__/**', '**/*.pyc', '**/*.pyo', 'node_modules/**', '**/node_modules/**'],
	/** JSON manifests: held when these top-level keys change (else auto); see also dependency specs. */
	heldWhenKeysChange: {
		'package.json': ['scripts', 'bin', 'config', 'workspaces', 'packageManager', 'overrides', 'resolutions', 'pnpm', 'engines', 'type', 'main', 'exports'],
		'**/package.json': ['scripts', 'bin', 'packageManager', 'overrides', 'resolutions', 'pnpm'],
	} as Record<string, string[]>,
	/** Dependency sections: any added or changed entry is held (review X-2: install scripts run on the host). */
	dependencyKeys: ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies', 'bundledDependencies', 'bundleDependencies'],
	/** Deleting more than this many files in one sync holds the rest (review W-6). */
	maxAutoDeletesPerSync: 100,
	/** ...and more than this many auto deletes in the rolling window holds further ones (review X-5). */
	maxAutoDeletesPerWindow: 200,
	deleteWindowMs: 10 * 60_000,
	/** Agent, IDE and hook config: "Always allow" is never offered (review X-1, Y-6). */
	neverAlways: [...AGENT_AND_IDE, '.env', '.env.*', '**/.env'],
	caps: { maxFileBytes: 16 << 20, maxFilesPerSync: 2000, maxBytesPerSync: 64 << 20, maxSyncsPerMinute: 120, maxDiffBytes: 64 << 10, maxJsonBytes: 1 << 20, maxBaselineEntries: 300_000 },
} as const;
