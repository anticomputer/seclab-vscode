# Local npm and pip installs go through GitHub CFS; CI keeps the public registries

- **Status:** accepted
- **Date:** 2026-11-05
- **Deciders:** anticomputer (user). Decision: "Install gh cfs: brew install azure-cli and gh extension install gh-cfs, then I'll run az login". Coordinator: the requirements below. Fork-build session: implementation.
- **Related:** [review](../security-reviews/20261105-cfs-local-builds.md), [local install cache](20261105-local-install-cache.md), [pinned tools](20261105-pinned-tools.md), [supply-chain exceptions](20261105-supply-chain-exceptions.md), example-org/internal-feed-docs `docs/package-feeds.md` and `docs/local-feed-access.md`, gh-cfs `docs/reference/docker.md` and `npm.md`

## Context
Since 2026-11-04 public npm, Yarn and PyPI downloads have been unavailable locally. That was the
"TLS EOF" outage, and it cost the build volume its `node_modules`. Local package
installs go through CFS, Azure Artifacts feeds that need a short-lived
Azure DevOps token. The CFS docs warn that install scripts and build backends can read that
token. Code-OSS's `npm ci` runs many install scripts.

## Decision
- **Fetch with the token; install without it** (Code-OSS, `./seclab build linux`).
  1. **Prepare.** The builder prepares the pinned tree (`PHASE=prepare`). Its
     `package.json`, `package-lock.json` and `.npmrc` files, and nothing else, are exported
     to `.work/npm-locks`.
  2. **Fetch.** `gh cfs -- docker build -f build/linux/Dockerfile.npm-fetch` runs `npm ci
     --ignore-scripts` over every lockfile.
     - The token is a BuildKit secret, and the npmrc built from it lives on a tmpfs, for
       that one `RUN`.
     - `replace-registry-host=npmjs`, never `always`.
     - The `RUN` fails if the token appears anywhere it keeps.
     - The resulting image, `seclab-npm-cache:<hash of the lockfile set>`, holds only npm's
       content cache.
  3. **Install.** The cache is copied into the build volume. `build.sh` then runs upstream's
     `npm ci` with its scripts, with no token, `--offline`, and the same registry rewrite so
     cache keys match. Nested installs from the postinstall inherit this.

  Every tarball is checked against the lockfile's integrity hash. Upstream lockfiles are never
  rewritten: CFS is a transport, not a source.
- **Lockfile entries without `integrity`.** Upstream leaves it out of 77 of 112 entries in
  `build/rspack`, a dev server. (`extensions/microsoft-authentication`'s two such entries are a
  local mock package and an extraneous entry, which npm never fetches.) npm resolves the
  `build/rspack` entries from registry metadata in CI as well, so no pin exists anywhere. An
  offline install can't find them by URL, because CFS redirects tarballs to signed blob URLs.
  - In the fetch, after `npm ci --ignore-scripts`, `build/linux/lock-fill.mjs` asks npm for
    exactly each such `name@version` (`npm pack --dry-run --json`, through CFS) and records
    its sha512 `integrity`. It adds only that field to entries that lacked it, and fails on
    anything that isn't sha512. The package set, versions, existing hashes and URLs are
    untouched. (`npm install --package-lock-only` doesn't fill an up-to-date lockfile;
    measured.) Where `resolved` is missing too, it adds the canonical `registry.npmjs.org`
    URL derived from the name and version, the form upstream records for every other entry.
    Without it npm doesn't look the tarball up by integrity (measured).
  - The filled lockfiles are copied over the build tree for the offline install. That tree
    is reset to pristine upstream on every build.
  - For those entries, CFS's bytes are trusted exactly as CI trusts npmjs's: no pin existed.
- **CI keeps the public registries.** The CFS Actions work only for repositories in the
  `github` org, and this is `anticomputer/seclab-vscode`. Hosted runners still reach
  `registry.npmjs.org`: every CI build on 2026-11-05 installed from it. So CI and local builds
  use different transports for the same lockfile hashes.
- **No registry-signature audit locally.** `npm audit signatures` doesn't work through CFS: it
  finds "no dependencies to audit that were installed from a supported registry" (measured
  2026-11-05). Local installs are stamped `cfs1-` (integrity only), not `sig1-`. The
  registry-origin check still runs (`npm-audit-signatures.sh --origin-only`: every `resolved`
  is `registry.npmjs.org`; review YY-1). CI still audits signatures.
- **Other local npm users.** The Level B harness packages the rogue extension with `vsce` from
  a local image (`build/vsce`) built the same way: fetched through CFS with no scripts, then
  run with no token and no network.
- **pip follows the same split:**
  - download hashed wheels with the token (`pip download --require-hashes`, CFS
    `example-pypi-feed` as the only index);
  - install offline with `--no-index`, without the token.

  The broker's images (`broker/`) are the broker session's; this recipe went to them.
- **Fails closed.** Without `gh cfs`, or if `gh cfs doctor --auth` fails, a local build stops
  with a message to run `az login`. Nothing falls back to a public registry.
- **The token never reaches a tab.** It is minted on the host, handed only to `docker build`
  as a secret, and used only in the fetch `RUN`. That build has no install scripts and no tab
  in reach. The build volume, the cache image and the builder never see it.
- **Register.** User-approved host prerequisites `host-azure-cli` and `host-gh-cfs`, and the
  transport `transport-cfs` (a new `transport` kind, which must be a recorded exception).

## Consequences
- **Verified 2026-11-05.**
  - A two-package lockfile was fetched through CFS, the in-`RUN` token scan was clean, and a
    `--network none` container with no token installed it with `npm ci --offline`, resolving
    the same integrity hashes.
  - The full local `./seclab build linux reh` then ran on the CFS path: fetch over all 63
    upstream lockfiles (77 `build/rspack` entries filled), the token-less offline install
    with upstream's scripts, the pinned ripgrep check, and the REH build.
- **Signed blob URLs in the npm cache.** CFS answers tarball requests with redirects to Azure
  blob SAS URLs (read-only, for that one package blob, expiring within about an hour). npm
  keeps them as cache keys, so they sit in the cache image and the build volume. They are not
  the CFS token (the fetch's token scan passes) and they grant only short-lived reads of
  public package bytes, but they are credentials of a kind. They stay in builder-only places:
  the cache image and the build volume, never a tab image or a tab.
- **Seven-day hold.** CFS holds new versions for 7 days, so a fresh Dependabot bump can fail
  locally until the feed has it. That is expected; never bypass CFS.
- **Token expiry.** `az` tokens expire. The user re-runs `az login`, and the build says so.
- **The CFS cache image is keyed by the lockfile set**, so an upstream bump fetches once.
  `./seclab clean-host --caches` removes old ones.
