# Security review: local npm installs through GitHub CFS

- **Date:** 2026-11-05
- **Scope:**
  - Round YY: `91e7b2c..87f56e0` (EDR [cfs-local-builds](../edr/20261105-cfs-local-builds.md)), plus the vsce image (`build/vsce`).
  - Threat model:
    - the CFS token (a real Azure DevOps credential) leaking into images, logs, argv, the build volume, or anything a tab or REH can reach;
    - upstream content (lockfiles, `.npmrc`, packages) running code or steering npm while the token is present;
    - the integrity fill weakening a pin.
- **Prompt injection:** none found.

## Round YY
Nothing medium or higher. The token stays in one `RUN` (BuildKit secret plus a tmpfs npmrc),
only npm uses it, install scripts are off three ways, and no tab-reachable artefact carries
it. The cache's Azure blob SAS keys stay in builder-only places (recorded in the EDR).

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| YY-1 | Low | build.sh | Local builds skipped the registry-origin check along with the signature audit. | Fixed | `npm-audit-signatures.sh --origin-only`: every `resolved` must be `registry.npmjs.org`, in both modes. Only the signature part is skipped through CFS. |
| YY-2 | Low | fetch | The token-bearing `RUN` still trusted upstream's other npm configuration: project `.npmrc` keys such as `git=`, and lockfile sources. | Fixed | Before npm runs: any non-registry `resolved` is refused, and so is any project `.npmrc` key outside a reviewed allowlist. `NPM_CONFIG_GIT=/bin/false`. |
| YY-3 | Low | lock-fill | It could fill a non-registry entry with a registry hash, and a name or version starting with `-` reached `npm pack` as an option. | Fixed | Entries with a non-registry `resolved` are refused. Names and versions must start with an alphanumeric (or `_`). `--` precedes the spec. |
| YY-4 | Low | fetch | The token grep covered only the kept directories. | Fixed | It covers the whole stage root filesystem except `/proc`, `/sys`, `/dev`, the secret mount and the auth tmpfs. |
| YY-5 | Low | build.sh | The filled lockfiles were overlaid unchecked (and a comment named a checker that no longer existed). | Fixed | `lock-fill.mjs --verify UPSTREAM FILLED` runs before each copy. Only `package-lock.json` files at existing upstream paths are copied. Tests: `build/linux/lock-fill.test.ts`. |
