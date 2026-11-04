# RPC capability filter is a required, default-deny boundary

- **Status:** proposed (pending the RPC-lockdown session's approved design)
- **Date:** 2026-11-04
- **Deciders:** seclab-vscode coordinator; RPC-lockdown session

## Context
A sandboxed REH talks back to the trusted workbench through `MainThread*` RPC
services, and those services do not check where the caller runs. In a remote
window `$executeCommand` runs any command, including ones that spawn a host
terminal. `$readFile` and `$writeFile` accept any URI scheme.
`SecretStorage` is global per extension ID. Without a filter, a sandboxed
extension can drive the host UI into running code on the host (confused
deputy).

## Decision
Add an RPC capability filter where the RPC protocol is wired up for a
sandboxed extension host. It is **default-deny**: an explicit allowlist by
`MainThread*` method, with argument constraints (command categories, URI
schemes limited to `vscode-remote://seclab+<self>`). A **build-time drift
check** fails the build when upstream adds or changes `MainThread*` methods
that are not classified. Delivered as one patch in `patches/` (M4).

## Alternatives considered
- **Denylist of known-dangerous commands**: rejected. It drifts silently as
  upstream adds commands.
- **Rely on the sandbox alone**: rejected. The RPC channel runs on the host
  side of the boundary.

## Consequences
- This is the main new security engineering. It is developed test-first
  against the rogue-extension fixture.
- Some extensions will break if they rely on host-only commands. That is
  accepted, with prompts where needed.

## Evidence
- [mainThreadCommands.ts#L81-L93](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadCommands.ts#L81-L93), [terminalRemote.ts#L16-L42](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/contrib/terminal/electron-browser/terminalRemote.ts#L16-L42), [mainThreadFileSystem.ts#L104-L119](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadFileSystem.ts#L104-L119), [mainThreadSecretState.ts#L90-L92](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadSecretState.ts#L90-L92)
- ARCHITECTURE.md §4.6
