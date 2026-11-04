# Every non-built-in extension runs in the tab (product `extensionKind` default `*`)

- **Status:** superseded-by [20261104-extension-placement-hardening](20261104-extension-placement-hardening.md) (decision kept; gaps closed)
- **Related:** [threat model ADR](20261104-threat-model-rogue-extension.md), [fork ADR](20261104-vscodium-style-fork.md); deviation from "M1 needs no core patches"

## Context
In a remote window, VS Code installs and runs an extension on the **local**
(host) side when its effective `extensionKind` prefers `ui`. A rogue extension
from the gallery only needs to declare `"extensionKind": ["ui"]` to run on the
host with full user privileges, which defeats the whole design.
`product.json#extensionKind` overrides are keyed per extension ID, with no
wildcard. The user setting `remote.extensionKind` takes precedence over
product.json, and a tab could try to write it (an M4 RPC concern).

## Decision
- **Patch `patches/0002-extensionkind-product-default.patch`** (2 hunks, 4 lines,
  `extensionManifestPropertiesService.ts`):
  1. `product.json#extensionKind["*"]` is the kind of every extension not listed
     explicitly;
  2. when `*` is set, the user setting `remote.extensionKind` is ignored.
- **product.json data** (`build/product/product.jq`):
  - `"*": ["workspace"]`;
  - explicit `ui` entries only for the Tab Manager and for upstream built-ins
    whose own manifest prefers `ui`. The latter are generated from the pinned
    source at build time; today they are github-authentication,
    microsoft-authentication, handlebars and simple-browser.
  - jq invariants fail the build if any other ID is `ui`.

## Alternatives considered
- **Enumerate known `ui` marketplace extensions**: rejected. An attacker
  simply publishes a new ID.
- **`extensions.allowed` policy**: rejected. It is an install gate on IDs, not
  placement, and doesn't stop an allowed extension from choosing `ui`.
- **Block local installs in the Tab Manager**: not possible from the
  extension API.

## Consequences
- Third-party UI extensions (themes with code, keymaps that need UI APIs) run
  in the tab or degrade. Live Share-style extensions won't work. This is
  accepted.
- The patch must be rebased on upstream bumps. It touches one method pair.

## Evidence
- Product lookup is per ID: `extensionManifestPropertiesService.ts` `getProductExtensionKind` at a717861c (`return this._productExtensionKindsMap.get(extensionId);`); the user setting precedes it in `getConfiguredExtensionKind`.
- prepare output: `ui-kind built-ins: ["seclab.tab-manager","vscode.github-authentication","vscode.handlebars","vscode.microsoft-authentication","vscode.simple-browser"]`.
