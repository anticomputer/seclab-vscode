# Package feeds through CFS: the tab holds a sentinel, the broker injects the Azure DevOps token

- **Status:** proposed (draft; implement with increment B4)
- **Date:** 2026-11-05
- **Deciders:**
  - anticomputer (user) supplied the context: "CFS context for broker builds and for tabs" and "CFS docs for the in-tab feed design".
  - The coordinator proposed the design and the default (off, per-tab prompt).
  - The broker session drafted it.
- **Related:** [ADR no real secret enters a tab](20261104-no-real-secret-enters-a-tab.md), [ADR broker model access](20261105-broker-model-access.md), [policy reference](../broker-policy.md)
- **Sources** (`github/cfs-at-github` at `8dcb42bcb7d27eb7eeb931b8ca1c2e3c64bb15a0`; a private repository, so cited as paths rather than links):
  - `docs/package-feeds.md`: feed names and URLs, tenant, resource, roles;
  - `docs/local-feed-access.md`: how a laptop obtains the token, the npm and pip auth shapes, redirects, and the install-script warning.

## Context
Under the managed-endpoint policy, public npm and PyPI are blocked. Packages
come only from GitHub's CFS feeds in Azure DevOps:
- **npm:** `github-cfs-oss`, at
  `https://pkgs.dev.azure.com/github-cfs/GitHubCFS/_packaging/github-cfs-oss/npm/registry/`;
- **Python:** `github-cfs-pypi`, at `…/_packaging/github-cfs-pypi/pypi/simple/`.

The feeds need a short-lived Azure DevOps token. On a laptop it comes from
`az account get-access-token --tenant 398a6654-997b-47e9-b12b-9515b896b4de
--resource 499b84ac-1321-427f-aa17-267ca6975798`. npm and pip send it as HTTP
Basic: username `cfs`, password the token (npm's `_password` holds the token
base64-encoded).

Two facts from the docs shape this design:
- **The token is the user's own identity.** The employee role is **Feed and
  Upstream Reader (Collaborator)**. It can download packages, and it can also
  *save new upstream packages into the shared feed*. So a pull of a version the
  feed doesn't have yet ingests that version into the org feed, under the
  user's identity. A GET does that; the bindings can't tell a pull from an
  ingestion.
- **"A command running as your user can read the temporary files."** The docs
  warn that install scripts can read the credential the wrapper writes.

Inside a tab, `npm install` and `pip install` would need this token. It is a
real credential, so the invariant says it must never enter the tab.

## Decision (proposed)
**1. Off by default; a per-tab prompt turns it on.** A tab gets no CFS
credential unless the user approves CFS for that tab. tabd shows the prompt,
the first time the tab needs a package or when the tab is created with
packages enabled. The prompt says installs will run under the user's
identity, and may add packages to the shared feed. Until approved, the tab has
no feed configuration, and egress to the feed host is denied like any other
host.

**2. The tab holds a sentinel; install scripts can't read the token.** tabd
writes the tab's npm and pip configuration with the feed URLs and the CFS
credential's sentinel:
- npm: `username=cfs`, `_password=<base64 of the sentinel>`;
- pip: `cfs:<sentinel>` in the index URL or `.netrc`.

Both clients send `Authorization: Basic …` with the sentinel inside. The
broker recognises the sentinel inside Basic, replaces the whole header with its
own rendering of the real token, and does so only on a bound route.

So the docs' install-script warning is met by design. An install script, or
anything else in the tab, can read only the sentinel. The sentinel is useless
outside this tab's broker, and useless there on any route but the feed reads.

**3. Bindings: GET only, on the exact feed paths.** Every other path and method
on `pkgs.dev.azure.com` (publishing, feed management, `_apis/**`) gets no
credential. A sentinel sent there is misplaced and blocked. Draft policy
fragment, validated against today's schema:

<!-- check: policy -->
```json
{
  "version": 1,
  "baseline": false,
  "allow": [
    {"id": "cfs-feeds", "host": "pkgs.dev.azure.com", "methods": ["GET"],
     "path": "/github-cfs/GitHubCFS/_packaging/**"}
  ],
  "credentials": [
    {
      "id": "cfs",
      "provider": "azure-devops",
      "inject": {"header": "Authorization", "fmt": "Basic {base64:cfs:{value}}"},
      "bind": [
        {"host": "pkgs.dev.azure.com", "path": "/github-cfs/GitHubCFS/_packaging/github-cfs-oss/npm/registry/**", "methods": ["GET"]},
        {"host": "pkgs.dev.azure.com", "path": "/github-cfs/GitHubCFS/_packaging/github-cfs-pypi/pypi/simple/**", "methods": ["GET"]}
      ]
    }
  ]
}
```

**4. Short-lived token, refreshed on the host.**
- tabd runs the `az` command above on the host. It checks the returned tenant,
  as the docs' helper does, and sends the token with
  `credential.provide {id: "cfs", value, expiresAt}`.
- After `expiresAt` the broker drops the value. The next use holds the request
  and emits `credential.needed`, tabd refreshes, and the request resumes
  without a retry. That also fixes the docs' caveat that "a long-running
  command does not automatically refresh it".
- The token is never written into the tab.

**5. Ingestion is a residual, budgeted per tab.** A tab with CFS enabled can
make the feed ingest upstream package versions under the user's identity.
Bindings can't prevent this: an ingestion is a GET. It is bounded three ways:
- CFS's own ingestion gates (malware scanning and the hold window for new
  versions);
- the per-tab prompt;
- a per-tab request budget on the feed host, over which the tab is denied and
  never prompted.

B4 generalises today's model-host budget (`models.budget`) to any credential
or host. The audit log records every credentialed feed request (`host`,
`path`, `status`), so ingestions are attributable to a tab.

**6. Trusted provider table entry** (tabd product data):
- resource `https://pkgs.dev.azure.com/github-cfs/GitHubCFS`;
- token source `az` with the tenant and resource above;
- the bindings above;
- `default: off, prompt per tab`.

The tab never chooses the feed URL, the tenant or the scope.

**7. Defence in depth, added with B4:**
- an Azure DevOps provider backstop file, denying credentialed calls to token
  and PAT endpoints (`_apis/tokens/**`) and to feed publishing;
- tests that the binding never injects on `PUT`, `POST`, `PATCH` or `DELETE`.

## Open items to measure when B4 lands
- **Redirects.** Downloads can redirect through `ms-feed-*.pkgs.visualstudio.com`
  to dynamic `*.vsblob.vsassets.io` hosts. Those need allow rules with no
  credential. Two things to measure:
  - whether npm or pip resend `Authorization` across the redirect. If they do,
    the broker blocks the sentinel as misplaced, which is fail closed, but
    installs would break;
  - whether the redirect URLs carry their own signature in the query.
- **Path case.** Azure DevOps paths are case-insensitive, while binding globs
  match exactly. A case variant fails closed (no credential), so tab
  configuration must use the canonical URLs above.
- **Lockfile URLs.** Lockfiles with literal public-registry URLs still go to
  the public hosts, and those are denied. `gh cfs migrate npm` rewrites
  selected ones on the host, never in the tab.

## Consequences
- Local image builds are separate. They go through CFS via BuildKit secret
  mounts, wired by the Fork-build session, and nothing in this ADR changes
  them.
- With CFS enabled, a rogue extension can pull packages, and cause ingestions,
  under the user's identity, up to the tab's budget. It never holds the token
  and can't use it anywhere else. Read access to a feed gives a payload
  nothing more
  ([README](../../broker/README.md#folder-open-loaders-beacons-and-package-registries)).
