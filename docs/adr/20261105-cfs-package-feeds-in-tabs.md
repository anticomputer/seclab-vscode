# Package feeds through CFS: the tab holds a sentinel, the broker injects the Azure DevOps token

- **Status:** accepted 2026-11-06 (the coordinator, relaying "ok continue work" for B4). The broker side is implemented in policy schema revision 6 (broker 0.6.0); the tabd side (prompt, `az` token source, tab configuration) follows in the Fork-build session.
- **Date:** 2026-11-05
- **Deciders:**
  - anticomputer (user) supplied the CFS context.
  - The coordinator proposed the design and the default (off, per-tab prompt).
  - The broker session drafted it.
- **Related:** [ADR no real secret enters a tab](20261104-no-real-secret-enters-a-tab.md), [ADR broker model access](20261105-broker-model-access.md), [policy reference](../broker-policy.md)
- **Sources** (`example-org/internal-feed-docs` at `0000000000000000000000000000000000000000`; a private repository, so cited as paths rather than links):
  - `docs/package-feeds.md`: feed names and URLs, tenant, resource, roles;
  - `docs/local-feed-access.md`: how a laptop obtains the token, the npm and pip auth shapes, redirects, and the install-script warning.

## Context
Under the managed-endpoint policy, public npm and PyPI are blocked. Packages
come only from GitHub's CFS feeds in Azure DevOps:
- **npm:** `example-npm-feed`, at
  `https://pkgs.dev.azure.com/example-org/ExampleProject/_packaging/example-npm-feed/npm/registry/`;
- **Python:** `example-pypi-feed`, at `…/_packaging/example-pypi-feed/pypi/simple/`.

The feeds need a short-lived Azure DevOps token. On a laptop it comes from
`az account get-access-token --tenant 00000000-0000-0000-0000-000000000003
--resource 499b84ac-1321-427f-aa17-267ca6975798`. npm and pip send it as HTTP
Basic: username `cfs`, password the token (npm's `_password` holds the token
base64-encoded).

Two facts from the docs shape this design:
- **The token is the user's own identity.** The user's feed role is **Feed and
  Upstream Reader (Collaborator)**. It can download packages, and it can also
  *save new upstream packages into the shared feed*. So a pull of a version the
  feed doesn't have yet ingests that version into the org feed, under the
  user's identity. A GET does that; the bindings can't tell a pull from an
  ingestion.
- **"A command running as your user can read the temporary files."** The docs
  warn that install scripts can read the credential the wrapper writes.

Inside a tab, `npm install` and `pip install` would need this token. It is a
real credential, so the invariant says it must never enter the tab.

## Decision
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
credential. A sentinel sent there is misplaced and blocked. The shipped policy
is [`broker/examples/cfs-feeds.policy.json`](../../broker/examples/cfs-feeds.policy.json):

<!-- check: policy -->
```json
{
  "version": 1,
  "baseline": false,
  "allow": [
    {"id": "cfs-npm", "host": "pkgs.dev.azure.com", "methods": ["GET"],
     "path": "/example-org/ExampleProject/_packaging/example-npm-feed/npm/registry/**"},
    {"id": "cfs-pypi", "host": "pkgs.dev.azure.com", "methods": ["GET"],
     "path": "/example-org/ExampleProject/_packaging/example-pypi-feed/pypi/**"}
  ],
  "credentials": [
    {
      "id": "cfs",
      "provider": "azure-devops",
      "inject": {"header": "Authorization", "fmt": "Basic {base64:cfs:{value}}"},
      "bind": [
        {"host": "pkgs.dev.azure.com", "path": "/example-org/ExampleProject/_packaging/example-npm-feed/npm/registry/**", "methods": ["GET"]},
        {"host": "pkgs.dev.azure.com", "path": "/example-org/ExampleProject/_packaging/example-pypi-feed/pypi/**", "methods": ["GET"]}
      ],
      "budget": {"requests": 5000, "bytes": 2147483648}
    }
  ]
}
```

The PyPI binding covers `pypi/**`, not only `pypi/simple/**`: the simple index
links files under the feed's `pypi/download/…` paths. Uploads are POST, so
they still get no credential.

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
- The feed's own ingestion gates (scanning and a hold window for new
  versions);
- the per-tab prompt;
- a per-tab budget on the credential (`credentials[].budget`, requests and
  bytes over the tab's lifetime). Over budget, the request is denied with
  `429` and never prompted (`credential.budget_exceeded`).

The budget is per credential rather than per host (revision 6), because the
side effect belongs to the identity, not the host. Use of a credential derived
from it counts against it too. The audit log records every credentialed
response as `credential.used` (`credentialId`, `status`, `respBytes`, host and
path), so ingestions are attributable to a tab.

From revision 7, `credential.import` takes the same `budget`, so tabd can
enable CFS on a running tab: it imports `cfs` with its bindings, budget and a
host-chosen sentinel (so the tab's `.npmrc` stays valid across restarts), then
adds the two feed rules with `policy.update addAllow`. Usage is keyed by
credential id, so a re-import never resets what was spent
(`test_cfs_enabled_on_a_running_tab_by_import_with_budget`).

**6. Trusted provider table entry** (tabd product data):
- resource `https://pkgs.dev.azure.com/example-org/ExampleProject`;
- token source `az` with the tenant and resource above;
- the bindings above;
- `default: off, prompt per tab`.

The tab never chooses the feed URL, the tenant or the scope.

**7. Defence in depth** (implemented in revision 6):
- the `azure-devops` provider backstop
  ([`providers/azure-devops.json`](../../broker/seclab_broker/data/providers/azure-devops.json)).
  It denies credentialed calls to the REST API under `_apis` (including PATs
  and feed management) and any write (POST, PUT, PATCH, DELETE) under
  `_packaging`, by host and by the credential's `provider`;
- tests that the binding never injects on `PUT`, `POST`, `PATCH` or `DELETE`
  (`test_cfs_feed_credential_is_get_only_budgeted_and_audited`).

## Measured with a real CFS pull (2026-11-06)
The Fork-build session pulled from CFS through a real tab and broker 0.7.0,
using this host's `az` (`tabd/test/e2e-cfs.ts`, EDR `20261106-cfs-feeds-tabd`):
`npm view`, `npm pack` and `pip download --no-deps`. The harness can't reach CFS.
- **Download paths.** npm tarballs stay under `npm/registry/**`. PyPI's simple
  index links files under a feed-GUID path,
  `/example-org/00000000-0000-0000-0000-000000000001/_packaging/00000000-0000-0000-0000-000000000002/pypi/download/**`,
  so that exact prefix is a third GET-only binding and allow rule
  ([`cfs-feeds.policy.json`](../../broker/examples/cfs-feeds.policy.json)).
- **Redirects.** Every download answers `303` to a storage blob,
  `<xyz>vsblobprodcus<NNN>.blob.core.windows.net/b-<id>/<hash>.blob` (for
  example `aaavsblobprodcus101`, `bbbvsblobprodcus102`, `cccvsblobprodcus103`), with a
  read-only SAS in the query that expires in about an hour. Several storage
  accounts appear, and none is `*.vsblob.vsassets.io`. curl and pip's
  `requests` send no `Authorization` across hosts, so no sentinel was
  misplaced; the broker denied the storage host. The coordinator offered
  three ways to allow the blob fetch:
  - (a) allow GET on `*.blob.core.windows.net`;
  - (b) the broker follows the `303` itself on the credentialed route, only
    to a provider-declared host pattern, with no credential;
  - (c) a new host-pattern form.

  **Decided (user, 2026-11-06): (b), broker revision 8.** Anyone can create
  a storage account, so (a) or (c) would give every process in the tab an
  exfiltration and payload channel. With (b) the target comes from the
  credentialed feed response, never from the tab, and the tab never reaches
  storage. The bounds:
  - only a `302`, `303` or `307` answering a request the CFS credential was
    injected into;
  - only to an https host on port 443 matching the `azure-devops` provider's
    `redirects` pattern,
    `^[a-z0-9]{3}vsblobprodcus[0-9]{1,4}\.blob\.core\.windows\.net$`,
    and not named by a deny rule;
  - one hop, GET, no credential and no client header, to a netguard-vetted
    address the broker pins, TLS verified;
  - the body is read up to the credential's remaining byte budget, charged
    to it, and handed to the tab as a `200` on its own URL, after the usual
    credentialed-response checks;
  - any other redirect on such a request is `502`. The Location, and the
    signature in it, never reach the tab in a header, body or error, and the
    audit (`credential.redirect_followed`, `credential.redirect_refused`)
    records host and path only.

  Tests: `test_redirects.py` (a canary signature in every Location, swept
  from everything the tab saw, the audit and the broker's logs) and
  `test_r8_redirect_follow_data_and_target_checks`.

  **Runtime proof (Fork-build, 2026-11-06,** `tabd/test/e2e-cfs.ts`, an OCI tab
  with CFS on through tabd, broker 0.8.0, no allow rule for storage):
  `npm install --ignore-scripts is-number@7.0.0` and
  `pip install --no-deps --require-hashes six==1.16.0` both succeed, the
  tarball and wheel arriving as `200` on the feed URL. The audit shows six
  `credential.redirect_followed` (303) and no refusal. No `sig=`,
  `vsblobprodcus` or `blob.core.windows.net` appears in the project,
  `~/.npm` (including `_cacache`), `~/.cache/pip`, or the npm and pip logs,
  and no `sig=` in the broker's logs, where storage names appear only as the
  audit's host and path. The first run found the shipped pattern missed the
  accounts' three-character prefix (`aaavsblobprodcus101`); it failed closed,
  and the pattern was fixed before landing.
- **Audit.** `credential.used` came only from `pkgs.dev.azure.com`, with
  statuses 200 and 303 (the 303s at 0 bytes). POST and `_apis` probes were
  refused.
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
