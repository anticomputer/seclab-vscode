# CFS package feeds in tabs: the tabd side (plan increment B4)

- **Status:** accepted (broker policy schema revision 7 on main at 47ccdc6; real-feed measurement pending)
- **Date:** 2026-11-06
- **Deciders:** Coordinator ("ok continue work" for B4). Broker session: revision 6, then 7 for import budgets. Fork-build session: implementation.
- **Related:** [ADR cfs-package-feeds-in-tabs](../adr/20261105-cfs-package-feeds-in-tabs.md), [egress prompts](20261106-egress-prompts.md)

## Context
The ADR puts GitHub's CFS npm and PyPI feeds inside tabs without the token ever entering the
tab: the tab holds a sentinel and the broker injects the user's Azure DevOps token on the
feed reads only. The broker side landed in revision 6. This record covers tabd and the Tab
Manager: the per-tab switch, the token source and the tab's npm and pip configuration.

## Decision
- **Off by default, per tab, from the user.**
  - The Tab Manager's command "Package Feeds (CFS) for This Tab…" shows a modal, then asks the user to type a random code (review EEE-3). The modal says that
    installs run under the user's identity, that a missing version gets added to the shared
    feed, and what the budget is.
  - On confirmation the Tab Manager sends `tab.packages.set {cfs: true}`.
  - tabd persists the setting and a host-chosen sentinel (`seclab_cfs_<32 random bytes>`) in
    a side file. `forget` removes the file.
  - Tabs can't reach `seclab.*` commands once the RPC filter lands. Until then a tab
    extension could invoke the command, but the modal still needs the user's click.
- **Credential:** `credential.import` (revision 7) rather than a policy credential:
  - id `cfs`, the persisted sentinel, provider `azure-devops`;
  - injected as `Basic {base64:cfs:{value}}`, on GET-only bindings for the two exact feed
    paths, with a budget of 5000 requests and 2 GiB;
  - then `policy.update addAllow` for `cfs-npm` and `cfs-pypi`.

  This happens on every broker start and at once on a running tab. Because the sentinel is
  stable, the tab's config stays valid across restarts. The broker keys budget counters by
  credential id, and a re-import never resets them.
- **Token source** (`tabd/src/cfs.ts`): tabd runs `/opt/homebrew/bin/az account
  get-access-token` with the CFS tenant and resource, fixed argv, then:
  - checks the returned tenant and the expiry, and keeps the token in memory only;
  - re-mints within 5 min of expiry; concurrent callers share one `az` run;
  - answers `credential.needed {id: "cfs"}` with `credential.provide`.

  The token is never audited, logged, written to disk or sent to the tab. Bring-up imports in
  the background: `az` can be slow or not logged in, and the tab still starts. A failure
  raises `tab.packages.problem` with `az`'s own message, and the Tab Manager tells the user
  to run `az login`.
- **Tab configuration:** the root install script, as for the proxy URL and CA, writes the
  following under `/run/seclab-broker` (root-owned, read-only to the tab):
  - `npmrc`: `registry=` and `username=cfs` / `_password=<base64 sentinel>`, keyed to the
    canonical feed URL;
  - `pip-index-url`: `https://cfs:<sentinel>@…/example-pypi-feed/pypi/simple/`.

  The feed URLs are fixed in the script; only the validated sentinel comes from input.
  `seclab-tab-env` exports `NPM_CONFIG_GLOBALCONFIG`, `NPM_CONFIG_REGISTRY` (env outranks a
  workspace `.npmrc`) and `PIP_INDEX_URL`, only when a broker is configured and the URL is
  exactly the expected shape. Turning feeds off removes both files.
- **Drivers:** a new optional `installFeed` writes or removes the config on a running tab,
  through the same root-only directory checks (OCI and sbx).

## Consequences
- Review [EEE](../security-reviews/20261106-cfs-feeds-tabd.md), with all five findings fixed:
  - feeds are refused below broker revision 7, whose import keeps `budget`;
  - CFS work is serialised per tab and re-checked after each slow step; a disable the
    broker can't confirm stops the tab;
  - enabling needs a typed random code after the modal;
  - only running sandboxes are touched;
  - the pip URL is parsed exactly.
- Unit tests cover:
  - off by default, and enabling on a running tab: the import's params, GET-only bindings,
    budget, allow rules, and config with the sentinel;
  - the same sentinel and a re-import on restart;
  - `credential.needed` refresh, and disabling: rules removed, revoke with a rotated
    sentinel, config removed;
  - no token in the audit log, and the `az` output checks (tenant, expiry);
  - the install script and `seclab-tab-env`, run as root in the test container. An
    unexpected index URL means no feeds.
- Images must be rebuilt for the `seclab-tab-env` change (`./seclab image oci`,
  `./seclab template sbx`).
- **Budget lifetime:** usage is keyed by credential id for the broker's lifetime. Turning
  feeds off and on again doesn't refill the budget, because a re-import never resets it. A
  fresh budget comes with the next broker start (a tab restart).
- **Open:** the ADR's real-feed measurements (download paths, redirects, resent
  `Authorization`, the `pypi/download/**` path), through a tab's broker with this host's
  `az`, once revision 7 is in a local broker image.
