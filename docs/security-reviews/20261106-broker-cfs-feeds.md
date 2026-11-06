# Security review: CFS package feeds in tabs, broker side (round 13)

- **Date:** 2026-11-06
- **Scope:** "broker: B4 CFS package feeds in tabs, broker side" (policy schema
  revision 6, broker 0.6.0) and the round 13 fix commit. Design:
  [ADR CFS package feeds in tabs](../adr/20261105-cfs-package-feeds-in-tabs.md).
  - `credentials[].budget`, `credential.used`, the `azure-devops` provider
    backstop and the `cfs-feeds` example policy.
  - **Threat model:** the user's Azure DevOps token (which can also ingest
    packages into the shared feed) reaching anything but GET on the feed
    paths; a tab escaping its budget; ingestions that can't be attributed.
- **Reviewer:** a general-purpose agent on an Opus-class CVP model with long
  context. It confirmed findings with the shipped matcher and broker in the
  unit image. It had no CFS token, by rule. Triage and fixes by the broker
  session.

## Findings
| # | Severity | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| 13-1 | Medium | Backstop | The write denies covered only one- and two-segment prefixes, so a write to `{org}.pkgs.visualstudio.com/_packaging/…` (organisation in the hostname) wasn't denied. | fixed (round 13 commit) | `**/_packaging` and `**/_packaging/**` for writes, at any depth. | `test_azure_devops_backstop` |
| 13-2 | Medium | Budget | The budget chain was one level deep, so a grandchild derived credential's use never reached the budgeted root. | fixed (round 13 commit) | Ancestors are walked up to the root, with a visited set. | `test_credential_budget_is_validated_and_counts_parent` |
| 13-3 | Medium | Backstop | By-host application missed most Azure DevOps hosts, including `feeds.dev.azure.com` (feed management), and the `visualstudio.com` apex. The shipped CFS credential was covered anyway, through `provider`. | fixed (round 13 commit) | Hosts are `dev.azure.com`, `*.dev.azure.com`, `visualstudio.com` and `*.visualstudio.com`. | `test_azure_devops_backstop` |
| 13-4 | Low | Backstop | The team-scoped REST route `/{org}/{project}/{team}/_apis/**` wasn't denied. | fixed (round 13 commit) | `**/_apis` and `**/_apis/**`, at any depth. | `test_azure_devops_backstop` |
| 13-5 | Medium | Observability | The two new audit types were missing from tabd's classifier. They were demoted to a bare notice with their fields dropped, so `credential.used` couldn't attribute ingestions. | fixed (round 13 commit) | Both are classified as `credential.use`. A tabd test now requires the classifier to list exactly the protocol's audit types. | `broker audit: observability classifies exactly the broker protocol's audit types` |
| 13-6 | Low | Budget | Response bytes are charged when a response completes: a flow that fails after injection counts its request but no bytes, and one request can overshoot the byte cap. | documented | The request cap is exact and is the hard bound; the byte cap is best-effort. Stated in the schema and changelog. | n/a |
| 13-7 | Low | Budget | Counters are keyed by credential id, so a `policy.load` that renames the credential starts a new counter. Budgets weren't visible to the controller. | documented; visibility fixed (round 13 commit) | The controller sets budgets and ids, and it is trusted; renaming is its choice, like raising the cap. `health` now reports `credentialBudgets`. | `test_credential_budget_is_validated_and_counts_parent` |
| 13-8 | Low | Budget | The budget was checked after the binding prompt, so a spent credential could still be prompted for. Not reachable today: budgets exist only on policy credentials, which are never unbound. | fixed (round 13 commit) | Checked before the prompt too. The check after the last wait stays. | Code review |
| 13-9 | Low | Backstop | Backstop matching kept trailing dots and spaces, which IIS-hosted services trim (`/_apis.`). | fixed (round 13 commit) | Each segment's trailing dots and whitespace are removed before matching. This can only widen the deny-list. | `test_azure_devops_backstop` |
| 13-10 | Low | Budget | WebSocket messages aren't charged, so a byte budget on a `websocket: true` binding wouldn't hold. Not reachable from the CFS policy. | fixed (round 13 commit) | A byte budget together with a websocket binding is refused at load. | `test_credential_budget_is_validated_and_counts_parent` |

Probed and held:
- **Method reach.** HEAD, POST, OPTIONS and TRACE don't match `GET`. Method
  overrides are refused. A non-GET carrying the sentinel is misplaced and
  gets 403.
- **Path tricks** (dot segments, `;`, `//`, encodings) are refused before
  matching. Case variants only narrow injection, and the backstop is
  case-insensitive.
- **Upgrades** are refused without `websocket: true`. mitmproxy doesn't
  follow redirects.
- **Basic forms.** The sentinel in the username, lowercase `basic`, and
  extra whitespace are recognised, and the whole header is replaced. A
  second `Authorization` header is collapsed. Unpadded base64 fails closed.
- **The budget check and charge** sit in one synchronous block with no
  `await` between them. A budget of 0 means never inject. Streamed bodies are
  off, so no response escapes charging.
- **`credential.used`** is emitted before any blocked response, with the
  upstream's status, and carries no values.
- **GET side effects** other than ingestion are all under `_apis`, which the
  backstop denies.
- **Versions** (0.6.0, revision 6) are consistent across the code, schema,
  changelog and tabd.
