# Security review: broker defences against folder-open loaders and beacons (tasks.json campaign)

- **Date:** 2026-11-04
- **Scope:** `fd70ed5..564d2e6` plus the fixes in the following commit. This
  is the broker side of [ADR defeat folder-open loaders](../adr/20261104-defeat-folder-open-loaders.md).
  Areas given explicit attention:
  - bypasses of the risky and raw-IP classification (IPv6 and mapped forms,
    wildcard DNS, normalisation, CONNECT vs Host, HTTP/2 `:authority`);
  - whether `allow-tab` can still be obtained for a risky host;
  - whether the tab can influence the gating or rate-limit state;
  - parsing of the proxy-auth origin label;
  - session-state semantics.

  Threat model: ARCHITECTURE.md §2, with a rogue extension or malicious
  workspace in full control of its tab.
- **Reviewer:** `security-review` agent (default model; it did not refuse). It
  ran the broker code in the unit-test container with no network. Triage by
  the broker session.
- **Related:** [ADR](../adr/20261104-defeat-folder-open-loaders.md), [ADR policy and protocol](../adr/20261104-broker-policy-and-control-protocol.md)

## Findings
| # | Severity | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| 1 | Medium | Raw-IP controls | Wildcard-DNS names (`<ip>.sslip.io`, `<ip>.nip.io`, …) resolve to the IP spelled inside them. The campaign's raw-IP C2 could therefore change one word and get a normal prompt that offers `allow-tab`, with no gating before the first user action. | fixed | Two layers. A new `ip-dns` category on the risky list covers nip.io, sslip.io, traefik.me, xip.io and nip.direct. Any hostname that spells an IPv4 address (dotted or dashed) is flagged `ip-in-hostname` and treated like a raw IP: gated before the first user action, and never offered `allow-tab`. | `test_ip_in_hostname_is_treated_like_a_raw_ip`, `test_ip_in_hostname_negatives` |
| 2 | Low | Proxy auth | `_LABEL_RE` (and `_USER_RE`/`_PASS_RE`) were anchored with `$`, which accepts one trailing newline, so `seclab+a\n` was accepted. | fixed | `fullmatch`. | `test_proxy_auth_origin_label` |
| 3 | Low (defence in depth) | Approvals | "Never `allow-tab` for risky hosts or raw IPs" was enforced only by the client. On a benign approval, the trusted client could pass any `rule` or `binding`, for example `*.vercel.app` or a raw IP, and the broker installed it. | fixed | The broker now checks that an approval-sourced rule or binding covers the held request. It also rejects rules for raw IPs, and rules or bindings that overlap a risky destination. | `test_allow_tab_rule_is_enforced_by_the_broker` |
| 4 | Low | docs-check | The baseline and examples overlap check missed a wildcard above a listed host (for example `*.github.com` covering `gist.github.com`). No current file was affected. | fixed | New `pattern_overlaps_risky()` is used by docs-check and the approval check. The baseline's Open VSX bucket under `*.blob.core.windows.net` is an explicit, reviewed exception in the list file. | `test_pattern_overlaps_risky` |
| 5 | Info | Semantics | If the client counts the Workspace Trust or "allow automatic tasks" click as a user action, the gate is already open when `runOn: folderOpen` fires. | fixed (spec) | The `tab.event` description now excludes consent interactions explicitly. That rule has been passed to the Fork-build session (tabd). | n/a (client contract) |
| 6 | Info | Risky list | The list was missing `*.devtunnels.ms`, `*.ngrok.dev`, `*.oastify.com`, `bore.pub`, object storage (`*.s3.amazonaws.com`, `storage.googleapis.com`, `*.blob.core.windows.net`, `*.r2.dev`) and the GitHub release-asset hosts. | fixed | Added. | covered by docs-check |
| 7 | Info | Example policy | `github.policy.json` allows `api.github.com GET /**`, which serves raw repository files (`Accept: application/vnd.github.raw`). That makes it an unprompted loader host comparable to raw.githubusercontent.com. | accepted | The example models a GitHub-API-using tab, and the payload still runs only inside the tab. It is recorded as a residual in the ADR. Tabs that don't need the API shouldn't allow it. | n/a |
| 8 | Info | DoS within the tab | A tab can use up `maxPerMinute`, or pre-trigger cooldowns, so that legitimate prompts in its own session are denied. | accepted | This is denial of service against the attacker's own tab; nothing is exposed. `prompt.reset` recovers. | n/a |

The reviewer confirmed **no issues** in these areas:
- **Classification:**
  - IPv6 and mapped forms;
  - trailing dot, case and fullwidth/IDN spellings (all normalised onto the
    listed host);
  - CONNECT, Host, SNI and `:authority` mismatches (421 before
    classification);
  - lazy upstream connect (nothing contacted before classification).
- **Control-only state:** the tab cannot influence `tab.event`,
  `prompt.reset` or `deny-new-destinations`.
- **Label safety:** label parsing allows no auth bypass and no timing oracle
  on the secret parts, and the label is JSON-escaped wherever it is shown.
- **Audit content:** `_deny_unprompted` audits only the request summary, the
  flags and the unverified label.

## Re-review
- **Result:** findings 1–6 were fixed in the commit that adds this record,
  each with the regression test named above. `broker/test.sh` passes, with
  docs-check, the unit tests and the integration tests. The fixes are small
  and targeted, and each is covered by its own tests, so they were not
  re-submitted to the agent.
- **No high or critical findings were open at any point.**
