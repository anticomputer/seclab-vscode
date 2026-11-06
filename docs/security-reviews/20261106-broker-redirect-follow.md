# Security review: broker-followed CFS download redirects (round 15)

- **Date:** 2026-11-06
- **Scope:** "broker: broker-followed CFS download redirects" (policy schema
  revision 8, broker 0.8.0) and the round 15 fix commit. Design: user
  decision (b) in
  [ADR CFS package feeds in tabs](../adr/20261105-cfs-package-feeds-in-tabs.md).
  - The broker follows a `302`, `303` or `307` answering a credentialed
    request, under a provider declaring `redirects` (azure-devops:
    `<xyz>vsblobprodcus<NNN>.blob.core.windows.net`), one hop, GET, no credential
    or client header, to a netguard-vetted pinned address.
  - **Threat model:** the signed storage URL (or any Location) reaching the
    tab, the audit or the broker's logs; the tab triggering or steering a
    follow, or reaching storage itself; SSRF; overspending the byte budget.
- **Reviewer:** a security-review agent on an Opus-class CVP model with long
  context, read-only. Triage and fixes by the broker session.

## Findings
| # | Severity | Area | Finding | Disposition | Fix / reason | Regression test |
|---|---|---|---|---|---|---|
| 15-1 | Low | Follow | The follow was gated on the provider, not on the injected credentials still existing. A credential dropped while its request was in flight (a `policy.load` without it, a revoke) left the read unbounded by any budget and the follow unaudited. | fixed (round 15 commit) | A follow needs every injected credential id to resolve; otherwise it is refused, and refusals are audited per injected id. | `test_r15_follow_refused_for_a_dropped_credential_or_a_credential_in_location` |
| 15-2 | Low | Budget | The byte budget was read before the fetch and charged after it, across awaits, so concurrent downloads each saw the whole remaining budget. | fixed (round 15 commit) | Each body chunk is checked and charged with no await between; a declared length that can't fit is refused before reading. | `test_concurrent_followed_redirects_cannot_overspend_the_byte_budget` |

Hardening taken from the review's residuals: a Location carrying a real
credential value is refused before anything is fetched (same regression test
as 15-1).

Runtime proof (Fork-build, a real OCI tab with CFS on, 2026-11-06) found the
first shipped pattern, `^vsblobprodcus[0-9]{1,4}…`, matched none of the real
accounts, which carry a three-character prefix (`5zbvsblobprodcus417`). It
failed closed (`502`, "host not declared by the provider"), and no signature
reached the tab. The test fixture had used the same wrong shape, so only the
real run could catch it. The pattern is now
`^[a-z0-9]{3}vsblobprodcus[0-9]{1,4}\.blob\.core\.windows\.net$`, the unit
test checks the three measured hosts, and the fixture aliases use the
measured shape.

Residuals, recorded:
- **The declared pattern names a namespace Microsoft doesn't reserve.**
  Azure Storage account names are self-service, so an unused
  `<xyz>vsblobprodcus<NNN>` name could be claimed. Using it needs control of a
  Location on a credentialed response under the provider: an open redirect
  on the feed, or a user-approved binding to an attacker host with
  `provider: azure-devops`, which already gives that host the tab's traffic.
  Narrowing the digits to measured accounts would break installs when CFS
  adds one.
- **Buffering.** With no byte budget, a follow can buffer up to 512 MiB and
  hold the tab's connection up to 300 s. CFS policies carry a byte budget.

Probed and held:
- **Containment.** On success the whole response is replaced (only
  `content-type`, `content-encoding`, `content-length`; trailers dropped; the
  redirect's body discarded). Every refusal replaces the response. Reasons are
  fixed text, exceptions are reported by type only, and `_hook_failed` logs no
  locals. Audits carry host and path, never the query; `redirectPath` is
  scrubbed for real and derived values and tagged untrusted. Duplicate
  `Location` headers join with `", "` and fail the control-character check.
- **Host pattern.** The load-time grammar admits only literal labels, `\.`
  and bounded `[a-z0-9-]` classes, anchored, so no pattern can widen past its
  literal suffix. No parsing differential: the validated host is what is
  resolved, verified (SNI, `check_hostname`) and sent as `Host`.
- **Netguard and TLS.** The shared `_vetted_ips` checks every address; the
  fetch connects to the pinned one. TLS 1.2 or later, the same trust bundle
  as mitmproxy, ALPN http/1.1.
- **Request cap.** The follow only checks bytes, so the request that used the
  last request in the budget still completes.
- **Tab steering.** The tab can't reach storage, can't set the Location,
  can't reach the control socket, and gets no follow on an uncredentialed
  request or under a provider without `redirects`.
- **Tests.** Every fixture Location carries a fresh canary signature; the
  final sweep checks everything the tab saw, the audit and the broker's
  docker logs.
