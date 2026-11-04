# Security review: Contagious-Interview fixture and AV-signature lint

- **Date:** 2026-11-04
- **Scope:**
  - the inert campaign fixture (`test/containment/fixtures/contagious-interview`) and its harness, `test/containment/campaign.ts`;
  - fixture-lint's AV-signature rules and the repo-wide `--av` pass;
  - the defanged loader text in docs.
- **Threat:**
  - the fixture harms the host if containment fails;
  - files on the host match an endpoint-protection signature (Endpoint protection quarantined a faithful `tasks.json`).
- **Decision records:** [EDR fixture-safety](../edr/20261104-fixture-safety.md) (addendum), [threat-model ADR, worked example](../adr/20261104-threat-model-rogue-extension.md).
- **Reviewer:** `security-review` agent.

## Round 1
| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| CI-A | **Medium** | AV content outside the lint | The broker ADR and README carried the campaign's literal loader (a real `vercel.app` URL piped into a shell), and the lint only walked test dirs. | Fixed | Docs defanged (`hxxps`, `[.]`, prose). A repo-wide `--av` pass over every tracked file (`av-url-loader`; `av-loader` for fixtures and any `tasks.json`) runs in `./seclab lint fixtures`. |
| CI-B | Low | IOC strings | C2 port and path, and the stage query, matched published family IOCs. | Fixed | Neutral stand-ins: `192.0.2.10:8443/api/v1/ping` and `stage.loader-standin.example.test/s/linux?v=2`. `~/.n2` is kept (coordinator spec) and written only to the tab's home. |
| CI-C | Low | Lint evasion | Missing fetchers and interpreters, `base64 -d \|`, the two-step `-o f && sh f`. | Fixed | Broader fetch and interpreter sets, new patterns, not opt-outable. The self-test samples are assembled at runtime. |
| CI-D | Low | Arming (escape case) | Tab-side code could rewrite `targets` to aim an escaped stage at user files; the marker write followed links and truncated. | Fixed | `run` must be under `/.work/` or `/.seclab-test/`; the marker is written with `wx`. |
| CI-E | Low | `inTab` | Could pass in a non-tab container built from the tab image. | Fixed | Also requires `tab=<id>` from the harness and a matching hostname. |
| CI-F | Low | Teardown | Planted inert files were left behind with `KEEP=1`. | Fixed | `disarmCampaign` always runs in cleanup. |
| CI-G | Info | Network, beacon, eval | Reserved targets; bounded loop and lifetime; responses never evaluated. | — | — |

## Round 2 (re-review)
CI-A to CI-F verified fixed.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| L-1 | Low | AV pass | Line-based: a fetch and pipe split across a continuation or two lines wasn't caught; one table row still read "`curl https://*.vercel.app/…`". | Fixed | Continuations are joined and a two-line window is checked; the row is defanged. |
| L-2 | Info | Run-dir check | Accepts any `/.work/`, not only this worktree's. | Accepted | With `wx`, the worst case is a new marker file in another `.work/`. |

Evidence:
- containment sbx 108/111 and oci 105/108, with the same 3 known-gap XFAILs: attribution (M2/M3) and the two write-back-gate checks;
- `fixture-lint --self-test` passes 21 cases;
- `--av` is clean on 200 tracked files;
- The endpoint's detection count is unchanged.

**No medium, high or critical findings remain.**
