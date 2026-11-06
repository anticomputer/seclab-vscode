# Security review: RPC filter stamp in product.json

- **Date:** 2026-11-06
- **Scope:** round DDD, `b9af5e5` and its fixes: `prepare.sh` step 7, the RPC stamp check
  in `check-release.sh`, and its self-test.
- **Threat model:** a build without the RPC filter must not pass as one with it, and the stamp
  must not lie about the policy table in the build.
- **Records:** [EDR rpc-policy-stamp](../edr/20261106-rpc-policy-stamp.md).
- **Prompt injection:** none found.

## Round DDD
Nothing medium or higher. Confirmed:
- prepare and check-release each derive the expected state, and any disagreement fails;
- 0005 under another name, only in a comment, without the table, or a table from another
  patch fails one or the other;
- CRLF, split hunks, context lines and a decoy header either hash consistently or fail
  closed;
- the linux builder (dash), the macOS native scan and the alpine container path all find
  `patches/`.

| # | Sev | Area | Finding | Disposition | Fix |
|---|---|---|---|---|---|
| DDD-1 | Low | check-release | An empty expectation skipped the stamp check silently. The hasher was a pipeline whose status was `cut`'s, and a failure to read the series turned into "absent". | Fixed | The hash comes from no pipeline and fails with the hasher. The series is read on its own. Only `absent` or a sha256 is accepted; anything else sets `bad`. |
| DDD-2 | Low | check-release | A greedy match could read a nested duplicate `seclabRpcPolicy`. | Fixed | Exactly one key when stamped, none otherwise. |
| DDD-3 | Low | EDR | The stamp shows the table was applied, not that the enforcing code was bundled or that the rest of the filter series is listed. | Documented, passed on | The EDR and the observability label say "policy table applied". A bundled literal required in the built JS is passed to the RPC session. |
