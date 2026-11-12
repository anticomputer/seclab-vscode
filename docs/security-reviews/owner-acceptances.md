# Owner acceptances

Each row records a decision by the project owner to accept a finding's risk until its closing
condition holds. Only the coordinator adds rows, on an explicit owner decision, each in its own
commit, landed before the change that closes the finding. No row quotes or paraphrases a
conversation. The findings register's gate (`build/docs/findings.ts`, EDR
`docs/edr/20261110-security-findings-register.md`) checks the rows: the finding's full key, the
date, the scope, the closing condition and the decision, and no quotation marks anywhere here.

| Finding | Date | Scope | Closing condition | Decision |
|---|---|---|---|---|
| 20261104-rpc-lockdown-design.md#4 | 2026-11-12 | residual 1, deferred laundering | closes when the response-side control lands with probes | accepted by the project owner |
| register#INC-4-R1 | 2026-11-12 | closed pull request refs, orphaned commits and cached views of pre-rewrite history | none: accepted with no purge request | accepted by the project owner |
