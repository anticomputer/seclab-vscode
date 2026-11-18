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
| 20261110-security-findings-register.md#HHHH-4 | 2026-11-18 | owner rows are written only by the coordinator; the gate checks their shape, not their author | a separate identity for automation enables a required reviewer on owner-acceptances.md | accepted by the project owner |
| 20261117-required-jobs-gate.md#RJG-1 | 2026-11-17 | required jobs run code the pull request controls, so a gutted job can conclude success; compensated by landing verify re-running the previous main's validators over the merged tree, and by coordinator review before arming of every pull request touching the workflows, seclab or build/; the forged-status residual remains | a separate identity for automation enables code-owner review of the workflows, seclab and build/ | accepted by the project owner |
