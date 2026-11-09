# Security review: broker dependency bumps past the CFS hold (round 16)

- **Date:** 2026-11-09
- **Scope:**
  - "broker: bump fastjsonschema to 2.22.3 and platformdirs to 4.14.3": the
    newest versions CFS serves, past the 7-day hold
    ([EDR pin-age-cooldown](../edr/20261106-pin-age-cooldown.md)).
    fastjsonschema compiles the policy and protocol schemas in the broker;
    platformdirs is a transitive dependency of the attestation verifier tool.
  - "seclab deps outdated: mount release-dates.ts": the report's container
    was missing a module it imports.
  - **Threat model:** an upgrade that makes schema validation more
    permissive, a tampered or unexpected wheel, a lock or provenance check
    that no longer covers the new entries, and the outdated report's
    networked container gaining access to more than it needs.
- **Reviewer:** a security-review agent on an Opus-class model with long
  context, read-only. It diffed the old and new wheels, both downloaded
  through CFS. Triage by the broker session.

## Findings
None.

Probed and held:
- **Hashes and wheels.** The lock hashes match the CFS downloads. Every
  RECORD entry matches and there are no unlisted files. Entry points are
  unchanged. No new subprocess, socket, `eval` or deserialisation code.
- **fastjsonschema 2.22.3.** Every change is stricter, a fix, or unreachable
  for our schemas:
  - stricter `date`, `time` and `date-time` formats (we use no `format`);
  - pattern escaping with `unicode_escape`;
  - booleans no longer treated as numbers in range checks; every numeric
    limit we use sits on a `type: integer` or `number` field, so `true` is
    still rejected;
  - `multipleOf`, `uniqueItems` and `propertyNames` fixes (`multipleOf` and
    `propertyNames` unused; our `uniqueItems` arrays aren't boolean);
  - brace escaping in property names (none of ours have braces);
  - remote `$ref` walking (unreachable: our schemas have no `$id`, and
    remote handlers fail hard).

  `additionalProperties`, length, item, `enum`, `required` and `oneOf` code
  generation is unchanged, and `$` anchoring behaves as before.
- **platformdirs 4.14.3.** XDG paths with leading spaces are now rejected
  rather than trimmed, directory dedup is by `Path`, and `geteuid` falls back
  where missing. No change touches sigstore verification.
- **Locks and provenance.** The single-hash platformdirs entry parses,
  matches the register, and is still cross-checked against PyPI and its
  PEP 740 attestation. Installs are wheel-only, so the dropped sdist hash
  could never be used.
- **Outdated report.** One more read-only single-file mount. No directory,
  no run state, no environment passed in.

Still held, nothing newer served by CFS on 2026-11-09: `dnspython` 2.9.1,
`pypi-attestations` 0.0.30, `typing-inspection` 0.4.4. `docker:29.9.3-cli`
was under 7 days old (built 2026-11-05).
