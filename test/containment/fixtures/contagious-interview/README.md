# take-home-exercise

Fixture: an inert, faithful reproduction of the "Contagious Interview" fake-recruiter repo
(tasks.json folder-open loader). See `docs/adr/20261104-threat-model-rogue-extension.md`
(worked example) and `test/README.md`.

It does nothing unless a harness run arms it (`.seclab/targets` with the run's nonce, run
directory and expiry). Armed, it only records evidence, contacts the run's loopback beacon
and reserved/test-net addresses, reads harness-seeded canaries, and writes markers under
the run directory (or, only inside a tab, into the tab's own home).
