# Sentinel format, binding and detection

- **Status:** accepted
- **Date:** 2026-11-04
- **Deciders:** broker session
- **Related:** [ADR no real secret enters a tab](../adr/20261104-no-real-secret-enters-a-tab.md)

## Context
The tab only ever holds sentinels. A sentinel has to work in ordinary
clients: a bearer token, an askpass or credential-helper password (Basic
auth), or an `X-Api-Key`. It must be infeasible to guess, must not look like
any real provider token (so secret scanners and our minted-token rules don't
confuse the two), and must be detectable wherever the tab puts it.

## Decision
- **Format.** Broker-minted sentinels are `SECLAB_SNTL_` followed by 43 base62
  characters from `secrets.choice`, which is about 256 bits
  ([`new_sentinel`](https://github.com/anticomputer/seclab-vscode/blob/b34dfb907f2550e1eae792253a4086cf844b2bae/broker/seclab_broker/credentials.py#L29)).
  - A policy may set a different prefix (`sentinelPrefix`, up to 16
    characters) for clients that check a format.
  - A host-supplied sentinel (`credential.import`) must be 32 to 256
    characters of `[A-Za-z0-9_.~-]` and unique.
- **Scope.** Each sentinel belongs to one tab and one credential. It stays the
  same across `policy.load` calls for the same credential id, and changes on
  `credential.revoke {rotateSentinel: true}` or when the broker restarts.
- **Binding.** A sentinel is swapped only if all of these hold:
  - it appears in the header named by a binding's `inject.header`, either raw
    or inside a decoded `Basic` value;
  - the request matches that binding's host, path, method and port;
  - the scheme is HTTPS.

  The header is overwritten with `inject.fmt` rendered with the real value.
  Supported placeholders are `{value}` and `{base64:…{value}…}`, so Basic auth
  for git is `Basic {base64:x-access-token:{value}}`.
- **Detection.** We look for every sentinel in the raw bytes and in its
  base64 cores, at all three alignments and in both the standard and URL-safe
  alphabets ([`b64_cores`](https://github.com/anticomputer/seclab-vscode/blob/b34dfb907f2550e1eae792253a4086cf844b2bae/broker/seclab_broker/credentials.py)).
  We search headers, the URL, raw and decoded bodies, trailers and WebSocket
  frames. Any occurrence that is not a valid placement is *misplaced*.
- **Inferring an inject spec for imported credentials.** On first use, the
  `inject` of an unconfirmed imported credential is inferred from where the
  tab put the sentinel (for example `Token {value}`), and the user confirms
  it.

## Alternatives considered
- **A sealed, tokenizer-style blob that carries its own destination:** it
  needs a client protocol change (`Proxy-Tokenizer`). Plain sentinels work
  with unmodified clients.
- **A provider-shaped prefix by default (`ghp_…`):** rejected. Sentinels
  would trip secret scanners and our own minted-token rules. It is available
  per credential only when a client needs it.
- **Injecting the credential whenever a request matches, with no sentinel
  present:** rejected. Any process in the tab could use the credential without
  the tab ever being handed it, which removes the opt-in signal and makes
  attribution harder.

## Consequences
- Every process in a tab can replay a sentinel it has seen, but only through
  its binding. That is the accepted per-tab blast radius.
- Base64 detection catches a sentinel smuggled inside Basic auth to a host
  that isn't bound (the test pins this).

## Evidence
- `test_sentinel_found_raw_and_in_basic_auth_and_base64_any_alignment` and
  `test_sentinel_stable_across_policy_reload` (unit tests).
- Integration tests:
  - swap and placement: `test_swap_only_on_binding_match`,
    `test_no_swap_on_wrong_path_or_method`,
    `test_sentinel_to_unbound_allowed_host_not_swapped`,
    `test_sentinel_in_query_of_bound_host_not_swapped`,
    `test_sentinel_in_other_header_of_bound_request`;
  - git and imported credentials: `test_git_clone_and_fetch_with_sentinel`,
    `test_imported_credential_binding_confirmed_on_first_use`.
