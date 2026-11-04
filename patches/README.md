# Core patch queue

Ordered `NNNN-short-concern.patch` files, applied with `git apply` by
`build/prepare.sh` in lexical order against the commit in `upstream.lock`.
A patch that doesn't apply fails the build.

Rules ([ADR](../docs/adr/20261104-vscodium-style-fork.md)):
- One concern per patch, under about 50 lines.
- Write an EDR (or ADR, if it changes the design) for each patch, and run a
  security review on each new or changed patch.
- Policy that can be expressed in `product.json` goes in
  `build/product/overrides.json`, not here.

The queue is **empty** for M0 and M1. The expected M4 patches are the RPC
capability filter, auth mediation, storage partitioning, webview egress, and an
`extensionKind` wildcard.
