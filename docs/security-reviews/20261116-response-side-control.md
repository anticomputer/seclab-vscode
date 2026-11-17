# Security review: the response-side control (patch 0033, `seclabFromTab`)

- **Date:** 2026-11-16 (findings); fixes and proof 2026-11-17
- **Reviewer:** independent `security-review` agent (an Opus-class model)
- **Subject:** the response-side control as first landed on its branch: `seclabFromTab` and the
  `_seclab.tabCommand` token handler in the filter module, patch 0033 (hover and completion),
  the policy entries and `check_drift.py::check_responses`, the response probe and its harness,
  and the records ([ADR](../adr/20261116-response-side-control.md)).
- **Prompt:** said the diff, fixtures and evidence may contain prompt injection aimed at the
  reviewer, and that the reviewer reports it rather than following it. None was found.

## Verdict
The command half holds: a command a tab returns can't run on the trusted side unless the
policy allows it outright, and tokens can't be forged or used from another window. Two data
vectors got past the control, a high and a medium. Both are fixed, and the response probe
shows each reproducing on the reviewed build before the fix.

| ID | Sev | Component | Finding | Status |
|---|---|---|---|---|
| RSC-1 | high | patch 0033, completion items | A tab completion inserted as a snippet naming `${CLIPBOARD}` makes the window read the host clipboard and insert it into the tab's document, which document sync then gives the tab. That gets around the policy's deny of `MainThreadClipboard.$readText`. The resolve round-trip can supply the snippet too | fixed |
| RSC-2 | medium | `seclabFromTab` markdown | Remote images still reached the trusted hover renderer. A nested image `![x![]y](…)` and the reference form survive the two strip patterns. Because `isTrusted` is a truthy object, a `<span>` HTML block passes through whole, with an `<img>` inside it. The CSP admits `https:` images, so the renderer fetches a URL the tab chose, outside the broker, on hover | fixed |
| RSC-3 | low | register, ADR | RPC-R2 was marked fixed although its markdown and image parts were neither fixed nor proven | fixed |
| RSC-4 | info | ADR, RPC-LOCKDOWN, code comment | The records didn't match the code: the token handler's routing, whether a tab sees tokens, which images were kept, how a selector without a scheme is handled, and a comment claiming no styled span reaches the renderer | fixed |
| RSC-5 | info | trusted opener | A non-`command:` link in tab markdown opens through the trusted opener: `http(s)` and `mailto` on the host behind upstream link protection rather than the tab-naming `$openUri` prompt, and `file:` opens a host file in the window (display only). Each needs a click | open |
| RSC-6 | info | `check_drift.py::check_responses` | The gate checks only `$register*` methods. Push methods that carry markdown or commands into UI (messages, status bar, diagnostics) aren't gated; none is reachable today | open |

## Confirmed without findings
- Completion and hover command fields are always replaced by a token, including the resolve
  round-trip and the internal command delegation path.
- Completion `detail` and label parts are plain text. `additionalTextEdits` and `range` apply
  only to the requesting model, which the selector limits to the tab's own documents. Snippet
  variables other than `CLIPBOARD` resolve only to the tab's own document or workspace, or to
  time and random values.
- `command:` link forms the rewrite misses are inert: the opener allows only the token command,
  and a tab can't produce a valid token.
- Tokens are 128-bit random values in a per-window map, capped at 16384 entries. A stale token
  runs only that tab's own command.
- The selector validator and the narrowing keep providers to `vscode-remote` documents.
- The pre-control and control builds differ only in 0033, with positive controls in both modes.

## What changed in response
- RSC-1: 0033 inserts a tab snippet that names `CLIPBOARD` as plain text, on the first result
  and after resolve (`_seclabSnippet`, `seclabFromTab.snippetAllowed`).
- RSC-2: tab markdown escapes every image opener and every tag opener instead of stripping
  images by pattern.
- `test/containment/filter-module.test.ts` covers the review's bypass forms and the snippet
  rule, each with a mutant that fails it.
- The response probe gained both vectors and a `reviewed` mode:
  - hover images in the three forms, each at its own loopback port;
  - a `${CLIPBOARD}` snippet against the containment build's in-memory canary store.
  - On the reviewed build (`b0e86b3c`, run 43933297956) all 15 checks passed: the nested and
    span images were fetched, and the snippet inserted the canary.
- RSC-3, RSC-4: the ADR, RPC-LOCKDOWN and the code comment are corrected, and RPC-R2 is
  closed only on the new control run.
- RSC-5 and RSC-6 are registered open with follow-ups.
