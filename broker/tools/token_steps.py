r"""Finding HH-1: in the docs workflow, the GitHub token reaches exactly one step, the attestation
bundle download, and no other step regains it (the docs gate and everything after it run
tokenless and verify offline from the downloaded bundles).
    python broker/tools/token_steps.py [WORKFLOW]     default .github/workflows/docs-check.yml
    python broker/tools/token_steps.py --self-test
The tool images carry no YAML parser, so this reads the text and fails closed. A step starts at a
`- ` list item directly under a `steps:` key, and runs until the next item at that indentation
or a shallower line. It covers:
  * every `${{ … }}` expression naming `github.token` or `secrets`, or handing on the whole
    `github` context (`toJSON(github)`, `github.*`, a computed `github[…]`), outside the one
    step whose name is exactly ALLOWED_STEP. Expressions are found across line breaks, in
    comments too (a comment mentioning one fails: rephrase it), and end at the first `}}`
    outside a single-quoted string (review BRK20D-1);
  * any raw sighting of `github.token`, `github['token']` or `secrets`, or of a GH_TOKEN or
    GITHUB_TOKEN name, outside that step, so an expression whose span is cut short (a `}}`
    inside a quoted string) is still seen (review BRK20R-2);
  * inside that step, any write to $GITHUB_ENV, $GITHUB_OUTPUT or $GITHUB_STATE, or a
    `::set-env`/`::set-output`/`::save-state` command, which would hand the token to later
    steps with no expression at all (review BRK20R-1);
  * any `secrets:` key (`secrets: inherit` or a mapping to a reusable workflow), anywhere;
  * any YAML numeric escape (`\x`, `\u`, `\U`, `\N`, `\_`, `\L`, `\P`), and any double-quoted
    value continued with a trailing backslash, anywhere: YAML decodes both before Actions sees
    the expression, so they could spell a name the scan can't see (review BRK20D-2);
  * exactly one step named ALLOWED_STEP, which must carry the token.
It is a regression check over a workflow that is also reviewed and linted (actionlint, zizmor),
not a YAML evaluator: forms Actions rejects (anchors) are out of scope.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ALLOWED_STEP = "Download attestation bundles (the only step with a token; gh on the runner)"
TOKEN = re.compile(r"\bgithub\s*(?:\.\s*token\b|\[\s*['\"]token['\"]\s*\])|\bsecrets\b", re.I)
# The whole github context carries the token: toJSON(github), github.*, a computed github[...]
# index. Allowed: a named property (github.ref) or a literal index other than token (BRK20D-1).
WHOLE_GITHUB = re.compile(r"\bgithub\b(?!\s*\.\s*[A-Za-z_])(?!\s*\[\s*'[^']*'\s*\])", re.I)
STRING = re.compile(r"'(?:[^']|'')*'")
# YAML decodes these in a double-quoted scalar before Actions sees the expression, so they could
# spell a name the scan can't see; the check reads raw text and refuses them (review BRK20D-2).
YAML_ESCAPE = re.compile(r"\\(?:[xuU][0-9A-Fa-f]|[N_LP])")
DQ_CONTINUATION = re.compile(r"^[^#\n]*\"[^\"\n]*\\[ \t]*$", re.M)
SECRETS_KEY = re.compile(r"^\s*(?:-\s+)?secrets\s*:", re.M)
# Actions resolves contexts and properties case-insensitively, so these do too (review BRK20C-1).
RAW_TOKEN = re.compile(TOKEN.pattern + r"|\bGH_TOKEN\b|\bGITHUB_TOKEN\b", re.I)
HANDOFF = re.compile(r"GITHUB_(?:ENV|OUTPUT|STATE)\b|::(?:set-env|set-output|save-state)\b")


def step_of_lines(text: str) -> list[str | None]:
    """For each line (index 0 = line 1): the enclosing step's name ("" for an unnamed step),
    or None outside any step."""
    out: list[str | None] = []
    steps_indent: int | None = None
    item_indent: int | None = None
    step: str | None = None
    for raw in text.splitlines():
        stripped = raw.strip()
        indent = len(raw) - len(raw.lstrip())
        if stripped and not stripped.startswith("#"):
            if steps_indent is not None and indent <= steps_indent:
                steps_indent = item_indent = step = None
            if re.fullmatch(r"steps:\s*", stripped):
                steps_indent, item_indent, step = indent, None, None
            elif steps_indent is not None and stripped.startswith("- "):
                if item_indent is None:
                    item_indent = indent
                if indent == item_indent:
                    m = re.match(r"-\s+name:\s*(.*)", stripped)
                    step = m[1].strip().strip("'\"") if m else ""
            elif step is not None and item_indent is not None and indent <= item_indent:
                step = None
        out.append(step)
    return out


def expressions(text: str):
    """(start offset, body) of each `${{ … }}`, ending at the first `}}` outside a single-quoted
    string (Actions' only string literal; '' escapes a quote), so a `}}` inside a string can't
    cut an expression short. An unterminated one runs to the end of the text (fail closed)."""
    i = 0
    while (start := text.find("${{", i)) != -1:
        j, quoted = start + 3, False
        while j < len(text):
            if text[j] == "'":
                if quoted and text[j + 1:j + 2] == "'":
                    j += 2
                    continue
                quoted = not quoted
            elif not quoted and text.startswith("}}", j):
                break
            j += 1
        yield start, text[start + 3:j]
        i = j + 2


def token_bearing(body: str) -> bool:
    """An expression that names the token or a secret, or hands on the whole github context."""
    return bool(TOKEN.search(body) or WHOLE_GITHUB.search(STRING.sub("''", body)))


def token_sites(text: str) -> list[tuple[int, str | None]]:
    """(line number, step name or None outside any step) for each token-bearing expression,
    by the line its `${{` opens on."""
    steps = step_of_lines(text)
    out = []
    for start, body in expressions(text):
        if token_bearing(body):
            n = text.count("\n", 0, start) + 1
            out.append((n, steps[n - 1] if n - 1 < len(steps) else None))
    return out


def check(text: str) -> list[str]:
    sites = token_sites(text)
    lines = text.splitlines()
    errors = [f"line {n}: a token outside the attestation download step"
              + (f" (in step {name!r})" if name else " (workflow or job level: every step gets it)")
              for n, name in sites if name != ALLOWED_STEP]
    errors += [f"line {n}: a token expression in a comment (fail closed: rephrase it)"
               for n, _name in sites if lines[n - 1].lstrip().startswith("#")]
    for m in SECRETS_KEY.finditer(text):
        errors.append(f"line {text.count(chr(10), 0, m.start()) + 1}: a secrets: key hands secrets on")
    for rx, what in ((YAML_ESCAPE, "a YAML numeric escape"),
                     (DQ_CONTINUATION, "a double-quoted value continued with a backslash")):
        for m in rx.finditer(text):
            errors.append(f"line {text.count(chr(10), 0, m.start()) + 1}: {what} (decoded before Actions; "
                          "fail closed)")
    steps = step_of_lines(text)
    for n, (line, step) in enumerate(zip(lines, steps), 1):
        if step != ALLOWED_STEP and RAW_TOKEN.search(line):
            errors.append(f"line {n}: a token name or expression outside the attestation download step")
        if step == ALLOWED_STEP and HANDOFF.search(line):
            errors.append(f"line {n}: the download step writes to a channel later steps read")
    named = len(re.findall(r"^\s*-\s+name:\s*['\"]?" + re.escape(ALLOWED_STEP) + r"['\"]?\s*$", text, re.M))
    if named != 1:
        errors.append(f"{named} steps are named {ALLOWED_STEP!r}; exactly one must be")
    if not any(name == ALLOWED_STEP for _n, name in sites):
        errors.append("no token in the attestation download step: the check has nothing to anchor on")
    return errors


def self_test() -> list[str]:
    ok_step = (f"      - name: {ALLOWED_STEP}\n"
               "        env:\n          GH_TOKEN: ${{ github.token }}\n"
               "        run: broker/tools/verify-images.sh --download x\n")
    head = "on: push\njobs:\n  docs:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@x\n"
    act = "/".join(("fake-owner", "fake-action")) + "@" + "x"  # built from parts: a fixture, not a real repository
    wf = "/".join(("fake-owner", "fake-repo", ".github", "workflows", "w.yml")) + "@" + "x"
    gate = "      - name: Docs gate\n        run: ./seclab docs check\n"
    outside = "a token outside the attestation download step"  # the ${{ }} expression rule
    raw = "a token name or expression outside"  # the raw-sighting rule
    # (name, workflow text, the message the case's own rule must report, or None for a pass). Each
    # case pins one rule: removing that rule alone fails it (review BRK20C-2, BRK20C-3).
    cases = [
        ("HH-1: a token only in the attestation download step passes", head + ok_step + gate, None),
        ("HH-1: a later step that regains the token fails",
         head + ok_step + gate.replace("        run:", "        env:\n          GH_TOKEN: ${{ github.token }}\n        run:"),
         outside),
        ("HH-1: a secret in a later step fails", head + ok_step + gate + "      - run: echo ${{ secrets.X }}\n", outside),
        ("HH-1: a job-level token fails",
         head.replace("    runs-on: x\n", "    runs-on: x\n    env:\n      GH_TOKEN: ${{ github.token }}\n")
         + ok_step + gate, "every step gets it"),
        ("HH-1: a workflow-level token fails",
         "env:\n  T: ${{ secrets.GITHUB_TOKEN }}\n" + head + ok_step + gate, "every step gets it"),
        ("HH-1: a token passed to an action's with: fails",
         head + ok_step + f"      - uses: {act}\n        with:\n          token: ${{{{ github.token }}}}\n", outside),
        ("HH-1: a token in a comment fails closed (rephrase the comment)",
         head + ok_step + "      # GH_TOKEN: ${{ github.token }} is never set here\n" + gate, "in a comment"),
        ("HH-1: a workflow with no token at all fails (nothing to anchor on)", head + gate, "nothing to anchor on"),
        ("BRK20-1: a later step whose name only starts like the download step fails",
         head + ok_step + "      - name: Download attestation bundles, then publish\n"
         "        env:\n          GH_TOKEN: ${{ github.token }}\n        run: x\n", "then publish"),
        ("BRK20-1: two steps named exactly as the download step fail", head + ok_step + ok_step + gate,
         "2 steps are named"),
        ("BRK20-2: a token after a ' #' inside a quoted string fails",
         head + ok_step + "      - run: curl -H \"X: #${{ secrets.X }}\" https://x.invalid/\n", outside),
        ("BRK20-2: an expression split across lines fails",
         head + ok_step + "      - env:\n          T: >-\n            ${{\n            github.token }}\n        run: x\n",
         outside),
        ("BRK20-2: github['token'] index syntax fails",
         head + ok_step + "      - run: echo ${{ github['token'] }}\n", outside),
        ("BRK20-2: toJSON(secrets) fails", head + ok_step + "      - run: echo '${{ toJSON(secrets) }}'\n", outside),
        ("BRK20-2: secrets: inherit to a reusable workflow fails",
         head + ok_step + gate + f"  other:\n    uses: {wf}\n    secrets: inherit\n", "a secrets: key hands secrets on"),
        ("BRK20R-1: the download step writing the token to $GITHUB_ENV fails",
         head + ok_step.replace("        run: broker/tools/verify-images.sh --download x\n",
                                "        run: |\n          broker/tools/verify-images.sh --download x\n"
                                "          echo \"GH_TOKEN=$GH_TOKEN\" >> \"$GITHUB_ENV\"\n") + gate,
         "writes to a channel later steps read"),
        ("BRK20R-1: the download step writing to $GITHUB_OUTPUT fails",
         head + ok_step.replace("        run: broker/tools/verify-images.sh --download x\n",
                                "        run: echo \"t=$GH_TOKEN\" >> \"$GITHUB_OUTPUT\"\n") + gate,
         "writes to a channel later steps read"),
        ("BRK20R-1: a later step naming GH_TOKEN with no expression fails",
         head + ok_step + "      - run: curl -H \"Authorization: Bearer $GH_TOKEN\" https://x.invalid/\n", raw),
        ("BRK20R-2: a '}}' inside a quoted string can't hide a secret",
         head + ok_step + "      - run: echo ${{ format('a}}b', secrets.GITHUB_TOKEN) }}\n", raw),
        ("BRK20C-1: an upper-case SECRETS context in a later step fails",
         head + ok_step + "      - run: echo ${{ SECRETS.MY_KEY }}\n", outside),
        ("BRK20C-1: a mixed-case GitHub.Token in a later step fails",
         head + ok_step + "      - run: echo ${{ GitHub.Token }}\n", outside),
        ("BRK20C-1: a lower-case gh_token name in a later step fails",
         head + ok_step + "      - run: curl -H \"Authorization: Bearer $gh_token\" https://x.invalid/\n", raw),
        ("BRK20D-1: toJSON(github) in a later step fails",
         head + ok_step + "      - env:\n          CONTEXT: ${{ toJSON(github) }}\n        run: x\n", outside),
        ("BRK20D-1: the github.* object filter in a later step fails",
         head + ok_step + "      - run: echo '${{ join(github.*, ',') }}'\n", outside),
        ("BRK20D-1: a computed github[...] index in a later step fails",
         head + ok_step + "      - run: echo ${{ github[format('{0}{1}', 'to', 'ken')] }}\n", outside),
        ("BRK20D-1: a '}}' inside a string doesn't end the expression early",
         head + ok_step + "      - run: echo ${{ format('a}}b', toJSON(github)) }}\n", outside),
        ("BRK20D-1: named github properties and string mentions stay allowed",
         head + ok_step + gate + "      - if: github.event_name == 'push'\n"
         "        run: echo ${{ github.ref }} ${{ github['run_id'] }} ${{ format('{0}', 'github') }}\n", None),
        ("BRK20D-2: a unicode escape in a double-quoted value fails",
         head + ok_step + "      - env:\n          ACCESS: \"${{ github['to\\u006ben'] }}\"\n        run: x\n",
         "a YAML numeric escape"),
        ("BRK20D-2: a hex escape in a double-quoted value fails",
         head + ok_step + "      - env:\n          ACCESS: \"${{ github['to\\x6ben'] }}\"\n        run: x\n",
         "a YAML numeric escape"),
        ("BRK20D-2: a double-quoted value joined across lines with a backslash fails",
         head + ok_step + "      - env:\n          ACCESS: \"${{ github['to\\\n            ken'] }}\"\n        run: x\n",
         "continued with a backslash"),
    ]
    failures = []
    for name, text, want in cases:
        try:
            errors = check(text)
        except Exception as e:  # noqa: BLE001 - a crash is a failed case, never a pass
            failures.append(f"{name}: raised {type(e).__name__}")
            continue
        if want is None and errors:
            failures.append(f"{name}: errors {errors}")
        elif want is not None and not any(want in e for e in errors):
            failures.append(f"{name}: no error containing {want!r} in {errors}")
    return failures


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        failures = self_test()
        for f in failures:
            print("token-steps self-test: FAIL: " + f, file=sys.stderr)
        print(f"token-steps self-test: {'ok' if not failures else 'FAILED'}", file=sys.stderr)
        return 1 if failures else 0
    path = Path(sys.argv[1] if len(sys.argv) > 1 else ".github/workflows/docs-check.yml")
    errors = check(path.read_text())
    for e in errors:
        print(f"token-steps: {path}: {e}", file=sys.stderr)
    if not errors:
        print(f"token-steps: ok ({path.name}: the token reaches only the attestation download)", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
