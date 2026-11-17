"""Finding HH-1: in the docs workflow, the GitHub token reaches exactly one step, the attestation
bundle download, and no other step regains it (the docs gate and everything after it run
tokenless and verify offline from the downloaded bundles). Every token-bearing expression
(`github.token`, `secrets.*`) must sit inside that step; one at the workflow or job level would
reach every step.
    python broker/tools/token_steps.py [WORKFLOW]     default .github/workflows/docs-check.yml
    python broker/tools/token_steps.py --self-test
Line-based (the tool images carry no YAML parser): a step starts at a `- ` list item directly
under a `steps:` key, and runs until the next item at that indentation or a shallower line.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ALLOWED_STEP = "Download attestation bundles"
TOKEN = re.compile(r"\$\{\{[^}]*\b(github\.token|secrets\.[A-Za-z_][A-Za-z0-9_]*)\b[^}]*\}\}")


def token_sites(text: str) -> list[tuple[int, str | None]]:
    """(line number, step name or None outside any step) for each token-bearing expression."""
    out: list[tuple[int, str | None]] = []
    steps_indent: int | None = None
    item_indent: int | None = None
    step: str | None = None
    for n, raw in enumerate(text.splitlines(), 1):
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
        code = raw.split(" #", 1)[0] if not raw.lstrip().startswith("#") else ""
        if TOKEN.search(code):
            out.append((n, step))
    return out


def check(text: str) -> list[str]:
    sites = token_sites(text)
    errors = [f"line {n}: a token outside the attestation download step"
              + (f" (in step {name!r})" if name else " (workflow or job level: every step gets it)")
              for n, name in sites if not (name or "").startswith(ALLOWED_STEP)]
    if not sites:
        errors.append("no token in the attestation download step: the check has nothing to anchor on")
    return errors


def self_test() -> list[str]:
    ok_step = ("      - name: Download attestation bundles (the only step with a token)\n"
               "        env:\n          GH_TOKEN: ${{ github.token }}\n"
               "        run: broker/tools/verify-images.sh --download x\n")
    head = "on: push\njobs:\n  docs:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@x\n"
    act = "/".join(("fake-owner", "fake-action")) + "@" + "x"  # built from parts: a fixture, not a real repository
    gate = "      - name: Docs gate\n        run: ./seclab docs check\n"
    cases = [  # (name, workflow text, want errors)
        ("HH-1: a token only in the attestation download step passes", head + ok_step + gate, False),
        ("HH-1: a later step that regains the token fails",
         head + ok_step + gate.replace("        run:", "        env:\n          GH_TOKEN: ${{ github.token }}\n        run:"),
         True),
        ("HH-1: a secret in a later step fails", head + ok_step + gate + "      - run: echo ${{ secrets.X }}\n", True),
        ("HH-1: a job-level token fails",
         head.replace("    runs-on: x\n", "    runs-on: x\n    env:\n      GH_TOKEN: ${{ github.token }}\n")
         + ok_step + gate, True),
        ("HH-1: a workflow-level token fails",
         "env:\n  T: ${{ secrets.GITHUB_TOKEN }}\n" + head + ok_step + gate, True),
        ("HH-1: a token passed to an action's with: fails",
         head + ok_step + f"      - uses: {act}\n        with:\n          token: ${{{{ github.token }}}}\n", True),
        ("HH-1: a token mentioned only in a comment passes",
         head + ok_step + "      # GH_TOKEN: ${{ github.token }} is never set here\n" + gate, False),
        ("HH-1: a workflow with no token at all fails (nothing to anchor on)", head + gate, True),
    ]
    failures = []
    for name, text, want in cases:
        try:
            got = bool(check(text))
        except Exception as e:  # noqa: BLE001 - a crash is a failed case, never a pass
            failures.append(f"{name}: raised {type(e).__name__}")
            continue
        if got != want:
            failures.append(f"{name}: {'errors' if got else 'no errors'}")
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
