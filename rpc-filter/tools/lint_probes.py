#!/usr/bin/env python3
"""Lint the probe payloads for anything that could harm the host.

The safety module enforces targets at runtime. This lint enforces *shape* at
review time, so a dangerous payload cannot be introduced and then quietly
bypass the guards by not calling them.

It is deliberately blunt. A probe exists to demonstrate reach, so it needs
almost none of the API surface this rejects, and a false positive is cheap
next to shipping a working exploit chain that runs on the user's Mac.

Usage:
    python3 lint_probes.py          # exit 1 on any violation
"""

from __future__ import annotations

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", ".."))

# Files that are probe payloads: they run inside the tab against a real host.
# Everything under test/containment that runs inside or against a tab. Scanned
# as a tree, not a hard-coded pair: the first version listed only the two probe
# files, so extension.js (which dumped the real environment and real auth
# sessions) and probe.sh (which egresses externally) were never linted.
PAYLOAD_ROOT = "test/containment"
PAYLOAD_SUFFIXES = (".js", ".sh")
# The guards legitimately name forbidden paths, in order to refuse them.
# The guards legitimately name forbidden paths in order to refuse them. The
# build-time copies are exempt too, but only because the guard-divergence check
# below proves they are byte-identical to the source.
EXEMPT = (
    "test/containment/probe-safety.js",
    "test/containment/rogue-extension/probe-safety.js",
    "test/containment/rogue-reh/probe-safety.js",
    "test/containment/benign-extension/probe-safety.js",
)


def payload_files(repo):
    out = []
    root = os.path.join(repo, PAYLOAD_ROOT)
    for dirpath, dirnames, filenames in os.walk(root):
        # Sorted in place: os.walk reads this list back to pick its descent
        # order, so without it the lint reports findings in filesystem order.
        dirnames[:] = sorted(d for d in dirnames if d not in ("node_modules", "fixtures"))
        for name in sorted(filenames):
            if not name.endswith(PAYLOAD_SUFFIXES):
                continue
            rel = os.path.relpath(os.path.join(dirpath, name), repo)
            if rel in EXEMPT:
                continue
            out.append(rel)
    return out

RULES = (
    # (id, regex, why)
    ("real-user-path",
     re.compile(r"""['"`][^'"`\n]*(?:\.ssh|\.aws|\.gnupg|\.kube|\.netrc|"""
                r"""\.git-credentials|Library/Keychains|/etc/passwd|/etc/shadow)"""),
     "names real user data; probes read only harness-seeded canaries"),
    ("external-host",
     re.compile(r"""['"`]https?://(?!127\.0\.0\.1[:/])[^'"`\s]+"""),
     "names a non-loopback URL; the local beacon is the only allowed destination"),
    ("process-spawn",
     re.compile(r"\b(?:child_process|execFile|execSync|spawnSync|spawn|exec)\s*\("),
     "spawns a process; a probe demonstrates reach, it does not run payloads"),
    ("destructive-fs",
     re.compile(r"\bfs\.(?:rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync|chmod|chmodSync|"
                r"chown|chownSync|rename|renameSync|truncate|truncateSync)\s*\("),
     "destructive or permission-changing filesystem call"),
    ("persistence",
     re.compile(r"LaunchAgents|LaunchDaemons|crontab|\.bashrc|\.zshrc|\.profile|launchctl"),
     "touches a persistence mechanism"),
    ("process-control",
     re.compile(r"\bprocess\.kill\s*\(|\bprocess\.exit\s*\(|\bkillall\b"),
     "kills processes"),
    ("shell-chaining",
     # Only flag a quoted string that actually looks like a command line: a
     # shell verb AND a chaining operator inside the same literal. Matching a
     # bare ` && ` spans ordinary JS (`String(err && err.stack)`).
     re.compile(r"""['"`][^'"`\n]*\b(?:rm|curl|wget|bash|sh|nc|osascript|open|chmod)\b"""
                r"""[^'"`\n]*(?:&&|\|\||;|\|)[^'"`\n]*['"`]"""),
     "chains shell commands; the only permitted command is the marker touch"),
    ("network-client",
     re.compile(r"\brequire\(['\"](?:https?|net|dgram|tls)['\"]\)"),
     "opens its own network client; egress goes to the beacon through the API under test"),
)

# Files that must go through the arming gate. Other scanned files (fixtures
# invoked only inside a tab) still get the content rules.
MUST_ARM = (
    "test/containment/rogue-extension/rpc-probes.js",
    "test/containment/rogue-reh/probes.js",
    "test/containment/rogue-extension/extension.js",
)
# An arming gate must not merely be MENTIONED: the call has to be followed
# closely by a bail-out, so a future edit cannot keep the call while gutting the
# check. Matches `const x = armed(root)` / `safety.context(...)` followed within
# a few lines by continue/return/if (!...).
ARMING_CALL = re.compile(r"(?:safety\.context\(|\barmed\s*\(\s*root\s*\))")
ARMING_BAIL = re.compile(r"\b(?:continue|return)\b|\bif\s*\(\s*!")
# Exemptions are LINE-scoped, never file-scoped. A file-wide exemption covered
# every future base64 use in a 110-line payload that writes its output where the
# attacker reads it; the justification only ever applied to one expression.
# Opt out on the exact line with a pragma:
#     const decoded = Buffer.from(t, 'base64');  // lint-allow: base64-canary-compare
PRAGMA = re.compile(r"//\s*lint-allow:\s*(?P<id>[\w-]+)")
ALLOWED_PRAGMAS = {"base64-canary-compare", "lit-probe-head"}

# Real user sources a probe may read only where the harness seeded a canary first: the
# source expression must be preceded, within a few code lines, by a check of the seeding
# fact that BAILS (throw/return) when it is absent.
#   (id, source, guard, why)
GUARDED_SOURCES = (
    ("unseeded-profile",
     re.compile(r"""scheme:\s*['"]vscode-userdata['"]|['"`]vscode-userdata:"""),
     re.compile(r"\.seclab-test"),
     "names a host profile resource; only the isolated ~/.seclab-test profile the harness launched, checked before use"),
    ("real-keychain",
     re.compile(r"\bkeytar\b|SecKeychain|find-(?:generic|internet)-password|Keychains/"),
     re.compile(r"(?!)"),
     "reads the keychain; no harness seeds it, so no probe may read it"),
)
GUARD_LOOKBACK = 10
GUARD_BAIL = re.compile(r"\bthrow\b|\breturn\b")

# The clipboard is read only through the test build's in-memory canary clipboard. Inverted: in
# a payload's CODE (strings and comments blanked, template substitutions kept) the identifier
# `clipboard` may appear only inside the argument list of `safety.withCanaryClipboard(...)`,
# which refuses unless the harness verified the app under test has it and returns only canary
# tokens. Paste actions, page-side clipboard APIs and dynamic property access on the API
# surface (`vscode.env[...]`, `Reflect.get(`, `globalThis[`) are refused outright (review
# rounds 16 and 18). A lint cannot follow every computed name; it complements the runtime
# guards (the canary store in the test build, withCanaryClipboard, the window.ts refusal).
CLIPBOARD_IDENT = re.compile(r"\bclipboard\b|\$readText\b")
PASTE_ACTION = re.compile(r"clipboardPasteAction|\bexecCommand\(\s*['\"`]paste|\bnavigator\.clipboard\b|\.paste\(\s*\)"
                          r"|\bvscode\.env\s*\[|\bReflect\.get\s*\(|\bglobalThis\s*\[")
CANARY_CLIPBOARD_CALL = re.compile(r"\bwithCanaryClipboard\s*\(")

# Run records hold facts, never values (test/containment/probe-safety.js, run records). In
# these files every file write's data must be `safety.recordJson(...)` (optionally inside
# enc.encode / Buffer.from) or a plain string literal.
RECORD_WRITERS = (
    "test/containment/rogue-extension/extension.js",
    "test/containment/rogue-extension/rpc-probes.js",
    "test/containment/rogue-reh/probes.js",
    "test/containment/benign-extension/extension.js",
)
WRITE_CALL = re.compile(r"\b(?:fs\.(?:writeFileSync|writeFile|appendFileSync|appendFile)|workspace\.fs\.writeFile)\s*\(")
RECORD_DATA = re.compile(r"""^(?:(?:enc\.encode|Buffer\.from)\(\s*)?(?:safety\.recordJson\(|(['"])(?:(?!\1)[^\\\n]|\\.)*\1\s*\)?$)""")
LIT_CALL = re.compile(r"\bsafety\.lit\s*\(")
STRING_LITERAL = re.compile(r"""^(['"])(?:(?!\1)[^\\\n]|\\.)*\1$""")
PROBE_CALL = re.compile(r"(?<!function )\b(?:probe|inconclusive)\s*\(\s*results\s*,")
PLAIN_REF = re.compile(r"^(?:v\.id|[A-Z][A-Z0-9_]*)$")
# A computed key in a record (`{ [x]: ... }`) could carry a host string as the key itself.
COMPUTED_KEY = re.compile(r"[{,]\s*\[[^\]\n]+\]\s*:")

# The system pasteboard is never used by any harness, tool or probe, in any form. Scanned
# over the whole harness tree, not only the payloads.
PASTEBOARD = re.compile(r"\bpbpaste\b|\bpbcopy\b|\bNSPasteboard\b|\b(?:get|set|return)\s+\(?the\s+clipboard\b|\bthe\s+clipboard\s+as\b|\bclipboard\s+info\b|\bUIPasteboard\b")
HARNESS_ROOTS = ("test", "build", "tabd", "sandbox", "broker", "extensions", "rpc-filter", "agentic", "patches", "seclab")
HARNESS_SUFFIXES = (".ts", ".js", ".mjs", ".cjs", ".py", ".sh", ".jxa", ".applescript", ".scpt", ".json", ".patch", "")
# The lint and its tests name the patterns in order to refuse them.
PASTEBOARD_EXEMPT = ("rpc-filter/tools/lint_probes.py", "rpc-filter/tools/test_lint_probes.py")


def _call_args(text: str, open_paren: int) -> list:
    """The top-level argument texts of the call whose '(' is at open_paren (strings skipped)."""
    args, depth, cur, i, quote = [], 0, [], open_paren + 1, None
    while i < len(text):
        ch = text[i]
        if quote:
            cur.append(ch)
            if ch == "\\":
                cur.append(text[i + 1] if i + 1 < len(text) else "")
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "'\"`":
            quote = ch
            cur.append(ch)
        elif ch in "([{":
            depth += 1
            cur.append(ch)
        elif ch in ")]}":
            if depth == 0:
                args.append("".join(cur).strip())
                return args
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    return args


def _call_span(text: str, open_paren: int) -> int:
    """Index just past the ')' that closes the '(' at open_paren."""
    depth, i, quote = 0, open_paren, None
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(text)


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _code_only(text: str) -> str:
    """The text with string literals and comments blanked to spaces (positions and newlines kept)."""
    out, i, n = list(text), 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            for j in (i, i + 1):
                if j < n:
                    out[j] = " "
            i += 2
            continue
        if ch in "'\"`":
            quote, i = ch, i + 1
            while i < n and text[i] != quote:
                if text[i] == "\\":
                    out[i] = " "
                    i += 1
                elif quote == "`" and text[i] == "$" and i + 1 < n and text[i + 1] == "{":
                    # A template substitution is code: keep it, up to its matching brace.
                    depth, i = 1, i + 2
                    while i < n and depth:
                        depth += {"{": 1, "}": -1}.get(text[i], 0)
                        i += 1
                    continue
                if i < n and text[i] != "\n":
                    out[i] = " "
                i += 1
            i += 1
            continue
        i += 1
    return "".join(out)


def clipboard_violations(rel: str, text: str) -> list:
    spans = [(m.end() - 1, _call_span(text, m.end() - 1)) for m in CANARY_CLIPBOARD_CALL.finditer(text)]
    out = []
    for m in CLIPBOARD_IDENT.finditer(_code_only(text)):
        if not any(a < m.start() < b for a, b in spans):
            out.append((rel, _line_of(text, m.start()), "clipboard-outside-canary",
                        "touches the clipboard outside safety.withCanaryClipboard(); only the test "
                        "build's in-memory canary clipboard may be read, never the system clipboard"))
    for m in PASTE_ACTION.finditer(text):
        out.append((rel, _line_of(text, m.start()), "clipboard-outside-canary",
                    "a paste action or page-side clipboard API; no probe pastes or reads a clipboard that way"))
    return out


def record_violations(rel: str, text: str, lines: list) -> list:
    out = []
    pragma_lines = {n for n, l in enumerate(lines, start=1) if (m := PRAGMA.search(l)) and m.group("id") == "lit-probe-head"}
    for m in WRITE_CALL.finditer(text):
        args = _call_args(text, m.end() - 1)
        data = args[1] if len(args) > 1 else ""
        if not RECORD_DATA.match(data):
            out.append((rel, _line_of(text, m.start()), "raw-record",
                        "writes data that is neither safety.recordJson(...) nor a string literal; a run "
                        f"record holds facts, never values\n      data: {data[:100]}"))
    for m in LIT_CALL.finditer(text):
        args = _call_args(text, m.end() - 1)
        n = _line_of(text, m.start())
        if not (len(args) == 1 and STRING_LITERAL.match(args[0])) and n not in pragma_lines:
            out.append((rel, n, "lit-not-literal",
                        "safety.lit() takes a string literal only; anything else could carry a host value"))
    for m in PROBE_CALL.finditer(text):
        args = _call_args(text, text.index("(", m.start()))
        for a in args[1:3]:
            if not (STRING_LITERAL.match(a) or PLAIN_REF.match(a)):
                out.append((rel, _line_of(text, m.start()), "probe-id-not-literal",
                            f"a probe id or policy ref must be a string literal (or v.id / a CONSTANT), got {a[:60]}"))
    for m in COMPUTED_KEY.finditer(_code_only(text)):
        out.append((rel, _line_of(text, m.start()), "computed-record-key",
                    "a computed object key; a record's keys are written in the source, never computed"))
    return out


def pasteboard_violations(root: str) -> list:
    out = []
    for top in HARNESS_ROOTS:
        base = os.path.join(root, top)
        paths = [base] if os.path.isfile(base) else []
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(d for d in dirnames if d not in ("node_modules", ".git"))
            paths.extend(os.path.join(dirpath, f) for f in sorted(filenames))
        for p in paths:
            rel = os.path.relpath(p, root)
            if rel in PASTEBOARD_EXEMPT or not os.path.splitext(p)[1] in HARNESS_SUFFIXES:
                continue
            if rel.endswith(".md"):
                continue
            try:
                with open(p, "r", encoding="utf-8") as fh:
                    for n, line in enumerate(fh, start=1):
                        if PASTEBOARD.search(line):
                            out.append((rel, n, "pasteboard",
                                        "uses the system pasteboard; no harness, tool or probe reads or "
                                        f"writes the user's clipboard\n      {line.strip()[:120]}"))
            except (UnicodeDecodeError, OSError):
                continue
    return out


def guarded_source_violations(rel: str, code: list) -> list:
    out = []
    for i, (n, line) in enumerate(code):
        for rid, source, guard, why in GUARDED_SOURCES:
            if not source.search(line):
                continue
            window = [l for _, l in code[max(0, i - GUARD_LOOKBACK):i + 1]]
            guarded = any(guard.search(l) for l in window) and any(GUARD_BAIL.search(l) for l in window)
            if not guarded:
                out.append((rel, n, rid, f"{why}\n      {line.strip()[:120]}"))
    return out


def main(argv: list | None = None) -> int:
    # An optional root lints another copy of the tree (how a fixed rule is shown to
    # catch the version it was written against).
    args = sys.argv[1:] if argv is None else argv
    root = os.path.abspath(args[0]) if args else REPO
    violations = []
    payloads = payload_files(root)
    if not payloads:
        # A lint over nothing reports clean; that is a lint that cannot fail.
        violations.append((root, 0, "no-payloads", "found no probe payloads to lint under this root"))
    for rel in payloads:
        path = os.path.join(root, rel)
        if not os.path.isfile(path):
            violations.append((rel, 0, "missing", "payload file not found"))
            continue
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        code = []
        for n, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("#"):
                continue
            code.append((n, line))
            for rid, pattern, why in RULES:
                if pattern.search(line):
                    violations.append((rel, n, rid, f"{why}\n      {stripped[:120]}"))
        # Also match across lines, so a construct split over two lines or built
        # by concatenation does not slip past a line-by-line scan.
        joined = "\n".join(l for _, l in code)
        flat = re.sub(r"['\"]\s*\+\s*['\"]", "", joined)
        for rid, pattern, why in RULES:
            if pattern.search(flat) and not any(v[0] == rel and v[2] == rid for v in violations):
                violations.append((rel, 0, rid, f"{why} (matched after joining lines)"))
        violations.extend(guarded_source_violations(rel, code))
        text = "\n".join(l if not (l.strip().startswith("//") or l.strip().startswith("*")) else "" for l in lines)
        violations.extend(clipboard_violations(rel, text))
        if rel in RECORD_WRITERS:
            violations.extend(record_violations(rel, text, lines))
        for n, line in code:
            if "fromCharCode" in line or "'base64'" in line:
                m = PRAGMA.search(line)
                if not m or m.group("id") not in ALLOWED_PRAGMAS:
                    violations.append((rel, n, "obfuscation",
                                       "builds strings via character codes or base64; "
                                       "add `// lint-allow: base64-canary-compare` on this "
                                       "line if it only decodes to compare against a canary"))
        if rel in MUST_ARM:
            gated = False
            for i, (n, line) in enumerate(code):
                if not ARMING_CALL.search(line):
                    continue
                window = "\n".join(l for _, l in code[i:i + 4])
                if ARMING_BAIL.search(window):
                    gated = True
                    break
            if not gated:
                violations.append((rel, 0, "no-arming",
                                   "no arming gate: a safety.context()/armed(root) call must be "
                                   "followed within a few lines by a bail-out"))
        # Any shell command must come from the guard, in this file.
        for n, line in code:
            if "touch '" in line and "markerCommand" not in line:
                violations.append((rel, n, "raw-shell-command",
                                   "builds a shell command without safety.markerCommand()"))

    # Every record writer must still be there: a renamed or deleted writer would otherwise drop
    # out of the record rule without a trace.
    for rel in RECORD_WRITERS:
        if not os.path.isfile(os.path.join(root, rel)):
            violations.append((rel, 0, "missing", "record writer not found; update RECORD_WRITERS"))
    violations.extend(pasteboard_violations(root))

    # Build-time copies of the guard must match the single source exactly.
    src = os.path.join(root, "test/containment/probe-safety.js")
    if os.path.isfile(src):
        with open(src, "rb") as fh:
            want = fh.read()
        for d in ("rogue-extension", "rogue-reh", "benign-extension"):
            copy = os.path.join(root, "test/containment", d, "probe-safety.js")
            if os.path.isfile(copy):
                with open(copy, "rb") as fh:
                    if fh.read() != want:
                        violations.append((f"test/containment/{d}/probe-safety.js", 0,
                                           "guard-divergence",
                                           "differs from test/containment/probe-safety.js"))

    if not violations:
        print("probe payloads clean: %d files, %d content rules + clipboard, record, lit, probe-id, pasteboard"
              % (len(payloads), len(RULES)))
        return 0

    for rel, n, rid, why in violations:
        where = f"{rel}:{n}" if n else rel
        print(f"FAIL [{rid}] {where}\n      {why}", file=sys.stderr)
    print(f"\n{len(violations)} violation(s). Probes demonstrate reach; they are "
          f"never payloads. See rpc-filter/AGENTS.md section 8.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
