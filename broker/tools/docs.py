"""Docs that cannot drift.

  python broker/tools/docs.py check      # fail if any generated section, example or cross-check is off
  python broker/tools/docs.py write      # regenerate the generated sections in place
  python broker/tools/docs.py commands   # print the `ci: run` shell blocks as one bash script

Run through broker/docs-check.sh (inside the broker unit image), not on the host.

Sources of truth:
  broker/schema/protocol.v1.json      methods, params, results, notifications, errors, audit types
  broker/schema/policy.v1.schema.json policy document
  broker/schema/capabilities.v1.json  capability matrix notes (+ core.CAPABILITIES for values)
  broker/seclab_broker/data/*         baseline, provider backstop, token rules
  broker/examples/*.json              example policies

Rules enforced on CHECKED_DOCS:
  * text between <!-- BEGIN GENERATED: x --> and <!-- END GENERATED: x --> equals the rendering;
  * every ```json block is preceded by <!-- check: KIND [NAME] --> and validates;
  * every ```sh block is preceded by <!-- ci: run --> or <!-- ci: skip: REASON -->.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

BROKER = Path(__file__).resolve().parents[1]
REPO = BROKER.parent
sys.path.insert(0, str(BROKER))

import seclab_broker  # noqa: E402
from seclab_broker import protocol  # noqa: E402
from seclab_broker.core import CAPABILITIES, Broker  # noqa: E402
from seclab_broker.policy import DATA_DIR, Policy, PolicyError, _schema as policy_schema  # noqa: E402

CHECKED_DOCS = [
    "broker/AGENTS.md",
    "broker/README.md",
    "docs/broker-protocol.md",
    "docs/broker-policy.md",
    "docs/adr/20261104-broker-policy-and-control-protocol.md",
    "docs/adr/20261104-no-real-secret-enters-a-tab.md",
    "docs/edr/20261104-broker-engine-mitmproxy.md",
    "docs/edr/20261104-sentinel-format-and-binding.md",
    "docs/edr/20261104-broker-per-tab-ca.md",
    "docs/edr/20261104-internal-network-dns-exfiltration.md",
    "docs/edr/20261104-broker-behind-sbx-fence.md",
    "docs/edr/20261104-broker-docs-from-sources-and-safe-fixtures.md",
    "docs/security-reviews/20261104-broker-m2-m3.md",
    "docs/security-reviews/20261104-broker-docs-drift-and-fixtures.md",
]
GEN_RE = re.compile(r"(<!-- BEGIN GENERATED: (\S+) [^>]*-->\n)(.*?)(<!-- END GENERATED: \2 -->)", re.S)
FENCE_RE = re.compile(r"^```(\w*)[^\n]*\n(.*?)^```[ \t]*$", re.S | re.M)
ANNOT_RE = re.compile(r"<!--\s*(check|ci):\s*(.*?)\s*-->\s*$")
SH_LANGS = ("sh", "bash", "shell")
POLICY_DEFS = set(policy_schema()["definitions"])


# ----------------------------------------------------------------- rendering helpers

def esc(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def type_str(s: dict) -> str:
    if "$ref" in s:
        name = s["$ref"].rsplit("/", 1)[-1]
        if name == "policy":
            return "[`Policy`](broker-policy.md)"
        if name in POLICY_DEFS:
            return f"[`{name}`](broker-policy.md#{name.lower()})"
        return f"[`{name}`](#{name.lower()})"
    if "const" in s:
        return f"`{json.dumps(s['const'])}`"
    if "enum" in s:
        return " \\| ".join(f"`{json.dumps(v)}`" for v in s["enum"])
    if "oneOf" in s:
        return " \\| ".join(type_str(x) for x in s["oneOf"])
    t = s.get("type")
    if t == "array":
        return type_str(s.get("items", {})) + "[]"
    if t == "object" and isinstance(s.get("additionalProperties"), dict):
        return "map of " + type_str(s["additionalProperties"])
    if isinstance(t, list):
        return " \\| ".join(f"`{x}`" for x in t)
    return f"`{t}`" if t else "any"


def constraints(s: dict) -> str:
    out = []
    for k, label in (("pattern", "pattern"), ("minLength", "min length"), ("maxLength", "max length"),
                     ("minimum", "min"), ("maximum", "max"), ("minItems", "min items"),
                     ("maxItems", "max items"), ("default", "default")):
        if k in s:
            v = s[k]
            out.append(f"{label} `{json.dumps(v) if k == 'default' else v}`")
    return "; ".join(out)


def field_rows(s: dict, prefix: str = "") -> list[str]:
    rows = []
    req = set(s.get("required", []))
    for name, sub in s.get("properties", {}).items():
        desc = sub.get("description", "")
        cons = constraints(sub)
        if cons:
            desc = (desc + " " if desc else "") + f"({cons})"
        rows.append(f"| `{prefix}{name}` | {type_str(sub)} | {'yes' if name in req else ''} | {esc(desc)} |")
        if sub.get("type") == "object" and "properties" in sub:
            rows += field_rows(sub, f"{prefix}{name}.")
    return rows


def fields_table(s: dict) -> str:
    if "$ref" in s:
        return f"{type_str(s)}\n"
    rows = field_rows(s)
    if not rows:
        return "none\n"
    return "| Field | Type | Required | Description |\n|---|---|---|---|\n" + "\n".join(rows) + "\n"


def json_block(kind: str, obj) -> str:
    return f"<!-- check: {kind} -->\n```json\n{json.dumps(obj, indent=1)}\n```\n"


def def_section(level: str, name: str, d: dict) -> str:
    desc = d.get("description", "")
    if "properties" in d:
        table = fields_table(d)
    else:
        cons = constraints(d)
        table = f"Type: {type_str(d)}{' (' + cons + ')' if cons else ''}\n"
    return f"<a id=\"{name.lower()}\"></a>\n{level} `{name}`\n\n{desc + chr(10) + chr(10) if desc else ''}{table}"


# ----------------------------------------------------------------- generated sections

def gen_errors() -> str:
    rows = [f"| {e['code']} | `{e['name']}` | {esc(e['description'])} |" for e in protocol.definition()["errors"]]
    return "| Code | Name | Meaning |\n|---|---|---|\n" + "\n".join(rows) + "\n"


def gen_methods() -> str:
    out = []
    for name, m in protocol.definition()["methods"].items():
        out.append(f"### `{name}`\n\n{m['description']}\n\n**Params**\n\n{fields_table(m['params'])}\n"
                   f"**Result**\n\n{fields_table(m['result'])}")
        for i, ex in enumerate(m.get("examples", [])):
            out.append(f"\nExample{'' if i == 0 else f' {i + 1}'}:\n\n"
                       + json_block(f"method.params {name}", ex["params"])
                       + json_block(f"method.result {name}", ex["result"]))
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def gen_notifications() -> str:
    out = []
    for name, n in protocol.definition()["notifications"].items():
        out.append(f"### `{name}`\n\n{n['description']}\n\n**Params**: {fields_table(n['params'])}")
        for ex in n.get("examples", []):
            out.append("Example:\n\n" + json_block(f"notification {name}", ex))
    return "\n".join(out).rstrip() + "\n"


def gen_types() -> str:
    defs = json.loads((BROKER / "schema" / "protocol.v1.json").read_text())["definitions"]
    return "\n".join(def_section("####", n, d) for n, d in defs.items()).rstrip() + "\n"


def gen_audit_types() -> str:
    rows = [f"| `{k}` | {esc(v)} |" for k, v in protocol.definition()["auditTypes"].items()]
    return "| Type | Meaning |\n|---|---|\n" + "\n".join(rows) + "\n"


def _cap() -> dict:
    return json.loads((BROKER / "schema" / "capabilities.v1.json").read_text())


def gen_capability_matrix() -> str:
    cap = _cap()
    engines = cap["engines"]
    lines = ["| Capability | `broker.hello` flag | " + " | ".join(e["label"] for e in engines) + " | Tests |",
             "|" + "---|" * (len(engines) + 3)]
    for row in cap["rows"]:
        cells = []
        for e in engines:
            c = row["cells"].get(e["id"], {})
            if "text" in c:
                cells.append(c["text"])
                continue
            value = CAPABILITIES.get(row["flag"]) if e["descriptor"] == "mitmproxy" else c.get("value")
            word = {True: "yes", False: "**no**", None: "?"}[value]
            cells.append(word + (f": {c['note']}" if c.get("note") else ""))
        flag = f"`{row['flag']}`" if row.get("flag") else ""
        tests = ", ".join(f"`{t.split(':', 1)[1]}`" if not t.startswith("sbx:") else f"sbx: `{t[4:]}`"
                          for t in row["tests"])
        lines.append(f"| {row['label']} | {flag} | " + " | ".join(esc(c) for c in cells) + f" | {tests} |")
    return "\n".join(lines) + "\n"


def gen_policy_fields() -> str:
    s = policy_schema()
    return (s.get("description", "") + "\n\n" if s.get("description") else "") + fields_table(s)


def gen_policy_definitions() -> str:
    return "\n".join(def_section("###", n, d) for n, d in policy_schema()["definitions"].items()).rstrip() + "\n"


def gen_policy_examples() -> str:
    out = []
    for f in sorted((BROKER / "examples").glob("*.json")):
        out.append(f"#### [`broker/examples/{f.name}`](../broker/examples/{f.name})\n\n"
                   + json_block("policy", json.loads(f.read_text())))
    return "\n".join(out)


def gen_baseline() -> str:
    data = json.loads((DATA_DIR / "baseline.v1.json").read_text())
    rows = [f"| `{r['id']}` | `{r['host']}` | {', '.join(r.get('methods', ['*']))} | `{r.get('path', '/**')}` |"
            for r in data["allow"]]
    return f"{data['description']}\n\n| Id | Host | Methods | Path |\n|---|---|---|---|\n" + "\n".join(rows) + "\n"


def gen_backstop() -> str:
    out = []
    for f in sorted((DATA_DIR / "providers").glob("*.json")):
        d = json.loads(f.read_text())
        rows = [f"| {', '.join(e['methods'])} | `{e['path']}` | {esc(e['reason'])} |" for e in d["deny"]]
        prefixes = ", ".join("`" + (p or "/") + "`" for p in d.get("pathPrefixes", [""]))
        out.append(f"#### `{d['provider']}`\n\nHosts: {', '.join('`' + h + '`' for h in d['hosts'])}. "
                   f"Path prefixes: {prefixes}. Source: {d['source']['openapi']}\n\n"
                   "| Methods | Path | Why |\n|---|---|---|\n" + "\n".join(rows) + "\n")
    return "\n".join(out)


def gen_token_rules() -> str:
    d = json.loads((DATA_DIR / "token-rules.json").read_text())
    rows = [f"| `{r['id']}` | {r['origin']} | {esc(r.get('note', ''))} |" for r in d["rules"]]
    return f"{d['source']}\n\n| Rule | Origin | Note |\n|---|---|---|\n" + "\n".join(rows) + "\n"


def gen_forbidden_headers() -> str:
    from seclab_broker.policy import FORBIDDEN_INJECT_HEADERS, METHOD_OVERRIDE_HEADERS
    return ("`inject.header` may not be any of: "
            + ", ".join(f"`{h}`" for h in sorted(FORBIDDEN_INJECT_HEADERS))
            + ", or any header starting with `proxy-`.\n\nRequests carrying any of "
            + ", ".join(f"`{h}`" for h in METHOD_OVERRIDE_HEADERS)
            + ", or a `_method` query parameter, are rejected with `400`.\n")


GENERATORS = {
    "protocol-errors": gen_errors, "protocol-methods": gen_methods,
    "protocol-notifications": gen_notifications, "protocol-types": gen_types,
    "protocol-audit-types": gen_audit_types, "capability-matrix": gen_capability_matrix,
    "policy-fields": gen_policy_fields, "policy-definitions": gen_policy_definitions,
    "policy-examples": gen_policy_examples, "policy-baseline": gen_baseline,
    "policy-backstop": gen_backstop, "policy-token-rules": gen_token_rules,
    "policy-forbidden-headers": gen_forbidden_headers,
}


def regenerate(text: str, path: str, errors: list[str]) -> str:
    def sub(m: re.Match) -> str:
        gen = GENERATORS.get(m.group(2))
        if gen is None:
            errors.append(f"{path}: unknown generated section {m.group(2)!r}")
            return m.group(0)
        return m.group(1) + gen() + m.group(4)
    return GEN_RE.sub(sub, text)


# ----------------------------------------------------------------- example and command checks

def check_example(kind: str, body: str) -> str | None:
    parts = kind.split()
    try:
        if parts[0] == "jsonrpc":
            for line in body.strip().splitlines():
                msg = json.loads(line)
                if msg.get("jsonrpc") != "2.0":
                    return f"not JSON-RPC 2.0: {line[:60]}"
                if "method" in msg:
                    k = "params" if "id" in msg else "notification"
                    names = protocol.method_names() if k == "params" else protocol.notification_names()
                    if msg["method"] not in names:
                        return f"unknown method {msg['method']}"
                    err = protocol.check(k, msg["method"], msg.get("params", {}))
                    if err:
                        return f"{msg['method']}: {err}"
            return None
        obj = json.loads(body)
        if parts[0] == "policy":
            Policy.from_json(obj)
            return None
        kinds = {"method.params": "params", "method.result": "result", "notification": "notification",
                 "definition": "definition"}
        if parts[0] in kinds and len(parts) == 2:
            return protocol.check(kinds[parts[0]], parts[1], obj)
        return f"unknown check kind {kind!r}"
    except (ValueError, PolicyError, KeyError) as e:
        return f"{type(e).__name__}: {e}"


def blocks(text: str):
    for m in FENCE_RE.finditer(text):
        before = text[:m.start()].rstrip().splitlines()
        annot = ANNOT_RE.search(before[-1]) if before else None
        yield m.group(1), m.group(2), annot, text[:m.start()].count("\n") + 1


def check_doc(path: str, text: str, errors: list[str]) -> None:
    for lang, body, annot, line in blocks(text):
        where = f"{path}:{line}"
        if lang == "json":
            if not annot or annot.group(1) != "check":
                errors.append(f"{where}: json block without <!-- check: KIND [NAME] -->")
                continue
            err = check_example(annot.group(2), body)
            if err:
                errors.append(f"{where}: example does not validate ({annot.group(2)}): {err}")
        elif lang in SH_LANGS:
            if not annot or annot.group(1) != "ci" or not re.match(r"^(run|skip: \S.*)$", annot.group(2)):
                errors.append(f"{where}: sh block without <!-- ci: run --> or <!-- ci: skip: REASON -->")


# ----------------------------------------------------------------- code <-> definition cross-checks

def source(*names: str) -> str:
    return "\n".join((BROKER / "seclab_broker" / n).read_text() for n in names)


def cross_checks(errors: list[str]) -> None:
    d = protocol.definition()
    code_methods = set(Broker.METHODS)
    if code_methods != protocol.method_names():
        errors.append(f"methods differ: code-only {sorted(code_methods - protocol.method_names())}, "
                      f"protocol-only {sorted(protocol.method_names() - code_methods)}")
    src = source("core.py", "engine_mitmproxy.py", "control.py", "__main__.py")
    notified = set(re.findall(r"\bnotify\(\s*\"([A-Za-z._]+)\"", src))
    if notified != protocol.notification_names():
        errors.append(f"notifications differ: code {sorted(notified)} vs protocol {sorted(protocol.notification_names())}")
    audited = set(re.findall(r"\baudit\(\s*\"([a-z._]+)\"", src))
    if audited != protocol.audit_types():
        errors.append(f"audit types differ: code-only {sorted(audited - protocol.audit_types())}, "
                      f"protocol-only {sorted(protocol.audit_types() - audited)}")
    codes = {int(c) for c in re.findall(r"(-32\d{3})", source("core.py", "control.py"))}
    if codes != protocol.error_codes():
        errors.append(f"error codes differ: code {sorted(codes)} vs protocol {sorted(protocol.error_codes())}")
    if d["protocol"] != seclab_broker.PROTOCOL:
        errors.append("protocol.v1.json 'protocol' differs from seclab_broker.PROTOCOL")
    for name, m in d["methods"].items():
        for ex in m.get("examples", []):
            for kind in ("params", "result"):
                err = protocol.check(kind, name, ex[kind])
                if err:
                    errors.append(f"protocol.v1.json example for {name} {kind}: {err}")
    for name, n in d["notifications"].items():
        for ex in n.get("examples", []):
            err = protocol.check("notification", name, ex)
            if err:
                errors.append(f"protocol.v1.json example for notification {name}: {err}")
    cap = _cap()
    flags = {r["flag"] for r in cap["rows"] if r.get("flag")}
    if flags != set(CAPABILITIES):
        errors.append(f"capability flags differ: descriptor {sorted(CAPABILITIES)} vs matrix {sorted(flags)}")
    engine_ids = {e["id"] for e in cap["engines"]}
    tests_src = "\n".join(p.read_text() for p in (BROKER / "tests").rglob("*.py"))
    sbx_src = (BROKER / "tests" / "sbx" / "validate.sh").read_text()
    for row in cap["rows"]:
        label = row["label"]
        if set(row["cells"]) - engine_ids:
            errors.append(f"capability row {label!r}: unknown engine ids")
        if not row["tests"]:
            errors.append(f"capability row {label!r} names no tests")
        for t in row["tests"]:
            kind, _, name = t.partition(":")
            ok = (kind in ("unit", "it") and re.search(rf"\bdef {re.escape(name)}\(", tests_src)) or \
                 (kind == "sbx" and f'check "{name}"' in sbx_src)
            if not ok:
                errors.append(f"capability row {label!r}: test {t!r} not found")
        for e in cap["engines"]:
            c = row["cells"].get(e["id"], {})
            if not row.get("flag") and "text" not in c:
                errors.append(f"capability row {label!r}: engine {e['id']} needs text")
            if row.get("flag") and e["descriptor"] == "mitmproxy" and "value" in c:
                errors.append(f"capability row {label!r}: mitmproxy value must come from the descriptor")
            if row.get("flag") and e["descriptor"] is None and "value" not in c:
                errors.append(f"capability row {label!r}: engine {e['id']} needs a value")


# ----------------------------------------------------------------- entry points

def run(mode: str) -> int:
    errors: list[str] = []
    for rel in CHECKED_DOCS:
        p = REPO / rel
        if not p.exists():
            errors.append(f"{rel}: missing")
            continue
        text = p.read_text()
        new = regenerate(text, rel, errors)
        if new != text:
            if mode == "write":
                p.write_text(new)
                print(f"regenerated {rel}", file=sys.stderr)
            else:
                errors.append(f"{rel}: generated sections are stale (run broker/docs-check.sh --write)")
        check_doc(rel, new, errors)
    cross_checks(errors)
    for e in errors:
        print("docs-check: " + e, file=sys.stderr)
    if not errors:
        print(f"docs-check: ok ({len(CHECKED_DOCS)} docs)", file=sys.stderr)
    return 1 if errors else 0


def commands() -> int:
    print("#!/usr/bin/env bash\n# Generated by broker/tools/docs.py: every `ci: run` shell block in the broker docs.")
    print("set -euo pipefail")
    for rel in CHECKED_DOCS:
        p = REPO / rel
        if not p.exists():
            continue
        for lang, body, annot, line in blocks(p.read_text()):
            if lang in SH_LANGS and annot and annot.group(1) == "ci" and annot.group(2) == "run":
                print(f"\necho '== {rel}:{line}' >&2\n(\nset -euxo pipefail\n{body.rstrip()}\n)")
    return 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    if cmd == "commands":
        sys.exit(commands())
    if cmd not in ("check", "write"):
        sys.exit(__doc__)
    sys.exit(run(cmd))
