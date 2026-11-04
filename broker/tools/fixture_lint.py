"""Fixture-safety lint for the broker's tests: nothing a test can contact is
real, and nothing committed looks like a real credential.

  python broker/tools/fixture_lint.py    # exit 1 on any violation (run by broker/docs-check.sh)

Rules (scope: broker/tests/integration, broker/tests/sbx):
  * every URL host and every `-x`/proxy target is test-owned: *.example.test, the
    pod's own containers (broker), loopback, host.docker.internal (sbx: only to the
    run's own loopback-published broker port, enforced by the sbx fence), or
    RFC 5737 documentation ranges;
  * every IPv4 literal is loopback, RFC 5737, or the suite's test range 11.250.0.0/16;
  * single-label hostnames are not test-owned (they can resolve via a LAN search domain);
  * no committed literal matches a minted-token rule (data/token-rules.json) or the
    gitleaks GitHub/AWS formats.
Scope: broker/tests/unit is exempt from the URL/IP rules (it never opens sockets:
the unit image runs with --network none) but not from the token rule.
"""

from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path

BROKER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BROKER))

from seclab_broker.scanner import find_minted  # noqa: E402

NETWORK_SCOPES = [BROKER / "tests" / "integration", BROKER / "tests" / "sbx"]
TOKEN_SCOPES = NETWORK_SCOPES + [BROKER / "tests" / "unit", BROKER / "examples"]
URL_RE = re.compile(r"\b(?:https?|wss?)://(?:[^@/\s'\"]*@)?(\[[0-9a-fA-F:.]+\]"
                    r"|(?:\$\{?\w+\}?|[A-Za-z0-9._-])*(?:\{[^}]*\}[A-Za-z0-9._-]*)*)")
PLACEHOLDER_RE = re.compile(r"\{[^}]*\}")
SHELL_VAR_RE = re.compile(r"\$\{?\w+\}?")
IPV4_RE = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")
EXTRA_TOKEN_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z2-7]{16}\b")
ALLOWED_HOST_RE = re.compile(
    r"^(?:[a-z0-9-]+\.)*example\.test$|^broker$|^localhost$|^host\.docker\.internal$")
TEST_NETS = [ipaddress.ip_network(n) for n in
             ("127.0.0.0/8", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
              "11.250.0.0/16", "0.0.0.0/32")]
SUFFIXES = {".py", ".sh", ".json", ".toml", ".txt", ""}


def files(scopes):
    for scope in scopes:
        for p in sorted(scope.rglob("*")):
            if p.is_file() and p.suffix in SUFFIXES and "requirements" not in p.name:
                yield p


def host_ok(h: str) -> bool:
    # f-string placeholders and shell variables: a whole-host one is checked where it is
    # built; a trailing f-string one is the path (`{host}{path}`); one inside a name is a
    # label (`d{i}.x.test`, `${sub}.evil.com`) and the rest of the name must be test-owned.
    if PLACEHOLDER_RE.fullmatch(h) or SHELL_VAR_RE.fullmatch(h):
        return True
    h = re.sub(r"(?<=.)\{[^}]*\}$", "", h)
    if PLACEHOLDER_RE.fullmatch(h) or SHELL_VAR_RE.fullmatch(h):
        return True
    h = SHELL_VAR_RE.sub("x", PLACEHOLDER_RE.sub("x", h))
    if not h:
        return False
    if h.startswith("["):
        try:
            ip = ipaddress.ip_address(h[1:-1])
        except ValueError:
            return False
        v4 = getattr(ip, "ipv4_mapped", None)
        return ip.is_loopback or (v4 is not None and v4.is_loopback)
    try:
        ip = ipaddress.ip_address(h)
        return any(ip in n for n in TEST_NETS)
    except ValueError:
        return bool(ALLOWED_HOST_RE.match(h.lower()))


def main() -> int:
    errors = []
    for p in files(NETWORK_SCOPES):
        rel = p.relative_to(BROKER.parent)
        for n, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
            if "fixture-lint: ignore" in line:
                continue
            for m in URL_RE.finditer(line):
                if not host_ok(m.group(1)):
                    errors.append(f"{rel}:{n}: URL host {m.group(1)!r} is not test-owned")
            for m in IPV4_RE.finditer(line):
                try:
                    ip = ipaddress.ip_address(m.group(1))
                except ValueError:
                    continue
                if not any(ip in net for net in TEST_NETS):
                    errors.append(f"{rel}:{n}: IP literal {m.group(1)} is not loopback/RFC 5737/test subnet")
    for p in files(TOKEN_SCOPES):
        rel = p.relative_to(BROKER.parent)
        for n, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
            hits = [h[0] for h in find_minted(line) if h[0] not in ("json-token-field", "form-token-field")]
            if EXTRA_TOKEN_RE.search(line):
                hits.append("aws-access-key")
            if hits:
                errors.append(f"{rel}:{n}: token-shaped literal ({', '.join(hits)})")
    for e in errors:
        print("fixture-lint: " + e, file=sys.stderr)
    if not errors:
        print("fixture-lint: ok", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
