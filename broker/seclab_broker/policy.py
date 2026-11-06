"""Engine-agnostic policy model: parsing, normalisation and matching.

Nothing in this module may import mitmproxy. Engines translate their native
request objects into a RequestView and ask this module for decisions.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

import fastjsonschema

DATA_DIR = Path(__file__).parent / "data"
DEFAULT_PORTS = {"https": 443, "http": 80}
METHOD_OVERRIDE_HEADERS = ("x-http-method-override", "x-http-method", "x-method-override")
# Headers the real value may never be injected into.
FORBIDDEN_INJECT_HEADERS = {
    "host", "content-length", "transfer-encoding", "connection", "upgrade", "te",
    "trailer", "keep-alive", "proxy-authorization", "proxy-connection", "cookie2",
    "expect", "content-encoding", "content-type",
}


class PolicyError(ValueError):
    """Raised for an invalid policy. Messages never contain credential values."""


def _schema_path() -> Path:
    packaged = DATA_DIR / "policy.v1.schema.json"
    if packaged.exists():
        return packaged
    return Path(__file__).resolve().parent.parent / "schema" / "policy.v1.schema.json"


@lru_cache(maxsize=1)
def _schema() -> dict:
    schema = json.loads(_schema_path().read_text())
    # Resolve every $ref locally; never let the validator fetch anything.
    schema.pop("$id", None)
    return schema


def _no_remote(uri: str) -> dict:
    raise PolicyError(f"remote schema references are not allowed: {uri}")


_HANDLERS = {"http": _no_remote, "https": _no_remote, "file": _no_remote}


@lru_cache(maxsize=1)
def _validator():
    return fastjsonschema.compile(_schema(), handlers=_HANDLERS)


@lru_cache(maxsize=None)
def _sub_validator(name: str):
    schema = _schema()
    sub = {"$schema": schema["$schema"], "definitions": schema["definitions"],
           "$ref": f"#/definitions/{name}"}
    return fastjsonschema.compile(sub, handlers=_HANDLERS)


def validate_fragment(name: str, obj: Any) -> None:
    try:
        _sub_validator(name)(obj)
    except fastjsonschema.JsonSchemaException as e:
        raise PolicyError(f"invalid {name}: {e.message}") from None


# --------------------------------------------------------------------------
# Normalisation
# --------------------------------------------------------------------------

_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_NUMERICISH = re.compile(r"^(0x[0-9a-f]*|[0-9]+)$")


def normalize_ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.scope_id:
            return None
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
    return ip


def normalize_host(host: str | None) -> str | None:
    """Canonical lowercase ASCII host, or None if it is not acceptable.

    Rejects zone ids, percent-encoding, numeric/hex host forms that resolvers
    would treat as IPv4 (e.g. ``2130706433``, ``0x7f.1``, ``127.1``), empty
    labels and anything outside LDH after IDNA encoding.
    """
    if not host:
        return None
    h = host.strip()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    h = h.lower()
    if h.endswith("."):
        h = h[:-1]
    if not h or len(h) > 253:
        return None
    ip = normalize_ip(h)
    if ip is not None:
        return ip.compressed
    if not h.isascii():
        try:
            h = h.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    labels = h.split(".")
    if any(not _LABEL.match(lbl) for lbl in labels):
        return None
    if _NUMERICISH.match(labels[-1]) or all(_NUMERICISH.match(lbl) for lbl in labels):
        return None
    return h


_FORBIDDEN_ENCODED = re.compile(r"%(2[eEfF]|5[cC]|00|3[bB]|25)")


def canonical_path(raw: str) -> tuple[str, str] | None:
    """Split and canonicalise a request target. Returns (decoded_path, raw_query).

    Returns None (deny) for anything a server might interpret differently from
    our matcher: dot segments, encoded '.', '/', '\\', ';', '%' or NUL, empty
    segments, backslashes, matrix parameters, control characters, invalid UTF-8.
    """
    if not raw or not raw.startswith("/"):
        return None
    path, _, query = raw.partition("?")
    if "#" in raw or "\\" in path or ";" in path:
        return None
    if _FORBIDDEN_ENCODED.search(path):
        return None
    try:
        decoded = urllib.parse.unquote(path, errors="strict")
    except UnicodeDecodeError:
        return None
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in decoded):
        return None
    if "//" in decoded:
        return None
    for seg in decoded.split("/")[1:]:
        if seg in (".", ".."):
            return None
    return decoded, query


def query_has_method_override(query: str) -> bool:
    for key, _ in urllib.parse.parse_qsl(query, keep_blank_values=True):
        if key.strip().lower() == "_method":
            return True
    return False


@lru_cache(maxsize=4096)
def compile_glob(pattern: str, ignore_case: bool = False) -> re.Pattern:
    out = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out), re.IGNORECASE if ignore_case else 0)


# A request path a binding can name literally: the schema's path alphabet without '*'.
LITERAL_PATH_RE = re.compile(r"/[A-Za-z0-9._~!$&'()+,=:@/-]{0,1023}")
# Agent-host tokens sealed to an advertised key (upstream agentHostAuth): never forwarded
# (engine) and never exported in a request summary.
SEALED_PREFIX = "copilot-sealed.v1."


# --------------------------------------------------------------------------
# Request view (what an engine hands us)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class RequestView:
    scheme: str
    host: str  # normalised
    port: int
    method: str
    path: str  # decoded canonical path, no query
    query: str = ""
    # The tab-side TCP source port of the proxy connection (revision 5): exact process
    # attribution for observability. Tab-influenced: a process can choose its source port.
    client_port: int | None = field(default=None, compare=False)

    @property
    def origin(self) -> tuple[str, str, int]:
        return (self.scheme, self.host, self.port)

    def summary(self) -> dict:
        """For audit and prompts. Tab-controlled: host, method, path (percent-encoded ASCII),
        and the query's key names (percent-encoded, deduplicated, capped; values never)."""
        import urllib.parse
        from .untrusted import display_path
        path = display_path(self.path)
        if SEALED_PREFIX in path:
            # Marker added after encoding, so a tab can't forge it (review 11c-4/11c-5).
            path = re.sub(re.escape(SEALED_PREFIX) + r"[^/]*", "[sealed]", path)
        out = {"scheme": self.scheme, "host": self.host[:253], "port": self.port,
               "method": self.method, "path": path}
        if self.client_port is not None:
            out["clientPort"] = self.client_port
        if self.query:
            keys = set()
            for k, _ in urllib.parse.parse_qsl(self.query, keep_blank_values=True):
                q = urllib.parse.quote(k, safe="")
                if len(q) > 64:
                    q = re.sub(r"%[0-9A-F]?$", "", q[:64])  # never split a %XX escape
                if SEALED_PREFIX in k:
                    q = "[sealed]"  # an agent-host sealed token is never exported (review 11b-7)
                keys.add(q)
            out["queryKeys"] = sorted(keys)[:32]
        return out


# --------------------------------------------------------------------------
# Rules and bindings
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class HostPattern:
    text: str

    def matches(self, host: str) -> bool:
        if self.text.startswith("*."):
            suffix = self.text[1:]
            return host.endswith(suffix) and len(host) > len(suffix)
        return host == self.text


def _parse_host_pattern(text: str) -> HostPattern:
    wildcard = text.startswith("*.")
    base = text[2:] if wildcard else text
    norm = normalize_host(base)
    if norm is None or norm != base:
        raise PolicyError(f"host {text!r} is not a canonical hostname or IP literal")
    if wildcard and normalize_ip(base) is not None:
        raise PolicyError(f"host {text!r}: wildcard on an IP literal")
    return HostPattern(("*." if wildcard else "") + norm)


@dataclass(frozen=True)
class Rule:
    host: HostPattern
    schemes: tuple[str, ...] = ("https",)
    ports: tuple[int, ...] | None = None
    methods: tuple[str, ...] = ("*",)
    path: str = "/**"
    id: str | None = None
    # "approval": its host came from a request the tab made.
    source: str = field(default="policy", compare=False)

    @classmethod
    def from_json(cls, obj: dict) -> "Rule":
        validate_fragment("rule", obj)
        return cls(
            host=_parse_host_pattern(obj["host"]),
            schemes=tuple(obj.get("schemes", ["https"])),
            ports=tuple(obj["ports"]) if "ports" in obj else None,
            methods=tuple(obj.get("methods", ["*"])),
            path=obj.get("path", "/**"),
            id=obj.get("id"),
        )

    def to_json(self) -> dict:
        out: dict[str, Any] = {"host": self.host.text, "schemes": list(self.schemes),
                               "methods": list(self.methods), "path": self.path}
        if self.ports is not None:
            out["ports"] = list(self.ports)
        if self.id:
            out["id"] = self.id
        return out

    def matches(self, req: RequestView) -> bool:
        if req.scheme not in self.schemes:
            return False
        ports = self.ports if self.ports is not None else (DEFAULT_PORTS[req.scheme],)
        if req.port not in ports:
            return False
        if not self.host.matches(req.host):
            return False
        if "*" not in self.methods and req.method not in self.methods:
            return False
        return compile_glob(self.path).fullmatch(req.path) is not None


@dataclass(frozen=True)
class DenyRule:
    """A destination the user blocked (revision 5). Precedence over every allow rule, the
    baseline, `allow-tab` grants, prompts and credential bindings. Unlike an allow rule,
    omitted `ports` means every port and omitted `schemes` means http and https, so a block
    can't be sidestepped by a non-default port or scheme."""
    id: str
    host: HostPattern
    schemes: tuple[str, ...] = ("http", "https")
    ports: tuple[int, ...] | None = None

    @classmethod
    def from_json(cls, obj: dict) -> "DenyRule":
        validate_fragment("denyRule", obj)
        return cls(id=obj["id"], host=_parse_host_pattern(obj["host"]),
                   schemes=tuple(obj.get("schemes", ["http", "https"])),
                   ports=tuple(obj["ports"]) if "ports" in obj else None)

    def to_json(self) -> dict:
        out: dict[str, Any] = {"id": self.id, "host": self.host.text, "schemes": list(self.schemes)}
        if self.ports is not None:
            out["ports"] = list(self.ports)
        return out

    def matches(self, req: RequestView) -> bool:
        # `*.x` on a deny rule also blocks the apex `x` (review 12-2): a block must not be
        # sidestepped by the bare domain, unlike an allow rule's strict-subdomain wildcard.
        host_ok = self.host.matches(req.host) or (self.host.text.startswith("*.") and req.host == self.host.text[2:])
        return req.scheme in self.schemes and (self.ports is None or req.port in self.ports) and host_ok


_B64_TOKEN = re.compile(r"\{base64:((?:[^{}]|\{value\})*)\}")


@dataclass(frozen=True)
class Inject:
    header: str
    fmt: str

    @classmethod
    def from_json(cls, obj: dict) -> "Inject":
        validate_fragment("inject", obj)
        header, fmt = obj["header"], obj["fmt"]
        if header.lower() in FORBIDDEN_INJECT_HEADERS or header.lower().startswith("proxy-"):
            raise PolicyError(f"inject.header {header!r} is not allowed")
        if not all(0x20 <= ord(c) < 0x7F for c in fmt):
            raise PolicyError("inject.fmt must be printable ASCII")
        stripped = _B64_TOKEN.sub("", fmt).replace("{value}", "")
        if "{" in stripped or "}" in stripped:
            raise PolicyError("inject.fmt has an unknown placeholder")
        if "{value}" not in fmt:
            raise PolicyError("inject.fmt must reference {value}")
        return cls(header=header, fmt=fmt)

    def to_json(self) -> dict:
        return {"header": self.header, "fmt": self.fmt}

    def render(self, value: str) -> str:
        def b64(m: re.Match) -> str:
            return base64.b64encode(m.group(1).replace("{value}", value).encode()).decode()

        return _B64_TOKEN.sub(b64, self.fmt).replace("{value}", value)


@dataclass(frozen=True)
class Binding:
    host: HostPattern
    path: str
    methods: tuple[str, ...]
    ports: tuple[int, ...] = (443,)
    inject: Inject | None = None
    # Injection into upgraded connections (WebSocket) only when the binding opts in.
    websocket: bool = False
    # "approval": its host, path, methods and inject came from a request the tab made.
    source: str = field(default="policy", compare=False)

    @classmethod
    def from_json(cls, obj: dict, default_inject: Inject | None = None) -> "Binding":
        validate_fragment("binding", obj)
        methods = tuple(obj["methods"])
        if "*" in methods:
            raise PolicyError("binding.methods must be explicit; '*' is not allowed")
        inject = Inject.from_json(obj["inject"]) if "inject" in obj else default_inject
        if inject is None:
            raise PolicyError("binding has no inject and the credential has no default inject")
        return cls(host=_parse_host_pattern(obj["host"]), path=obj["path"], methods=methods,
                   ports=tuple(obj.get("ports", [443])), inject=inject,
                   websocket=obj.get("websocket", False) is True)

    def to_json(self) -> dict:
        out = {"host": self.host.text, "path": self.path, "methods": list(self.methods),
               "ports": list(self.ports)}
        if self.inject:
            out["inject"] = self.inject.to_json()
        if self.websocket:
            out["websocket"] = True
        return out

    def matches(self, req: RequestView, upgrade: str | None = None) -> bool:
        """`upgrade`: the request's `Upgrade` token, if any. An upgraded connection gets a
        credential only from a binding with `websocket: true`, and only for WebSocket."""
        if upgrade is not None and not (self.websocket and upgrade == "websocket"):
            return False
        # Credentials are never injected over cleartext.
        return (req.scheme == "https" and req.port in self.ports
                and self.host.matches(req.host) and req.method in self.methods
                and compile_glob(self.path).fullmatch(req.path) is not None)


def parse_bindings(bind: Any, default_inject: Inject | None) -> list[Binding]:
    items = bind if isinstance(bind, list) else [bind]
    return [Binding.from_json(b, default_inject) for b in items]


@dataclass(frozen=True)
class CredentialSpec:
    id: str
    bindings: tuple[Binding, ...]
    provider: str | None = None
    sentinel_prefix: str | None = None
    derive: tuple["DeriveRule", ...] = ()
    # (requests, bytes) caps over the tab's lifetime; None means uncapped (revision 6).
    budget: tuple[int | None, int | None] | None = None

    @classmethod
    def from_json(cls, obj: dict) -> "CredentialSpec":
        default_inject = Inject.from_json(obj["inject"]) if "inject" in obj else None
        bindings = tuple(parse_bindings(obj["bind"], default_inject))
        derive = parse_derive(obj.get("derive", []))
        return cls(id=obj["id"], bindings=bindings,
                   provider=obj.get("provider"), sentinel_prefix=obj.get("sentinelPrefix"),
                   derive=derive, budget=parse_budget(obj["id"], obj.get("budget"), bindings, derive))


def parse_budget(cid: str, b: dict | None, bindings, derive) -> tuple[int | None, int | None] | None:
    """A credential budget (policy `credentials[].budget`, or `credential.import` from
    revision 7), already schema-validated, as (requests, bytes)."""
    if b is None:
        return None
    budget = (b.get("requests"), b.get("bytes"))
    check_budget_bindings(cid, budget, [*bindings, *(x for r in derive for x in r.bindings)])
    return budget


def check_budget_bindings(cid: str, budget: tuple | None, bindings) -> None:
    # WebSocket messages aren't charged, so a byte cap there would not hold (review 13-10);
    # derived children roll up to this budget too (13b-1), and so do bindings confirmed later.
    if budget is not None and budget[1] is not None and any(x.websocket for x in bindings):
        raise PolicyError(f"credential {cid!r}: a byte budget can't be combined with a websocket binding")


@dataclass(frozen=True)
class DeriveRule:
    """A controller-declared derivation (secure-agentic D7): when a credentialed request on
    exactly this route succeeds, the JSON string at top-level `field` is a credential the
    upstream minted. It is replaced by a sentinel and bound to `bindings`, which the
    controller chose, never anything the response says. The only way a derived credential
    can be bound wider than its parent."""
    id: str
    host: str
    path: str
    method: str
    field: str
    bindings: tuple[Binding, ...]

    def matches(self, req: RequestView) -> bool:
        return (req.scheme == "https" and req.host == self.host and req.path == self.path
                and req.method == self.method and not req.query)

    @classmethod
    def from_json(cls, obj: dict) -> "DeriveRule":
        validate_fragment("derive", obj)
        frm = obj["from"]
        host = _parse_host_pattern(frm["host"])
        if host.text.startswith("*.") or "*" in frm["path"]:
            raise PolicyError("derive.from must name one exact host and path")
        inject = Inject.from_json(obj["inject"]) if "inject" in obj else None
        bindings = tuple(parse_bindings(obj["bind"], inject))
        if any(b.host.text.startswith("*.") for b in bindings):
            raise PolicyError("derived bindings must name exact hosts")
        return cls(id=obj["id"], host=host.text, path=frm["path"], method=frm["method"],
                   field=obj["field"], bindings=bindings)


def parse_derive(items: list) -> tuple[DeriveRule, ...]:
    rules = tuple(DeriveRule.from_json(d) for d in items)
    if len({r.id for r in rules}) != len(rules):
        raise PolicyError("duplicate derive rule id")
    return rules


@dataclass(frozen=True)
class PromptConfig:
    enabled: bool = True
    timeout_seconds: float = 60.0
    max_pending: int = 16
    max_held_flows: int = 256
    deny_cooldown_seconds: float = 300.0
    max_per_minute: int = 6
    offer_deny_new_after: int = 3
    raw_ip_destinations: str = "deny"
    quiet_period_seconds: float = 30.0
    auto_deny_risky_before_user_action: bool = True


@dataclass(frozen=True)
class RiskyEntry:
    host: HostPattern
    category: str


@lru_cache(maxsize=1)
def risky_destinations() -> tuple[RiskyEntry, ...]:
    data = json.loads((DATA_DIR / "risky-destinations.v1.json").read_text())
    return tuple(RiskyEntry(_parse_host_pattern(e["host"]), e["category"]) for e in data["entries"])


def risky_category(host: str, extra: tuple[RiskyEntry, ...] = ()) -> str | None:
    for entry in risky_destinations() + extra:
        if entry.host.matches(host):
            return entry.category
    return None


_EMBEDDED_V4 = re.compile(r"(?:^|[.-])((?:\d{1,3}[.-]){3}\d{1,3})(?=$|[.-])")


def embedded_ipv4(host: str) -> str | None:
    """An IPv4 address spelled inside a hostname (`1.2.3.4.sslip.io`, `ec2-1-2-3-4.x`).
    Wildcard-DNS services resolve such names to that address, so they are raw IPs in disguise."""
    if normalize_ip(host) is not None:
        return None
    for m in _EMBEDDED_V4.finditer(host):
        parts = re.split(r"[.-]", m.group(1))
        if all(int(p) <= 255 for p in parts):
            return ".".join(parts)
    return None


def pattern_overlaps_risky(pattern: str, extra: tuple[RiskyEntry, ...] = ()) -> bool:
    """True if any host the pattern can match is a risky destination, or vice versa."""
    if normalize_ip(pattern.removeprefix("*.")) is not None:
        return False
    if not pattern.startswith("*."):
        return risky_category(pattern, extra) is not None or embedded_ipv4(pattern) is not None
    suffix = pattern[2:]
    for entry in risky_destinations() + extra:
        e = entry.host.text
        e_base = e.removeprefix("*.")
        if e_base == suffix or e_base.endswith("." + suffix):  # listed host lies under the wildcard
            return True
        if e.startswith("*.") and (suffix.endswith("." + e_base)):  # wildcard lies under a listed wildcard
            return True
    return False


def risk_flags(req: "RequestView", extra: tuple[RiskyEntry, ...] = ()) -> list[str]:
    """Destination properties worth showing in a prompt. Engine-agnostic."""
    flags = []
    if normalize_ip(req.host) is not None:
        flags.append("raw-ip")
    elif embedded_ipv4(req.host):
        flags.append("ip-in-hostname")
    cat = risky_category(req.host, extra)
    if cat:
        flags.append(f"risky-destination:{cat}")
    if req.scheme == "http":
        flags.append("cleartext")
    if req.port != DEFAULT_PORTS[req.scheme]:
        flags.append("nonstandard-port")
    return flags


@dataclass
class Policy:
    version: int
    tab_id: str | None
    baseline: bool
    prompt: PromptConfig
    sentinel_mismatch: str
    rules: list[Rule]
    credentials: list[CredentialSpec]
    risky: tuple[RiskyEntry, ...] = ()
    models: Any = None  # models.ModelPolicy
    deny: list[DenyRule] = field(default_factory=list)
    raw: dict = field(repr=False, default_factory=dict)

    @classmethod
    def from_json(cls, obj: Any) -> "Policy":
        from .models import ModelPolicy
        providers()  # shipped backstop data is checked before any policy is accepted (review 11b-5)
        try:
            _validator()(obj)
        except fastjsonschema.JsonSchemaException as e:
            raise PolicyError(f"policy does not match schema: {e.message}") from None
        rules = [Rule.from_json(r) for r in obj.get("allow", [])]
        creds = [CredentialSpec.from_json(c) for c in obj.get("credentials", [])]
        ids = [r.id for r in rules if r.id]
        if len(ids) != len(set(ids)):
            raise PolicyError("duplicate allow rule id")
        cids = [c.id for c in creds]
        if len(cids) != len(set(cids)):
            raise PolicyError("duplicate credential id")
        deny = [DenyRule.from_json(d) for d in obj.get("deny", [])]
        if len({d.id for d in deny}) != len(deny):
            raise PolicyError("duplicate deny rule id")
        p = obj.get("prompt", {})
        return cls(
            version=obj["version"],
            tab_id=obj.get("tabId"),
            baseline=obj.get("baseline", True),
            prompt=PromptConfig(
                enabled=p.get("enabled", True),
                timeout_seconds=float(p.get("timeoutSeconds", 60)),
                max_pending=int(p.get("maxPending", 16)),
                max_held_flows=int(p.get("maxHeldFlows", 256)),
                deny_cooldown_seconds=float(p.get("denyCooldownSeconds", 300)),
                max_per_minute=int(p.get("maxPerMinute", 6)),
                offer_deny_new_after=int(p.get("offerDenyNewAfter", 3)),
                raw_ip_destinations=p.get("rawIpDestinations", "deny"),
                quiet_period_seconds=float(p.get("quietPeriodSeconds", 30)),
                auto_deny_risky_before_user_action=bool(p.get("autoDenyRiskyBeforeUserAction", True)),
            ),
            sentinel_mismatch=obj.get("sentinelMismatch", "block"),
            rules=rules,
            credentials=creds,
            risky=tuple(RiskyEntry(_parse_host_pattern(e["host"]), e["category"])
                        for e in obj.get("riskyDestinations", [])),
            models=ModelPolicy.from_json(obj.get("models")),
            deny=deny,
            raw=obj,
        )

    @classmethod
    def deny_all(cls) -> "Policy":
        return cls.from_json({"version": 1, "baseline": False})

    def effective_rules(self) -> Iterable[Rule]:
        if self.baseline:
            yield from baseline_rules()
        yield from self.rules

    def allow_match(self, req: RequestView) -> Rule | None:
        for rule in self.effective_rules():
            if rule.matches(req):
                return rule
        return None

    def deny_match(self, req: RequestView) -> DenyRule | None:
        """Checked before everything else (revision 5)."""
        return next((d for d in self.deny if d.matches(req)), None)

    def to_json(self) -> dict:
        out = dict(self.raw)
        out["allow"] = [r.to_json() for r in self.rules]
        if self.deny or "deny" in out:
            out["deny"] = [d.to_json() for d in self.deny]
        return out


@lru_cache(maxsize=1)
def baseline_rules() -> tuple[Rule, ...]:
    data = json.loads((DATA_DIR / "baseline.v1.json").read_text())
    return tuple(Rule.from_json(r) for r in data["allow"])


# --------------------------------------------------------------------------
# Provider backstop: endpoints that let a tab mint its own durable credential
# --------------------------------------------------------------------------

def _trim_segment(seg: str) -> str:
    """Trailing dots and any (Unicode) whitespace, as IIS/.NET trims them (review 13-9/13b-2)."""
    return re.sub(r"[.\s]+$", "", seg)


@dataclass(frozen=True)
class BackstopEntry:
    provider: str
    methods: tuple[str, ...]
    path: str
    reason: str

    def matches(self, req: RequestView, prefixes: tuple[str, ...]) -> bool:
        if "*" not in self.methods and req.method not in self.methods:
            return False
        # Servers that trim trailing dots or whitespace from a segment (IIS/ASP.NET, which
        # serves Azure DevOps) would route `/_apis.` as `/_apis`; match what they route
        # (review 13-9). This can only make the deny-list match more.
        path = "/".join(_trim_segment(seg) for seg in req.path.split("/")).rstrip("/") or "/"
        return any(compile_glob(prefix + self.path, ignore_case=True).fullmatch(path)
                   for prefix in prefixes)


@dataclass(frozen=True)
class BackstopException:
    """A coordinator-approved, data-level hole in a provider's backstop: one method on one
    exact path (case-sensitive, no trailing-slash variant), with no body, query or upgrade.
    Its response is held to the no-credential-fields check in the engine.

    `response_fields`: when set, the response's top-level fields allowed. With `strict_fields`
    any other top-level field blocks the response (a finding); without, others are dropped
    (and audited) after the whole document has passed the check. Both apply on every status.
    `drop_fields`: top-level fields always dropped (and audited) whatever their shape, for
    objects that may carry a third party's credential (managed_settings `telemetry`, with
    its OTLP headers; review 11b-2). `benign_keys`: exact JSON paths the credential-name
    check accepts (measured false positives such as `$.token_based_billing`); token-shaped
    keys and values and URL userinfo are refused everywhere regardless."""
    provider: str
    method: str
    path: str
    reason: str
    response_fields: frozenset[str] | None = None
    benign_keys: frozenset[str] = frozenset()
    strict_fields: bool = False
    drop_fields: frozenset[str] = frozenset()

    def is_benign(self, json_path: str) -> bool:
        """`benign_keys` are exact JSON paths (`$.a`, `$.a.*.b`; `*` is one object key), so a
        benign name is accepted only where it was measured (review 11-3)."""
        return any(re.fullmatch(re.escape(p).replace(r"\*", r"[^.\[\]]+"), json_path) for p in self.benign_keys)

    def matches(self, req: RequestView, prefixes: tuple[str, ...]) -> bool:
        return req.method == self.method and not req.query and any(req.path == p + self.path for p in prefixes)


@dataclass(frozen=True)
class Provider:
    name: str
    hosts: tuple[HostPattern, ...]
    path_prefixes: tuple[str, ...]
    deny: tuple[BackstopEntry, ...]
    exceptions: tuple[BackstopException, ...] = ()


_BACKSTOP_KEYS = {"provider", "description", "source", "hosts", "pathPrefixes", "exceptions", "deny"}
_EXCEPTION_KEYS = {"method", "path", "reason", "responseFields", "benignKeys", "strictFields", "dropFields"}
_DENY_KEYS = {"methods", "path", "reason"}


def _check_backstop_file(name: str, d: dict) -> None:
    """Shipped provider data is a security control: an unknown or misspelt key (say
    `responseField`) must fail at load rather than silently disable a check (review 11-1)."""
    def bad(where: str, obj: Any, allowed: set[str], required: set[str]) -> None:
        if not isinstance(obj, dict) or set(obj) - allowed or required - set(obj):
            raise PolicyError(f"providers/{name}: malformed {where}")
    bad("file", d, _BACKSTOP_KEYS, {"provider", "hosts", "deny"})
    for e in d.get("exceptions", []):
        bad("exception", e, _EXCEPTION_KEYS, {"method", "path", "reason"})
        if e.get("strictFields") and "responseFields" not in e:
            raise PolicyError(f"providers/{name}: strictFields needs responseFields")
        for k in ("responseFields", "benignKeys", "dropFields"):
            if k in e and not (isinstance(e[k], list) and all(isinstance(x, str) and x for x in e[k])):
                raise PolicyError(f"providers/{name}: {k} must be a list of names")
        for f in e.get("responseFields", []) + e.get("dropFields", []):
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", f):
                raise PolicyError(f"providers/{name}: {f!r} is not a top-level field name")
        for p in e.get("benignKeys", []):
            if not re.fullmatch(r"\$(\.([A-Za-z0-9_-]+|\*))+", p):
                raise PolicyError(f"providers/{name}: benign key {p!r} is not a JSON path")
    for e in d["deny"]:
        bad("deny entry", e, _DENY_KEYS, _DENY_KEYS)
        if any(_trim_segment(s) != s for s in e["path"].split("/")):
            # Request paths are trimmed before matching, so this entry could never match (13b-3).
            raise PolicyError(f"providers/{name}: deny path {e['path']!r} has a segment ending in a dot or space")


@lru_cache(maxsize=1)
def providers() -> dict[str, Provider]:
    out = {}
    for f in sorted((DATA_DIR / "providers").glob("*.json")):
        d = json.loads(f.read_text())
        _check_backstop_file(f.name, d)
        out[d["provider"]] = Provider(
            name=d["provider"],
            hosts=tuple(_parse_host_pattern(h) for h in d["hosts"]),
            path_prefixes=tuple(d.get("pathPrefixes", [""])),
            deny=tuple(BackstopEntry(d["provider"], tuple(e["methods"]), e["path"], e["reason"])
                       for e in d["deny"]),
            exceptions=tuple(BackstopException(
                d["provider"], e["method"], e["path"], e["reason"],
                frozenset(e["responseFields"]) if "responseFields" in e else None,
                frozenset(e.get("benignKeys", [])), bool(e.get("strictFields", False)),
                frozenset(e.get("dropFields", []))) for e in d.get("exceptions", [])),
        )
    return out


def backstop_exception(req: RequestView, extra_provider: str | None = None) -> BackstopException | None:
    """The approved exception covering this request, if any (callers also require no body
    and no upgrade, which a RequestView doesn't carry)."""
    for prov in providers().values():
        applies = any(h.matches(req.host) for h in prov.hosts) or prov.name == extra_provider
        if applies:
            for e in prov.exceptions:
                if e.matches(req, prov.path_prefixes):
                    return e
    return None


def backstop_denies(req: RequestView, extra_provider: str | None = None) -> BackstopEntry | None:
    for prov in providers().values():
        applies = any(h.matches(req.host) for h in prov.hosts) or prov.name == extra_provider
        if not applies:
            continue
        for entry in prov.deny:
            if entry.matches(req, prov.path_prefixes):
                return entry
    return None
