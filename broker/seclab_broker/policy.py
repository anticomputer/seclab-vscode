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


@lru_cache(maxsize=4)
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

    @property
    def origin(self) -> tuple[str, str, int]:
        return (self.scheme, self.host, self.port)

    def summary(self) -> dict:
        """For audit and prompts. Tab-controlled: host, method, path (percent-encoded ASCII)."""
        from .untrusted import display_path
        return {"scheme": self.scheme, "host": self.host[:253], "port": self.port,
                "method": self.method, "path": display_path(self.path)}


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

    @classmethod
    def from_json(cls, obj: dict) -> "CredentialSpec":
        default_inject = Inject.from_json(obj["inject"]) if "inject" in obj else None
        return cls(id=obj["id"], bindings=tuple(parse_bindings(obj["bind"], default_inject)),
                   provider=obj.get("provider"), sentinel_prefix=obj.get("sentinelPrefix"),
                   derive=parse_derive(obj.get("derive", [])))


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
                and req.method == self.method)

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
    raw: dict = field(repr=False, default_factory=dict)

    @classmethod
    def from_json(cls, obj: Any) -> "Policy":
        from .models import ModelPolicy
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

    def to_json(self) -> dict:
        out = dict(self.raw)
        out["allow"] = [r.to_json() for r in self.rules]
        return out


@lru_cache(maxsize=1)
def baseline_rules() -> tuple[Rule, ...]:
    data = json.loads((DATA_DIR / "baseline.v1.json").read_text())
    return tuple(Rule.from_json(r) for r in data["allow"])


# --------------------------------------------------------------------------
# Provider backstop: endpoints that let a tab mint its own durable credential
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class BackstopEntry:
    provider: str
    methods: tuple[str, ...]
    path: str
    reason: str

    def matches(self, req: RequestView, prefixes: tuple[str, ...]) -> bool:
        if "*" not in self.methods and req.method not in self.methods:
            return False
        path = req.path.rstrip("/") or "/"
        return any(compile_glob(prefix + self.path, ignore_case=True).fullmatch(path)
                   for prefix in prefixes)


@dataclass(frozen=True)
class BackstopException:
    """A coordinator-approved, data-level hole in a provider's backstop: one method on one
    exact path (case-sensitive, no trailing-slash variant), with no body, query or upgrade.
    Its response is held to the no-credential-fields check in the engine."""
    provider: str
    method: str
    path: str
    reason: str

    def matches(self, req: RequestView, prefixes: tuple[str, ...]) -> bool:
        return req.method == self.method and not req.query and any(req.path == p + self.path for p in prefixes)


@dataclass(frozen=True)
class Provider:
    name: str
    hosts: tuple[HostPattern, ...]
    path_prefixes: tuple[str, ...]
    deny: tuple[BackstopEntry, ...]
    exceptions: tuple[BackstopException, ...] = ()


@lru_cache(maxsize=1)
def providers() -> dict[str, Provider]:
    out = {}
    for f in sorted((DATA_DIR / "providers").glob("*.json")):
        d = json.loads(f.read_text())
        out[d["provider"]] = Provider(
            name=d["provider"],
            hosts=tuple(_parse_host_pattern(h) for h in d["hosts"]),
            path_prefixes=tuple(d.get("pathPrefixes", [""])),
            deny=tuple(BackstopEntry(d["provider"], tuple(e["methods"]), e["path"], e["reason"])
                       for e in d["deny"]),
            exceptions=tuple(BackstopException(d["provider"], e["method"], e["path"], e["reason"])
                             for e in d.get("exceptions", [])),
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
