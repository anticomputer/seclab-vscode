"""Model-host policy: per-tab budgets and a fail-closed request body policy.

A model API that accepts server-side tools (remote MCP, web fetch, code execution,
connectors) can be told to fetch a URL the caller chooses, which turns the provider into
a relay for workspace data. Host, path and method bindings don't look at bodies, so
requests to a model host also pass this check, which only ever denies:

  * the host must belong to a provider declared in the policy (a request to a known
    model host with no declared provider is denied);
  * the method and path must be one of the provider's endpoints; no upgrades;
  * a body must be strict JSON: identity encoding, a JSON media type, UTF-8, no duplicate
    keys, no escapes in keys, bounded depth; anything unparseable is denied;
  * every top-level key must be listed for the provider;
  * every element of a tool field must have an allowed `type` (or a granted one).

Engine-agnostic: works on method, path, headers and body bytes.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from .policy import DATA_DIR, HostPattern, PolicyError, _parse_host_pattern, compile_glob

MAX_DEPTH = 64
_JSON_TYPE = re.compile(r"^application/(?:[a-z0-9.+-]*\+)?json\s*(?:;\s*charset\s*=\s*\"?utf-8\"?\s*)?$", re.I)


@dataclass(frozen=True)
class Endpoint:
    path: str
    methods: tuple[str, ...]

    def matches(self, method: str, path: str) -> bool:
        return method in self.methods and compile_glob(self.path).fullmatch(path) is not None


@dataclass(frozen=True)
class Provider:
    id: str
    hosts: tuple[HostPattern, ...]
    endpoints: tuple[Endpoint, ...]
    fields: frozenset[str]
    tool_fields: tuple[str, ...]
    tool_types: frozenset[str]
    untyped_tool: str | None

    @classmethod
    def from_json(cls, obj: dict) -> "Provider":
        return cls(
            id=obj["id"],
            hosts=tuple(_parse_host_pattern(h) for h in obj["hosts"]),
            endpoints=tuple(Endpoint(e["path"], tuple(e["methods"])) for e in obj["endpoints"]),
            fields=frozenset(obj["fields"]),
            tool_fields=tuple(obj.get("toolFields", ["tools"])),
            tool_types=frozenset(obj.get("toolTypes", [])),
            untyped_tool=obj.get("untypedTool"),
        )


@dataclass(frozen=True)
class ModelPolicy:
    providers: tuple[Provider, ...] = ()
    max_requests: int = 5000
    max_bytes: int = 1 << 30
    grants: frozenset[tuple[str, str]] = frozenset()

    @classmethod
    def from_json(cls, obj: dict | None) -> "ModelPolicy":
        obj = obj or {}
        builtin = builtin_providers()
        providers = []
        for p in obj.get("providers", []):
            if isinstance(p, str):
                if p not in builtin:
                    raise PolicyError(f"unknown built-in model provider {p!r}")
                p = builtin[p]
            providers.append(Provider.from_json(p))
        providers = tuple(providers)
        ids = [p.id for p in providers]
        if len(ids) != len(set(ids)):
            raise PolicyError("duplicate model provider id")
        grants = frozenset((g["provider"], g["toolType"]) for g in obj.get("grants", []))
        unknown = {p for p, _ in grants} - set(ids)
        if unknown:
            raise PolicyError(f"model grant names an unknown provider: {sorted(unknown)}")
        budget = obj.get("budget", {})
        return cls(providers=providers, max_requests=int(budget.get("requests", 5000)),
                   max_bytes=int(budget.get("bytes", 1 << 30)), grants=grants)

    def provider_for(self, host: str) -> Provider | None:
        return next((p for p in self.providers if any(h.matches(host) for h in p.hosts)), None)


@lru_cache(maxsize=1)
def builtin_providers() -> dict[str, dict]:
    data = json.loads((DATA_DIR / "model-providers.v1.json").read_text())
    return {p["id"]: p for p in data["providers"]}


@lru_cache(maxsize=1)
def known_model_hosts() -> tuple[HostPattern, ...]:
    data = json.loads((DATA_DIR / "model-hosts.v1.json").read_text())
    return tuple(_parse_host_pattern(e["host"]) for e in data["entries"])


def is_model_host(host: str, policy: ModelPolicy) -> bool:
    return policy.provider_for(host) is not None or any(h.matches(host) for h in known_model_hosts())


# ----------------------------------------------------------------- strict JSON

class StrictJSONError(ValueError):
    pass


class _Parser:
    """RFC 8259 JSON, stricter: no duplicate keys, no escapes in keys, no NaN/Infinity,
    no lone surrogates, bounded depth. Keys are compared exactly as written."""

    _WS = " \t\n\r"
    _NUM = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")

    def __init__(self, text: str) -> None:
        self.s, self.i = text, 0

    def parse(self) -> Any:
        v = self._value(0)
        self._ws()
        if self.i != len(self.s):
            raise StrictJSONError("trailing data")
        return v

    def _ws(self) -> None:
        while self.i < len(self.s) and self.s[self.i] in self._WS:
            self.i += 1

    def _value(self, depth: int) -> Any:
        if depth > MAX_DEPTH:
            raise StrictJSONError("nesting too deep")
        self._ws()
        if self.i >= len(self.s):
            raise StrictJSONError("unexpected end")
        c = self.s[self.i]
        if c == "{":
            return self._object(depth)
        if c == "[":
            return self._array(depth)
        if c == '"':
            return self._string(key=False)
        for lit, val in (("true", True), ("false", False), ("null", None)):
            if self.s.startswith(lit, self.i):
                self.i += len(lit)
                return val
        m = self._NUM.match(self.s, self.i)
        if m and m.end() > self.i:
            self.i = m.end()
            return json.loads(m.group(0))
        raise StrictJSONError(f"unexpected character at {self.i}")

    def _object(self, depth: int) -> dict:
        self.i += 1
        out: dict = {}
        self._ws()
        if self.s.startswith("}", self.i):
            self.i += 1
            return out
        while True:
            self._ws()
            if not self.s.startswith('"', self.i):
                raise StrictJSONError("object key must be a string")
            k = self._string(key=True)
            if k in out:
                raise StrictJSONError("duplicate key")
            self._ws()
            if not self.s.startswith(":", self.i):
                raise StrictJSONError("expected ':'")
            self.i += 1
            out[k] = self._value(depth + 1)
            self._ws()
            if self.s.startswith(",", self.i):
                self.i += 1
                continue
            if self.s.startswith("}", self.i):
                self.i += 1
                return out
            raise StrictJSONError("expected ',' or '}'")

    def _array(self, depth: int) -> list:
        self.i += 1
        out: list = []
        self._ws()
        if self.s.startswith("]", self.i):
            self.i += 1
            return out
        while True:
            out.append(self._value(depth + 1))
            self._ws()
            if self.s.startswith(",", self.i):
                self.i += 1
                continue
            if self.s.startswith("]", self.i):
                self.i += 1
                return out
            raise StrictJSONError("expected ',' or ']'")

    def _string(self, key: bool) -> str:
        start = self.i
        self.i += 1
        while True:
            j = self.i
            while j < len(self.s) and self.s[j] not in '"\\' and self.s[j] >= " ":
                j += 1
            if j >= len(self.s):
                raise StrictJSONError("unterminated string")
            c = self.s[j]
            if c < " ":
                raise StrictJSONError("control character in string")
            if c == "\\":
                if key:
                    raise StrictJSONError("escape in object key")
                j += 2 if self.s[j + 1:j + 2] != "u" else 6
                self.i = j
                continue
            self.i = j + 1
            raw = self.s[start:self.i]
            try:
                v = json.loads(raw)
            except ValueError:
                raise StrictJSONError("bad string escape") from None
            if any(0xD800 <= ord(ch) <= 0xDFFF for ch in v):
                raise StrictJSONError("lone surrogate")
            return v


def parse_strict(data: bytes) -> Any:
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise StrictJSONError("body is not UTF-8") from None
    if text.startswith("\ufeff"):
        raise StrictJSONError("byte order mark")
    return _Parser(text).parse()


# ----------------------------------------------------------------- the check

@dataclass
class BodyVerdict:
    ok: bool
    reason: str = ""
    provider: str | None = None
    tools: list[str] = field(default_factory=list)
    # Tab-chosen text (a field name or tool type) kept out of `reason`.
    detail: str | None = None


def check_request(policy: ModelPolicy, host: str, method: str, path: str, headers: dict[str, list[str]],
                  body: bytes, upgrade: str | None) -> BodyVerdict:
    """`headers`: lower-cased name -> every value. Only ever denies."""
    p = policy.provider_for(host)
    if p is None:
        return BodyVerdict(False, "model host has no declared provider")
    if upgrade is not None:
        return BodyVerdict(False, "no upgrades on model hosts", p.id)
    if not any(e.matches(method, path) for e in p.endpoints):
        return BodyVerdict(False, "endpoint not allowed for this provider", p.id)
    enc = [v.strip().lower() for v in headers.get("content-encoding", [])]
    if any(e not in ("", "identity") for e in enc):
        return BodyVerdict(False, "content encoding must be identity", p.id)
    if not body:
        return BodyVerdict(True, provider=p.id)
    ctypes = headers.get("content-type", [])
    if len(ctypes) != 1 or not _JSON_TYPE.match(ctypes[0].strip()):
        return BodyVerdict(False, "body must be a single application/json content type", p.id)
    try:
        doc = parse_strict(body)
    except StrictJSONError as e:
        return BodyVerdict(False, f"body is not strict JSON ({e})", p.id)
    if not isinstance(doc, dict):
        return BodyVerdict(False, "body must be a JSON object", p.id)
    extra = sorted(set(doc) - p.fields)
    if extra:
        return BodyVerdict(False, "field not allowed for this provider", p.id, detail=extra[0])
    allowed = p.tool_types | {t for prov, t in policy.grants if prov == p.id}
    seen: list[str] = []
    for f in p.tool_fields:
        if f not in doc:
            continue
        tools = doc[f]
        if not isinstance(tools, list):
            return BodyVerdict(False, f"{f} must be an array", p.id)
        for t in tools:
            if not isinstance(t, dict):
                return BodyVerdict(False, f"{f} element must be an object", p.id)
            ttype = t.get("type", p.untyped_tool)
            if not isinstance(ttype, str) or ttype not in allowed:
                return BodyVerdict(False, "tool type not allowed", p.id, detail=str(ttype))
            seen.append(ttype)
    return BodyVerdict(True, provider=p.id, tools=seen)


@dataclass
class Budget:
    requests: int = 0
    bytes: int = 0

    def exhausted(self, policy: ModelPolicy) -> str | None:
        if self.requests >= policy.max_requests:
            return "request budget exhausted"
        if self.bytes >= policy.max_bytes:
            return "byte budget exhausted"
        return None
