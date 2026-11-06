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
import urllib.parse
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from .policy import DATA_DIR, HostPattern, PolicyError, _parse_host_pattern, compile_glob

MAX_DEPTH = 64
_JSON_TYPE = re.compile(r"^application/(?:[a-z0-9.+-]*\+)?json\s*(?:;\s*charset\s*=\s*\"?utf-8\"?\s*)?$", re.I)


@dataclass(frozen=True)
class Endpoint:
    """One method set on one path. `fields`, `tool_types` and `untyped_tool`, when given,
    replace the provider's for this endpoint (measured per-endpoint allowlists). An endpoint
    with `requires_grant` is denied unless a grant names its `id` (Tier C)."""
    path: str
    methods: tuple[str, ...]
    id: str | None = None
    fields: frozenset[str] | None = None
    tool_types: frozenset[str] | None = None
    untyped_tool: str | None = None
    requires_grant: bool = False

    @classmethod
    def from_json(cls, e: dict) -> "Endpoint":
        if e.get("requiresGrant") and not e.get("id"):
            raise PolicyError(f"model endpoint {e['path']!r} requires a grant but has no id")
        return cls(e["path"], tuple(e["methods"]), e.get("id"),
                   frozenset(e["fields"]) if "fields" in e else None,
                   frozenset(e["toolTypes"]) if "toolTypes" in e else None,
                   e.get("untypedTool"), bool(e.get("requiresGrant", False)))

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
    auth_headers: frozenset[str] = frozenset()
    auth_query: frozenset[str] = frozenset()

    @classmethod
    def from_json(cls, obj: dict) -> "Provider":
        return cls(
            id=obj["id"],
            hosts=tuple(_parse_host_pattern(h) for h in obj["hosts"]),
            endpoints=tuple(Endpoint.from_json(e) for e in obj["endpoints"]),
            fields=frozenset(obj["fields"]),
            tool_fields=tuple(obj.get("toolFields", ["tools"])),
            tool_types=frozenset(obj.get("toolTypes", [])),
            untyped_tool=obj.get("untypedTool"),
            auth_headers=frozenset(h.lower() for h in obj.get("authHeaders", [])),
            auth_query=frozenset(q.lower() for q in obj.get("authQueryParams", [])),
        )


# Where a model API might take a credential. Every value found in one of these, plus a
# provider's own `authHeaders`/`authQueryParams`, must hold a sentinel of this tab.
CREDENTIAL_HEADERS = frozenset({"authorization", "x-api-key", "api-key", "x-goog-api-key",
                                "ocp-apim-subscription-key", "openai-api-key", "anthropic-api-key",
                                "x-auth-token", "cookie"})
CREDENTIAL_QUERY = frozenset({"key", "api-key", "api_key", "apikey", "subscription-key", "access_token",
                              "token", "auth", "sig", "signature", "code"})


def credential_values(p: Provider | None, headers: dict[str, list[str]], query: str) -> list[tuple[str, str]]:
    """(location, value) for every place a credential could ride on a model request."""
    names = CREDENTIAL_HEADERS | (p.auth_headers if p else frozenset())
    out = [(f"header:{n}", v) for n, vs in headers.items() if n in names for v in vs]
    qnames = CREDENTIAL_QUERY | (p.auth_query if p else frozenset())
    out += [(f"query:{k.lower()}", v) for k, v in urllib.parse.parse_qsl(query, keep_blank_values=True)
            if k.lower() in qnames]
    return out


@dataclass(frozen=True)
class ModelPolicy:
    providers: tuple[Provider, ...] = ()
    max_requests: int = 5000
    max_bytes: int = 1 << 30
    grants: frozenset[tuple[str, str]] = frozenset()
    endpoint_grants: frozenset[tuple[str, str]] = frozenset()

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
        raw = obj.get("grants", [])
        grants = frozenset((g["provider"], g["toolType"]) for g in raw if "toolType" in g)
        endpoint_grants = frozenset((g["provider"], g["endpoint"]) for g in raw if "endpoint" in g)
        unknown = {p for p, _ in grants | endpoint_grants} - set(ids)
        if unknown:
            raise PolicyError(f"model grant names an unknown provider: {sorted(unknown)}")
        by_id = {p.id: p for p in providers}
        for prov, eid in endpoint_grants:
            if not any(e.id == eid and e.requires_grant for e in by_id[prov].endpoints):
                raise PolicyError(f"model grant names no grantable endpoint {eid!r} of provider {prov!r}")
        budget = obj.get("budget", {})
        return cls(providers=providers, max_requests=int(budget.get("requests", 5000)),
                   max_bytes=int(budget.get("bytes", 1 << 30)), grants=grants,
                   endpoint_grants=endpoint_grants)

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
        folds: set[str] = set()
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
            folded = k.casefold()
            if folded in folds:
                # Case-insensitive decoders (Go encoding/json) would merge these.
                raise StrictJSONError("keys differ only in case")
            folds.add(folded)
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
    ep = next((e for e in p.endpoints if e.matches(method, path)), None)
    if ep is None:
        return BodyVerdict(False, "endpoint not allowed for this provider", p.id)
    if ep.requires_grant and (p.id, ep.id) not in policy.endpoint_grants:
        return BodyVerdict(False, "endpoint needs a grant", p.id, detail=ep.id)
    fields = p.fields if ep.fields is None else ep.fields
    tool_types = p.tool_types if ep.tool_types is None else ep.tool_types
    untyped = ep.untyped_tool if ep.untyped_tool is not None else (p.untyped_tool if ep.tool_types is None else None)
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
    extra = sorted(set(doc) - fields)
    if extra:
        return BodyVerdict(False, "field not allowed for this provider", p.id, detail=extra[0])
    allowed = tool_types | {t for prov, t in policy.grants if prov == p.id}
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
            ttype = t.get("type", untyped)
            if any(k != "type" and k.casefold() == "type" for k in t):
                return BodyVerdict(False, "tool type key in another case", p.id)
            if not isinstance(ttype, str) or ttype not in allowed:
                return BodyVerdict(False, "tool type not allowed", p.id, detail=str(ttype))
            seen.append(ttype)
    if REMOTE_CONTENT_GRANT not in allowed:
        content = {k: v for k, v in doc.items() if k not in p.tool_fields}
        where = _remote_content(content)
        if where is not None:
            return BodyVerdict(False, "remote content the provider would fetch", p.id, detail=where)
    return BodyVerdict(True, provider=p.id, tools=seen)


# A grant `toolType` that lets the provider fetch URLs named in message content.
REMOTE_CONTENT_GRANT = "remote-content"
# Keys whose value the providers treat as a resource to fetch (image_url, file_url, Anthropic
# `source.url`, MCP `server_url`, ...). Matched case-insensitively, at any depth. Inline
# `data:` URIs are content, not a fetch, and pass.
_URL_KEYS = frozenset({"url", "uri", "href", "image_url", "file_url", "server_url", "audio_url",
                       "video_url", "document_url", "source_url", "link"})
_FETCHED_SOURCE_TYPES = frozenset({"url", "uri", "image_url", "file_url"})


def _remote_content(node: Any, path: str = "$") -> str | None:
    """JSON path of the first value a provider would fetch, else None."""
    if isinstance(node, list):
        for i, v in enumerate(node):
            hit = _remote_content(v, f"{path}[{i}]")
            if hit:
                return hit
        return None
    if not isinstance(node, dict):
        return None
    t = node.get("type")
    if isinstance(t, str) and t.casefold() in _FETCHED_SOURCE_TYPES and "data" not in node:
        target = node.get("url", node.get(t))
        if not _inline(target.get("url") if isinstance(target, dict) else target):
            return f"{path}.type"
    for k, v in node.items():
        if k == "input" and t == "tool_use":
            continue  # a client tool call the model made: run in the tab, never fetched by the provider
        if k.casefold() in _URL_KEYS:
            target = v.get("url") if isinstance(v, dict) else v
            if isinstance(v, dict) and "url" not in v:
                hit = _remote_content(v, f"{path}.{k}")
                if hit:
                    return hit
                continue
            if not _inline(target):
                return f"{path}.{k}"
            continue
        hit = _remote_content(v, f"{path}.{k}")
        if hit:
            return hit
    return None


def _inline(v: Any) -> bool:
    return isinstance(v, str) and v[:5].casefold() == "data:"


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
