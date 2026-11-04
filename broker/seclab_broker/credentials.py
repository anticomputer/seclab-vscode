"""Credential custody: sentinels, real values (memory only) and scanners.

Invariant: a real value never leaves this process except inside the one header
a matching binding names, on a request to the bound upstream.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import secrets
import string
import time
import urllib.parse
from dataclasses import dataclass, field

from .policy import Binding, CredentialSpec, Inject, PolicyError

SENTINEL_PREFIX = "SECLAB_SNTL_"
_ALPHABET = string.ascii_letters + string.digits
_SENTINEL_OK = re.compile(r"^[A-Za-z0-9_.~-]{32,256}$")
MAX_VALUE_LEN = 16384


def new_sentinel(prefix: str | None = None) -> str:
    # 43 base62 characters ≈ 256 bits.
    return (SENTINEL_PREFIX if prefix is None else prefix) + "".join(
        secrets.choice(_ALPHABET) for _ in range(43))


def check_sentinel(s: str) -> None:
    if not isinstance(s, str) or not _SENTINEL_OK.match(s):
        raise PolicyError("sentinel must be 32-256 characters of [A-Za-z0-9_.~-]")


def check_value(v: object) -> str:
    if not isinstance(v, str) or not (8 <= len(v) <= MAX_VALUE_LEN):
        raise PolicyError("credential value must be a string of 8..16384 characters")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in v):
        raise PolicyError("credential value contains control characters")
    return v


def b64_cores(data: bytes) -> list[bytes]:
    """Base64 fragments of `data` that appear whatever bytes surround it."""
    out: list[bytes] = []
    for k, start in ((0, 0), (1, 2), (2, 3)):
        enc = base64.b64encode(b"\0" * k + data)
        core = enc[start:4 * ((len(data) + k) // 3)]
        if len(core) >= 12:
            out.append(core)
            out.append(core.translate(bytes.maketrans(b"+/", b"-_")))
    return list(dict.fromkeys(out))


def encoded_variants(value: str) -> dict[bytes, str]:
    raw = value.encode()
    v: dict[bytes, str] = {raw: "raw"}
    for core in b64_cores(raw):
        v.setdefault(core, "base64")
    for enc in (urllib.parse.quote(value, safe=""), urllib.parse.quote_plus(value)):
        v.setdefault(enc.encode(), "urlencoded")
    v.setdefault(raw.hex().encode(), "hex")
    v.setdefault(raw.hex().upper().encode(), "hex")
    v.setdefault(json.dumps(value)[1:-1].encode(), "json")
    return v


def header_has_sentinel(header_value: str, sentinel: str) -> bool:
    if sentinel in header_value:
        return True
    decoded = _basic_decode(header_value)
    return decoded is not None and sentinel in decoded


def _basic_decode(header_value: str) -> str | None:
    parts = header_value.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "basic":
        return None
    try:
        return base64.b64decode(parts[1].strip(), validate=True).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return None


def _canonical_header(name: str) -> str:
    return "-".join(part.capitalize() for part in name.split("-"))


def infer_inject(header: str, header_value: str, sentinel: str) -> Inject | None:
    """Propose an inject spec from where the caller put an unbound sentinel."""
    header = _canonical_header(header)
    try:
        if sentinel in header_value and "{" not in header_value and "}" not in header_value:
            return Inject.from_json({"header": header, "fmt": header_value.replace(sentinel, "{value}")})
        decoded = _basic_decode(header_value)
        if decoded and sentinel in decoded and "{" not in decoded and "}" not in decoded:
            return Inject.from_json({"header": header,
                                     "fmt": "Basic {base64:" + decoded.replace(sentinel, "{value}") + "}"})
    except PolicyError:
        return None
    return None


@dataclass
class Credential:
    id: str
    sentinel: str
    bindings: list[Binding]
    origin: str  # policy | import | derived
    confirmed: bool = True
    provider: str | None = None
    parent_id: str | None = None
    proposed: list[Binding] = field(default_factory=list)
    value: str | None = field(default=None, repr=False)
    expires_at: float | None = None
    source: dict = field(default_factory=dict)

    def has_value(self) -> bool:
        if self.value is None:
            return False
        if self.expires_at is not None and time.time() >= self.expires_at:
            self.value = None
            return False
        return True

    def public(self) -> dict:
        return {
            "id": self.id, "origin": self.origin, "sentinel": self.sentinel,
            "confirmed": self.confirmed, "hasValue": self.has_value(),
            "bind": [b.to_json() for b in self.bindings],
            "proposedBind": [b.to_json() for b in self.proposed],
            "provider": self.provider, "parentId": self.parent_id,
        }


class _Matcher:
    def __init__(self, table: dict[bytes, tuple[str, str]]):
        self.table = table
        keys = sorted(table, key=len, reverse=True)
        self.rx = re.compile(b"|".join(re.escape(k) for k in keys)) if keys else None

    def find(self, data: bytes) -> list[tuple[str, str, int, int]]:
        if self.rx is None or not data:
            return []
        return [(*self.table[m.group(0)], m.start(), m.end()) for m in self.rx.finditer(data)]


class CredentialStore:
    def __init__(self) -> None:
        self._by_id: dict[str, Credential] = {}
        self._rebuild()

    # ---- lifecycle -------------------------------------------------------
    def apply_policy(self, specs: list[CredentialSpec]) -> None:
        """Define policy credentials. Sentinels and values survive reloads for the same id."""
        wanted = {s.id for s in specs}
        for cid in [c.id for c in self._by_id.values() if c.origin == "policy" and c.id not in wanted]:
            self._drop(cid)
        for spec in specs:
            existing = self._by_id.get(spec.id)
            if existing is not None and existing.origin != "policy":
                raise PolicyError(f"credential id {spec.id!r} is already used by an imported credential")
            if existing is None:
                self._by_id[spec.id] = Credential(
                    id=spec.id, sentinel=new_sentinel(spec.sentinel_prefix),
                    bindings=list(spec.bindings), origin="policy", provider=spec.provider)
            else:
                existing.bindings = list(spec.bindings)
                existing.provider = spec.provider
        self._rebuild()

    def import_credential(self, cid: str, value: str, sentinel: str | None,
                          bindings: list[Binding], proposed: list[Binding],
                          provider: str | None, source: dict) -> Credential:
        check_value(value)
        if sentinel is not None:
            check_sentinel(sentinel)
            owner = self.by_sentinel(sentinel)
            if owner is not None and owner.id != cid:
                raise PolicyError("sentinel is already in use")
        existing = self._by_id.get(cid)
        if existing is not None and existing.origin == "policy":
            raise PolicyError(f"credential id {cid!r} is defined by the policy")
        cred = Credential(
            id=cid, sentinel=sentinel or (existing.sentinel if existing else new_sentinel()),
            bindings=list(bindings), origin="import", confirmed=bool(bindings),
            provider=provider, proposed=list(proposed), value=value, source=source)
        self._by_id[cid] = cred
        self._rebuild()
        return cred

    def derive(self, parent: Credential, value: str, rule_id: str) -> Credential:
        for c in self._by_id.values():
            if c.value == value:
                return c
        n = 1 + sum(1 for c in self._by_id.values() if c.parent_id == parent.id)
        cred = Credential(
            id=f"{parent.id}.derived-{n}", sentinel=new_sentinel(), bindings=list(parent.bindings),
            origin="derived", provider=parent.provider, parent_id=parent.id, value=value,
            source={"rule": rule_id})
        self._by_id[cred.id] = cred
        self._rebuild()
        return cred

    def provide(self, cid: str, value: str, expires_at: float | None) -> Credential:
        cred = self._by_id.get(cid)
        if cred is None:
            raise KeyError(cid)
        cred.value = check_value(value)
        cred.expires_at = expires_at
        self._rebuild()
        return cred

    def confirm_binding(self, cid: str, binding: Binding) -> Credential:
        cred = self._by_id[cid]
        cred.bindings.append(binding)
        cred.confirmed = True
        return cred

    def revoke(self, cid: str, rotate: bool) -> Credential:
        cred = self._by_id.get(cid)
        if cred is None:
            raise KeyError(cid)
        cred.value = None
        cred.expires_at = None
        if rotate:
            cred.sentinel = new_sentinel()
        for child in [c for c in self._by_id.values() if c.parent_id == cid]:
            self._drop(child.id)
        self._rebuild()
        return cred

    def clear(self) -> None:
        for c in self._by_id.values():
            c.value = None
        self._by_id.clear()
        self._rebuild()

    def _drop(self, cid: str) -> None:
        cred = self._by_id.pop(cid, None)
        if cred is not None:
            cred.value = None

    # ---- lookup ----------------------------------------------------------
    def get(self, cid: str) -> Credential | None:
        return self._by_id.get(cid)

    def all(self) -> list[Credential]:
        return list(self._by_id.values())

    def by_sentinel(self, s: str) -> Credential | None:
        cid = self._sentinel_ids.get(s)
        return self._by_id.get(cid) if cid else None

    def _rebuild(self) -> None:
        self._sentinel_ids = {c.sentinel: c.id for c in self._by_id.values()}
        stable: dict[bytes, tuple[str, str]] = {}
        for c in self._by_id.values():
            raw = c.sentinel.encode()
            stable[raw] = (c.id, "raw")
            for core in b64_cores(raw):
                stable.setdefault(core, (c.id, "base64"))
        self._sentinel_matcher = _Matcher(stable)
        real: dict[bytes, tuple[str, str]] = {}
        for c in self._by_id.values():
            if c.value is not None:
                for k, kind in encoded_variants(c.value).items():
                    real.setdefault(k, (c.id, kind))
        self._real_matcher = _Matcher(real)

    # ---- scanning --------------------------------------------------------
    def find_sentinels(self, data: bytes) -> list[tuple[str, str, int, int]]:
        return self._sentinel_matcher.find(data)

    def find_real(self, data: bytes) -> list[tuple[str, str, int, int]]:
        return self._real_matcher.find(data)

    def scrub(self, text: str) -> str:
        """Replace any real value or sentinel in text (for audit, logs, errors)."""
        data = text.encode("utf-8", "surrogateescape")
        hits = sorted(self.find_real(data) + self.find_sentinels(data), key=lambda h: h[2])
        if not hits:
            return text
        out, pos = [], 0
        for cid, kind, s, e in hits:
            if s < pos:
                continue
            out.append(data[pos:s])
            out.append(f"[redacted:{cid}]".encode())
            pos = e
        out.append(data[pos:])
        return b"".join(out).decode("utf-8", "replace")
