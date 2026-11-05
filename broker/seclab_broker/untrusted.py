"""Tab-controlled text that leaves the broker (audit events, prompts) is made safe to
show to humans and to hand to an LLM: no control, format (bidi, zero-width) or
line-separator characters, bounded length, paths rendered as percent-encoded ASCII,
and every tab-controlled field named in an `untrusted` list so consumers can quote it
as data rather than read it as instructions.
"""

from __future__ import annotations

import unicodedata
import urllib.parse
from typing import Any

MAX_TEXT = 512
_DROP = {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}
# Unicode Default_Ignorable_Code_Point characters outside the categories above (fillers,
# variation selectors, combining grapheme joiner): invisible, so they can hide or spoof.
_IGNORABLE = ((0x034F, 0x034F), (0x115F, 0x1160), (0x17B4, 0x17B5), (0x180B, 0x180F),
              (0x3164, 0x3164), (0xFE00, 0xFE0F), (0xFFA0, 0xFFA0), (0xE0100, 0xE01EF))
# Audit-event keys whose values the tab (or an upstream it chose) controls.
UNTRUSTED_AUDIT_KEYS = ("host", "path", "method", "location", "header", "server", "origin", "detail", "tools")


def _ignorable(ch: str) -> bool:
    o = ord(ch)
    return any(lo <= o <= hi for lo, hi in _IGNORABLE)


def clean(text: str, cap: int = MAX_TEXT) -> str:
    out = "".join(ch for ch in text if unicodedata.category(ch) not in _DROP and not _ignorable(ch))
    if len(out) > cap:
        out = out[:cap] + f"…[+{len(out) - cap}]"
    return out


def _elide(text: str, cap: int) -> str:
    """ASCII middle elision that never splits a %XX escape and fits within cap. The
    marker uses brackets, which the encoders below always escape, so it can't be forged."""
    if len(text) <= cap:
        return text
    keep = cap - 24
    end, start = keep * 2 // 3, len(text) - (keep - keep * 2 // 3)
    while "%" in text[max(0, end - 2):end]:
        end -= 1
    while "%" in text[max(0, start - 2):start]:
        start += 1
    return f"{text[:end]}...[{start - end} elided]...{text[start:]}"


def display_path(path: str, cap: int = MAX_TEXT) -> str:
    """Decoded canonical path -> ASCII for display: non-ASCII, spaces and anything that is
    not a plain URL path character is percent-encoded, so nothing can hide or reorder.
    Long paths keep their beginning and end."""
    return _elide(urllib.parse.quote(path, safe="/!$&'()*+,;=:@-._~"), cap)


def display_host(host: str) -> str:
    """A raw, unvalidated authority -> ASCII (canonical hosts pass through unchanged)."""
    return _elide(urllib.parse.quote(host, safe="-._~:"), 253)


def sanitize(obj: Any) -> Any:
    if isinstance(obj, str):
        return clean(obj)
    if isinstance(obj, dict):
        return {k: sanitize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [sanitize(v) for v in obj]
    return obj


def untrusted_paths(event: dict) -> list[str]:
    paths = [k for k in UNTRUSTED_AUDIT_KEYS if k in event]
    risk = event.get("risk")
    if isinstance(risk, dict) and isinstance(risk.get("origin"), dict) and risk["origin"].get("label"):
        paths.append("risk.origin.label")
    source = event.get("source")
    if isinstance(source, dict):
        # Import provenance (workspace file names, askpass prompt labels) may be the tab's
        # choice; tag it whatever the kind.
        paths += [f"source.{k}" for k in ("path", "label", "rule") if k in source]
    return paths
