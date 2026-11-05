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
# Audit-event keys whose values the tab (or an upstream it chose) controls.
UNTRUSTED_AUDIT_KEYS = ("host", "path", "method", "location", "header", "server", "origin")


def clean(text: str, cap: int = MAX_TEXT) -> str:
    out = "".join(ch for ch in text if unicodedata.category(ch) not in _DROP)
    if len(out) > cap:
        out = out[:cap] + f"…[+{len(out) - cap}]"
    return out


def display_path(path: str, cap: int = 512) -> str:
    """Decoded canonical path -> ASCII for display: non-ASCII, spaces and anything that is
    not a plain URL path character is percent-encoded, so nothing can hide or reorder."""
    return clean(urllib.parse.quote(path, safe="/!$&'()*+,;=:@-._~"), cap)


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
