"""Response scanning for credentials newly minted by an upstream."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache

from .policy import DATA_DIR


@dataclass(frozen=True)
class TokenRule:
    id: str
    rx: re.Pattern


@lru_cache(maxsize=1)
def token_rules() -> tuple[TokenRule, ...]:
    data = json.loads((DATA_DIR / "token-rules.json").read_text())
    return tuple(TokenRule(r["id"], re.compile(r["regex"])) for r in data["rules"])


def find_minted(text: str) -> list[tuple[str, str, int, int]]:
    """(rule_id, secret, start, end) for every token-looking span, deduplicated by span."""
    hits: dict[tuple[int, int], tuple[str, str, int, int]] = {}
    for rule in token_rules():
        for m in rule.rx.finditer(text):
            try:
                s, e = m.span("secret")
            except IndexError:
                s, e = m.span()
            if s < 0:
                continue
            hits.setdefault((s, e), (rule.id, text[s:e], s, e))
    # Drop spans contained in a longer span.
    out = []
    for h in sorted(hits.values(), key=lambda h: (h[2], -(h[3] - h[2]))):
        if out and h[2] < out[-1][3]:
            continue
        out.append(h)
    return out
