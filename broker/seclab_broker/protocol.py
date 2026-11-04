"""Control-protocol definition (schema/protocol.v1.json), loaded and compiled.

The broker validates every request's params against it. Tests validate
results and live notifications against it, and docs/broker-protocol.md is
generated from it, so the code, tests and docs share one definition.
"""

from __future__ import annotations

import copy
import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable

import fastjsonschema

from .policy import DATA_DIR, _HANDLERS, _schema as policy_schema


def _path(name: str) -> Path:
    packaged = DATA_DIR / name
    if packaged.exists():
        return packaged
    return Path(__file__).resolve().parent.parent / "schema" / name


@lru_cache(maxsize=1)
def definition() -> dict:
    """protocol.v1.json with the policy schema's definitions merged in."""
    proto = json.loads(_path("protocol.v1.json").read_text())
    pol = copy.deepcopy(policy_schema())
    pol_defs = pol.pop("definitions")
    pol.pop("$schema", None)
    clash = set(pol_defs) & set(proto["definitions"])
    if clash:
        raise RuntimeError(f"protocol and policy definitions clash: {sorted(clash)}")
    proto["definitions"].update(pol_defs)
    proto["definitions"]["policy"] = pol
    return proto


def _compile(schema: dict) -> Callable[[Any], Any]:
    root = {"$schema": "http://json-schema.org/draft-07/schema#",
            "definitions": definition()["definitions"], **schema}
    return fastjsonschema.compile(root, handlers=_HANDLERS)


@lru_cache(maxsize=None)
def validator(kind: str, name: str) -> Callable[[Any], Any]:
    """kind: 'params' | 'result' | 'notification' | 'definition'."""
    d = definition()
    if kind == "params":
        return _compile(d["methods"][name]["params"])
    if kind == "result":
        return _compile(d["methods"][name]["result"])
    if kind == "notification":
        return _compile(d["notifications"][name]["params"])
    if kind == "definition":
        return _compile({"$ref": f"#/definitions/{name}"})
    raise KeyError(kind)


def check(kind: str, name: str, obj: Any) -> str | None:
    """None if valid, else a message that names the failing path, never the value."""
    try:
        validator(kind, name)(obj)
    except fastjsonschema.JsonSchemaException as e:
        return e.message
    return None


def method_names() -> set[str]:
    return set(definition()["methods"])


def notification_names() -> set[str]:
    return set(definition()["notifications"])


def audit_types() -> set[str]:
    return set(definition()["auditTypes"])


def error_codes() -> set[int]:
    return {e["code"] for e in definition()["errors"]}
