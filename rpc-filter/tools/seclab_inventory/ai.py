"""Surface (e): trusted-side AI surfaces.

A tab controls content -- workspace files, terminal output, tool results --
that a trusted-side LLM agent reads. That agent acts with host privileges, so
the tab can drive a confused deputy by writing text rather than by making a
call. Nothing in surfaces (a)-(d) sees this: the chat agent runs *in the
trusted workbench*, so when it reads a tab's files and invokes a trusted-side
tool, no RPC crosses the sandbox boundary and the RPC filter has nothing to
inspect.

Two things are enumerated, because together they decide whether a tab's text
can reach a host effect:

* **Tools**, with the layer they execute in. The layer is decided by the
  directory: ``electron-browser`` and ``node`` code has no remote-extension-host
  copy, so in a remote window such a tool runs *on the host* while the
  workspace is remote. ``IToolData.runsInWorkspace`` is upstream's own name for
  this distinction, and most workbench tools leave it undeclared.

* **Agent settings**, with their ``ConfigurationScope``. A setting that a
  workspace can write is a setting the tab can write. Upstream is careful with
  the ones that matter -- ``chat.tools.global.autoApprove`` is
  ``APPLICATION_MACHINE`` -- but that is a property to re-check on every bump,
  not to assume.

Both are extracted rather than listed, so the drift gate covers them like
every other surface.
"""

from __future__ import annotations

import os
import re

from .sources import SourceTree, strip_block_comments

SCAN_DIRS = ("src/vs",)

# Where a file executes, from its path. Ordered: the first match wins.
_LAYERS = (
    ("/electron-browser/", "electron-browser"),
    ("/electron-main/", "electron-main"),
    ("/node/", "node"),
    ("/browser/", "browser"),
    ("/worker/", "worker"),
    ("/common/", "common"),
)

# Layers with no remote-extension-host copy: code here runs on the host even
# when the window's workspace is remote.
HOST_LAYERS = ("electron-browser", "electron-main", "node", "browser", "worker")

_TOOL_LITERAL = re.compile(
    r"(?:const|let|var)\s+(?P<var>\w+)\s*:\s*IToolData\s*=\s*\{", re.M)
_GET_TOOL_DATA = re.compile(r"getToolData\(\)\s*:\s*IToolData\s*\{\s*return\s*\{", re.M)

_CONFIG_SCOPE = re.compile(r"scope:\s*ConfigurationScope\.(\w+)")
_ENUM_MEMBER = re.compile(r"^\s*(?P<name>\w+)\s*=\s*'(?P<val>[^'\n]*)'\s*,?\s*$", re.M)


def _layer_of(rel: str) -> str:
    for marker, name in _LAYERS:
        if marker in rel:
            return name
    return "unknown"


def _balanced(text: str, start: int) -> str:
    """Body of the object literal whose opening brace is at or before ``start``."""
    depth = 0
    for j in range(start, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[start + 1:j]
    return ""


def _field(body: str, name: str) -> str | None:
    m = re.search(r"\b%s\s*:\s*([^,\n]+)" % re.escape(name), body)
    return m.group(1).strip() if m else None


def _tool_entries(tree: SourceTree, rel: str, text: str) -> list:
    out = []
    starts = [m.end() - 1 for m in _TOOL_LITERAL.finditer(text)]
    starts += [m.end() - 1 for m in _GET_TOOL_DATA.finditer(text)]
    for start in sorted(set(starts)):
        body = _balanced(text, start)
        if not body:
            continue
        raw_id = _field(body, "id")
        if raw_id is None:
            continue
        literal = re.match(r"^'([^']*)'$", raw_id)
        runs = _field(body, "runsInWorkspace")
        declared = None if runs is None else runs.lower().startswith("true")
        layer = _layer_of(rel)
        out.append({
            "id": literal.group(1) if literal else None,
            "id_expression": None if literal else raw_id,
            "file": rel,
            # Where the IToolData literal is declared. Supporting evidence
            # only: a tool declared in `common` is registered by a contribution
            # in some other layer, and that is where it executes.
            "declared_in_layer": layer,
            # The question that matters, answered conservatively. Only an
            # explicit `runsInWorkspace: true` is evidence that a tool executes
            # in the (possibly remote) workspace; upstream says so itself. An
            # undeclared tool is assumed to reach the host, because assuming
            # otherwise is the direction that loses containment, and 25 of the
            # host-reaching tools leave it undeclared.
            "runs_in_workspace_declared": declared,
            "may_reach_host_in_remote_window": declared is not True,
            "permalink": tree.permalink(rel, _line_at(text, start)),
        })
    return out


def _line_at(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _enum_values(tree: SourceTree, rel: str, enum: str) -> dict:
    """`Member -> 'setting.id'` for a string enum of setting ids."""
    text = strip_block_comments(tree.text(rel))
    m = re.search(r"enum\s+%s\b[^{]*\{" % re.escape(enum), text)
    if not m:
        return {}
    body = _balanced(text, m.end() - 1)
    return {mm.group("name"): mm.group("val") for mm in _ENUM_MEMBER.finditer(body)}


def _settings(tree: SourceTree) -> list:
    """Registered configuration properties for chat/agent/MCP, with their scope.

    Both key forms are handled. A literal ``'chat.x': { ... }`` and a computed
    ``[ChatConfiguration.X]: { ... }``; the latter is most of them, and a scan
    that only reads literals sees about a third of the surface.

    **Tab-writability is not workspace-writability.** In a remote window the
    client reads *remote user settings* from ``environment.settingsPath`` -- a
    path the REH supplies, so a file inside the tab -- and it reads them with
    ``REMOTE_MACHINE_SCOPES``
    (``src/vs/workbench/services/configuration/common/configuration.ts:32``),
    which includes ``MACHINE`` **and** ``APPLICATION_MACHINE``. So in a
    ``seclab+`` window a tab can set any scope except ``APPLICATION``.

    An earlier version of this scan treated ``APPLICATION_MACHINE`` as out of
    reach, on the reasoning that a *workspace* file cannot set it. That is true
    and irrelevant: the tab does not need the workspace file, it supplies the
    remote user settings. The mistake mattered -- it is why
    ``chat.tools.global.autoApprove`` was reported as unreachable when a tab
    can in fact set it.
    """
    enums = {}
    for rel, name in (
        ("src/vs/workbench/contrib/chat/common/constants.ts", "ChatConfiguration"),
    ):
        enums.update(_enum_values(tree, rel, name))

    want = re.compile(r"^(chat|mcp|inlineChat|github\.copilot)\b")
    key_re = re.compile(
        r"(?:\[\s*(?:ChatConfiguration|McpConfiguration)\.(?P<member>\w+)\s*\]"
        r"|'(?P<literal>[\w.]+)'"
        r"|\"(?P<literal2>[\w.]+)\")\s*:\s*\{")
    seen = {}
    for subdir in SCAN_DIRS:
        for rel in tree.walk(subdir):
            raw = tree.text(rel)
            if "ConfigurationScope" not in raw:
                continue
            text = strip_block_comments(raw)
            for m in key_re.finditer(text):
                key = (enums.get(m.group("member")) if m.group("member")
                       else (m.group("literal") or m.group("literal2")))
                if not key or not want.search(key) or key in seen:
                    continue
                body = _balanced(text, m.end() - 1)
                sm = _CONFIG_SCOPE.search(body)
                scope = sm.group(1) if sm else "WINDOW"
                seen[key] = {
                    "id": key,
                    "scope": scope,
                    # Everything except APPLICATION is in REMOTE_MACHINE_SCOPES,
                    # and the tab supplies the remote settings file.
                    "tab_writable": scope != "APPLICATION",
                    "file": rel,
                    "permalink": tree.permalink(rel, _line_at(text, m.start())),
                }
    return [seen[k] for k in sorted(seen)]


def build(tree: SourceTree) -> dict:
    """Assemble surface (e)."""
    from .commands import _constant_index, _resolve_expr

    tools = []
    for subdir in SCAN_DIRS:
        for rel in tree.walk(subdir):
            raw = tree.text(rel)
            if "IToolData" not in raw:
                continue
            tools.extend(_tool_entries(tree, rel, strip_block_comments(raw)))

    # Most tool ids are constants. Resolve them the same way command ids are
    # resolved -- per use site, refusing to guess -- so a tool is named rather
    # than left as an expression nobody can match against a probe.
    constants = _constant_index(tree)
    for t in tools:
        if t["id"] is None and t["id_expression"]:
            value, reason = _resolve_expr(tree, constants, t["id_expression"], t["file"])
            t["id"] = value
            t["id_unresolved_reason"] = None if value else reason

    tools.sort(key=lambda t: (t["id"] or t["id_expression"] or "", t["file"]))
    settings = _settings(tree)
    reaching = [t for t in tools if t["may_reach_host_in_remote_window"]]
    undeclared = [t for t in reaching if t["runs_in_workspace_declared"] is None]

    by_layer = {}
    for t in tools:
        by_layer[t["declared_in_layer"]] = by_layer.get(t["declared_in_layer"], 0) + 1

    return {
        "note": (
            "Tools a trusted-side agent can invoke, and the agent settings a "
            "workspace might influence. The RPC filter does not cover this "
            "surface: the agent runs in the trusted workbench, so a tab that "
            "steers it through instruction files causes a host effect without "
            "any RPC crossing the sandbox boundary. 'may_reach_host' is "
            "conservative -- only an explicit runsInWorkspace: true clears a "
            "tool -- because assuming the other way loses containment."),
        "tools": tools,
        "tool_count": len(tools),
        "tools_by_declared_layer": dict(sorted(by_layer.items())),
        "may_reach_host_count": len(reaching),
        "may_reach_host_undeclared_count": len(undeclared),
        "settings": settings,
        "setting_count": len(settings),
        "tab_writable_setting_count": sum(
            1 for s in settings if s["tab_writable"]),
    }
