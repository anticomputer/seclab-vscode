"""Surface (c): IPC channels and callbacks the *client* exposes to the server.

This surface exists because the REH server process runs inside the tab and is
therefore hostile under our threat model. It is reached over the remote
management / extension-host connection and never passes through
``RPCProtocol``, so a filter limited to ``MainThread*`` does not see it at all.

Two directions are extracted:

``client_served_channels``
    Channels the workbench registers on the remote connection
    (``connection.registerChannel(...)``). The server calls these directly and
    picks every argument.

``server_initiated_callbacks``
    Places where the client subscribes to a server-sent event or request and
    then *acts* on it: running a command, opening a window, launching a URI.

Both are located by scanning, not by a hand-written list, so an upstream bump
that adds a channel shows up as drift.
"""

from __future__ import annotations

import re

from .sources import SourceTree, strip_block_comments

SCAN_DIRS = ("src/vs/workbench", "src/vs/platform")

# connection.registerChannel('name', new SomeChannel(...)) on a *remote* connection.
_REGISTER = re.compile(
    r"(?P<recv>\w+(?:\.getConnection\(\)\??)?)\.registerChannel\(\s*"
    r"(?P<name>'[^']+'|[A-Za-z_$][\w.]*)\s*,\s*new\s+(?P<cls>\w+)"
)
# The receiver must be a remote-agent connection, not the shared process or the
# Electron main process: those are trusted-side-only and out of scope here.
_REMOTE_RECEIVERS = ("connection", "remoteAgentService.getConnection()",
                     "remoteAgentConnection", "_connection")
_EXCLUDE_RECEIVERS = ("sharedProcessService", "mainProcessService", "server",
                      "sharedProcessConnection")

# `case 'method':` inside an IServerChannel call()/listen() switch.
_CASE = re.compile(r"case\s+'(?P<name>[^']+)'\s*:")

# Server-initiated work the client performs.
_CALLBACK_HINTS = (
    ("executes a command chosen by the server", re.compile(r"onExecuteCommand")),
    ("opens a window or folder for the server", re.compile(r"_remoteCLI\.windowOpen|onDidRequestWindowOpen")),
    ("opens an external URI for the server", re.compile(r"_remoteCLI\.openExternal|onDidRequestOpenExternal")),
    ("installs or manages extensions for the server", re.compile(r"_remoteCLI\.manageExtensions")),
    ("reports host status to the server", re.compile(r"_remoteCLI\.getSystemStatus")),
)


def _channel_methods(tree: SourceTree, cls: str) -> dict:
    """Find the class implementing ``cls`` and list its call()/listen() cases."""
    for subdir in SCAN_DIRS:
        for rel in tree.walk(subdir):
            raw = tree.text(rel)
            if ("class %s" % cls) not in raw:
                continue
            text = strip_block_comments(raw)
            m = re.search(r"class %s\b" % re.escape(cls), text)
            if not m:
                continue
            line = 1 + text[: m.start()].count("\n")
            cases = sorted({c.group("name") for c in _CASE.finditer(text)})
            proxied = "ProxyChannel.fromService" in text
            # A channel built from URI.revive(args[...]) lets the server choose
            # the URI, which is the download-channel pattern.
            revives_uri = bool(re.search(r"URI\.revive\(\s*(?:arg|args\[)", text))
            return {
                "file": rel,
                "line": line,
                "permalink": tree.permalink(rel, line),
                "methods": cases,
                "proxy_channel": proxied,
                "revives_caller_supplied_uri": revives_uri,
            }
    return {"file": None, "line": 0, "permalink": None, "methods": [],
            "proxy_channel": False, "revives_caller_supplied_uri": False}


def _served_channels(tree: SourceTree) -> list:
    out = []
    for subdir in SCAN_DIRS:
        for rel in tree.walk(subdir):
            raw = tree.text(rel)
            if ".registerChannel(" not in raw:
                continue
            text = strip_block_comments(raw)
            for m in _REGISTER.finditer(text):
                recv = m.group("recv")
                if any(x in recv for x in _EXCLUDE_RECEIVERS):
                    continue
                if not any(x in recv for x in _REMOTE_RECEIVERS):
                    continue
                line = 1 + text[: m.start()].count("\n")
                name = m.group("name").strip("'")
                impl = _channel_methods(tree, m.group("cls"))
                out.append({
                    "channel": name,
                    "channel_name_is_constant": not m.group("name").startswith("'"),
                    "implementation": m.group("cls"),
                    "registered_in": rel,
                    "registered_line": line,
                    "registration_permalink": tree.permalink(rel, line),
                    "implementation_permalink": impl["permalink"],
                    "methods": impl["methods"],
                    "proxy_channel": impl["proxy_channel"],
                    "revives_caller_supplied_uri": impl["revives_caller_supplied_uri"],
                })
    return sorted(out, key=lambda c: c["channel"])


def _callbacks(tree: SourceTree) -> list:
    out = []
    for subdir in SCAN_DIRS:
        for rel in tree.walk(subdir):
            raw = tree.text(rel)
            text = None
            for description, pattern in _CALLBACK_HINTS:
                if pattern.pattern.split("|")[0].strip("\\") not in raw and \
                        not pattern.search(raw):
                    continue
                if text is None:
                    text = strip_block_comments(raw)
                for m in pattern.finditer(text):
                    line = 1 + text[: m.start()].count("\n")
                    out.append({
                        "effect": description,
                        "symbol": m.group(0),
                        "file": rel,
                        "line": line,
                        "permalink": tree.permalink(rel, line),
                    })
    # De-duplicate on (file, symbol); the same hint can match repeatedly.
    seen = set()
    unique = []
    for c in out:
        key = (c["file"], c["symbol"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(c)
    return sorted(unique, key=lambda c: (c["file"], c["line"]))


def build(tree: SourceTree) -> dict:
    served = _served_channels(tree)
    callbacks = _callbacks(tree)
    return {
        "client_served_channels": served,
        "client_served_channel_count": len(served),
        "server_initiated_callbacks": callbacks,
        "server_initiated_callback_count": len(callbacks),
    }
