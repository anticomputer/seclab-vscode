"""Surface (c2): server-initiated pushes the workbench subscribes to.

A ``MainThread*`` filter sees calls the extension host *makes*. It does not see
the other direction: events the REH server pushes to the trusted workbench,
which the workbench then acts on. ``remoteTerminal``'s ``onExecuteCommand`` is
the proof that this direction matters -- the server names a command and the
workbench runs it, crossing none of ``RPCProtocol``, ``ChannelServer`` or the
command taint.

This module replaces a hand-written list of five regexes that named
``onExecuteCommand``, ``_remoteCLI.windowOpen`` and friends directly. That list
could only ever rediscover what someone had already found: it would have been
just as green on a tree where upstream added a sixth push. The sweep below is
structural instead, and rests on one property of the IPC layer:

    **Every server-to-client push bottoms out in ``IChannel.listen``.**

``ChannelClient.listen`` is the only way a server-side ``IServerChannel`` can
deliver an event to the client (see ``base/parts/ipc/common/ipc.ts``). So the
complete set of server-initiated events on a connection is the set of
``listen`` calls reachable from a channel obtained from that connection, plus
the ``onXxx`` members of any interface handed to ``ProxyChannel.toService``,
which generates a ``listen`` per member.

The walk is therefore:

1. find every channel acquired from a *remote agent* connection
   (``getChannel`` / ``withChannel``), excluding the shared-process and
   Electron main-process connections, which are trusted-side only;
2. resolve each to its sink -- a channel-client class, a ``ProxyChannel``
   service interface, or direct use of the channel variable;
3. enumerate the ``listen`` calls (or ``onXxx`` members) of that sink;
4. find where the workbench subscribes to the resulting event and record what
   the handler does.

Anything that cannot be resolved at steps 2-3 is reported in ``unresolved``
and fails ``check.sh``. That direction is deliberate. The failure this project
keeps hitting is a gate that passes because it never asked the question, and a
sweep that silently drops a channel it could not follow is exactly that: it
would report fewer pushes and look like progress. An unresolved channel is
visible work; a quietly skipped one is a hole with a green check over it.
"""

from __future__ import annotations

import re

from .commands import _constant_index, _resolve_expr
from .sources import SourceTree, strip_block_comments

SCAN_DIRS = ("src/vs/workbench", "src/vs/platform")

# Receivers that are *not* the REH: these connections terminate in trusted
# local processes, so pushes over them are not attacker-controlled.
# Files whose `connection` variable is a trusted local process, not the REH.
_TRUSTED_FILES = (
    "/sharedProcess/", "/electron-main/", "/node/sharedProcess",
)

_TRUSTED_RECEIVERS = (
    "sharedProcessService", "mainProcessService", "sharedProcessConnection",
    "mainProcessConnection", "workerServer", "utilityProcess",
    "_managementConnection", "outputService", "registry",
)

# A channel taken off a connection. The receiver is captured so trusted-side
# connections can be excluded by name.
# A channel taken off a connection. The receiver is captured so trusted-side
# connections can be excluded by name.
#
# The receiver must not be able to swallow an opening bracket. An earlier
# character class included `(` and `)` so that `getConnection()` would match,
# but that let the receiver start *before* an enclosing call: in
# `super(connection.getChannel(NAME))` it matched `super(connection`, which
# moved the match start past the `super(` the sink detection needed to see.
# Optional call brackets are spelled out instead of being folded into the class.
_ACQUIRE = re.compile(
    r"(?P<recv>[\w.$]+(?:\(\))?(?:\??\.[\w$]+(?:\(\))?)*)"
    r"\.(?P<how>getChannel|withChannel)"
    r"(?:<[^>()]*>)?\(\s*(?P<name>'[^']*'|[A-Za-z_$][\w.$]*)")

# The sinks a channel can flow into.
_NEW_CLIENT = re.compile(r"new\s+(?P<cls>\w+)\s*\(")
_CREATE_INSTANCE = re.compile(r"createInstance\(\s*(?P<cls>\w+)")
_TO_SERVICE = re.compile(r"ProxyChannel\.toService<\s*(?P<iface>[\w.]+)")

# A server-sent event subscription inside a channel client.
_LISTEN = re.compile(
    r"\.listen\s*(?:<(?:[^<>]|<[^<>]*>)*>)?\s*\(\s*"
    r"(?P<name>'[^']*'|[A-Za-z_$][\w.$]*)")

# `readonly onFoo: Event<T>` / `get onFoo(): Event<T>` in a ProxyChannel
# interface. ProxyChannel.toService turns each of these into a listen.
_EVENT_MEMBER = re.compile(
    r"(?m)^[ \t]*(?:readonly\s+|get\s+)?(?P<name>on[A-Z][\w$]*)\s*"
    r"(?:\(\s*\)\s*)?:\s*Event<")


def _body_after(text: str, start: int, span: int = 400) -> str:
    """The source immediately following a match, for sink detection."""
    return text[start:start + span]


def _find_block(text: str, keyword: str, name: str):
    """Locate ``class X``/``interface X`` and return (start, end, line)."""
    m = re.search(r"\b%s\s+%s\b" % (keyword, re.escape(name)), text)
    if not m:
        return None
    brace = text.find("{", m.end())
    if brace < 0:
        return None
    depth, i = 0, brace
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    return brace, i, 1 + text[: m.start()].count("\n")


def _locate(tree: SourceTree, name: str) -> list:
    """Every (rel, kind, start, end, line) defining ``name`` as class/interface."""
    found = []
    for subdir in SCAN_DIRS:
        for rel in tree.walk(subdir):
            raw = tree.text(rel)
            if name not in raw:
                continue
            text = strip_block_comments(raw)
            for kind in ("class", "interface"):
                blk = _find_block(text, kind, name)
                if blk:
                    found.append((rel, kind, blk[0], blk[1], blk[2], text))
    return found


# Anchored to the start of a line. The member's *type* routinely contains
# braces -- `Event<{ reqId: number; commandId: string }>` -- so a pattern that
# tried to bound the match with `[^{}]*$` never reached the declaration and
# returned nothing for every getter-style event.
_MEMBER_BEFORE = re.compile(
    r"(?m)^[ \t]*(?:export\s+|public\s+|private\s+|protected\s+|static\s+"
    r"|readonly\s+|abstract\s+|override\s+)*(?:get\s+)?"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*(?:\(\s*\))?\s*[:(=]")


def _accessor_before(body: str, upto: int):
    """The member whose body contains this ``listen``, e.g. ``onExecuteCommand``.

    The name on the wire and the name the workbench subscribes to are not the
    same. ``remoteTerminalChannel.ts`` sends ``$onExecuteCommand`` but exposes
    ``get onExecuteCommand()``, and subscribers write the latter. Keying the
    subscription search on the wire name found nothing, so the one push already
    known to execute host code was reported as acting on nothing.
    """
    head = body[max(0, upto - 600):upto]
    hits = list(_MEMBER_BEFORE.finditer(head))
    return hits[-1].group("name") if hits else None


def _base_classes(text: str, name: str) -> list:
    m = re.search(r"\bclass\s+%s\b[^{]*?\bextends\s+(?P<base>[\w.]+)"
                  % re.escape(name), text)
    if m:
        return [m.group("base").split(".")[-1]]
    m = re.search(r"\binterface\s+%s\b[^{]*?\bextends\s+(?P<bases>[^{]+)"
                  % re.escape(name), text)
    if m:
        return [b.strip().split("<")[0].split(".")[-1]
                for b in m.group("bases").split(",") if b.strip()]
    return []


def _events_of_sink(tree: SourceTree, consts: dict, sink: str, _seen=None) -> tuple:
    """Server-sent events a sink exposes, and any reason it could not be read.

    Returns ``(events, problem)``. ``problem`` is non-empty when the sink could
    not be located or yielded nothing, which is reported rather than skipped.
    """
    blocks = _locate(tree, sink)
    if not blocks:
        return [], "sink %s not found in scanned source" % sink

    events = []
    for rel, kind, start, end, line, text in blocks:
        body = text[start:end]
        for m in _LISTEN.finditer(body):
            token = m.group("name")
            if token.startswith("'"):
                value, reason = token.strip("'"), None
            else:
                value, reason = _resolve_expr(tree, consts, token, rel)
            ln = line + body[: m.start()].count("\n")
            events.append({
                "event": value,
                "accessor": _accessor_before(body, m.start()),
                "token": token,
                "unresolved_reason": reason,
                "via": "listen",
                "file": rel,
                "line": ln,
                "permalink": tree.permalink(rel, ln),
            })
        if kind == "interface":
            # ProxyChannel generates one listen per Event<T> member.
            for m in _EVENT_MEMBER.finditer(body):
                ln = line + body[: m.start()].count("\n")
                events.append({
                    "event": m.group("name"),
                    "accessor": m.group("name"),
                    "token": m.group("name"),
                    "unresolved_reason": None,
                    "via": "proxy_channel_member",
                    "file": rel,
                    "line": ln,
                    "permalink": tree.permalink(rel, ln),
                })
    if not events:
        # The channel client may inherit its events. Follow `extends` once per
        # name, so a wrapper subclass does not hide its base's pushes.
        seen = _seen or {sink}
        for rel, kind, start, end, line, text in blocks:
            for base in _base_classes(text, sink):
                if base in seen:
                    continue
                seen.add(base)
                inherited, problem = _events_of_sink(tree, consts, base, seen)
                if inherited:
                    return inherited, None
        # Located, and genuinely silent. That is an answer, not a failure:
        # the channel carries calls but pushes nothing, so there is no event to
        # give a verdict to. Only a sink that cannot be *found* is unresolved,
        # because that is the case where the sweep does not know what it missed.
        return [], "SILENT"
    return events, None


def _enclosing_calls(text: str, pos: int, limit: int = 6) -> list:
    """Callee names whose argument list still encloses ``pos``, innermost first.

    The sink almost always *wraps* the acquisition rather than following it::

        instantiationService.createInstance(RemoteTerminalChannelClient,
            connection.remoteAuthority, connection.getChannel(NAME))

        super(connection.getChannel(REMOTE_FILE_SYSTEM_CHANNEL_NAME), ...)

    An earlier version searched forward from the match instead, which found
    whatever call happened to come next in the file. That is how the terminal
    channel -- the one surface already known to carry host code execution --
    resolved to ``RemoteTerminalBackend`` and reported no pushes at all. A
    sweep that misses its own worked example is not measuring anything, so the
    direction is now derived from the brackets rather than from proximity.
    """
    out, depth, i = [], 0, pos - 1
    while i >= 0 and len(out) < limit:
        ch = text[i]
        if ch in ")]}":
            depth += 1
        elif ch in "]}":
            depth += 1
        elif ch == "(":
            if depth == 0:
                j = i - 1
                while j >= 0 and text[j] in " \t\n":
                    j -= 1
                k = j
                while k >= 0 and (text[k].isalnum() or text[k] in "_$."):
                    k -= 1
                name = text[k + 1:j + 1]
                if name:
                    out.append(name)
            else:
                depth -= 1
        i -= 1
    return out


def _enclosing_class(text: str, pos: int):
    """The class whose body contains ``pos``, for a ``super(channel)`` sink."""
    best = None
    for m in re.finditer(r"\bclass\s+(?P<name>\w+)\b", text):
        if m.start() < pos:
            best = m.group("name")
        else:
            break
    return best


def _sink_of(text: str, pos: int, end: int) -> tuple:
    """What the channel acquired here flows into: (kind, name) or (None, None)."""
    # 1. An enclosing call: `new X(... channel ...)`, `createInstance(X, ...)`,
    #    `ProxyChannel.toService<I>(channel)`, `super(channel)`.
    for callee in _enclosing_calls(text, pos):
        if callee.endswith("createInstance"):
            m = re.match(r"\s*(?P<cls>\w+)", text[text.index("(", pos - 400) + 1:]) \
                if False else None
            # The class is the first argument of createInstance.
            idx = text.rfind("createInstance", 0, pos)
            if idx >= 0:
                m = re.search(r"createInstance\(\s*(?P<cls>\w+)", text[idx:pos + 1])
                if m:
                    return "channel_client", m.group("cls")
        if callee.startswith("ProxyChannel.toService") or callee == "ProxyChannel.toService":
            idx = text.rfind("ProxyChannel.toService", 0, pos)
            m = re.search(r"ProxyChannel\.toService<\s*(?P<iface>[\w.]+)", text[idx:pos + 1])
            if m:
                return "proxy_channel", m.group("iface")
        if callee == "super":
            cls = _enclosing_class(text, pos)
            if cls:
                return "channel_client", cls
        if callee.startswith("new "):
            return "channel_client", callee[4:]
        bare = callee.split(".")[-1]
        if bare and bare[0].isupper():
            return "channel_client", bare

    # `new X(` immediately before the acquisition, on the same statement.
    head = text[max(0, pos - 300):pos]
    news = list(_NEW_CLIENT.finditer(head))
    if news:
        return "channel_client", news[-1].group("cls")

    # 2. The channel is handed to a callback: `withChannel(name, channel => ...)`
    #    or assigned to a variable used later in the file.
    window = _body_after(text, end, 1200)
    m = _TO_SERVICE.search(window)
    if m:
        return "proxy_channel", m.group("iface")
    m = _CREATE_INSTANCE.search(window)
    if m:
        return "channel_client", m.group("cls")
    m = _NEW_CLIENT.search(window)
    if m:
        return "channel_client", m.group("cls")
    # Chained directly onto the acquisition: `getChannel(x).listen(...)`.
    # Checked against the text immediately after the call, not "somewhere in
    # the next 600 characters" -- a loose scan treated an *unrelated* listen
    # further down the file as if it were on this channel, which turned an
    # unfollowable channel into a confident wrong answer.
    if re.match(r"\s*\)?\s*\.listen\b", window):
        return "inline", None

    # 2b. `withChannel(NAME, channel => { ... channel.listen(...) ... })`:
    #     the channel is bound as the callback's parameter. Bind that name and
    #     look for uses of it, rather than treating the callback as opaque.
    cb = re.match(r"\s*,\s*(?:async\s*)?\(?\s*(?P<p>[A-Za-z_$][\w$]*)\s*\)?"
                  r"(?::[^=]*)?\s*=>", window)
    if cb:
        param = cb.group("p")
        body = window[cb.end():]
        tm = _TO_SERVICE.search(body)
        if tm and re.search(r"\b%s\b" % re.escape(param),
                            body[tm.end():tm.end() + 120]):
            return "proxy_channel", tm.group("iface")
        if re.search(r"\b%s\s*\.listen\b" % re.escape(param), body):
            return "callback", param
        for pat, kind in ((_CREATE_INSTANCE, "channel_client"),
                          (_NEW_CLIENT, "channel_client")):
            nm = pat.search(body)
            if nm and re.search(r"\b%s\b" % re.escape(param),
                                body[nm.end():nm.end() + 200]):
                return kind, nm.groupdict().get("cls")

    # 3. The channel is bound to a name and used further down the file:
    #    `const channel = connection.getChannel(X); ... new Client(channel)`.
    head = text[max(0, pos - 200):pos]
    m = re.search(r"(?:const|let|var)?\s*(?P<var>[\w.$]+)\s*=\s*$", head)
    if m:
        var = m.group("var").split(".")[-1]
        rest = text[end:]
        for pat, kind in ((_TO_SERVICE, "proxy_channel"),
                          (_CREATE_INSTANCE, "channel_client"),
                          (_NEW_CLIENT, "channel_client")):
            for um in pat.finditer(rest):
                # Only if the bound name is actually an argument of that call.
                tail = rest[um.end():um.end() + 300]
                arg = tail.split(")")[0]
                if re.search(r"\b%s\b" % re.escape(var), arg):
                    g = um.groupdict()
                    return kind, g.get("iface") or g.get("cls")
        sm = re.search(r"\bsuper\s*\(\s*%s\b" % re.escape(var), rest)
        if sm:
            cls = _enclosing_class(text, pos)
            if cls:
                return "channel_client", cls
        if re.search(r"\b%s\s*\.listen\b" % re.escape(var), rest):
            return "inline", None

    # 4. Call-only. The channel is handed to an opaque callback, or bound to a
    #    name, but nothing in this module ever listens on a channel or builds a
    #    ProxyChannel service. A channel the client only *calls* carries no
    #    server-initiated push, so there is no event to give a verdict to.
    #
    #    Deliberately file-scoped and conservative: it reports call-only when
    #    the whole module is free of `.listen` and `ProxyChannel.toService`,
    #    and otherwise leaves the channel unresolved. Guessing in the other
    #    direction would hide a push behind a green check.
    if ".listen" not in text and "ProxyChannel.toService" not in text:
        return "call_only", None
    return None, None


def _acquisitions(tree: SourceTree, consts: dict) -> list:
    """Every channel taken off a remote-agent connection."""
    out = []
    for subdir in SCAN_DIRS:
        for rel in tree.walk(subdir):
            raw = tree.text(rel)
            if "getChannel" not in raw and "withChannel" not in raw:
                continue
            if any(t in rel for t in _TRUSTED_FILES):
                continue
            text = strip_block_comments(raw)
            for m in _ACQUIRE.finditer(text):
                recv = m.group("recv")
                if any(t in recv for t in _TRUSTED_RECEIVERS):
                    continue
                # Must name a remote connection. `connection`, `_connection`,
                # `remoteAgentConnection`, `remoteConnection`, `c`, or a
                # `getConnection()` call.
                low = recv.lower()
                if not ("connection" in low or "remoteagent" in low):
                    continue
                token = m.group("name")
                if token.startswith("'"):
                    name, reason = token.strip("'"), None
                else:
                    name, reason = _resolve_expr(tree, consts, token, rel)
                kind, sink = _sink_of(text, m.start(), m.end())
                line = 1 + text[: m.start()].count("\n")
                out.append({
                    "channel": name,
                    "channel_token": token,
                    "channel_unresolved_reason": reason,
                    "receiver": recv,
                    "how": m.group("how"),
                    "sink_kind": kind,
                    "sink": sink,
                    "file": rel,
                    "line": line,
                    "permalink": tree.permalink(rel, line),
                })
    return out


def _subscriptions(tree: SourceTree, accessors: set) -> dict:
    """Where the workbench subscribes to a server-sent event, and what it does.

    The effect tags are a reading aid for the person writing the verdict, not
    the control. Completeness comes from the sweep above and safety from
    default-deny: an event nobody classified is denied, so a missing tag costs
    compatibility, never containment.
    """
    effects = (
        ("executes a command", re.compile(r"executeCommand|_commandService")),
        ("opens a window or folder", re.compile(r"windowOpen|openWindow")),
        ("opens an external URI", re.compile(r"openExternal|openerService")),
        ("manages extensions", re.compile(r"manageExtensions|install|uninstall")),
        ("writes to the file system", re.compile(r"writeFile|createFile|mkdir")),
        ("reports host state back", re.compile(r"getSystemStatus|getEnvironment")),
        ("forwards or opens a tunnel", re.compile(r"Tunnel|forwardPort")),
        ("shows UI to the user", re.compile(r"notificationService|dialogService|showMessage")),
    )
    hits = {}
    for subdir in SCAN_DIRS:
        for rel in tree.walk(subdir):
            raw = tree.text(rel)
            if not any(a in raw for a in accessors):
                continue
            text = strip_block_comments(raw)
            for acc in accessors:
                if acc not in text:
                    continue
                for m in re.finditer(r"\.%s\s*\(" % re.escape(acc), text):
                    line = 1 + text[: m.start()].count("\n")
                    handler = _body_after(text, m.end(), 600)
                    tags = sorted({d for d, p in effects if p.search(handler)})
                    hits.setdefault(acc, []).append({
                        "file": rel,
                        "line": line,
                        "permalink": tree.permalink(rel, line),
                        "effects": tags,
                    })
    return hits


def build(tree: SourceTree) -> dict:
    consts = _constant_index(tree)
    acquisitions = _acquisitions(tree, consts)

    pushes, unresolved, silent = [], [], []
    for acq in acquisitions:
        if acq["channel"] is None:
            unresolved.append({**acq, "problem": "channel name unresolved: %s"
                               % acq["channel_unresolved_reason"]})
            continue
        if acq["sink_kind"] is None:
            unresolved.append({**acq, "problem": "channel flows into no "
                               "recognised sink; cannot enumerate its pushes"})
            continue
        if acq["sink_kind"] == "call_only":
            silent.append({**acq, "reason": "channel is call-only: this module "
                           "never listens on a channel"})
            continue
        if acq["sink_kind"] == "callback":
            # Events listened on the callback's channel parameter.
            raw = strip_block_comments(tree.text(acq["file"]))
            start = raw.find("withChannel", 0)
            sink_events, problem = [], None
            for m in re.finditer(
                    r"\b%s\s*\.listen\s*(?:<(?:[^<>]|<[^<>]*>)*>)?\s*\(\s*"
                    r"(?P<name>'[^']*'|[A-Za-z_$][\w.$]*)" % re.escape(acq["sink"] or ""),
                    raw):
                token = m.group("name")
                value = token.strip("'") if token.startswith("'") else \
                    _resolve_expr(tree, consts, token, acq["file"])[0]
                ln = 1 + raw[: m.start()].count("\n")
                sink_events.append({
                    "event": value, "accessor": _accessor_before(raw, m.start()),
                    "token": token, "unresolved_reason": None,
                    "via": "callback_listen", "file": acq["file"], "line": ln,
                    "permalink": tree.permalink(acq["file"], ln),
                })
            if not sink_events:
                unresolved.append({**acq, "problem":
                                   "callback parameter never listened on"})
                continue
        elif acq["sink_kind"] == "inline":
            sink_events, problem = [], None
            # Direct `.listen` on the acquired variable, in this file only.
            raw = strip_block_comments(tree.text(acq["file"]))
            for m in _LISTEN.finditer(_body_after(raw, acq["line"], 0) or raw):
                token = m.group("name")
                value = token.strip("'") if token.startswith("'") else \
                    _resolve_expr(tree, consts, token, acq["file"])[0]
                ln = 1 + raw[: m.start()].count("\n")
                sink_events.append({
                    "event": value, "token": token, "unresolved_reason": None,
                    "via": "inline_listen", "file": acq["file"], "line": ln,
                    "permalink": tree.permalink(acq["file"], ln),
                })
        else:
            sink_events, problem = _events_of_sink(tree, consts, acq["sink"])
        if problem == "SILENT":
            silent.append({**acq, "reason": "sink exposes no server-sent event"})
            continue
        if problem:
            unresolved.append({**acq, "problem": problem})
            continue
        for ev in sink_events:
            if ev["event"] is None:
                unresolved.append({**acq, "problem": "event name unresolved: %s (%s)"
                                   % (ev["token"], ev["unresolved_reason"])})
                continue
            pushes.append({
                "key": "push:%s:%s" % (acq["channel"], ev["event"]),
                "channel": acq["channel"],
                "event": ev["event"],
                "via": ev["via"],
                "sink": acq["sink"],
                "sink_kind": acq["sink_kind"],
                "acquired_in": acq["file"],
                "acquisition_permalink": acq["permalink"],
                "declared_in": ev["file"],
                "declaration_permalink": ev["permalink"],
                "accessor": ev.get("accessor"),
            })

    # Deduplicate: a channel can be acquired in more than one file.
    seen, unique = set(), []
    for p in sorted(pushes, key=lambda p: p["key"]):
        if p["key"] in seen:
            continue
        seen.add(p["key"])
        unique.append(p)

    accessors = {p["accessor"] for p in unique
                 if p.get("accessor") and p["accessor"].startswith("on")}
    subs = _subscriptions(tree, accessors)
    for p in unique:
        p["subscriptions"] = subs.get(p.get("accessor"), [])
        p["acts_on_push"] = bool(
            any(s["effects"] for s in p["subscriptions"]))

    return {
        "server_initiated_pushes": unique,
        "server_initiated_push_count": len(unique),
        "acting_push_count": sum(1 for p in unique if p["acts_on_push"]),
        "channels_without_pushes": sorted(
            silent, key=lambda u: (u["file"], u["line"])),
        "channels_without_pushes_count": len(silent),
        "unresolved_channels": sorted(
            unresolved, key=lambda u: (u["file"], u["line"])),
        "unresolved_channel_count": len(unresolved),
    }
