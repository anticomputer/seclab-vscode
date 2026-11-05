"""Surface (a): the MainThread* RPC surface an extension host can call.

Three things are extracted, because they are not the same set:

1. ``MainContext`` entries: the proxy identifiers the extension host can
   address. The wire key is the *string* ``sid`` passed to
   ``createProxyIdentifier``, which is NOT always the property name
   (e.g. ``MainThreadLanguageModelTools`` is registered as
   ``'MainThreadChatSkills'``). The numeric ``nid`` is assigned by module
   load order and must never be used as a policy key.
2. ``MainThread*Shape`` interface methods: the *declared* contract.
3. The methods actually present on the registered customer class.

(3) is the real attack surface, not (2). ``RPCProtocol._doInvokeHandler``
looks the method up with ``actor[methodName]`` and only checks that it is a
function, so any callable property on the instance is reachable, whether or
not it appears in the Shape interface. The generator reports the difference
as ``undeclared_methods``.
"""

from __future__ import annotations

import re

from .sources import SourceTree, strip_block_comments

PROTOCOL = "src/vs/workbench/api/common/extHost.protocol.ts"
CUSTOMER_DIRS = ("src/vs/workbench/api", "src/vs/workbench/contrib")

_PROXY_ID = re.compile(
    r"^\s*(?P<key>\w+)\s*:\s*createProxyIdentifier<\s*(?P<shape>[\w<>, ]+?)\s*>\(\s*'(?P<sid>[^']+)'\s*\)",
    re.M,
)
_NAMED_CUSTOMER = re.compile(
    r"@extHostNamedCustomer\(\s*MainContext\.(?P<key>\w+)\s*\)\s*(?:export\s+)?class\s+(?P<cls>\w+)"
)
# The decorator is not the only registration path. Several services are
# registered imperatively by another customer, e.g. MainThreadDocumentsAndEditors
# registers MainThreadDocuments and MainThreadTextEditors, and
# MainThreadWebviewManager registers the whole webview family. Scanning only for
# the decorator silently omits them, including every webview service.
_SET_CUSTOMER = re.compile(
    r"\.set\(\s*(?:\w+\.)?MainContext\.(?P<key>\w+)\s*,"
)
# A method declaration inside an interface body or a class body.
_IFACE_METHOD = re.compile(r"^\s*(?P<name>\$\w+)\s*(?:<[^>]*>)?\s*\(", re.M)
_CLASS_METHOD = re.compile(
    r"^\s{1,4}(?:public\s+|private\s+|protected\s+|async\s+|readonly\s+|override\s+|static\s+)*"
    r"(?P<name>\$\w+)\s*(?:<[^>]*>)?\s*\(",
    re.M,
)


def _context_block(text: str, const_name: str) -> str:
    start = text.find("export const %s = {" % const_name)
    if start < 0:
        return ""
    end = text.find("\n};", start)
    return text[start: end if end > 0 else len(text)]


def _line_of(tree: SourceTree, rel: str, needle: str) -> int:
    for i, line in enumerate(tree.lines(rel), start=1):
        if needle in line:
            return i
    return 0


def extract_proxy_identifiers(tree: SourceTree, const_name: str) -> dict:
    """Map property key -> {sid, shape, line, permalink} for a *Context const."""
    text = tree.text(PROTOCOL)
    block = _context_block(text, const_name)
    out = {}
    for m in _PROXY_ID.finditer(block):
        key = m.group("key")
        line = _line_of(tree, PROTOCOL, m.group(0).strip()[:60])
        out[key] = {
            "key": key,
            "sid": m.group("sid"),
            "shape": m.group("shape"),
            "line": line,
            "permalink": tree.permalink(PROTOCOL, line),
            # The sid is what travels on the wire; flag when it diverges from
            # the property name, because a policy keyed on the wrong one is a
            # silent bypass.
            "sid_differs_from_key": m.group("sid") != key,
        }
    return out


def _interface_body(text: str, name: str) -> tuple:
    """Return (body, start_offset) for ``export interface <name> ... { ... }``."""
    m = re.search(r"export interface %s\b[^{]*\{" % re.escape(name), text)
    if not m:
        return "", -1
    depth = 0
    i = m.end() - 1
    for j in range(i, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[m.end():j], m.start()
    return "", -1


def extract_shape_methods(tree: SourceTree, shape: str) -> list:
    """Declared ``$`` methods of a ``MainThread*Shape`` interface."""
    text = strip_block_comments(tree.text(PROTOCOL))
    body, _ = _interface_body(text, shape.split("<")[0])
    if not body:
        return []
    seen = []
    for m in _IFACE_METHOD.finditer(body):
        if m.group("name") not in seen:
            seen.append(m.group("name"))
    return seen


def _split_params(params: str) -> list:
    """Split a parameter list on top-level commas, respecting nesting."""
    out, depth, cur, quote = [], 0, [], None
    for ch in params:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "'\"`":
            quote = ch
            cur.append(ch)
            continue
        if ch in "<([{":
            depth += 1
        elif ch in ">)]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    if "".join(cur).strip():
        out.append("".join(cur))
    return out


def _param_list(body: str, start: int) -> str:
    """Text between the parentheses of a method whose '(' is at ``start``."""
    depth = 0
    for j in range(start, len(body)):
        if body[j] == "(":
            depth += 1
        elif body[j] == ")":
            depth -= 1
            if depth == 0:
                return body[start + 1:j]
    return ""


def extract_uri_positions(tree: SourceTree, shape: str) -> dict:
    """Map method -> parameter positions whose declared type mentions UriComponents.

    This is the positional truth the filter's URI constraint has to mirror.
    It matters because ``URI.revive`` does not look for a ``$mid`` marker: it
    builds a URI from any truthy object it is handed
    (``src/vs/base/common/uri.ts``), and a consumer like
    ``MainThreadFileSystem.$readFile`` calls it on a fixed argument position
    regardless of what that object looks like on the wire. A validator that
    hunts the argument graph for URI-*shaped* values therefore disagrees with
    the consumer in both directions, and the dangerous direction is a miss:
    plain ``{scheme, path}`` components with no marker are revived by the
    consumer but invisible to a shape-based search.

    Positions are reported for any parameter whose type mentions
    ``UriComponents``, including arrays and optionals, so a nested or repeated
    URI argument is not silently dropped.
    """
    text = strip_block_comments(tree.text(PROTOCOL))
    body, _ = _interface_body(text, shape.split("<")[0])
    out = {}
    if not body:
        return out
    for m in _IFACE_METHOD.finditer(body):
        params = _split_params(_param_list(body, m.end() - 1))
        positions = [i for i, p in enumerate(params) if "UriComponents" in p]
        if positions:
            out.setdefault(m.group("name"), positions)
    return out


def extract_named_customers(tree: SourceTree) -> dict:
    """Map MainContext key -> {class, file, line, methods}.

    Covers both registration paths: the ``@extHostNamedCustomer`` decorator and
    imperative ``context.set(MainContext.X, instance)``.
    """
    out = {}
    set_sites = {}
    class_index = {}

    for subdir in CUSTOMER_DIRS:
        for rel in tree.walk(subdir):
            raw = tree.text(rel)
            has_decorator = "extHostNamedCustomer" in raw
            has_set = "MainContext." in raw and ".set(" in raw
            if not has_decorator and not has_set and "class MainThread" not in raw:
                continue
            text = strip_block_comments(raw)

            for m in re.finditer(r"(?:export\s+)?class\s+(?P<cls>MainThread\w*)", text):
                class_index.setdefault(m.group("cls"), rel)

            if has_decorator:
                for m in _NAMED_CUSTOMER.finditer(text):
                    key, cls = m.group("key"), m.group("cls")
                    line = _line_of(tree, rel, "@extHostNamedCustomer(MainContext.%s)" % key)
                    out[key] = {
                        "key": key,
                        "class": cls,
                        "file": rel,
                        "line": line,
                        "permalink": tree.permalink(rel, line),
                        "registration": "extHostNamedCustomer",
                        "methods": _class_methods(text, cls),
                    }
            if has_set:
                for m in _SET_CUSTOMER.finditer(text):
                    key = m.group("key")
                    line = 1 + text[: m.start()].count("\n")
                    set_sites.setdefault(key, (rel, line))

    # Resolve imperative registrations. Upstream names the implementing class
    # after the MainContext key, so look that class up directly; fall back to
    # recording the registration site alone rather than dropping the service.
    for key, (rel, line) in set_sites.items():
        if key in out:
            continue
        impl_file = class_index.get(key)
        methods = []
        if impl_file:
            methods = _class_methods(strip_block_comments(tree.text(impl_file)), key)
        out[key] = {
            "key": key,
            "class": key if impl_file else None,
            "file": impl_file or rel,
            "line": _line_of(tree, impl_file, "class %s" % key) if impl_file else line,
            "permalink": tree.permalink(impl_file or rel,
                                        _line_of(tree, impl_file, "class %s" % key)
                                        if impl_file else line),
            "registration": "context.set",
            "registered_at": tree.permalink(rel, line),
            "methods": methods,
        }
    return out


def _class_methods(text: str, cls: str) -> list:
    """``$`` methods declared on ``class cls`` (its own body only)."""
    m = re.search(r"class %s\b[^{]*\{" % re.escape(cls), text)
    if not m:
        return []
    depth = 0
    for j in range(m.end() - 1, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                body = text[m.end():j]
                break
    else:
        return []
    seen = []
    for mm in _CLASS_METHOD.finditer(body):
        if mm.group("name") not in seen:
            seen.append(mm.group("name"))
    return seen


def build(tree: SourceTree) -> dict:
    """Assemble surface (a)."""
    main = extract_proxy_identifiers(tree, "MainContext")
    exthost = extract_proxy_identifiers(tree, "ExtHostContext")
    customers = extract_named_customers(tree)

    services = []
    for key, proxy in sorted(main.items()):
        declared = extract_shape_methods(tree, proxy["shape"])
        customer = customers.get(key)
        implemented = customer["methods"] if customer else []
        undeclared = [m for m in implemented if m not in declared]
        unimplemented = [m for m in declared if m not in implemented]
        services.append({
            "key": key,
            "sid": proxy["sid"],
            "sid_differs_from_key": proxy["sid_differs_from_key"],
            "shape": proxy["shape"],
            "protocol_permalink": proxy["permalink"],
            "customer_class": customer["class"] if customer else None,
            "customer_file": customer["file"] if customer else None,
            "customer_permalink": customer["permalink"] if customer else None,
            "registration": customer["registration"] if customer else None,
            "declared_methods": declared,
            "implemented_methods": implemented,
            # Reachable via actor[methodName] despite not being in the Shape.
            "undeclared_methods": undeclared,
            "declared_but_not_found": unimplemented,
            # Parameter positions the consumer will hand to URI.revive. The
            # filter's URI constraint is keyed on these rather than on the
            # shape of values found in the argument graph; see
            # extract_uri_positions for why a shape-based search is unsound.
            "uri_arg_positions": extract_uri_positions(tree, proxy["shape"]),
        })

    return {
        "services": services,
        "service_count": len(services),
        "method_count": sum(len(set(s["declared_methods"]) | set(s["implemented_methods"]))
                            for s in services),
        "exthost_context_proxies": sorted(exthost.keys()),
        "unmapped_main_context_keys": sorted(k for k in main if k not in customers),
    }
