"""Render the inventory JSON as a reviewable Markdown document."""

from __future__ import annotations


def _link(text: str, url) -> str:
    return "[%s](%s)" % (text, url) if url else text


def _header(inv: dict) -> list:
    sha = inv["upstream_sha"]
    return [
        "# RPC attack-surface inventory",
        "",
        "**Generated. Do not edit by hand.** Regenerate with",
        "`rpc-filter/tools/run.sh` (see [AGENTS.md](../AGENTS.md)).",
        "",
        "| | |",
        "|---|---|",
        "| Upstream | `microsoft/vscode@%s` |" % sha[:12],
        "| SHA source | %s |" % inv["upstream_sha_origin"],
        "| Schema | %d |" % inv["schema"],
        "",
        "Every surface here is a way code inside a tab can make the **trusted**",
        "side act, or make it interpret tab-supplied data with authority. The",
        "filter is default-deny: anything in this inventory without a verdict in",
        "`rpc-filter/policy/policy.json` fails the drift check and fails the build.",
        "",
    ]


def _surface_a(a: dict, lines: list) -> None:
    undeclared_total = sum(len(s["undeclared_methods"]) for s in a["services"])
    lines += [
        "## (a) `MainThread*` RPC, extension host to workbench",
        "",
        "%d services, %d distinct methods." % (a["service_count"], a["method_count"]),
        "",
        "`RPCProtocol._doInvokeHandler` resolves the target with",
        "`actor[methodName]` and only checks that it is a function, so the",
        "callable surface is **every `$` method on the customer class**, not just",
        "the `MainThread*Shape` interface. %d methods are callable without being"
        % undeclared_total,
        "declared in a Shape.",
        "",
        "The wire key is the string `sid` passed to `createProxyIdentifier`, which",
        "is not always the `MainContext` property name. Policy keys on `sid`.",
        "The numeric `nid` is assigned by module load order and must never be a key.",
        "",
        "| Service (`MainContext` key) | Wire `sid` | Customer class | Methods | Undeclared |",
        "|---|---|---|---:|---:|",
    ]
    for s in a["services"]:
        sid = "`%s`" % s["sid"]
        if s["sid_differs_from_key"]:
            sid += " **(differs)**"
        cls = _link("`%s`" % s["customer_class"], s["customer_permalink"]) \
            if s["customer_class"] else "_none found_"
        total = len(set(s["declared_methods"]) | set(s["implemented_methods"]))
        lines.append("| %s | %s | %s | %d | %d |" % (
            _link("`%s`" % s["key"], s["protocol_permalink"]), sid, cls,
            total, len(s["undeclared_methods"])))
    lines.append("")

    divergent = [s for s in a["services"] if s["sid_differs_from_key"]]
    if divergent:
        lines += [
            "### Services whose wire `sid` differs from the property name", "",
            "A policy keyed on the property name would never match these, and the",
            "call would fall through to whatever the default is. With default-deny",
            "that is a breakage; with any allow-by-default it is a silent bypass.",
            "",
        ]
        for s in divergent:
            lines.append("- `MainContext.%s` travels as `'%s'` — %s"
                         % (s["key"], s["sid"], _link("protocol", s["protocol_permalink"])))
        lines.append("")

    undeclared = [s for s in a["services"] if s["undeclared_methods"]]
    if undeclared:
        lines += [
            "### Callable but not declared in the Shape interface", "",
            "These exist on the registered instance and are therefore reachable",
            "over RPC. Reviewing only the `.protocol.ts` interfaces misses them.",
            "",
        ]
        for s in undeclared:
            lines.append("- **%s** (`%s`): %s" % (
                s["key"], s["customer_file"] or "?",
                ", ".join("`%s`" % m for m in s["undeclared_methods"])))
        lines.append("")

    if a["unmapped_main_context_keys"]:
        lines += [
            "### `MainContext` entries with no `@extHostNamedCustomer` found", "",
            "Either registered through a path this scan does not model, or dead.",
            "Both need a verdict.", "",
            ", ".join("`%s`" % k for k in a["unmapped_main_context_keys"]), "",
        ]


def _surface_b(b: dict, lines: list) -> None:
    lines += [
        "## (b) Command registry reachable via `$executeCommand`",
        "",
        "%d commands found. `$executeCommand` takes the id from the caller, so"
        % b["command_count"],
        "the whole registry is reachable from a tab.",
        "",
        "| Category | Commands |",
        "|---|---:|",
    ]
    for cat, count in b["by_category"].items():
        lines.append("| `%s` | %d |" % (cat, count))
    lines += ["", "Categories are a review aid only. They grant nothing: the policy",
              "table still needs a verdict per command id.", ""]
    if b["unresolved_id_expressions"]:
        lines += [
            "### Command ids built from non-literal expressions", "",
            "%d registrations use a constant or computed id that this static scan"
            % b["unresolved_count"],
            "cannot resolve. Default-deny means these are denied until classified,",
            "so the cost is compatibility, not containment.", "",
            ", ".join("`%s`" % e for e in b["unresolved_id_expressions"][:40]),
            "", "Full list in `inventory.json`.", "",
        ]


def _surface_c(c: dict, lines: list) -> None:
    lines += [
        "## (c) Channels the client serves to the server",
        "",
        "The REH server process runs **inside the tab**, so it is hostile. These",
        "channels are called by the server over the remote connection and never",
        "pass through `RPCProtocol`, so a filter scoped to `MainThread*` does not",
        "see them.",
        "",
        "%d client-served channels, %d server-initiated callbacks."
        % (c["client_served_channel_count"], c["server_initiated_callback_count"]),
        "",
    ]
    for ch in c["client_served_channels"]:
        lines += [
            "### `%s` → `%s`" % (ch["channel"], ch["implementation"]),
            "",
            "- Registered: %s" % _link(
                "`%s:%d`" % (ch["registered_in"], ch["registered_line"]),
                ch["registration_permalink"]),
            "- Implementation: %s" % _link("`%s`" % ch["implementation"],
                                           ch["implementation_permalink"]),
        ]
        if ch["methods"]:
            lines.append("- Methods: %s" % ", ".join("`%s`" % m for m in ch["methods"]))
        if ch["revives_caller_supplied_uri"]:
            lines.append("- **Revives a caller-supplied URI**: the server chooses the "
                         "URI, so this reads and writes wherever the trusted side can.")
        if ch["proxy_channel"]:
            lines.append("- **`ProxyChannel.fromService`**: the whole service "
                         "interface is exposed; the method list is not a bound.")
        lines.append("")
    if c["server_initiated_callbacks"]:
        lines += ["### Server-initiated callbacks the client acts on", "",
                  "| Effect | Site |", "|---|---|"]
        for cb in c["server_initiated_callbacks"]:
            lines.append("| %s | %s |" % (
                cb["effect"],
                _link("`%s:%d`" % (cb["file"], cb["line"]), cb["permalink"])))
        lines.append("")


def _surface_d(d: dict, lines: list) -> None:
    lines += [
        "## (d) Tab-supplied data the trusted side interprets with authority",
        "",
        "Not calls: values that start in a tab and are parsed and acted on by the",
        "trusted side. %d sink classes over %d sites."
        % (d["upstream_sink_count"], d["upstream_site_count"]),
        "",
        "| Surface | Authority it confers | Sites |",
        "|---|---|---:|",
    ]
    for s in d["upstream_sinks"]:
        lines.append("| `%s` | %s | %d |" % (s["surface"], s["authority"],
                                             s.get("site_count", 0)))
    lines += ["", "Representative sites, with permalinks, are in `inventory.json`.", ""]
    if d["local_surfaces"]:
        lines += ["### Our own components reachable from a tab", "",
                  "| Component | Role | Status |", "|---|---|---|"]
        for s in d["local_surfaces"]:
            lines.append("| `%s` | %s | %s |" % (s["surface"], s["authority"], s["status"]))
        lines.append("")


def render_markdown(inv: dict) -> str:
    lines = _header(inv)
    s = inv["surfaces"]
    _surface_a(s["a_mainthread_rpc"], lines)
    _surface_b(s["b_command_registry"], lines)
    _surface_c(s["c_client_served_channels"], lines)
    _surface_d(s["d_tab_supplied_data"], lines)
    return "\n".join(lines).rstrip() + "\n"
