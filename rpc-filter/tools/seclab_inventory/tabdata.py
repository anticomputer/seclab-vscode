"""Surface (d): tab-supplied data the trusted side interprets with authority.

These are not calls. They are values that originate in a tab -- workspace
configuration read over the remote file system, markdown and hover strings,
tree item and notification actions, terminal escape sequences, URIs handed to
openers, webview HTML -- which the *trusted* side then parses and acts on.

The scan locates the sinks. It deliberately reports candidate sites rather
than verdicts: a human classifies each one in the policy table, and the drift
check fails when a new site appears unclassified.

Also covered here: surfaces specific to our own design that the tab can reach,
namely the tab supervisor (`seclab-tabd`) and the per-tab broker. Those live in
this repo rather than upstream, so they are scanned from the repo when present
and reported as pending while they are still TODO.
"""

from __future__ import annotations

import os
import re

from .sources import SourceTree, strip_block_comments

SCAN_DIRS = ("src/vs/workbench", "src/vs/platform", "src/vs/editor", "src/vs/base")

# Each entry: (surface id, authority it confers, regex)
_SINKS = (
    ("command-uri-in-markdown",
     "a `command:` URI in tab-authored markdown runs a command on the trusted side",
     re.compile(r"\bisTrusted\b|Schemas\.command\b|'command:'|\"command:\"")),
    ("markdown-string-trust",
     "MarkdownString.isTrusted decides whether embedded command links execute",
     re.compile(r"isTrusted\s*[:=]")),
    ("terminal-osc-sequence",
     "OSC/escape sequences written by the tab are parsed by the trusted terminal UI",
     re.compile(r"registerOscHandler|parseKeyValueAssignment|VSCodeOscPt|ITerminalAddon")),
    ("terminal-link-opener",
     "links detected in tab terminal output are opened by the trusted side",
     re.compile(r"TerminalLinkOpener|registerLinkProvider|ITerminalLinkOpener")),
    ("open-external",
     "a URI chosen by the tab is handed to the host OS opener",
     re.compile(r"\bopenExternal\s*\(|\$openExternal\b")),
    ("as-external-uri",
     "asExternalUri can mint a host-reachable URI or tunnel for the tab",
     re.compile(r"asExternalUri\s*\(|\$asExternalUri\b")),
    ("uri-handler",
     "vscode:// callbacks are routed into extensions and can carry OAuth codes",
     re.compile(r"registerUriHandler|IURLHandler\b|handleURL\s*\(")),
    ("tunnel-and-port-forward",
     "the tab asks the trusted side to open or forward a port",
     re.compile(r"\$openTunnel\b|forwardPort\s*\(|ITunnelService\b|RemoteTunnel\b")),
    ("webview-content",
     "tab-authored HTML renders in the trusted renderer and can fetch any origin",
     re.compile(r"\$setHtml\b|setHtml\s*\(|WebviewContentOptions|localResourceRoots")),
    ("clipboard",
     "clipboard read returns whatever the user copied, often a credential",
     re.compile(r"\$readText\b|clipboardService\.readText")),
    ("workspace-configuration",
     "workspace settings read from the tab change trusted-side behaviour",
     re.compile(r"ConfigurationScope\.(?:MACHINE|MACHINE_OVERRIDABLE|APPLICATION)|"
                r"restrictedSettings|IConfigurationInitData")),
    ("mcp-server-definition",
     "MCP server definitions from config carry secret inputs and env",
     re.compile(r"McpServerDefinition|mcp\.json|IMcpConfiguration")),
    ("quick-input-password",
     "a password QuickInput captures a real user secret on the trusted side",
     re.compile(r"password\s*:\s*true|\$input\s*\(")),
    ("proxy-and-kerberos-auth",
     "proxy and Kerberos credentials are returned to the caller",
     re.compile(r"\$lookupAuthorization\b|\$lookupKerberosAuthorization\b")),
    ("extension-identity-argument",
     "an extension identity supplied as an RPC argument drives a trust decision",
     re.compile(r"\$(?:getPassword|setPassword|deletePassword|getSession|removeSession)\s*\(")),
)

# Our own components. Scanned from the repo, not upstream.
_LOCAL_SURFACES = (
    ("seclab-tabd", "rpc-filter/../supervisor",
     "tab supervisor JSON-RPC over stdio; issues the per-tab identity"),
    ("broker", "broker",
     "per-tab mitmproxy broker; the only egress and the sentinel swap point"),
)


def _scan_upstream(tree: SourceTree) -> list:
    hits = {}
    for subdir in SCAN_DIRS:
        for rel in tree.walk(subdir):
            raw = tree.text(rel)
            text = None
            for sid, authority, pattern in _SINKS:
                if not pattern.search(raw):
                    continue
                if text is None:
                    text = strip_block_comments(raw)
                m = pattern.search(text)
                if not m:
                    continue
                line = 1 + text[: m.start()].count("\n")
                entry = hits.setdefault(sid, {
                    "surface": sid,
                    "authority": authority,
                    "sites": [],
                })
                if len(entry["sites"]) < 12:
                    entry["sites"].append({
                        "file": rel,
                        "line": line,
                        "permalink": tree.permalink(rel, line),
                    })
                entry["site_count"] = entry.get("site_count", 0) + 1
    return [hits[k] for k in sorted(hits)]


def _scan_local(repo_root: str) -> list:
    out = []
    for name, rel, description in _LOCAL_SURFACES:
        path = os.path.normpath(os.path.join(repo_root, rel))
        out.append({
            "surface": name,
            "authority": description,
            "present": os.path.isdir(path),
            "path": rel,
            "status": "present" if os.path.isdir(path) else "TODO (not built yet)",
        })
    return out


def build(tree: SourceTree, repo_root: str) -> dict:
    upstream = _scan_upstream(tree)
    return {
        "upstream_sinks": upstream,
        "upstream_sink_count": len(upstream),
        "upstream_site_count": sum(s.get("site_count", 0) for s in upstream),
        "local_surfaces": _scan_local(repo_root),
    }
