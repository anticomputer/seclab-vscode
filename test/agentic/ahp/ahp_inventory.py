"""Class (f): the Agent Host Protocol surface a tab's agent host can reach.

Draft for the RPC-lockdown session's generator (plan §3.3). It inventories every
place the protocol is defined or handled, because a handler added upstream
without a protocol change is exactly the drift a message-map-only scan misses:

* the method maps in protocol/common/messages.ts, both directions
  (client->server requests, server->client requests, and both notification maps);
* the ActionType enum (state actions carried in dispatchAction / action);
* the vendor extension methods in agentHostExtensionProtocol.ts, with direction
  taken from the map that keys them;
* the case labels and method comparisons in the client's message handlers in
  agentHostProtocolClient.ts, grouped by enclosing method;
* registerSingleton calls for agent-host connection services, with the window
  (editor workbench or Agents window) the registering file belongs to.

Source is comment-stripped with the RPC generator's string-aware,
length-preserving strip_block_comments (imported, not copied), so offsets and
permalinks stay true. ``--self-test`` injects one of each surface kind, plus a
string containing ``/*`` before it, and fails if any is missed.

Standard library only; runs in the pinned python image with --network none.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile

from seclab_inventory.sources import strip_block_comments  # RPC-lockdown, fixed at 8d92392

PIN = "a717861c07586a53d83b80d742cd3f59b20a6273"
MESSAGES = "src/vs/platform/agentHost/common/state/protocol/common/messages.ts"
ACTIONS = "src/vs/platform/agentHost/common/state/protocol/common/actions.ts"
EXTENSION = "src/vs/platform/agentHost/common/agentHostExtensionProtocol.ts"
CLIENT = "src/vs/platform/agentHost/browser/agentHostProtocolClient.ts"
MAPS = {
    "CommandMap": "client->server request",
    "ServerCommandMap": "server->client request",
    "ClientNotificationMap": "client->server notification",
    "ServerNotificationMap": "server->client notification",
}
EXT_MAPS = {
    "IAgentHostExtensionCommandMap": "client->server request",
    "IAgentHostExtensionServerCommandMap": "server->client request",
    "IAgentHostExtensionNotificationMap": "server->client notification",
}
SINGLETON = re.compile(r"registerSingleton\(\s*(I\w*(?:AgentHost|Tunnel|CloudSandbox|MissionControl|DevContainer)\w*Service)\s*,\s*(\w+)")


def read(root: str, rel: str) -> str:
    with open(os.path.join(root, rel), encoding="utf-8") as f:
        return f.read()


def line_at(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def link(rel: str, line: int) -> str:
    return f"https://github.com/microsoft/vscode/blob/{PIN}/{rel}#L{line}"  # fixture-lint: allow non-test-host -- permalink text for evidence, never fetched


def block(code: str, header: re.Pattern) -> tuple[int, int] | None:
    """Span of the brace block that follows ``header`` in comment-stripped code."""
    m = header.search(code)
    if not m:
        return None
    start = code.index("{", m.end() - 1)
    depth = 0
    for j in range(start, len(code)):
        if code[j] == "{":
            depth += 1
        elif code[j] == "}":
            depth -= 1
            if depth == 0:
                return start, j
    raise ValueError(f"unbalanced block after {header.pattern}")


def top_level_keys(code: str, span: tuple[int, int]) -> list[tuple[str, int]]:
    """Keys at depth 1 of an interface body: 'name': or [ConstName]:."""
    out, depth = [], 0
    i, end = span[0], span[1]
    key = re.compile(r"\s*(?:'([^']+)'|\[(\w+)\])\s*:")
    while i < end:
        c = code[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        elif depth == 1 and (i == span[0] + 1 or code[i - 1] in ";\n\t {"):
            m = key.match(code, i)
            if m:
                out.append((m.group(1) or m.group(2), m.start()))
                i = m.end()
                continue
        i += 1
    return out


def extract(root: str) -> dict:
    surfaces = []
    problems = []

    raw = read(root, MESSAGES)
    code = strip_block_comments(raw)
    for name, direction in MAPS.items():
        span = block(code, re.compile(r"export interface %s\s*\{" % name))
        if not span:
            problems.append(f"{MESSAGES}: {name} not found")
            continue
        for key, off in top_level_keys(code, span):
            surfaces.append({"kind": "method", "id": key, "direction": direction, "map": name, "permalink": link(MESSAGES, line_at(raw, off))})

    raw = read(root, ACTIONS)
    code = strip_block_comments(raw)
    span = block(code, re.compile(r"export const enum ActionType\s*\{"))
    if not span:
        problems.append(f"{ACTIONS}: ActionType not found")
    else:
        for m in re.finditer(r"(\w+)\s*=\s*'([^']+)'", code[span[0]:span[1]]):
            off = span[0] + m.start()
            surfaces.append({"kind": "action", "id": m.group(2), "member": m.group(1), "permalink": link(ACTIONS, line_at(raw, off))})

    raw = read(root, EXTENSION)
    code = strip_block_comments(raw)
    consts = {m.group(1): (m.group(2), m.start()) for m in re.finditer(r"export const (\w+ExtensionMethod)\s*=\s*'([^']+)'", code)}
    directions: dict[str, list[str]] = {}
    for name, direction in EXT_MAPS.items():
        span = block(code, re.compile(r"export interface %s\s*\{" % name))
        if not span:
            problems.append(f"{EXTENSION}: {name} not found")
            continue
        for key, _ in top_level_keys(code, span):
            directions.setdefault(key, []).append(direction)
    for const, (method, off) in sorted(consts.items()):
        surfaces.append({"kind": "extension-method", "id": method, "constant": const,
                         "direction": directions.get(const, ["unmapped"]), "permalink": link(EXTENSION, line_at(raw, off))})

    raw = read(root, CLIENT)
    code = strip_block_comments(raw)
    methods = [(m.start(), m.group(1)) for m in re.finditer(r"\n\t(?:private |protected |public )?(?:async )?(_?\w+)\s*\([^)]*\)\s*(?::[^{]*)?\{", code)]
    def enclosing(off: int) -> str:
        name = "?"
        for start, n in methods:
            if start > off:
                break
            name = n
        return name
    for m in re.finditer(r"case\s+(?:'([^']+)'|(\w+ExtensionMethod))\s*:|method\s*===\s*'([^']+)'", code):
        label = m.group(1) or m.group(3) or consts.get(m.group(2), (m.group(2), 0))[0]
        surfaces.append({"kind": "client-handler", "id": label, "handler": enclosing(m.start()), "permalink": link(CLIENT, line_at(raw, m.start()))})

    for dirpath, dirnames, filenames in os.walk(os.path.join(root, "src/vs")):
        dirnames[:] = [d for d in dirnames if d not in ("test", "node_modules")]
        for fn in filenames:
            if not fn.endswith(".ts"):
                continue
            rel = os.path.relpath(os.path.join(dirpath, fn), root)
            raw = read(root, rel)
            if "registerSingleton" not in raw:
                continue
            code = strip_block_comments(raw)
            for m in SINGLETON.finditer(code):
                window = "agents-window" if rel.startswith("src/vs/sessions/") else "editor-or-shared"
                surfaces.append({"kind": "connection-service", "id": m.group(1), "impl": m.group(2), "window": window, "permalink": link(rel, line_at(raw, m.start()))})

    # Every reverse request in the protocol must have a client handler, and vice versa.
    reverse = {s["id"] for s in surfaces if s["kind"] == "method" and s["direction"] == "server->client request"}
    handled = {s["id"] for s in surfaces if s["kind"] == "client-handler"}
    for r in sorted(reverse - handled):
        problems.append(f"server->client request {r} has no client handler case (scanner gap or dead method)")

    counts: dict[str, int] = {}
    for s in surfaces:
        counts[s["kind"]] = counts.get(s["kind"], 0) + 1
    return {"schema": "seclab-ahp-inventory/0", "upstream_sha": PIN, "counts": counts, "problems": problems, "surfaces": surfaces}


def self_test() -> int:
    """Inject one of each surface kind behind a '/*' inside a string; all must be found."""
    files = {
        MESSAGES: "const g = '**/*plan*.md';\nexport interface CommandMap {\n\t'injectedReq': { params: X; result: Y };\n}\n"
                  "export interface ServerCommandMap {\n\t'injectedReverse': { params: X; result: Y };\n}\n"
                  "export interface ClientNotificationMap {\n}\nexport interface ServerNotificationMap {\n\t'injected/notify': { params: X };\n}\n",
        ACTIONS: "const s = '/* not a comment';\nexport const enum ActionType {\n\tInjected = 'injected/action',\n}\n",
        EXTENSION: "const t = 'a/*b';\nexport const InjectedExtensionMethod = 'vendor/injected';\n"
                   "export interface IAgentHostExtensionCommandMap {\n}\nexport interface IAgentHostExtensionServerCommandMap {\n\t[InjectedExtensionMethod]: { params: X; result: Y };\n}\n"
                   "export interface IAgentHostExtensionNotificationMap {\n}\n",
        CLIENT: "const u = '/*';\nclass C {\n\tprivate _handleReverseRequest(id: number, method: string): void {\n\t\tswitch (method) {\n\t\t\tcase 'injectedReverse': {}\n\t\t\tcase InjectedExtensionMethod: {}\n\t\t}\n\t}\n}\n",
        "src/vs/workbench/x/injected.ts": "const v = '/*';\nregisterSingleton(IInjectedAgentHostService, InjectedImpl, 1);\n",
    }
    with tempfile.TemporaryDirectory(dir=os.environ.get("SELFTEST_DIR")) as root:
        for rel, text in files.items():
            os.makedirs(os.path.dirname(os.path.join(root, rel)), exist_ok=True)
            with open(os.path.join(root, rel), "w", encoding="utf-8") as f:
                f.write(text)
        inv = extract(root)
    ids = {(s["kind"], s["id"]) for s in inv["surfaces"]}
    want = {("method", "injectedReq"), ("method", "injectedReverse"), ("method", "injected/notify"), ("action", "injected/action"),
            ("extension-method", "vendor/injected"), ("client-handler", "injectedReverse"), ("client-handler", "vendor/injected"),
            ("connection-service", "IInjectedAgentHostService")}
    missing = want - ids
    ext = next((s for s in inv["surfaces"] if s["id"] == "vendor/injected" and s["kind"] == "extension-method"), None)
    if ext and ext["direction"] != ["server->client request"]:
        missing.add(("extension-direction", str(ext["direction"])))
    if inv["problems"]:
        missing.add(("problems", "; ".join(inv["problems"])))
    print("ahp-inventory self-test:", "ok" if not missing else f"FAIL missing {sorted(missing)}")
    return 0 if not missing else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source")
    ap.add_argument("--out")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    inv = extract(a.source)
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(inv, f, indent=1, sort_keys=True)
        f.write("\n")
    print(json.dumps({"counts": inv["counts"], "problems": inv["problems"]}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
