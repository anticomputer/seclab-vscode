"""Surface (b): the command registry reachable through ``$executeCommand``.

``MainThreadCommands.$executeCommand`` forwards to ``ICommandService.executeCommand``
with an id the caller chooses, so every registered command is reachable from a
tab. There is no runtime dump available at generation time, so this is a static
scan of every registration form used upstream.

Completeness is enforced two ways rather than assumed:

* ids built from non-literal expressions are still captured, in
  ``unresolved``, so they show up as work rather than vanishing;
* the filter is default-deny, so a command this scan misses is denied, not
  allowed. A miss costs compatibility, never containment.
"""

from __future__ import annotations

import json
import os
import re

from .sources import SourceTree, strip_block_comments

SCAN_DIRS = ("src/vs", "extensions")

_PATTERNS = (
    # CommandsRegistry.registerCommand('id', ...)
    ("CommandsRegistry.registerCommand",
     re.compile(r"CommandsRegistry\.registerCommand\(\s*'(?P<id>[^']+)'")),
    # CommandsRegistry.registerCommand({ id: 'id', ... })
    ("CommandsRegistry.registerCommand",
     re.compile(r"CommandsRegistry\.registerCommand\(\s*\{\s*id\s*:\s*'(?P<id>[^']+)'")),
    # KeybindingsRegistry.registerCommandAndKeybindingRule({ id: 'id' })
    ("KeybindingsRegistry.registerCommandAndKeybindingRule",
     re.compile(r"registerCommandAndKeybindingRule\(\s*\{\s*id\s*:\s*'(?P<id>[^']+)'")),
    # MenuRegistry.addCommand({ id: 'id' })
    ("MenuRegistry.addCommand",
     re.compile(r"MenuRegistry\.addCommand\(\s*\{\s*id\s*:\s*'(?P<id>[^']+)'")),
    # registerAction2 / Action2 subclasses: super({ id: 'id', ... })
    ("Action2",
     re.compile(r"super\(\s*\{\s*id\s*:\s*'(?P<id>[^']+)'")),
    # registerEditorCommand/registerEditorAction style: id: 'x' next to a known base
    ("EditorCommand",
     re.compile(r"\bid\s*:\s*'(?P<id>[a-zA-Z][\w.+-]*\.[\w.+-]+)'\s*,[^\n]*\n\s*(?:precondition|label|title|weight)")),
    # Any register*(...) helper taking an object literal with a string id.
    # Upstream defines many domain-specific wrappers -- registerTerminalAction,
    # registerActiveInstanceAction and friends -- and enumerating them by name
    # is how workbench.action.terminal.newLocal went missing from a 2792-id
    # scan. Match the shape instead of the helper name.
    ("register*Action",
     re.compile(r"\bregister\w*\(\s*\{(?:[^{}]|\{[^{}]*\})*?\bid\s*:\s*'(?P<id>[^']+)'")),
    # registerCommandAlias('old', 'new'): the old id stays callable.
    ("registerCommandAlias",
     re.compile(r"registerCommandAlias\(\s*'(?P<id>[^']+)'")),
    ("registerCommandAlias",
     re.compile(r"registerCommandAlias\(\s*'[^']+'\s*,\s*'(?P<id>[^']+)'")),
)

# Same registration forms, but with a non-literal id. Captured so that a
# constant-based id is visible as unresolved work rather than silently missing.
_UNRESOLVED = (
    re.compile(r"CommandsRegistry\.registerCommand\(\s*(?P<expr>[A-Z][\w.]*)\s*,"),
    re.compile(r"(?:CommandsRegistry\.registerCommand|registerCommandAndKeybindingRule|MenuRegistry\.addCommand)"
               r"\(\s*\{\s*id\s*:\s*(?P<expr>[A-Za-z_$][\w.]*)\s*[,}]"),
    re.compile(r"super\(\s*\{\s*id\s*:\s*(?P<expr>[A-Z][\w.]*(?:\.\w+)*)\s*[,}]"),
    # The generic register*({ id: Constant }) form, e.g. registerTerminalAction.
    re.compile(r"\bregister\w*\(\s*\{(?:[^{}]|\{[^{}]*\})*?\bid\s*:\s*(?P<expr>[A-Za-z_$][\w.]*)\s*[,}]"),
    re.compile(r"registerCommandAlias\(\s*(?P<expr>[A-Za-z_$][\w.]*)\s*[,)]"),
)


def _constant_index(tree: SourceTree) -> dict:
    """Resolve the string constants that command registrations refer to.

    Upstream registers most command ids through a constant or an enum member
    rather than a literal. Without this, over a thousand real commands would be
    reported as "unresolved" and would never get a policy verdict.

    Three forms are indexed:
      ``const NAME = 'id'``            -> ``NAME``
      ``enum E { Member = 'id' }``     -> ``E.Member``
      ``class C { static ... ID = 'id' }`` -> ``C.ID``
    """
    consts = {}
    members = {}
    const_re = re.compile(
        r"(?:export\s+)?const\s+(?P<name>[A-Za-z_$][\w$]*)"
        r"(?:\s*:\s*[\w<>.\[\]|'\" ]+)?\s*=\s*'(?P<val>[^']+)'\s*;")
    container_re = re.compile(
        r"(?:export\s+)?(?:declare\s+)?(?:const\s+)?(?:enum|namespace|class)\s+(?P<name>[A-Za-z_$][\w$]*)\b[^{]*\{")
    member_re = re.compile(
        r"(?:public\s+|static\s+|readonly\s+)*(?P<name>[A-Za-z_$][\w$]*)"
        r"(?:\s*:\s*[\w<>.\[\]|'\" ]+)?\s*=\s*'(?P<val>[^']+)'")

    for subdir in SCAN_DIRS:
        for rel in tree.walk(subdir):
            raw = tree.text(rel)
            if "= '" not in raw:
                continue
            text = strip_block_comments(raw)
            for m in const_re.finditer(text):
                consts.setdefault(m.group("name"), m.group("val"))
            for cm in container_re.finditer(text):
                depth, body = 0, None
                for j in range(cm.end() - 1, len(text)):
                    if text[j] == "{":
                        depth += 1
                    elif text[j] == "}":
                        depth -= 1
                        if depth == 0:
                            body = text[cm.end():j]
                            break
                if not body:
                    continue
                for mm in member_re.finditer(body):
                    key = "%s.%s" % (cm.group("name"), mm.group("name"))
                    members.setdefault(key, mm.group("val"))
    consts.update(members)
    return consts


def _scan_typescript(tree: SourceTree) -> tuple:
    found = {}
    unresolved = {}
    for subdir in SCAN_DIRS:
        for rel in tree.walk(subdir):
            raw = tree.text(rel)
            if "register" not in raw and "super({" not in raw \
                    and "addCommand" not in raw:
                continue
            text = strip_block_comments(raw)
            for source, pattern in _PATTERNS:
                for m in pattern.finditer(text):
                    cid = m.group("id")
                    entry = found.setdefault(cid, {
                        "id": cid, "sources": [], "files": [],
                    })
                    if source not in entry["sources"]:
                        entry["sources"].append(source)
                    if rel not in entry["files"]:
                        entry["files"].append(rel)
            for pattern in _UNRESOLVED:
                for m in pattern.finditer(text):
                    expr = m.group("expr")
                    unresolved.setdefault(expr, []).append(rel)
    return found, unresolved


def _scan_builtin_extension_manifests(tree: SourceTree) -> dict:
    """``contributes.commands`` from the built-in extensions shipped in the build."""
    found = {}
    ext_root = tree.path("extensions")
    if not os.path.isdir(ext_root):
        return found
    for name in sorted(os.listdir(ext_root)):
        manifest = os.path.join(ext_root, name, "package.json")
        if not os.path.isfile(manifest):
            continue
        try:
            with open(manifest, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue
        for cmd in (data.get("contributes") or {}).get("commands") or []:
            cid = cmd.get("command")
            if not cid:
                continue
            entry = found.setdefault(cid, {"id": cid, "sources": [], "files": []})
            if "contributes.commands" not in entry["sources"]:
                entry["sources"].append("contributes.commands")
            rel = os.path.relpath(manifest, tree.root)
            if rel not in entry["files"]:
                entry["files"].append(rel)
    return found


def _category(cid: str) -> str:
    """Coarse bucket used to make the policy table reviewable.

    This is a *grouping* aid only. It never grants anything: the policy table
    still has to name a verdict for every command id.
    """
    c = cid.lower()
    rules = (
        ("host-process", ("terminal.newlocal", "terminal.sendsequence", "openinintegratedterminal",
                          "workbench.action.terminal", "task.", "tasks.", "debug.")),
        ("extension-management", ("extension", "workbench.extensions")),
        ("host-filesystem", ("workbench.action.files", "revealfileinos", "copyfilepath",
                             "openfilefolder", "openrecent", "addrootfolder", "files.")),
        ("window-and-workspace", ("workbench.action.window", "workbench.action.quit",
                                  "workbench.action.reloadwindow", "openfolder", "newwindow",
                                  "vscode.openfolder", "workbench.action.closewindow")),
        ("settings-and-policy", ("workbench.action.opensettings", "settings.", "configuration",
                                 "workbench.action.opensettingsjson", "update.")),
        ("external-and-uri", ("vscode.open", "vscode.env.openexternal", "openexternal",
                              "asexternaluri", "browser", "simplebrowser")),
        ("secrets-and-auth", ("auth", "secret", "credential", "signin", "login")),
        ("remote-and-tunnel", ("remote.", "tunnel", "forwardport", "_remotecli")),
        ("editor-local", ("editor.", "cursor", "workbench.action.navigate")),
    )
    for bucket, needles in rules:
        if any(n in c for n in needles):
            return bucket
    if cid.startswith("_"):
        return "internal-underscore"
    return "unclassified"


def build(tree: SourceTree) -> dict:
    ts_found, unresolved = _scan_typescript(tree)
    manifest_found = _scan_builtin_extension_manifests(tree)
    constants = _constant_index(tree)

    # Resolve constant-valued ids so they get a verdict like any other command.
    still_unresolved = {}
    for expr, files in unresolved.items():
        value = constants.get(expr)
        if value is None:
            still_unresolved[expr] = files
            continue
        entry = ts_found.setdefault(value, {"id": value, "sources": [], "files": []})
        tag = "constant:%s" % expr
        if tag not in entry["sources"]:
            entry["sources"].append(tag)
        for f in files:
            if f not in entry["files"]:
                entry["files"].append(f)

    merged = dict(ts_found)
    for cid, entry in manifest_found.items():
        if cid in merged:
            for s in entry["sources"]:
                if s not in merged[cid]["sources"]:
                    merged[cid]["sources"].append(s)
            for f in entry["files"]:
                if f not in merged[cid]["files"]:
                    merged[cid]["files"].append(f)
        else:
            merged[cid] = entry

    commands = []
    for cid in sorted(merged):
        entry = merged[cid]
        commands.append({
            "id": cid,
            "category": _category(cid),
            "sources": sorted(entry["sources"]),
            # Cap the file list: some ids are registered in many places and the
            # inventory should stay diffable.
            "files": sorted(entry["files"])[:4],
            "permalink": tree.permalink(sorted(entry["files"])[0]) if entry["files"] else None,
        })

    by_category = {}
    for c in commands:
        by_category[c["category"]] = by_category.get(c["category"], 0) + 1

    return {
        "commands": commands,
        "command_count": len(commands),
        "by_category": dict(sorted(by_category.items())),
        "unresolved_id_expressions": sorted(still_unresolved.keys()),
        "unresolved_count": len(still_unresolved),
        "resolved_from_constants": sum(
            1 for c in commands if any(s.startswith("constant:") for s in c["sources"])),
    }
