#!/usr/bin/env python3
"""Build-time drift check for the RPC capability filter.

This is what keeps the filter maintainable across upstream bumps. It fails the
build when upstream adds or changes a surface that the policy table has not
classified, and when a policy edit would break one of the stated invariants.

Four checks:

``check_keys``
    Every ``rpc`` key in the policy is a real wire ``sid`` in the inventory, and
    every ``channels`` key is a real channel. Catches a policy entry that looks
    right but would never match -- the dangerous failure mode, because the call
    then falls through to the default.

``check_coverage``
    Every inventoried surface resolves to a verdict, and the full
    surface-to-verdict mapping matches the digest recorded in
    ``policy/coverage.json``. A new upstream method or command changes the
    digest and fails the build with an explicit diff.

``check_invariants``
    The invariants declared in the policy actually hold over the resolved
    verdicts: nothing with credential-access impact is reachable, nothing whose
    identity comes from arguments is merely allowed.

``check_undeclared``
    Every method that is callable but not declared in a ``MainThread*Shape``
    has an explicit verdict, since review that reads only the protocol file
    would miss it.

Exit codes: 0 pass, 1 drift or violation, 2 bad input.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
INVENTORY = os.path.join(REPO_ROOT, "rpc-filter", "inventory", "inventory.json")
POLICY = os.path.join(REPO_ROOT, "rpc-filter", "policy", "policy.json")
COVERAGE = os.path.join(REPO_ROOT, "rpc-filter", "policy", "coverage.json")
VALIDATORS_SRC = os.path.join(REPO_ROOT, "rpc-filter", "patch-src", "seclabArgValidators.ts")


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""

REACHABLE = ("allow", "allow_with_constraint", "prompt")
CREDENTIAL_IMPACTS = ("credential-access",)


def _load(path: str):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def resolve_rpc(policy: dict, sid: str, method: str) -> tuple:
    """Return (verdict, entry) for one RPC method."""
    service = policy.get("rpc", {}).get(sid)
    if service is None:
        return policy["default_verdict"], None
    entry = (service.get("methods") or {}).get(method)
    if entry is None:
        return service.get("service_default", policy["default_verdict"]), None
    return entry["verdict"], entry


def resolve_command(policy: dict, command: dict) -> tuple:
    """Return (verdict, entry) for one command id."""
    cmds = policy.get("commands", {})
    exact = (cmds.get("exact") or {}).get(command["id"])
    if exact is not None:
        return exact["verdict"], exact
    for rule in cmds.get("rules") or []:
        match = rule.get("match") or {}
        if "category" in match and match["category"] == command["category"]:
            return rule["verdict"], rule
        if "prefix" in match and command["id"].startswith(match["prefix"]):
            return rule["verdict"], rule
    return policy["default_verdict"], None


def build_mapping(inv: dict, policy: dict) -> dict:
    """The full surface -> verdict mapping, which the digest pins.

    Reachable surfaces record a fingerprint of their whole policy entry, not
    just the verdict. Otherwise editing ``residual_impact`` or weakening a
    ``constraint`` leaves the digest unchanged and the change never surfaces in
    review -- which is how a relabelling silently becomes a mitigation.
    """
    mapping = {}

    def record(key: str, verdict: str, entry) -> None:
        if verdict in REACHABLE and isinstance(entry, dict):
            blob = json.dumps(entry, sort_keys=True)
            mapping[key] = "%s#%s" % (verdict, hashlib.sha256(
                blob.encode("utf-8")).hexdigest()[:12])
        else:
            mapping[key] = verdict

    for service in inv["surfaces"]["a_mainthread_rpc"]["services"]:
        sid = service["sid"]
        methods = sorted(set(service["declared_methods"])
                         | set(service["implemented_methods"]))
        for m in methods:
            verdict, entry = resolve_rpc(policy, sid, m)
            record("rpc:%s.%s" % (sid, m), verdict, entry)
    for command in inv["surfaces"]["b_command_registry"]["commands"]:
        verdict, entry = resolve_command(policy, command)
        record("cmd:%s" % command["id"], verdict, entry)
    channels = policy.get("channels", {})
    for ch in inv["surfaces"]["c_client_served_channels"]["client_served_channels"]:
        name = ch["channel"]
        entry = channels.get(name)
        record("chan:%s" % name,
               entry["verdict"] if entry else policy["default_verdict"], entry)
    # (c2) Server-initiated pushes. These were previously skipped by name --
    # the mapping ignored anything starting with `chan:` and the probe checker
    # blanket-exempted the prefix -- so the deny verdict on
    # remoteTerminal.onExecuteCommand sat in the policy, outside the digest,
    # with nothing enforcing it. A verdict that no gate can see is a comment.
    push_policy = policy.get("pushes") or {}
    for push in inv["surfaces"]["c2_server_initiated_pushes"]["server_initiated_pushes"]:
        entry = push_policy.get(push["key"])
        record(push["key"],
               entry["verdict"] if entry else policy["default_verdict"], entry)

    for sink in inv["surfaces"]["d_tab_supplied_data"]["upstream_sinks"]:
        entry = (policy.get("tab_data") or {}).get(sink["surface"])
        record("data:%s" % sink["surface"],
               entry["verdict"] if entry else policy["default_verdict"], entry)

    # (e) Trusted-side AI surfaces. These are not reachable *through* the
    # filter -- the agent runs in the trusted workbench, so a tab steering it
    # through instruction files produces a host effect with no RPC crossing the
    # boundary. They are pinned here anyway so the gate notices upstream adding
    # a tool, or a setting's scope changing to one a workspace can write. An
    # inventory nothing checks is the failure this project keeps repeating.
    ai = inv["surfaces"].get("e_trusted_ai_surfaces") or {}
    policy_ai = policy.get("trusted_ai") or {}
    for tool in ai.get("tools", []):
        key = "ai-tool:%s" % (tool.get("id") or tool.get("id_expression"))
        entry = (policy_ai.get("tools") or {}).get(key.split(":", 1)[1])
        verdict = entry["verdict"] if entry else policy_ai.get(
            "default_verdict", policy["default_verdict"])
        # The reachability that matters for this surface is not the filter's
        # verdict but whether the tool can touch the host, so it is part of the
        # pinned value: a tool that stops declaring runsInWorkspace must
        # resurface for review.
        record("%s|host=%s" % (key, tool.get("may_reach_host_in_remote_window")),
               verdict, entry)
    for setting in ai.get("settings", []):
        entry = (policy_ai.get("settings") or {}).get(setting["id"])
        verdict = entry["verdict"] if entry else policy_ai.get(
            "default_verdict", policy["default_verdict"])
        # Both the scope and the conclusion drawn from it are pinned. Scope
        # alone is not enough: when the rule for reading a scope was corrected
        # -- APPLICATION_MACHINE turned out to be tab-writable, because a
        # remote window reads remote user settings from a REH-supplied path
        # with REMOTE_MACHINE_SCOPES -- every scope string stayed the same and
        # the gate said nothing. A change in what we believe a surface can do
        # has to surface in review, not only a change upstream made.
        # `unreg` is pinned separately from scope because it *overrides*
        # scope: a setting registered only in the Agents window has no scope at
        # all where editor windows read it, so an APPLICATION-scoped setting is
        # still tab-writable there. A new one appearing has to fail the check.
        record("ai-setting:%s|scope=%s|unreg=%s|tab_writable=%s"
               % (setting["id"], setting["scope"],
                  setting.get("unregistered_where_read"),
                  setting.get("tab_writable")),
               verdict, entry)
    return mapping


def _verdict_of(value: str) -> str:
    return value.split("#", 1)[0]


def digest(mapping: dict) -> str:
    blob = "\n".join("%s=%s" % (k, mapping[k]) for k in sorted(mapping))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def check_keys(inv: dict, policy: dict) -> list:
    errors = []
    sids = {s["sid"] for s in inv["surfaces"]["a_mainthread_rpc"]["services"]}
    keys = {s["key"] for s in inv["surfaces"]["a_mainthread_rpc"]["services"]}
    for key in policy.get("rpc", {}):
        if key in sids:
            continue
        if key in keys:
            errors.append(
                "policy.rpc['%s'] uses the MainContext property name, not the wire sid. "
                "It would never match. Key on the sid from inventory.json." % key)
        else:
            errors.append("policy.rpc['%s'] is not a known service sid." % key)
    known_channels = {c["channel"] for c
                      in inv["surfaces"]["c_client_served_channels"]["client_served_channels"]}
    for name in policy.get("channels", {}):
        if name == "note":
            continue
        if name not in known_channels:
            errors.append("policy.channels['%s'] matches no channel in the inventory." % name)

    # A policy entry for a command the inventory does not know about is a
    # warning sign about the *scanner*, not the policy: the command exists
    # upstream (that is why someone wrote a verdict for it) but the generator
    # did not find it, so sibling commands registered the same way are also
    # missing and are silently resolving to the category default.
    known_commands = {c["id"] for c in inv["surfaces"]["b_command_registry"]["commands"]}
    for cid in (policy.get("commands", {}).get("exact") or {}):
        if cid not in known_commands:
            errors.append(
                "policy.commands.exact['%s'] is not in the inventory. The scanner is missing "
                "its registration form, so other commands registered the same way are "
                "unclassified. Fix the generator rather than the policy." % cid)

    # Categories may only withhold authority, never grant it.
    for rule in policy.get("commands", {}).get("rules") or []:
        if rule.get("verdict") != "deny":
            errors.append(
                "commands rule %s has verdict '%s'. Category rules are a substring heuristic "
                "over command ids and may only carry 'deny'; promote individual ids in "
                "commands.exact instead." % (rule.get("match"), rule.get("verdict")))
    return errors


def check_coverage(mapping: dict) -> list:
    if not os.path.isfile(COVERAGE):
        return ["%s is missing. Run with --accept to record the current mapping."
                % os.path.relpath(COVERAGE, REPO_ROOT)]
    recorded = _load(COVERAGE)
    if recorded.get("digest") == digest(mapping):
        return []
    errors = ["the surface-to-verdict mapping changed since it was last reviewed."]
    old = recorded.get("mapping") or {}
    added = sorted(set(mapping) - set(old))
    removed = sorted(set(old) - set(mapping))
    changed = sorted(k for k in set(mapping) & set(old) if mapping[k] != old[k])
    for k in added[:40]:
        errors.append("  NEW       %s -> %s" % (k, mapping[k]))
    if len(added) > 40:
        errors.append("  ... and %d more new surfaces" % (len(added) - 40))
    for k in changed[:40]:
        errors.append("  CHANGED   %s: %s -> %s" % (k, old[k], mapping[k]))
    for k in removed[:40]:
        errors.append("  REMOVED   %s (was %s)" % (k, old[k]))
    errors.append("Classify the new surfaces in policy.json, then re-run with --accept.")
    return errors


def _residual(entry: dict) -> list:
    """Impact that remains after the verdict and its constraint are applied.

    ``impact`` is the worst case with no filter at all, which is what makes the
    inventory useful for ranking. The invariants have to be checked against
    what survives mitigation, otherwise a correctly constrained method like
    ``$readFile`` -- whose constraint is exactly what removes the credential
    reach -- would be indistinguishable from an unmitigated one.

    An entry that claims a constraint removes an impact must say so
    explicitly; absent ``residual_impact`` the full impact stands.
    """
    if "residual_impact" in entry:
        return entry["residual_impact"]
    return entry.get("impact") or []


def check_citations(policy: dict) -> list:
    """Every in-repo path an invariant cites must resolve, and tests must exist.

    An invariant now has to name what checks it, which creates a new way to be
    wrong: naming a check that does not exist. A citation to a missing test
    reads exactly like a citation to a passing one, which is the failure the
    enforcement fields were added to prevent, so the citations are resolved
    rather than trusted.

    Paths are recognised by shape (``dir/file.ext`` with a known source
    extension), so prose is not mistaken for a path. ``path::symbol`` also
    requires the symbol to appear in the file, which is what catches a renamed
    or never-written test.

    A citation that is agreed but not yet landed belongs in
    ``checked_by_pending``, where it is visibly unverified instead of quietly
    wrong, and is exempt from this check.
    """
    errors = []
    path_re = re.compile(r"\b([\w.-]+(?:/[\w.-]+)*\.(?:py|ts|js|sh|json|md))(?:::(\w+))?")
    search_roots = (REPO_ROOT, os.path.join(REPO_ROOT, "rpc-filter", "tools"))
    for entry in policy.get("invariants", []):
        for field in ("enforced_by", "checked_by"):
            text = entry.get(field) or ""
            for rel, symbol in path_re.findall(text):
                full = next((os.path.join(r, rel) for r in search_roots
                             if os.path.isfile(os.path.join(r, rel))), None)
                if full is None:
                    errors.append(
                        "invariant '%s' %s cites %s, which does not exist. If it is agreed "
                        "but not yet landed, record it in checked_by_pending instead."
                        % (entry.get("id", "<unnamed>"), field, rel))
                    continue
                if symbol:
                    with open(full, "r", encoding="utf-8", errors="replace") as fh:
                        if symbol not in fh.read():
                            errors.append(
                                "invariant '%s' %s cites %s::%s, but %s is not in that file."
                                % (entry.get("id", "<unnamed>"), field, rel, symbol, symbol))
    return errors


def check_invariants(inv: dict, policy: dict) -> list:
    errors = []
    for sid, service in policy.get("rpc", {}).items():
        for method, entry in (service.get("methods") or {}).items():
            verdict = entry["verdict"]
            if any(i in CREDENTIAL_IMPACTS for i in _residual(entry)) and verdict in REACHABLE:
                errors.append(
                    "invariant no-real-secret-in-tab: %s.%s still has credential-access impact "
                    "after mitigation but verdict is '%s'. Must be deny or rewrite, or the "
                    "constraint must remove it via residual_impact." % (sid, method, verdict))
            if entry.get("identity_from_argument") and verdict in REACHABLE:
                errors.append(
                    "invariant identity-never-from-arguments: %s.%s takes identity from an "
                    "argument but verdict is '%s'. Must be deny or rewrite."
                    % (sid, method, verdict))
            if entry.get("residual_impact") is not None and not entry.get("constraint") \
                    and verdict not in ("deny", "rewrite"):
                errors.append(
                    "%s.%s claims reduced residual impact but names no constraint."
                    % (sid, method))
    for name, entry in list((policy.get("channels") or {}).items()) \
            + list((policy.get("pushes") or {}).items()):
        if name == "note" or not isinstance(entry, dict):
            continue
        if any(i in CREDENTIAL_IMPACTS for i in _residual(entry)) \
                and entry.get("verdict") in REACHABLE:
            errors.append("invariant no-real-secret-in-tab: channel '%s' is reachable." % name)

    # An invariant that names no enforcement is decoration, and decoration in a
    # policy table reads as assurance. Every listed invariant must say what
    # enforces it and what checks it -- including "not checkable here", which is
    # an honest answer for a rule shared with another component.
    for entry in policy.get("invariants", []):
        for field in ("enforced_by", "checked_by"):
            if not entry.get(field):
                errors.append(
                    "invariant '%s' has no %s. State what enforces it and what checks it; "
                    "if it is an agreement enforced elsewhere, say so explicitly."
                    % (entry.get("id", "<unnamed>"), field))
    errors.extend(check_citations(policy))

    # commands.exact is resolved before rules, so the `seclab.` deny rule can be
    # overridden by an exact entry. The rule states the intent; this is what
    # makes it hold.
    for cid, entry in ((policy.get("commands", {}) or {}).get("exact") or {}).items():
        if cid.startswith("seclab.") and entry.get("verdict") in REACHABLE:
            errors.append(
                "invariant no-seclab-commands-from-tabs: command '%s' is reachable "
                "('%s') through commands.exact, which is resolved before the deny "
                "rule on the 'seclab.' prefix. The fork's own commands exist to ask "
                "the user to approve what a tab may not do itself; a tab that can "
                "raise them supplies the prompt." % (cid, entry.get("verdict")))

    # Every surface that is actually reachable must have been reviewed as an
    # individual entry carrying an impact assessment. Checking only the entries
    # someone chose to write misses exactly the dangerous case: a surface made
    # reachable by a bulk rule that nobody looked at.
    for service in inv["surfaces"]["a_mainthread_rpc"]["services"]:
        methods = sorted(set(service["declared_methods"])
                         | set(service["implemented_methods"]))
        for method in methods:
            verdict, entry = resolve_rpc(policy, service["sid"], method)
            if verdict not in REACHABLE:
                continue
            if entry is None:
                errors.append(
                    "%s.%s is reachable ('%s') through a service default with no reviewed "
                    "entry. Reachability must be granted per method."
                    % (service["sid"], method, verdict))
            elif "impact" not in entry:
                errors.append("%s.%s is reachable but records no impact."
                              % (service["sid"], method))
    for command in inv["surfaces"]["b_command_registry"]["commands"]:
        verdict, entry = resolve_command(policy, command)
        if verdict not in REACHABLE:
            continue
        exact = (policy.get("commands", {}).get("exact") or {})
        if command["id"] not in exact:
            errors.append(
                "command '%s' is reachable ('%s') through a category rule. Reachability must "
                "be granted per id in commands.exact." % (command["id"], verdict))
        elif "impact" not in entry:
            errors.append("command '%s' is reachable but records no impact." % command["id"])
    return errors


def check_undeclared(inv: dict, policy: dict) -> list:
    errors = []
    for service in inv["surfaces"]["a_mainthread_rpc"]["services"]:
        for method in service["undeclared_methods"]:
            _, entry = resolve_rpc(policy, service["sid"], method)
            if entry is None:
                errors.append(
                    "%s.%s is callable via actor[methodName] but is not declared in %s and has "
                    "no explicit verdict. Classify it explicitly."
                    % (service["sid"], method, service["shape"]))
    return errors


def check_enforcement(mapping: dict, policy: dict, repo_root: str) -> list:
    """Every deny verdict must name code that refuses it, and that code must exist.

    A verdict is a claim about runtime behaviour. Written down and checked by
    nothing, it reads as assurance while changing no behaviour at all -- which
    is exactly what happened to ``remoteTerminal.onExecuteCommand``: denied in
    the policy, skipped by a name-based exemption in this file, and enforced
    nowhere, while the increment claimed a tab could not execute host code.

    Three things are checked, because each of the three failed independently at
    some point in this project:

    1. every key prefix carrying a ``deny`` has an entry in ``enforcement``;
    2. the patch it names is in ``patches/series``, so it is actually applied;
    3. the symbol it names appears in that patch, so the entry still points at
       live code after a rewrite rather than at a function that was renamed.

    It deliberately does not try to prove the code *runs*. That is what the
    runtime probes are for; a static gate that claimed it would be one more
    check that passes without asking the question.
    """
    errors = []
    enforcement = policy.get("enforcement") or {}
    prefixes = sorted((k for k in enforcement if k != "note"),
                      key=len, reverse=True)

    # Classes whose enforcement is inherently per-surface. A prefix entry can
    # never stand in for these, and `whole_class` must not be able to buy the
    # exemption: when this rule lived in a flag, injecting the review's own
    # finding back into the policy passed, because the injection simply set the
    # flag. A control the policy file can switch off is not a control.
    PER_KEY_CLASSES = ("push:",)
    for prefix in PER_KEY_CLASSES:
        entry = enforcement.get(prefix)
        if isinstance(entry, dict) and entry.get("whole_class"):
            errors.append(
                "enforcement['%s'] claims whole_class, but this class is "
                "refused one subscription at a time, so a single entry cannot "
                "vouch for its keys. Give each denied key its own entry."
                % prefix)

    denied_prefixes = set()
    for key, value in mapping.items():
        if _verdict_of(value) != "deny":
            continue
        # An exact entry always wins. A prefix entry stands in for its keys
        # only when it is a genuine whole-class control -- one mechanism that
        # covers everything under it. Server-initiated pushes are not like
        # that: each denied push is refused by not registering its own
        # subscription, so a single `push:` entry naming one patch vouched for
        # 18 keys of which exactly one was enforced. That is the finding this
        # gate was written to prevent, reproduced by the gate itself.
        if key in enforcement:
            match = key
        else:
            match = next((p for p in prefixes
                          if key.startswith(p)
                          and enforcement[p].get("whole_class")
                          and not any(key.startswith(c)
                                      for c in PER_KEY_CLASSES)), None)
        if match is None:
            errors.append(
                "no enforcement point for denied surface '%s': add the prefix to "
                "policy.enforcement naming the patch and symbol that refuses it."
                % key)
        else:
            denied_prefixes.add(match)

    series_path = os.path.join(repo_root, "patches", "series")
    series = ""
    if os.path.exists(series_path):
        with open(series_path, encoding="utf-8") as fh:
            series = fh.read()

    for prefix in sorted(denied_prefixes):
        entry = enforcement[prefix]
        if entry.get("unenforced_accepted"):
            # Explicitly accepted as unenforced. Not a pass for the surface --
            # it is a denied capability with nothing refusing it -- but it is
            # recorded and counted rather than hidden, which is the whole
            # difference between a known gap and the silent one this gate
            # exists to catch.
            continue
        patch, symbol = entry.get("patch"), entry.get("symbol")
        if not patch or not symbol:
            errors.append("enforcement['%s'] must name both a patch and a symbol."
                          % prefix)
            continue
        if patch not in series:
            errors.append(
                "enforcement['%s'] names patch '%s', which is not in patches/series, "
                "so nothing applies it." % (prefix, patch))
            continue
        patch_path = os.path.join(repo_root, "patches", patch)
        if not os.path.exists(patch_path):
            errors.append("enforcement['%s'] names patch '%s', which does not exist."
                          % (prefix, patch))
            continue
        with open(patch_path, encoding="utf-8", errors="replace") as fh:
            body = fh.read()
        if symbol not in body:
            errors.append(
                "enforcement['%s'] names symbol '%s', which does not appear in %s. "
                "Either the enforcement moved and the entry is stale, or it was "
                "removed and the deny verdict is now unenforced."
                % (prefix, symbol, patch))
    return errors


def check_log_trust(mapping: dict) -> list:
    """Hold the two facts the decision log's trustworthiness rests on.

    The Tab Manager forwards `seclabRpcFilter.log` to tabd as *trusted*. That
    is only sound while a tab can neither forge lines nor write the file, and
    both are policy decisions that could be relaxed by someone who has no idea
    a log depends on them. Stated in a comment, the dependency would be found
    again only after it stopped holding.
    """
    errors = []
    for key, value in mapping.items():
        if key.startswith("rpc:MainThreadLogger.") \
                and _verdict_of(value) != "deny":
            errors.append(
                "invariant rpc-filter-log-is-trustworthy: %s is not denied, so "
                "a tab could forge lines in the filter's decision log." % key)
    writes = ("rpc:MainThreadFileSystem.$writeFile",
              "rpc:MainThreadFileSystem.$mkdir",
              "rpc:MainThreadFileSystem.$copy",
              "rpc:MainThreadFileSystem.$rename")
    for key in writes:
        value = mapping.get(key)
        if value is None:
            continue
        verdict = _verdict_of(value)
        if key.endswith("$writeFile"):
            if verdict not in ("deny", "allow_with_constraint"):
                errors.append(
                    "invariant rpc-filter-log-is-trustworthy: %s is '%s'. It "
                    "must stay denied or URI-constrained, or a tab can write "
                    "the window logs directory directly." % (key, verdict))
        elif verdict != "deny":
            errors.append(
                "invariant rpc-filter-log-is-trustworthy: %s is not denied, "
                "which reopens a create-then-rename route into the window "
                "logs directory." % key)
    return errors


def _leaf_problem(cid: str, entry: dict, exceptions: set) -> str | None:
    """Why a reachable command is not an acceptable leaf exception, or None."""
    if cid not in exceptions:
        return "it is not one of the residual's recorded leaf_exceptions"
    if entry.get("verdict") != "allow_with_constraint":
        return "a leaf exception must be allow_with_constraint, with its arguments validated"
    if entry.get("leaf") is not True:
        return "its entry does not claim leaf: true"
    if not entry.get("leaf_evidence"):
        return "its entry gives no leaf_evidence that the handler never reaches ICommandService"
    if not entry.get("validator"):
        return "its entry names no argument validator"
    return None


def check_residuals(mapping: dict, policy: dict) -> list:
    """Hold the conditions a recorded residual says it depends on.

    A residual risk written only in prose is forgotten exactly when it stops
    being true. ``deferred-laundering`` is safe only while no reachable command
    can launder: with every command denied, a laundered call is refused for
    being denied rather than for being laundered. The moment someone allows a
    command -- a reasonable thing to want, and the obvious next compatibility
    fix -- the gap becomes reachable, and nothing in review would connect that
    change to a paragraph in section 7.

    So the dependency is checked rather than described. While the residual is
    open, a command may be reachable only as a recorded **leaf exception**: its
    handler is shown (``leaf_evidence``) never to reach ICommandService, so there
    is nothing to launder, and its arguments are validated (``validator``),
    because a leaf can still leak or spoof host state on its own. Any other
    reachable command fails the build until the residual is marked fixed.
    """
    errors = []
    residuals = policy.get("residuals") or {}
    entry = residuals.get("deferred-laundering")
    if isinstance(entry, dict) and not entry.get("fixed"):
        exceptions = set(entry.get("leaf_exceptions") or [])
        exact = (policy.get("commands", {}) or {}).get("exact") or {}
        reachable = sorted(
            key for key, value in mapping.items()
            if key.startswith("cmd:") and _verdict_of(value) != "deny")
        offenders = []
        for key in reachable:
            why = _leaf_problem(key[4:], exact.get(key[4:]) or {}, exceptions)
            if why:
                offenders.append((key, why))
        for key, why in offenders[:20]:
            errors.append(
                "%s is not denied, but the deferred-laundering residual is "
                "unfixed: a handler that defers a global executeCommand "
                "escapes both the taint and the backstop, and %s. Fix the "
                "residual and set residuals['deferred-laundering'].fixed, or "
                "keep the verdict at deny." % (key, why))
        if len(offenders) > 20:
            errors.append("... and %d more non-denied commands."
                          % (len(offenders) - 20))
        for cid in sorted(exceptions - {k[4:] for k in reachable}):
            errors.append(
                "residuals['deferred-laundering'].leaf_exceptions names %s, "
                "which is not reachable. A stale exception is a pre-approved "
                "allow waiting for someone to flip the verdict; remove it." % cid)
    return errors


def check_validators(policy: dict, source: str) -> list:
    """Every named validator exists, is used, and sits on a verdict that runs it.

    A validator name the filter cannot find denies at run time, which is the
    safe direction but breaks the surface silently; a validator nothing names is
    dead code that reads as protection. Both fail here.
    """
    errors = []
    m = re.search(r"SECLAB_VALIDATORS[^=]*=\s*new Map\(\[(.*?)\]\);", source, re.S)
    defined = set(re.findall(r"\[\s*'(\w+)'\s*,", m.group(1))) if m else set()
    if not defined:
        return ["seclabArgValidators.ts defines no SECLAB_VALIDATORS map"]
    used = set()
    entries = []
    for sid, service in (policy.get("rpc") or {}).items():
        for method, e in (service.get("methods") or {}).items():
            entries.append(("rpc:%s.%s" % (sid, method), e))
    for cid, e in ((policy.get("commands", {}) or {}).get("exact") or {}).items():
        entries.append(("cmd:%s" % cid, e))
    for ref, e in entries:
        name = e.get("validator")
        if name is None:
            if ref.startswith("cmd:") and e.get("verdict") == "allow_with_constraint":
                errors.append("%s is allow_with_constraint but names no validator; "
                              "its constraint would deny every call" % ref)
            continue
        used.add(name)
        if name not in defined:
            errors.append("%s names validator '%s', which seclabArgValidators.ts "
                          "does not define" % (ref, name))
        if e.get("verdict") not in ("allow_with_constraint", "rewrite"):
            errors.append("%s names validator '%s' but its verdict '%s' never runs it"
                          % (ref, name, e.get("verdict")))
    for name in sorted(defined - used):
        errors.append("validator '%s' is defined but no policy entry names it" % name)
    return errors


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--accept", action="store_true",
                        help="record the current mapping as reviewed (use after classifying)")
    args = parser.parse_args(argv)

    for path in (INVENTORY, POLICY):
        if not os.path.isfile(path):
            print("error: %s missing; regenerate the inventory first" % path, file=sys.stderr)
            return 2

    inv = _load(INVENTORY)
    policy = _load(POLICY)

    if inv["upstream_sha"] != policy["upstream_sha"]:
        print("error: inventory is at %s but policy claims %s"
              % (inv["upstream_sha"][:12], policy["upstream_sha"][:12]), file=sys.stderr)
        return 2

    mapping = build_mapping(inv, policy)

    if args.accept:
        with open(COVERAGE, "w", encoding="utf-8") as fh:
            json.dump({
                "upstream_sha": inv["upstream_sha"],
                "digest": digest(mapping),
                "surface_count": len(mapping),
                "mapping": mapping,
            }, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print("recorded %d surfaces, digest %s" % (len(mapping), digest(mapping)[:16]))
        return 0

    failures = []
    for name, check in (("keys", lambda: check_keys(inv, policy)),
                        ("undeclared", lambda: check_undeclared(inv, policy)),
                        ("invariants", lambda: check_invariants(inv, policy)),
                        ("coverage", lambda: check_coverage(mapping)),
                        ("enforcement",
                         lambda: check_enforcement(mapping, policy, REPO_ROOT)),
                        ("residuals",
                         lambda: check_residuals(mapping, policy)),
                        ("validators", lambda: check_validators(policy, _read(VALIDATORS_SRC))),
                        ("log-trust", lambda: check_log_trust(mapping))):
        errors = check()
        if errors:
            failures.append((name, errors))

    accepted = sorted(k for k, v in (policy.get("enforcement") or {}).items()
                      if isinstance(v, dict) and v.get("unenforced_accepted"))
    if accepted:
        print("WARNING: %d denied surfaces are accepted-unenforced (no code "
              "refuses them):" % len(accepted))
        for k in accepted:
            print("  %s" % k)

    if not failures:
        reachable = sum(1 for v in mapping.values() if _verdict_of(v) in REACHABLE)
        print("drift check passed: %d surfaces, %d reachable, %d denied"
              % (len(mapping), reachable, len(mapping) - reachable))
        return 0

    for name, errors in failures:
        print("FAIL [%s]" % name, file=sys.stderr)
        for e in errors:
            print("  %s" % e, file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
