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
    for sink in inv["surfaces"]["d_tab_supplied_data"]["upstream_sinks"]:
        entry = (policy.get("tab_data") or {}).get(sink["surface"])
        record("data:%s" % sink["surface"],
               entry["verdict"] if entry else policy["default_verdict"], entry)
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
        if name in ("note", "server_initiated"):
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
    for name, entry in (policy.get("channels") or {}).items():
        if name in ("note", "server_initiated") or not isinstance(entry, dict):
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
                        ("coverage", lambda: check_coverage(mapping))):
        errors = check()
        if errors:
            failures.append((name, errors))

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
