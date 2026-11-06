"""Engine-agnostic broker state: policy, credentials, approvals, audit, control methods.

The proxy engine (see engine_mitmproxy.py) calls into Broker for every decision.
Control clients (see control.py) call the rpc_* methods.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import re
import secrets
import sys
import time
import uuid
from collections import deque
from dataclasses import dataclass, field, replace
from typing import Any, Callable

from . import POLICY_SCHEMA_REVISION, POLICY_SCHEMA_VERSION, PROTOCOL, VERSION, protocol
from .credentials import Credential, CredentialStore
from .models import Budget
from .untrusted import display_path, sanitize, untrusted_paths
from .policy import (LITERAL_PATH_RE, Binding, DenyRule, Inject, Policy, PolicyError, RequestView, Rule, normalize_ip,
                     check_budget_bindings, parse_bindings, parse_budget, parse_derive, pattern_overlaps_risky,
                     risk_flags, validate_fragment)

log = logging.getLogger("seclab.broker")

DECISIONS = ("allow-once", "allow-tab", "deny", "deny-new-destinations")
# The policy schema's caps on `allow` and `deny` (policy.v1.schema.json maxItems).
MAX_ALLOW_RULES = 1024
MAX_DENY_RULES = 1024
REQUEST_KEYS = ("host", "method", "path", "rawAuthority", "detail", "tools", "queryKeys")
_USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_PASS_RE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")  # >= 128 bits as base64url
_LABEL_RE = re.compile(r"^[A-Za-z0-9._:-]{1,96}$")
_SOURCE_KINDS = ("workspace-scan", "password-input", "user", "host")
TAB_EVENTS = ("opened", "userAction")


def _hostile(flags: list[str]) -> bool:
    """Destinations that never get `allow-tab` and are gated until the first user action."""
    return any(f in ("raw-ip", "ip-in-hostname") or f.startswith("risky-destination:") for f in flags)


class RpcError(Exception):
    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(message)
        self.code, self.message, self.data = code, message, data


def invalid(msg: str) -> RpcError:
    return RpcError(-32602, msg)


@dataclass
class Approval:
    id: str
    kind: str  # egress | credential-binding
    key: tuple
    request: dict
    created: float
    deadline: float
    suggested: dict
    decisions: tuple[str, ...]
    risk: dict
    credential_id: str | None = None
    view: RequestView | None = None  # the real held request; `request` is its display form
    waiters: list[asyncio.Future] = field(default_factory=list)

    def public(self) -> dict:
        out = {"approvalId": self.id, "kind": self.kind, "request": self.request,
               "createdAt": self.created, "expiresAt": self.deadline, "waiting": len(self.waiters),
               "decisions": list(self.decisions), "risk": self.risk,
               "untrusted": ["request.host", "request.method", "request.path"]
               + (["request.queryKeys"] if "queryKeys" in self.request else [])
               + (["request.clientPort"] if "clientPort" in self.request else [])
               + (["risk.origin.label"] if self.risk.get("origin", {}).get("label") else [])}
        if self.kind == "egress":
            out["suggestedRule"] = self.suggested
            out["untrusted"].append("suggestedRule.host")
        else:
            out["credentialId"] = self.credential_id
            out["suggestedBinding"] = self.suggested
            out["untrusted"] += ["suggestedBinding.host", "suggestedBinding.path", "suggestedBinding.methods"] + (
                ["suggestedBinding.inject.header", "suggestedBinding.inject.fmt"] if "inject" in self.suggested else [])
        return sanitize(out)


def binding_untrusted(prefix: str) -> list[str]:
    return [f"{prefix}.{k}" for k in ("host", "path", "methods", "inject.header", "inject.fmt")]


@dataclass
class Decision:
    allow: bool
    reason: str
    once: bool = False


class Broker:
    def __init__(self, tab_id: str | None = None, engine: str = "mitmproxy",
                 engine_version: str = "") -> None:
        self.tab_id = tab_id
        self.engine, self.engine_version = engine, engine_version
        self.policy = Policy.deny_all()
        self.revision = 0
        self.creds = CredentialStore()
        self.approvals: dict[str, Approval] = {}
        self._approval_by_key: dict[tuple, str] = {}
        self._cooldown: dict[tuple, float] = {}
        self._cred_waiters: dict[str, list[asyncio.Future]] = {}
        self.held = 0
        self._proxy_auth: tuple[bytes, bytes] | None = None
        self.auth_epoch = 0
        self.ca_pem: str | None = None
        self.started = time.time()
        self._audit_seq = 0
        self._audit_ring: deque[dict] = deque(maxlen=2000)
        self._sinks: set[Callable[[str, dict], None]] = set()
        self.proxy_listening = False
        self.on_shutdown: Callable[[], None] | None = None
        # Session prompt state (survives policy.load; cleared by prompt.reset).
        self.opened_at = time.time()
        self.user_action_at: float | None = None
        self.deny_new = False
        self.session_denials = 0
        self._prompt_times: deque[float] = deque()
        # Model-host usage for this tab's lifetime (never reset by policy.load).
        self.model_usage = Budget()
        # Per-credential usage for this tab's lifetime, by credential id (revision 6).
        self.credential_usage: dict[str, Budget] = {}

    # --------------------------------------------------------- credential budgets
    def _budget_chain(self, cred: Credential) -> list[Credential]:
        """The credential and every credential it was derived from, up to the root: a derived
        token's use counts against each ancestor's budget (review 13-2)."""
        out, seen = [cred], {cred.id}
        c = cred
        while c.parent_id and c.parent_id not in seen:
            parent = self.creds.get(c.parent_id)
            if parent is None:
                break
            out.append(parent)
            seen.add(parent.id)
            c = parent
        return out

    def credential_budget_exceeded(self, cred: Credential) -> tuple[str, str] | None:
        """(credential id, reason) if this credential, or the one it derives from, is out of
        budget; None otherwise. Over budget is denied, never prompted."""
        for c in self._budget_chain(cred):
            if c.budget is None:
                continue
            used = self.credential_usage.get(c.id, Budget())
            max_req, max_bytes = c.budget
            if max_req is not None and used.requests >= max_req:
                return c.id, "request budget exhausted"
            if max_bytes is not None and used.bytes >= max_bytes:
                return c.id, "byte budget exhausted"
        return None

    def credential_bytes_left(self, cred: Credential) -> tuple[int, str] | None:
        """The fewest bytes left on any byte budget in the credential's chain, and that
        budget's credential id; None if none is capped (revision 8: bounds a broker-followed
        redirect's read)."""
        left = [(max(0, c.budget[1] - self.credential_usage.get(c.id, Budget()).bytes), c.id)
                for c in self._budget_chain(cred) if c.budget is not None and c.budget[1] is not None]
        return min(left) if left else None

    def charge_credential(self, cred: Credential, requests: int = 0, nbytes: int = 0) -> None:
        for c in self._budget_chain(cred):
            used = self.credential_usage.setdefault(c.id, Budget())
            used.requests += requests
            used.bytes += nbytes

    # ------------------------------------------------------------------ sinks
    def add_sink(self, sink: Callable[[str, dict], None]) -> None:
        self._sinks.add(sink)

    def remove_sink(self, sink: Callable[[str, dict], None]) -> None:
        self._sinks.discard(sink)

    @property
    def controllers(self) -> int:
        return len(self._sinks)

    def notify(self, method: str, params: dict) -> None:
        for sink in list(self._sinks):
            try:
                sink(method, params)
            except Exception:  # a broken controller must not break the proxy
                log.exception("notification sink failed")

    def audit(self, type_: str, **fields: Any) -> None:
        self._audit_seq += 1
        event = {"seq": self._audit_seq, "ts": round(time.time(), 3), "type": type_}
        if self.tab_id:
            event["tabId"] = self.tab_id
        event.update(fields)
        # The tab's own request fields can never hold a real value (none ever enters the
        # tab), so only host- and policy-supplied values and sentinels are scrubbed there;
        # upstream-derived values must not be able to erase them (review round 5 #1).
        event = {k: (self.creds.scrub(v, derived=False) if k in REQUEST_KEYS and isinstance(v, str)
                     else [self.creds.scrub(x, derived=False) if isinstance(x, str) else x for x in v]
                     if k in REQUEST_KEYS and isinstance(v, list)
                     else self._scrub_obj(v)) for k, v in event.items()}
        event = sanitize(event)
        tagged = untrusted_paths(event)
        if tagged:
            event["untrusted"] = tagged
        self._audit_ring.append(event)
        print(json.dumps({"audit": event}, separators=(",", ":")), file=sys.stderr, flush=True)
        self.notify("audit.event", event)

    def _scrub_obj(self, obj: Any) -> Any:
        if isinstance(obj, str):
            return self.creds.scrub(obj)
        if isinstance(obj, dict):
            return {k: self._scrub_obj(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self._scrub_obj(v) for v in obj]
        return obj

    # ------------------------------------------------------------- proxy auth
    def check_proxy_auth(self, username: str | None, password: str | None) -> tuple[bool, str | None]:
        """(ok, origin label). The username may carry an origin label: `<user>+<label>`.
        The label is set by whatever launched the client inside the tab, so it is
        advisory only (any process in the tab can claim any label)."""
        if self._proxy_auth is None or username is None or password is None:
            return False, None
        base, sep, label = username.partition("+")
        label_ok = not sep or bool(_LABEL_RE.fullmatch(label))
        u_ok = hmac.compare_digest(base.encode("utf-8", "surrogateescape"), self._proxy_auth[0])
        p_ok = hmac.compare_digest(password.encode("utf-8", "surrogateescape"), self._proxy_auth[1])
        if u_ok & p_ok & label_ok:
            return True, (label if sep else None)
        return False, None

    # ------------------------------------------------------------------ risk
    def risk(self, req: RequestView, origin: str | None) -> dict:
        now = time.time()
        since_open = round(now - self.opened_at, 1)
        flags = risk_flags(req, self.policy.risky)
        if self.user_action_at is None and since_open <= self.policy.prompt.quiet_period_seconds:
            flags.append("early-after-open")
        if self.user_action_at is None:
            flags.append("no-user-action-yet")
        return {"flags": flags, "origin": {"label": origin, "verified": False},
                "secondsSinceOpen": since_open, "userActionSeen": self.user_action_at is not None}

    # -------------------------------------------------------------- decisions
    def allowed(self, req: RequestView) -> Rule | None:
        return self.policy.allow_match(req)

    async def ask_egress(self, req: RequestView, origin: str | None = None) -> Decision:
        risk = self.risk(req, origin)
        flags = risk["flags"]
        hostile = _hostile(flags)
        cfg = self.policy.prompt
        if self.deny_new:
            return self._deny_unprompted("deny-new-destinations", req, risk)
        if "raw-ip" in flags and cfg.raw_ip_destinations == "deny":
            return self._deny_unprompted("raw-ip-destination", req, risk)
        if hostile and cfg.auto_deny_risky_before_user_action and self.user_action_at is None:
            return self._deny_unprompted("risky-before-user-action", req, risk)
        key = ("egress",) + req.origin
        suggested = {"host": req.host, "schemes": [req.scheme], "ports": [req.port],
                     "methods": ["*"], "path": "/**"}
        decisions = ["allow-once"] + ([] if hostile else ["allow-tab"]) + ["deny"]
        if self.session_denials >= cfg.offer_deny_new_after:
            decisions.append("deny-new-destinations")
        return await self._ask(key, "egress", req, suggested, None, tuple(decisions), risk)

    async def ask_binding(self, req: RequestView, cred: Credential, inject: Inject | None,
                          origin: str | None = None) -> Decision:
        key = ("binding", cred.id, req.scheme, req.host, req.port, req.method, req.path,
               inject.header.lower() if inject else None, inject.fmt if inject else None)
        # The suggested path is the request path *as a literal*. Binding paths are globs, so
        # a tab-chosen path like `/x/**` must never become a wildcard suggestion; a path the
        # binding grammar cannot express literally is shown encoded and cannot be persisted.
        literal = LITERAL_PATH_RE.fullmatch(req.path) is not None
        suggested = {"host": req.host, "path": req.path if literal else display_path(req.path).replace("*", "%2A"),
                     "methods": [req.method], "ports": [req.port]}
        if inject is not None:
            suggested["inject"] = inject.to_json()
        risk = self.risk(req, origin)
        hostile = _hostile(risk["flags"])
        decisions = ("allow-once", "deny") if hostile or not literal else ("allow-once", "allow-tab", "deny")
        return await self._ask(key, "credential-binding", req, suggested, cred.id, decisions, risk)

    def _deny_unprompted(self, reason: str, req: RequestView, risk: dict) -> Decision:
        self.audit("request.denied_unprompted", reason=reason, risk=risk, **req.summary())
        return Decision(False, reason)

    async def _ask(self, key: tuple, kind: str, req: RequestView, suggested: dict,
                   cred_id: str | None, decisions: tuple[str, ...], risk: dict) -> Decision:
        cfg = self.policy.prompt
        if not cfg.enabled:
            return Decision(False, "prompt-disabled")
        if not self._sinks:
            return Decision(False, "no-controller")
        now = time.time()
        if self._cooldown.get(key, 0) > now:
            return Decision(False, "deny-cooldown")
        if self.held >= cfg.max_held_flows:
            self.audit("approval.queue_full", limit="maxHeldFlows", **req.summary())
            return Decision(False, "hold-queue-full")
        aid = self._approval_by_key.get(key)
        approval = self.approvals.get(aid) if aid else None
        if approval is None:
            if len(self.approvals) >= cfg.max_pending:
                self.audit("approval.queue_full", limit="maxPending", **req.summary())
                return Decision(False, "approval-queue-full")
            while self._prompt_times and now - self._prompt_times[0] > 60:
                self._prompt_times.popleft()
            if len(self._prompt_times) >= cfg.max_per_minute:
                self.audit("approval.rate_limited", limit=cfg.max_per_minute, risk=risk, **req.summary())
                return Decision(False, "prompt-rate-limited")
            self._prompt_times.append(now)
            approval = Approval(id=uuid.uuid4().hex, kind=kind, key=key, request=req.summary(), view=req,
                                created=now, deadline=now + cfg.timeout_seconds,
                                suggested=suggested, decisions=decisions, risk=risk,
                                credential_id=cred_id)
            self.approvals[approval.id] = approval
            self._approval_by_key[key] = approval.id
            asyncio.get_running_loop().call_at(
                asyncio.get_running_loop().time() + cfg.timeout_seconds,
                self._expire, approval.id)
            self.audit("approval.requested", approvalId=approval.id, kind=kind,
                       credentialId=cred_id, risk=risk, **req.summary())
            self.notify("approval.requested", approval.public())
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        approval.waiters.append(fut)
        self.held += 1
        try:
            return await fut
        finally:
            self.held -= 1

    def _expire(self, aid: str) -> None:
        if aid in self.approvals:
            self._resolve(aid, "deny", by="timeout")

    def _resolve(self, aid: str, decision: str, by: str) -> Approval:
        approval = self.approvals.pop(aid)
        self._approval_by_key.pop(approval.key, None)
        allow = decision in ("allow-once", "allow-tab")
        if not allow and by != "deny-rule":
            # A user's block isn't a prompt refusal: no cooldown that would outlive an unblock,
            # and no step toward offering deny-new-destinations (review 12-3/12-4).
            self.session_denials += 1
            self._cooldown[approval.key] = time.time() + self.policy.prompt.deny_cooldown_seconds
        result = Decision(allow, f"{decision}:{by}", once=decision == "allow-once")
        for fut in approval.waiters:
            if not fut.done():
                fut.set_result(result)
        self.audit("approval.resolved", approvalId=aid, kind=approval.kind, decision=decision, by=by)
        self.notify("approval.resolved", {"approvalId": aid, "decision": decision, "by": by})
        return approval

    async def wait_for_value(self, cred: Credential) -> bool:
        if cred.has_value():
            return True
        if not self._sinks:
            return False
        if self.held >= self.policy.prompt.max_held_flows:
            return False
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        waiters = self._cred_waiters.setdefault(cred.id, [])
        first = not waiters
        waiters.append(fut)
        if first:
            self.audit("credential.needed", credentialId=cred.id)
            self.notify("credential.needed", {"id": cred.id})
        self.held += 1
        try:
            await asyncio.wait_for(asyncio.shield(fut), self.policy.prompt.timeout_seconds)
        except asyncio.TimeoutError:
            self.audit("credential.unavailable", credentialId=cred.id, reason="timeout")
            return False
        finally:
            self.held -= 1
            if fut in waiters:
                waiters.remove(fut)
            if not waiters:
                self._cred_waiters.pop(cred.id, None)
        return cred.has_value()

    # ------------------------------------------------------------ rpc methods
    def rpc_broker_hello(self, params: dict) -> dict:
        return {"protocol": PROTOCOL, "version": VERSION, "tabId": self.tab_id,
                "engine": self.engine, "engineVersion": self.engine_version,
                "policySchema": {"version": POLICY_SCHEMA_VERSION, "revision": POLICY_SCHEMA_REVISION},
                "capabilities": CAPABILITIES}

    def rpc_health(self, params: dict) -> dict:
        return {
            "status": "ok" if self.proxy_listening else "starting",
            "uptimeSeconds": round(time.time() - self.started, 1),
            "proxy": {"listening": self.proxy_listening, "authConfigured": self._proxy_auth is not None},
            "policy": {"revision": self.revision, "rules": len(self.policy.rules),
                       "credentials": len(self.policy.credentials)},
            "pendingApprovals": len(self.approvals),
            "heldFlows": self.held,
            "credentials": len(self.creds.all()),
            "controllers": self.controllers,
            "prompt": {"denyNewDestinations": self.deny_new, "sessionDenials": self.session_denials,
                       "promptsLastMinute": sum(1 for t in self._prompt_times if time.time() - t <= 60),
                       "userActionSeen": self.user_action_at is not None},
            "models": {"requests": self.model_usage.requests, "bytes": self.model_usage.bytes,
                       "maxRequests": self.policy.models.max_requests, "maxBytes": self.policy.models.max_bytes},
            # Revision 6: usage of every budgeted credential (review 13-7).
            "credentialBudgets": [
                {"id": c.id, "requests": self.credential_usage.get(c.id, Budget()).requests,
                 "bytes": self.credential_usage.get(c.id, Budget()).bytes,
                 **({"maxRequests": c.budget[0]} if c.budget[0] is not None else {}),
                 **({"maxBytes": c.budget[1]} if c.budget[1] is not None else {})}
                for c in self.creds.all() if c.budget is not None],
        }

    def rpc_tab_event(self, params: dict) -> dict:
        kind = params["kind"]
        if kind == "opened":
            self.opened_at = time.time()
            self.user_action_at = None
        else:
            self.user_action_at = time.time()
        self.audit("tab.event", kind=kind)
        return {}

    def rpc_prompt_reset(self, params: dict) -> dict:
        self.deny_new = False
        self.session_denials = 0
        self._cooldown.clear()
        self._prompt_times.clear()
        self.audit("prompt.reset")
        return {}

    def rpc_proxy_auth_set(self, params: dict) -> dict:
        user, pw = params.get("username"), params.get("password")
        if not isinstance(user, str) or not _USER_RE.fullmatch(user):
            raise invalid("username must match [A-Za-z0-9._-]{1,64}")
        if not isinstance(pw, str) or not _PASS_RE.fullmatch(pw):
            raise invalid("password must be 22-128 characters of [A-Za-z0-9_-] (>=128 bits)")
        self._proxy_auth = (user.encode(), pw.encode())
        self.auth_epoch += 1
        self.audit("proxy.auth_set", epoch=self.auth_epoch)
        return {"epoch": self.auth_epoch}

    def rpc_policy_load(self, params: dict) -> dict:
        obj = params.get("policy")
        policy = Policy.from_json(obj)
        if self.tab_id and policy.tab_id and policy.tab_id != self.tab_id:
            raise invalid("policy tabId does not match this broker")
        self.creds.apply_policy(policy.credentials)
        self.policy = policy
        self.revision += 1
        self._cooldown.clear()
        self.audit("policy.loaded", revision=self.revision, rules=len(policy.rules),
                   credentials=[c.id for c in policy.credentials], denyRules=len(policy.deny))
        self._resolve_denied_prompts()
        return {"revision": self.revision,
                "sentinels": {c.id: c.sentinel for c in self.creds.all() if c.origin == "policy"}}

    def _resolve_denied_prompts(self) -> None:
        """Prompts waiting on a now-blocked destination resolve as deny, never as a later
        allow (revision 5)."""
        for aid, approval in list(self.approvals.items()):
            if approval.view is not None and self.policy.deny_match(approval.view) is not None:
                self._resolve(aid, "deny", by="deny-rule")

    def rpc_policy_get(self, params: dict) -> dict:
        out = {"revision": self.revision, "policy": self.policy.to_json()}
        tagged = [f"policy.allow.{i}.host" for i, r in enumerate(self.policy.rules) if r.source == "approval"]
        if tagged:
            out["untrusted"] = tagged
        return out  # rules are schema-restricted ASCII; capping would corrupt what is persisted

    def rpc_policy_update(self, params: dict) -> dict:
        add = params.get("addAllow", [])
        remove = params.get("removeAllow", [])
        add_deny = params.get("addDeny", [])
        remove_deny = params.get("removeDeny", [])
        if not all(isinstance(x, list) for x in (add, remove, add_deny, remove_deny)):
            raise invalid("addAllow, removeAllow, addDeny and removeDeny must be arrays")
        new_rules = [Rule.from_json(r) for r in add]
        existing_ids = {r.id for r in self.policy.rules if r.id}
        for rid in remove:
            if rid not in existing_ids:
                raise invalid(f"no allow rule with id {rid!r}")
        for r in new_rules:
            if r.id and (r.id in existing_ids and r.id not in remove):
                raise invalid(f"duplicate allow rule id {r.id!r}")
        try:
            new_deny = [DenyRule.from_json(d) for d in add_deny]
        except PolicyError as e:
            raise invalid(str(e)) from None
        deny_ids = {d.id for d in self.policy.deny}
        for did in remove_deny:
            if did not in deny_ids:
                raise invalid(f"no deny rule with id {did!r}")
        added_ids = [d.id for d in new_deny]
        if len(set(added_ids)) != len(added_ids) or any(d in deny_ids and d not in remove_deny for d in added_ids):
            raise invalid("duplicate deny rule id")
        # Stay within the schema caps, so what policy.get returns can always be reloaded
        # (review 12-6): a controller that persists and replays must never lose its blocks.
        n_rules = len([r for r in self.policy.rules if r.id not in remove]) + len(new_rules)
        n_deny = len([d for d in self.policy.deny if d.id not in remove_deny]) + len(new_deny)
        if n_rules > MAX_ALLOW_RULES or n_deny > MAX_DENY_RULES:
            raise invalid(f"policy would exceed {MAX_ALLOW_RULES} allow or {MAX_DENY_RULES} deny rules")
        self.policy.rules = [r for r in self.policy.rules if r.id not in remove] + new_rules
        self.policy.deny = [d for d in self.policy.deny if d.id not in remove_deny] + new_deny
        self.revision += 1
        change = {"added": [r.to_json() for r in new_rules], "removed": remove}
        if add_deny or remove_deny:
            change.update(addedDeny=[d.to_json() for d in new_deny], removedDeny=remove_deny)
        self.audit("policy.updated", revision=self.revision, **change)
        self.notify("policy.changed", {"revision": self.revision, **change, "by": "controller"})
        self._resolve_denied_prompts()
        return {"revision": self.revision}

    def rpc_credential_provide(self, params: dict) -> dict:
        cid = params.get("id")
        exp = params.get("expiresAt")
        if exp is not None and not isinstance(exp, (int, float)):
            raise invalid("expiresAt must be a number (unix seconds)")
        try:
            cred = self.creds.provide(cid, params.get("value"), exp)
        except KeyError:
            raise invalid("unknown credential id") from None
        self.audit("credential.provided", credentialId=cred.id, expiresAt=exp)
        for fut in self._cred_waiters.get(cred.id, []):
            if not fut.done():
                fut.set_result(True)
        return {}

    def rpc_credential_revoke(self, params: dict) -> dict:
        try:
            cred = self.creds.revoke(params.get("id"), bool(params.get("rotateSentinel", False)))
        except KeyError:
            raise invalid("unknown credential id") from None
        self.audit("credential.revoked", credentialId=cred.id,
                   rotated=bool(params.get("rotateSentinel", False)))
        return {"sentinel": cred.sentinel}

    def rpc_credential_import(self, params: dict) -> dict:
        cid = params.get("id")
        validate_fragment("id", cid)
        inject = Inject.from_json(params["inject"]) if "inject" in params else None
        bind = parse_bindings(params["bind"], inject) if params.get("bind") else []
        proposed = parse_bindings(params["proposedBind"], inject) if params.get("proposedBind") else []
        provider = params.get("provider")
        if provider is not None and (not isinstance(provider, str) or not re.match(r"^[a-z0-9-]{1,32}$", provider)):
            raise invalid("invalid provider")
        source = params.get("source") or {"kind": "host"}
        if not isinstance(source, dict) or source.get("kind") not in _SOURCE_KINDS:
            raise invalid(f"source.kind must be one of {_SOURCE_KINDS}")
        source = {k: v for k, v in source.items() if k in ("kind", "path", "rule", "label")
                  and isinstance(v, str) and len(v) <= 512}
        derive = parse_derive(params.get("derive", []))
        budget = parse_budget(cid, params.get("budget"), [*bind, *proposed], derive)
        cred = self.creds.import_credential(cid, params.get("value"), params.get("sentinel"),
                                            bind, proposed, provider, source, derive, budget)
        self.audit("credential.imported", credentialId=cred.id, confirmed=cred.confirmed,
                   source=source)
        return {"id": cred.id, "sentinel": cred.sentinel, "confirmed": cred.confirmed}

    def rpc_credential_list(self, params: dict) -> dict:
        creds = self.creds.all()
        out = {"credentials": [c.public() for c in creds]}
        tagged = [p for i, c in enumerate(creds) for j, b in enumerate(c.bindings) if b.source == "approval"
                  for p in binding_untrusted(f"credentials.{i}.bind.{j}")]
        if tagged:
            out["untrusted"] = tagged
        return out  # bindings are schema-restricted ASCII; capping would corrupt what is persisted

    def rpc_approval_list(self, params: dict) -> dict:
        return {"approvals": [a.public() for a in self.approvals.values()]}

    def rpc_approval_decide(self, params: dict) -> dict:
        aid, decision = params.get("approvalId"), params.get("decision")
        if decision not in DECISIONS:
            raise invalid(f"decision must be one of {DECISIONS}")
        approval = self.approvals.get(aid) if isinstance(aid, str) else None
        if approval is None:
            raise invalid("unknown or already resolved approvalId")
        if decision not in approval.decisions:
            raise invalid(f"decision {decision!r} is not offered for this approval")
        if decision == "deny-new-destinations":
            self.deny_new = True
            self.audit("prompt.deny_new", approvalId=aid)
            self._resolve(aid, decision, by="controller")
            for other in [a.id for a in self.approvals.values() if a.kind == "egress"]:
                self._resolve(other, "deny", by="controller")
            return {}
        if decision == "allow-tab":
            held = approval.view
            if held is None:
                raise invalid("approval has no held request")
            if approval.kind == "egress":
                rule = replace(Rule.from_json(params.get("rule") or approval.suggested), source="approval")
                # Broker-enforced, not just client-enforced: an approval can only widen
                # policy around the request it was asked about, never onto risky hosts.
                if not rule.matches(held):
                    raise invalid("rule does not cover the held request")
                if normalize_ip(rule.host.text.removeprefix("*.")) is not None or \
                        pattern_overlaps_risky(rule.host.text, self.policy.risky):
                    raise invalid("an approval cannot add a rule for a raw IP or a risky destination")
                if len(self.policy.rules) >= MAX_ALLOW_RULES:
                    # Stay reloadable (review 12b-1); the controller can still answer allow-once.
                    raise invalid(f"policy already has {MAX_ALLOW_RULES} allow rules")
                self.policy.rules.append(rule)
                self.revision += 1
                self.notify("policy.changed", {
                    "revision": self.revision, "added": [rule.to_json()], "removed": [], "by": "approval",
                    "approvalId": aid, "untrusted": ["added.0.host"]})
            else:
                cred = self.creds.get(approval.credential_id or "")
                if cred is None:
                    raise invalid("credential no longer exists")
                binding = replace(Binding.from_json(params.get("binding") or approval.suggested), source="approval")
                if not binding.matches(held):
                    raise invalid("binding does not cover the held request")
                if pattern_overlaps_risky(binding.host.text, self.policy.risky):
                    raise invalid("an approval cannot bind a credential to a risky destination")
                check_budget_bindings(cred.id, cred.budget, [binding])
                self.creds.confirm_binding(cred.id, binding)
                self.notify("credential.bindingConfirmed",
                            {"id": cred.id, "binding": binding.to_json(), "approvalId": aid,
                             "untrusted": binding_untrusted("binding")})
        self._resolve(aid, decision, by="controller")
        return {}

    def rpc_ca_get(self, params: dict) -> dict:
        if not self.ca_pem:
            raise RpcError(-32001, "CA not ready")
        der_sha = hashlib.sha256(self.ca_pem.encode()).hexdigest()
        return {"certPem": self.ca_pem, "pemSha256": der_sha}

    def rpc_audit_tail(self, params: dict) -> dict:
        limit = params.get("limit", 100)
        if not isinstance(limit, int) or not 1 <= limit <= 2000:
            raise invalid("limit must be 1..2000")
        return {"events": list(self._audit_ring)[-limit:]}

    def rpc_broker_shutdown(self, params: dict) -> dict:
        self.creds.clear()
        self.audit("broker.shutdown", reason=str(params.get("reason", "requested"))[:64])
        if self.on_shutdown:
            asyncio.get_running_loop().call_later(0.05, self.on_shutdown)
        return {}

    METHODS = {
        "broker.hello": "rpc_broker_hello",
        "health": "rpc_health",
        "proxy.auth.set": "rpc_proxy_auth_set",
        "policy.load": "rpc_policy_load",
        "policy.get": "rpc_policy_get",
        "policy.update": "rpc_policy_update",
        "credential.provide": "rpc_credential_provide",
        "credential.revoke": "rpc_credential_revoke",
        "credential.import": "rpc_credential_import",
        "credential.list": "rpc_credential_list",
        "approval.list": "rpc_approval_list",
        "approval.decide": "rpc_approval_decide",
        "ca.get": "rpc_ca_get",
        "audit.tail": "rpc_audit_tail",
        "broker.shutdown": "rpc_broker_shutdown",
        "tab.event": "rpc_tab_event",
        "prompt.reset": "rpc_prompt_reset",
    }

    def dispatch(self, method: str, params: Any) -> Any:
        name = self.METHODS.get(method)
        if name is None or method not in protocol.method_names():
            raise RpcError(-32601, "method not found")
        if params is None:
            params = {}
        if not isinstance(params, dict):
            raise invalid("params must be an object")
        problem = protocol.check("params", method, params)
        if problem is not None:
            raise invalid(self.creds.scrub(problem))
        try:
            return getattr(self, name)(params)
        except PolicyError as e:
            raise invalid(self.creds.scrub(str(e))) from None


CAPABILITIES = {
    "holdAndResume": True,
    "pathMethodBinding": True,
    "placementOnlyInjection": True,
    "responseScanning": True,
    "mintedTokenResentinelize": True,
    "providerBackstop": True,
    "perTabCA": True,
    "http2": True,
    "websocket": True,
    "runtimeMutablePolicy": True,
    "proxyAuth": True,
    "upstreamAddressGuard": True,
    "credentialImport": True,
    "riskyDestinationList": True,
    "rawIpDeny": True,
    "promptFloodControl": True,
    "userActionGating": True,
    "originLabel": True,
    "untrustedTextTagged": True,
    "websocketOptIn": True,
    "modelBodyPolicy": True,
    "modelBudget": True,
    "trustedDerivation": True,
    "denyRules": True,
    "credentialBudget": True,
    "credentialRedirectFollow": True,
}


def random_password() -> str:
    return secrets.token_urlsafe(16)
