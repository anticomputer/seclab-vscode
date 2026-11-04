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
from dataclasses import dataclass, field
from typing import Any, Callable

from . import PROTOCOL, VERSION
from .credentials import Credential, CredentialStore
from .policy import (Binding, Inject, Policy, PolicyError, RequestView, Rule, parse_bindings,
                     validate_fragment)

log = logging.getLogger("seclab.broker")

DECISIONS = ("allow-once", "allow-tab", "deny")
_USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_PASS_RE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")  # >= 128 bits as base64url
_SOURCE_KINDS = ("workspace-scan", "password-input", "user", "host")


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
    credential_id: str | None = None
    waiters: list[asyncio.Future] = field(default_factory=list)

    def public(self) -> dict:
        out = {"approvalId": self.id, "kind": self.kind, "request": self.request,
               "createdAt": self.created, "expiresAt": self.deadline, "waiting": len(self.waiters),
               "decisions": list(DECISIONS)}
        if self.kind == "egress":
            out["suggestedRule"] = self.suggested
        else:
            out["credentialId"] = self.credential_id
            out["suggestedBinding"] = self.suggested
        return out


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
        event = self._scrub_obj(event)
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
    def check_proxy_auth(self, username: str | None, password: str | None) -> bool:
        if self._proxy_auth is None or username is None or password is None:
            return False
        u_ok = hmac.compare_digest(username.encode("utf-8", "surrogateescape"), self._proxy_auth[0])
        p_ok = hmac.compare_digest(password.encode("utf-8", "surrogateescape"), self._proxy_auth[1])
        return u_ok & p_ok

    # -------------------------------------------------------------- decisions
    def allowed(self, req: RequestView) -> Rule | None:
        return self.policy.allow_match(req)

    async def ask_egress(self, req: RequestView) -> Decision:
        key = ("egress",) + req.origin
        suggested = {"host": req.host, "schemes": [req.scheme], "ports": [req.port],
                     "methods": ["*"], "path": "/**"}
        return await self._ask(key, "egress", req, suggested, None)

    async def ask_binding(self, req: RequestView, cred: Credential, inject: Inject | None) -> Decision:
        key = ("binding", cred.id, req.scheme, req.host, req.port, req.method, req.path,
               inject.header.lower() if inject else None, inject.fmt if inject else None)
        suggested = {"host": req.host, "path": req.path, "methods": [req.method], "ports": [req.port]}
        if inject is not None:
            suggested["inject"] = inject.to_json()
        return await self._ask(key, "credential-binding", req, suggested, cred.id)

    async def _ask(self, key: tuple, kind: str, req: RequestView, suggested: dict,
                   cred_id: str | None) -> Decision:
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
            approval = Approval(id=uuid.uuid4().hex, kind=kind, key=key, request=req.summary(),
                                created=now, deadline=now + cfg.timeout_seconds,
                                suggested=suggested, credential_id=cred_id)
            self.approvals[approval.id] = approval
            self._approval_by_key[key] = approval.id
            asyncio.get_running_loop().call_at(
                asyncio.get_running_loop().time() + cfg.timeout_seconds,
                self._expire, approval.id)
            self.audit("approval.requested", approvalId=approval.id, kind=kind,
                       credentialId=cred_id, **req.summary())
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
        if not allow:
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
        }

    def rpc_proxy_auth_set(self, params: dict) -> dict:
        user, pw = params.get("username"), params.get("password")
        if not isinstance(user, str) or not _USER_RE.match(user):
            raise invalid("username must match [A-Za-z0-9._-]{1,64}")
        if not isinstance(pw, str) or not _PASS_RE.match(pw):
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
                   credentials=[c.id for c in policy.credentials])
        return {"revision": self.revision,
                "sentinels": {c.id: c.sentinel for c in self.creds.all() if c.origin == "policy"}}

    def rpc_policy_get(self, params: dict) -> dict:
        return {"revision": self.revision, "policy": self.policy.to_json()}

    def rpc_policy_update(self, params: dict) -> dict:
        add = params.get("addAllow", [])
        remove = params.get("removeAllow", [])
        if not isinstance(add, list) or not isinstance(remove, list):
            raise invalid("addAllow and removeAllow must be arrays")
        new_rules = [Rule.from_json(r) for r in add]
        existing_ids = {r.id for r in self.policy.rules if r.id}
        for rid in remove:
            if rid not in existing_ids:
                raise invalid(f"no allow rule with id {rid!r}")
        for r in new_rules:
            if r.id and (r.id in existing_ids and r.id not in remove):
                raise invalid(f"duplicate allow rule id {r.id!r}")
        self.policy.rules = [r for r in self.policy.rules if r.id not in remove] + new_rules
        self.revision += 1
        self.audit("policy.updated", revision=self.revision, added=[r.to_json() for r in new_rules],
                   removed=remove)
        self.notify("policy.changed", {"revision": self.revision,
                                       "added": [r.to_json() for r in new_rules], "removed": remove,
                                       "by": "controller"})
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
        cred = self.creds.import_credential(cid, params.get("value"), params.get("sentinel"),
                                            bind, proposed, provider, source)
        self.audit("credential.imported", credentialId=cred.id, confirmed=cred.confirmed,
                   source=source)
        return {"id": cred.id, "sentinel": cred.sentinel, "confirmed": cred.confirmed}

    def rpc_credential_list(self, params: dict) -> dict:
        return {"credentials": [c.public() for c in self.creds.all()]}

    def rpc_approval_list(self, params: dict) -> dict:
        return {"approvals": [a.public() for a in self.approvals.values()]}

    def rpc_approval_decide(self, params: dict) -> dict:
        aid, decision = params.get("approvalId"), params.get("decision")
        if decision not in DECISIONS:
            raise invalid(f"decision must be one of {DECISIONS}")
        approval = self.approvals.get(aid) if isinstance(aid, str) else None
        if approval is None:
            raise invalid("unknown or already resolved approvalId")
        if decision == "allow-tab":
            if approval.kind == "egress":
                rule = Rule.from_json(params.get("rule") or approval.suggested)
                self.policy.rules.append(rule)
                self.revision += 1
                self.notify("policy.changed", {"revision": self.revision, "added": [rule.to_json()],
                                               "removed": [], "by": "approval", "approvalId": aid})
            else:
                cred = self.creds.get(approval.credential_id or "")
                if cred is None:
                    raise invalid("credential no longer exists")
                binding = Binding.from_json(params.get("binding") or approval.suggested)
                self.creds.confirm_binding(cred.id, binding)
                self.notify("credential.bindingConfirmed",
                            {"id": cred.id, "binding": binding.to_json(), "approvalId": aid})
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
    }

    def dispatch(self, method: str, params: Any) -> Any:
        name = self.METHODS.get(method)
        if name is None:
            raise RpcError(-32601, "method not found")
        if params is None:
            params = {}
        if not isinstance(params, dict):
            raise invalid("params must be an object")
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
}


def random_password() -> str:
    return secrets.token_urlsafe(16)
