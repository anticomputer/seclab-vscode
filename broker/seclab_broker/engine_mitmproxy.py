"""mitmproxy engine adapter: translates mitmproxy flows into broker decisions.

Hooks used (mitmproxy 12.3.1): http_connect, requestheaders, request, response,
websocket_message, tcp_start, udp_start, server_connect. Hooks run as separate
asyncio tasks per flow, so holding one flow never blocks another
(mitmproxy/proxy/server.py, ConnectionHandler.server_event -> hook_task).
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import functools
import json
import logging
import re
import socket
import time
import weakref
from typing import Any

from mitmproxy import connection, http, tcp, udp
from mitmproxy.net.http import url as mitm_url
from mitmproxy.proxy import server_hooks

from .core import Broker
from .credentials import Credential, header_has_sentinel, infer_inject
from .netguard import deny_reason
from .policy import (METHOD_OVERRIDE_HEADERS, SEALED_PREFIX, Binding, PolicyError, RequestView, backstop_denies,
                     backstop_exception, canonical_path, normalize_host, normalize_ip,
                     query_has_method_override, validate_fragment)
from .scanner import find_minted
from .models import StrictJSONError, check_request, credential_values, is_model_host, parse_strict
from .untrusted import display_host, display_path

log = logging.getLogger("seclab.engine")
_METHOD = re.compile(r"^[A-Z]{1,16}$")
_TEXTUAL = re.compile(r"^(text/|application/(.*json|.*xml|javascript|x-www-form-urlencoded))|json")
DNS_TIMEOUT = 10.0
SESSION_HEADERS = {"set-cookie", "set-cookie2", "authentication-info", "proxy-authentication-info"}
# WebSocket server messages are scanned together with this much of what the tab already
# received on the connection, so a token is found even when it spans messages. It must
# exceed the longest token rule (json-token-field: 4096 plus its key).
WS_WINDOW = 8192
REDACTED_MARK = "[seclab-redacted:"
# Keys that name a credential, in a backstop exception's response.
CREDENTIAL_KEY = re.compile(r"token|secret|passw|credential|api[_-]?key|private[_-]?key|session|cookie|bearer|jwt",
                            re.I)
# A URL carrying a credential in its userinfo (`scheme://user:secret@host`, an encoded colon,
# a token as the user as in `https://<token>@host`, or the scheme-relative `//user:pw@host`
# at a word boundary); a plain short user such as `ssh://git@host` is not one, and the
# authority after `@` must look like a host (review 11c-3).
URL_USERINFO = re.compile(r"(?:[A-Za-z][A-Za-z0-9+.-]*:|(?<![^\s\"'<(,=]))//"
                          r"(?:(?:[^/?#\s@:%]|%(?![3][aA])[0-9A-Fa-f]{2})*(?::|%3[aA])[^/?#\s@]*|[^/?#\s@:]{16,})"
                          r"@(?=[A-Za-z0-9\[])")


def fail_closed(fn):
    """An exception in a hook must never let a flow continue unmodified
    (mitmproxy's addon manager logs hook exceptions and carries on)."""
    if asyncio.iscoroutinefunction(fn):
        @functools.wraps(fn)
        async def awrapper(self, obj):
            try:
                return await fn(self, obj)
            except Exception:
                self._hook_failed(fn.__name__, obj)
        return awrapper

    @functools.wraps(fn)
    def wrapper(self, obj):
        try:
            return fn(self, obj)
        except Exception:
            self._hook_failed(fn.__name__, obj)
    return wrapper


def _parse_basic(value: str) -> tuple[str, str] | None:
    parts = value.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "basic":
        return None
    try:
        user, _, pw = base64.b64decode(parts[1].strip(), validate=True).decode("utf-8").partition(":")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return user, pw


def _textual(headers: http.Headers) -> bool:
    ctype = headers.get("content-type", "").lower().strip()
    return not ctype or bool(_TEXTUAL.search(ctype))


def _upgrade_token(r: http.Request) -> str | None:
    """The protocol a request upgrades to, lower-cased; None for a plain request. HTTP/2
    extended CONNECT counts as an upgrade to an unknown protocol (never credentialed).
    Any upgrade signal counts, not just `Upgrade`: mitmproxy switches to WebSocket on a 101
    response plus the request's `Sec-WebSocket-Version`, whatever else the request said."""
    if r.method == "CONNECT":
        return "connect"
    u = r.headers.get_all("upgrade")
    if len(u) == 1:
        return u[0].strip().lower()
    if u or any(k.lower().startswith("sec-websocket-") for k in r.headers) or \
            "upgrade" in r.headers.get("connection", "").lower():
        return "malformed-upgrade"
    return None


def _path_representable(path: str) -> bool:
    try:
        validate_fragment("path", path)
    except PolicyError:
        return False
    return True


class SeclabAddon:
    def __init__(self, broker: Broker, local_ips: frozenset) -> None:
        self.b = broker
        self.local_ips = local_ips
        self.authed: weakref.WeakKeyDictionary[connection.Client, int] = weakref.WeakKeyDictionary()
        self.tunnels: weakref.WeakKeyDictionary[connection.Client, tuple[str, int]] = weakref.WeakKeyDictionary()
        self._last_auth_audit = 0.0
        self._auth_failures = 0

    # ------------------------------------------------------------ lifecycle
    def running(self) -> None:
        self.b.proxy_listening = True

    def _hook_failed(self, hook: str, obj: Any) -> None:
        # Contain first; auditing may fail for the same reason the hook did.
        if isinstance(obj, http.HTTPFlow):
            if hook == "websocket_message" and obj.websocket is not None:
                obj.websocket.messages[-1].drop()
            else:
                self._respond(obj, 502, "broker internal error", "error")
            obj.resume()
        elif isinstance(obj, server_hooks.ServerConnectionHookData):
            obj.server.error = "seclab: broker internal error"
        elif hasattr(obj, "kill") and getattr(obj, "killable", False):
            obj.kill()
        try:
            log.exception("hook %s failed; failed closed", hook)
            self.b.audit("engine.error", hook=hook)
        except Exception:
            pass

    # ------------------------------------------------------------ responses
    def _respond(self, flow: http.HTTPFlow, status: int, reason: str, kind: str = "denied",
                 headers: dict | None = None) -> None:
        hdrs = {"Content-Type": "application/json", "X-Seclab-Broker": kind}
        hdrs.update(headers or {})
        flow.metadata["seclab.synthetic"] = True
        flow.response = http.Response.make(
            status, json.dumps({"error": "seclab-broker", "status": kind, "reason": reason}), hdrs)

    def _summary(self, flow: http.HTTPFlow) -> dict:
        view = flow.metadata.get("seclab.view")
        if view is not None:
            return view.summary()
        r = flow.request
        out = {"scheme": r.scheme, "host": display_host(r.pretty_host), "port": r.port,
               "method": display_host(r.method)[:16], "path": display_path(r.path.split("?", 1)[0])}
        peer = flow.client_conn.peername
        if peer and isinstance(peer[1], int):
            out["clientPort"] = peer[1]
        return out

    def _deny(self, flow: http.HTTPFlow, status: int, reason: str, **extra: Any) -> None:
        self._respond(flow, status, reason)
        origin = flow.metadata.get("seclab.origin")
        if origin:
            extra.setdefault("origin", {"label": origin, "verified": False})
        self.b.audit("request.denied", status=status, reason=reason, **self._summary(flow), **extra)

    # ------------------------------------------------------------ proxy auth
    def _authenticate(self, flow: http.HTTPFlow) -> bool:
        creds = _parse_basic(flow.request.headers.get("Proxy-Authorization", ""))
        flow.request.headers.pop("Proxy-Authorization", None)
        if creds is not None:
            ok, label = self.b.check_proxy_auth(*creds)
            if ok:
                flow.metadata["seclab.origin"] = label
                return True
        self._auth_failures += 1
        now = time.monotonic()
        if now - self._last_auth_audit >= 1.0:
            self.b.audit("proxy.auth_failed", count=self._auth_failures,
                         client=str(flow.client_conn.peername[0]) if flow.client_conn.peername else None)
            self._last_auth_audit, self._auth_failures = now, 0
        self._respond(flow, 407, "proxy authentication required", "auth-required",
                      {"Proxy-Authenticate": 'Basic realm="seclab-broker"'})
        return False

    @fail_closed
    def http_connect(self, flow: http.HTTPFlow) -> None:
        if not self._authenticate(flow):
            return
        host = normalize_host(flow.request.host)
        if host is None:
            self._deny(flow, 400, "invalid CONNECT target")
            return
        self.authed[flow.client_conn] = (self.b.auth_epoch, flow.metadata.get("seclab.origin"))
        self.tunnels[flow.client_conn] = (host, flow.request.port)

    # ------------------------------------------------------------ request view
    def _view(self, flow: http.HTTPFlow) -> tuple[RequestView | None, str]:
        r = flow.request
        if r.scheme not in ("http", "https"):
            return None, "unsupported scheme"
        host = normalize_host(r.host)
        if host is None:
            return None, "invalid host"
        port = r.port
        method = r.method.upper()
        if not _METHOD.match(method) or method != r.method:
            return None, "invalid method"
        hosts = r.headers.get_all("host")
        if len(hosts) > 1:
            return None, "multiple Host headers"
        default_port = 443 if r.scheme == "https" else 80
        authorities = list(hosts)
        # HTTP/1 absolute-form inside a tunnel keeps its authority and mitmproxy
        # would forward it as-is; origin servers route on it (RFC 9112 §3.2.2).
        if r.authority:
            authorities.append(r.authority)
        for a in authorities:
            try:
                ah, ap = mitm_url.parse_authority(a, check=True)
            except ValueError:
                return None, "invalid authority"
            if (normalize_host(ah), ap or default_port) != (host, port):
                return None, "authority mismatch"
        tunnel = self.tunnels.get(flow.client_conn)
        if tunnel is not None and tunnel != (host, port):
            return None, "request authority does not match CONNECT target"
        sni = flow.client_conn.sni
        if sni and normalize_host(sni) != host:
            return None, "TLS SNI does not match request authority"
        for h in METHOD_OVERRIDE_HEADERS:
            if h in r.headers:
                return None, "method override headers are not allowed"
        cp = canonical_path(r.path)
        if cp is None:
            return None, "non-canonical path"
        path, query = cp
        if query_has_method_override(query):
            return None, "method override parameter is not allowed"
        peer = flow.client_conn.peername
        return RequestView(r.scheme, host, port, method, path, query,
                           client_port=peer[1] if peer and isinstance(peer[1], int) else None), ""

    # ------------------------------------------------------------ egress
    @fail_closed
    async def requestheaders(self, flow: http.HTTPFlow) -> None:
        if flow.response is not None:
            return
        tunnel_auth = self.authed.get(flow.client_conn)
        if tunnel_auth is None or tunnel_auth[0] != self.b.auth_epoch:
            if not self._authenticate(flow):
                return
        else:
            flow.request.headers.pop("Proxy-Authorization", None)
            flow.metadata["seclab.origin"] = tunnel_auth[1]
        view, err = self._view(flow)
        if view is None:
            self._deny(flow, 421 if "mismatch" in err or "SNI" in err else 400, err)
            return
        if not (flow.request.is_http2 or flow.request.is_http3):
            flow.request.authority = ""  # always forward origin-form
        flow.metadata["seclab.view"] = view
        # A user's block beats every allow rule, the baseline, allow-tab grants, prompts and
        # credential bindings (revision 5); nothing is forwarded or asked.
        blocked = self.b.policy.deny_match(view)
        if blocked is not None:
            self._deny(flow, 403, f"denied by rule {blocked.id}", ruleId=blocked.id)
            return
        rule = self.b.allowed(view)
        if rule is not None:
            flow.metadata["seclab.rule"] = rule.id or rule.host.text
            return
        flow.intercept()
        try:
            decision = await self.b.ask_egress(view, flow.metadata.get("seclab.origin"))
            if decision.allow:
                flow.metadata["seclab.rule"] = f"approval:{decision.reason}"
            else:
                self._deny(flow, 403, f"egress denied ({decision.reason})")
        finally:
            flow.resume()

    # ------------------------------------------------------------ credentials
    def _sentinel_locations(self, flow: http.HTTPFlow) -> list[tuple[str, str, str | None, str | None]]:
        """(credential_id, location, header_name, header_value) for every sentinel occurrence."""
        r = flow.request
        out: list[tuple[str, str, str | None, str | None]] = []
        for name, value in r.headers.fields:
            for cid, _kind, _s, _e in self.b.creds.find_sentinels(value):
                n = name.decode("latin-1")
                out.append((cid, f"header:{n.lower()}", n, value.decode("latin-1")))
        for cid, _k, _s, _e in self.b.creds.find_sentinels(r.path.encode("utf-8", "surrogateescape")):
            out.append((cid, "url", None, None))
        if r.trailers:
            for _name, value in r.trailers.fields:
                for cid, _k, _s, _e in self.b.creds.find_sentinels(value):
                    out.append((cid, "trailer", None, None))
        bodies = [r.raw_content or b""]
        try:
            decoded = r.get_content(strict=True)
            if decoded and decoded != bodies[0]:
                bodies.append(decoded)
        except ValueError:
            pass
        seen = set()
        for body in bodies:
            for cid, _k, _s, _e in self.b.creds.find_sentinels(body):
                if cid not in seen:
                    seen.add(cid)
                    out.append((cid, "body", None, None))
        return out

    def _model_gate(self, flow: http.HTTPFlow, view: RequestView, upgrade: str | None) -> bool:
        """Model-host body policy and budget. True to continue; False after denying."""
        r, models = flow.request, self.b.policy.models
        headers: dict[str, list[str]] = {}
        for k, v in r.headers.fields:
            headers.setdefault(k.decode("latin-1").lower(), []).append(v.decode("latin-1"))
        body = r.raw_content or b""
        verdict = check_request(models, view.host, view.method, view.path, headers, body, upgrade)
        if not verdict.ok:
            self.b.audit("model.denied", reason=verdict.reason, provider=verdict.provider,
                         **({"detail": verdict.detail} if verdict.detail is not None else {}), **view.summary())
            self._deny(flow, 403, f"model request denied: {verdict.reason}")
            return False
        query = r.path.split("?", 1)[1] if "?" in r.path else ""
        for where, value in credential_values(models.provider_for(view.host), headers, query):
            if not self.b.creds.find_sentinels(value.encode("utf-8", "surrogateescape")):
                # Only this tab's sentinels authenticate to a model host: no tab-held key,
                # so every model call is the user's, budgeted and audited here.
                self.b.audit("sentinel.misplaced", credentialId="none", location=where,
                             action="block", **view.summary())
                self._deny(flow, 403, "model host credential must be a sentinel of this tab")
                return False
        why = self.b.model_usage.exhausted(models)
        if why:
            self.b.audit("model.budget_exceeded", reason=why, provider=verdict.provider,
                         requests=self.b.model_usage.requests, bytes=self.b.model_usage.bytes, **view.summary())
            self._deny(flow, 429, f"model budget for this tab: {why}")
            return False
        self.b.model_usage.requests += 1
        self.b.model_usage.bytes += len(body)
        flow.metadata["seclab.model"] = {"provider": verdict.provider, "reqBytes": len(body),
                                         "tools": verdict.tools, "start": time.monotonic()}
        return True

    @fail_closed
    async def request(self, flow: http.HTTPFlow) -> None:
        view: RequestView | None = flow.metadata.get("seclab.view")
        if flow.response is not None:
            return
        if view is None:
            self._deny(flow, 403, "request was not classified")
            return
        blocked = self.b.policy.deny_match(view)  # a block added since requestheaders
        if blocked is not None:
            self._deny(flow, 403, f"denied by rule {blocked.id}", ruleId=blocked.id)
            return
        upgrade = _upgrade_token(flow.request)
        sealed = SEALED_PREFIX.encode()
        hits = [f"header:{n.decode('latin-1').lower()}" for n, v in flow.request.headers.fields if sealed in v.lower()]
        if sealed in flow.request.path.encode("utf-8", "surrogateescape").lower():
            hits.append("url")
        if sealed in (flow.request.raw_content or b"").lower():
            hits.append("body")
        if hits:
            # A token sealed for the agent host is never forwarded, wherever it goes.
            self.b.audit("sentinel.misplaced", credentialId="sealed-token", location=hits[0],
                         action="block", **view.summary())
            self._deny(flow, 403, "sealed token in a request")
            return
        if is_model_host(view.host, self.b.policy.models) and not self._model_gate(flow, view, upgrade):
            return
        planned: dict[str, tuple[Credential, Binding]] = {}
        unbound: list[tuple[Credential, str, str]] = []
        misplaced: list[tuple[str, str]] = []
        ws_refused = False
        for cid, where, hname, hvalue in self._sentinel_locations(flow):
            cred = self.b.creds.get(cid)
            if cred is None:
                continue
            binding = None
            if hname is not None and header_has_sentinel(hvalue or "", cred.sentinel):
                binding = next((b for b in cred.bindings if b.matches(view, upgrade)
                                and b.inject and b.inject.header.lower() == hname.lower()), None)
                if binding is None and upgrade is not None:
                    # Never into an upgraded connection unless a binding opts in, and never
                    # through a first-use prompt (the suggestion can't carry the opt-in).
                    ws_refused = ws_refused or any(b.matches(view) for b in cred.bindings) or not cred.confirmed
                elif binding is None and not cred.confirmed and view.scheme == "https":
                    unbound.append((cred, hname, hvalue or ""))
                    continue
            if binding is not None:
                if cid in planned:
                    misplaced.append((cid, where))
                else:
                    planned[cid] = (cred, binding)
            else:
                misplaced.append((cid, where))

        if ws_refused:
            self._deny(flow, 403, "credential injection into an upgraded connection needs a binding "
                                  "with websocket: true")
            return

        if misplaced:
            for cid, where in misplaced:
                self.b.audit("sentinel.misplaced", credentialId=cid, location=where,
                             action=self.b.policy.sentinel_mismatch, **view.summary())
            if self.b.policy.sentinel_mismatch == "block":
                self._deny(flow, 403, "credential sentinel used outside its binding")
                return

        for cred, _b in list(planned.values()) + [(c, None) for c, _h, _v in unbound]:
            if cred.confirmed and any(r.matches(view) for r in cred.derive_rules):
                # The one exemption (ADR broker-model-access): the controller declared this exact
                # route as a mint, so its token is replaced structurally (fail closed) and never
                # reaches the tab, which is what the backstop exists to guarantee.
                self.b.audit("credential.backstop_exempt", credentialId=cred.id, reason="declared derive route",
                             **view.summary())
                continue
            entry = backstop_denies(view, cred.provider)
            if entry is not None:
                exc = backstop_exception(view, cred.provider)
                if exc is not None and not (flow.request.raw_content or b"") and upgrade is None:
                    flow.metadata["seclab.backstop_exception"] = exc
                    self.b.audit("credential.backstop_exempt", credentialId=cred.id,
                                 reason="approved backstop exception", **view.summary())
                    continue
                self.b.audit("credential.backstop_denied", credentialId=cred.id,
                             provider=entry.provider, rule=entry.path, **view.summary())
                self._deny(flow, 403, "endpoint can mint durable credentials; blocked by provider backstop")
                return

        flow.intercept()
        try:
            for cred, hname, hvalue in unbound:
                # The suggested binding is built from the tab-chosen path. A path with glob
                # metacharacters (or one the schema cannot express) would turn "allow" into a
                # wildcard binding, so it is never offered.
                if "*" in view.path or not _path_representable(view.path):
                    self._deny(flow, 403, "request path cannot be expressed as an exact binding")
                    return
                inject = infer_inject(hname, hvalue, cred.sentinel)
                proposed = next((b for b in cred.proposed if b.matches(view)), None)
                if proposed is not None and proposed.inject is not None:
                    inject = proposed.inject
                if inject is None:
                    self._deny(flow, 403, "cannot infer how to inject an unbound credential")
                    return
                decision = await self.b.ask_binding(view, cred, inject, flow.metadata.get("seclab.origin"))
                if not decision.allow:
                    self._deny(flow, 403, f"credential binding denied ({decision.reason})")
                    return
                binding = next((b for b in cred.bindings if b.matches(view, upgrade) and b.inject
                                and b.inject.header.lower() == inject.header.lower()), None)
                if binding is None:
                    if not decision.once:
                        self._deny(flow, 403, "approved binding does not cover this request")
                        return
                    # allow-once: a one-shot binding for exactly this request
                    binding = Binding.from_json({"host": view.host, "path": view.path,
                                                 "methods": [view.method], "ports": [view.port],
                                                 "inject": inject.to_json()})
                planned[cred.id] = (cred, binding)

            headers_used: set[str] = set()
            for cred, binding in planned.values():
                assert binding.inject is not None
                h = binding.inject.header.lower()
                if h in headers_used:
                    self._deny(flow, 403, "conflicting credentials for one header")
                    return
                headers_used.add(h)
                if not await self.b.wait_for_value(cred):
                    self._deny(flow, 503, "credential unavailable")
                    return

            injected = []
            for cred, binding in planned.values():
                assert binding.inject is not None and cred.value is not None
                flow.request.headers[binding.inject.header] = binding.inject.render(cred.value)
                injected.append(cred.id)
                self.b.audit("credential.injected", credentialId=cred.id,
                             header=binding.inject.header, **view.summary())
            if injected:
                flow.metadata["seclab.injected"] = injected
                if upgrade == "websocket" and all(b.websocket for _c, b in planned.values()):
                    flow.metadata["seclab.ws_ok"] = True
            origin = flow.metadata.get("seclab.origin")
            self.b.audit("request.allowed", rule=flow.metadata.get("seclab.rule"),
                         injected=injected, **({"origin": {"label": origin, "verified": False}}
                                               if origin else {}), **view.summary())
        finally:
            flow.resume()

    # ------------------------------------------------------------ responses
    def _bound_host(self, view: RequestView | None) -> bool:
        if view is None:
            return False
        return any(b.host.matches(view.host) for c in self.b.creds.all() for b in c.bindings)

    def _scrub_real(self, data: bytes, textual: bool) -> tuple[bytes, str | None]:
        """Replace raw echoes of real values by their sentinels; any other encoding blocks."""
        hits = self.b.creds.find_real(data)
        if not hits:
            return data, None
        if any(kind != "raw" for _c, kind, _s, _e in hits) or not textual:
            return data, f"credential echo ({hits[0][1]})"
        out, pos = [], 0
        for cid, _kind, s, e in hits:
            if s < pos:
                continue
            cred = self.b.creds.get(cid)
            out += [data[pos:s], cred.sentinel.encode() if cred else b"[redacted]"]
            pos = e
        out.append(data[pos:])
        return b"".join(out), None

    def _minted_hits(self, text: str) -> list[tuple[str, str, int, int]]:
        return [h for h in find_minted(text)
                if self.b.creds.by_sentinel(h[1]) is None and not h[1].startswith(REDACTED_MARK)]

    def _scrub_minted(self, text: str, flow: http.HTTPFlow, where: str, context: str = "") -> str:
        """Re-sentinelise or redact minted tokens in `text`. `context` is text the tab
        already received just before it (WebSocket); it is matched against, never rewritten."""
        view = flow.metadata.get("seclab.view")
        injected = flow.metadata.get("seclab.injected") or []
        n = len(context)
        hits = [(r, sec, s - n, e - n) for r, sec, s, e in self._minted_hits(context + text) if s >= n]
        if not hits:
            return text
        out, pos = [], 0
        for rule_id, secret, s, e in hits:
            out.append(text[pos:s])
            parent = self.b.creds.get(injected[0]) if injected else None
            derived = None
            if parent is not None:
                try:
                    derived = self.b.creds.derive(parent, secret, rule_id)
                except PolicyError as err:
                    self.b.audit("token.redacted", rule=rule_id, location=where, reason=str(err),
                                 **(view.summary() if view else {}))
            if derived is not None:
                out.append(derived.sentinel)
                self.b.audit("credential.derived", credentialId=derived.id, parentId=parent.id,
                             rule=rule_id, location=where, **(view.summary() if view else {}))
                self.b.notify("credential.derived", {"id": derived.id, "parentId": parent.id,
                                                     "rule": rule_id, "sentinel": derived.sentinel})
            else:
                out.append(f"[seclab-redacted:{rule_id}]")
                if parent is None:
                    self.b.audit("token.redacted", rule=rule_id, location=where,
                                 **(view.summary() if view else {}))
            pos = e
        out.append(text[pos:])
        return "".join(out)

    def _block_response(self, flow: http.HTTPFlow, reason: str, **extra: Any) -> None:
        status = flow.response.status_code if flow.response else None
        self.b.audit("response.blocked", reason=reason, status=status, **extra, **self._summary(flow))
        self._respond(flow, 502, f"response blocked: {reason}", "blocked")

    @fail_closed
    def response(self, flow: http.HTTPFlow) -> None:
        resp = flow.response
        if resp is None or flow.metadata.get("seclab.synthetic"):
            return
        view = flow.metadata.get("seclab.view")
        injected = bool(flow.metadata.get("seclab.injected"))
        model = flow.metadata.pop("seclab.model", None)
        if model is not None and view is not None:
            resp_bytes = len(resp.raw_content or b"")
            self.b.model_usage.bytes += resp_bytes
            self.b.audit("model.call", provider=model["provider"], reqBytes=model["reqBytes"],
                         respBytes=resp_bytes, status=resp.status_code, tools=model["tools"],
                         durationMs=round((time.monotonic() - model["start"]) * 1000), **view.summary())
        if resp.status_code == 101 and injected and not flow.metadata.get("seclab.ws_ok"):
            # The upstream switched protocols on a credentialed request that was not approved
            # as a WebSocket (mitmproxy decides on the response); never relay the stream.
            flow.websocket = None
            return self._block_response(flow, "protocol switch on a credentialed request without "
                                              "a websocket: true binding")
        textual = _textual(resp.headers)
        derive_route = bool(self._derivations(flow, view)) and not 200 <= resp.status_code < 300
        if flow.metadata.get("seclab.backstop_exception") is not None or derive_route:
            # Exception routes always, and derive routes when not 2xx (so "derived or blocked"
            # holds whatever the status): no credential-named field, no token-shaped value.
            exc = flow.metadata.get("seclab.backstop_exception")
            why, detail, kept = self._exception_response_check(resp, exc)
            if why:
                self.b.audit("credential.backstop_exception_blocked", reason=why,
                             **({"detail": detail} if detail else {}), **self._summary(flow))
                return self._block_response(flow, f"backstop exception response: {why}")
            if kept is not None:
                # The whole document passed; fields outside the exception's measured allowlist
                # never reach the tab. Their names are the upstream's choice: `detail` only.
                doc, dropped = kept
                resp.content = json.dumps(doc, separators=(",", ":")).encode()
                self.b.audit("credential.backstop_exception_filtered", reason="field outside the allowlist",
                             detail=",".join(dropped)[:512], **self._summary(flow))
        # Any flow that carried a real value, and any response from a bound host,
        # is scanned for credentials the upstream may have minted.
        scan_minted = injected or self._bound_host(view)

        new_fields = []
        for name, value in resp.headers.fields:
            hname = name.decode("latin-1").lower()
            if injected and hname in SESSION_HEADERS:
                # A session issued in answer to a credentialed request is a derived
                # credential the tab could replay on any path; never pass it on.
                self.b.audit("session.stripped", header=hname, **self._summary(flow))
                continue
            value, why = self._scrub_real(value, True)
            if why:
                # The header name is the upstream's choice: keep it out of `reason`, in the
                # tagged `header` field.
                return self._block_response(flow, f"response header: {why}", header=hname)
            if scan_minted:
                value = self._scrub_minted(value.decode("latin-1"), flow, f"header:{hname}").encode(
                    "latin-1", "replace")
            new_fields.append((name, value))
        resp.headers.fields = tuple(new_fields)

        if resp.trailers:
            kept_trailers = []
            for name, value in resp.trailers.fields:
                if self.b.creds.find_real(value) or (scan_minted and find_minted(value.decode("latin-1"))):
                    return self._block_response(flow, "credential material in trailers")
                if injected and name.decode("latin-1").lower() in SESSION_HEADERS:
                    self.b.audit("session.stripped", header=name.decode("latin-1").lower(), **self._summary(flow))
                    continue
                kept_trailers.append((name, value))
            resp.trailers.fields = tuple(kept_trailers)

        raw = resp.raw_content or b""
        try:
            body = resp.get_content(strict=True) or b""
        except ValueError:
            if self.b.creds.find_real(raw) or injected:
                return self._block_response(flow, "undecodable response body on a credentialed flow")
            return
        orig = body
        derivations = self._derivations(flow, view)
        if derivations and 200 <= resp.status_code < 300:
            body, why = self._derive(flow, view, derivations, body)
            if why:
                return self._block_response(flow, f"trusted derivation failed: {why}")
        body2, why = self._scrub_real(body, textual)
        if why:
            return self._block_response(flow, why)
        if scan_minted and body2:
            if textual:
                body2 = self._scrub_minted(body2.decode("utf-8", "surrogateescape"), flow,
                                           "body").encode("utf-8", "surrogateescape")
            elif injected and find_minted(body2.decode("latin-1")):
                return self._block_response(flow, "token-like material in a non-text credentialed response")
        if body2 != orig:
            resp.content = body2

    def _exception_response_check(self, resp: http.Response, exc=None):
        """An approved backstop exception's response (ADR broker-model-access): a strict JSON
        object with no credential-named key (bar the exception's exact benign JSON paths), no
        token-shaped key or value and no URL userinfo, in the body, headers or trailers;
        anything else is blocked and surfaced as a finding. A bodiless response passes after
        the header and trailer checks (a 204/304). The field allowlist applies to 2xx only; an
        error body still gets every other check. Returns (why, detail, kept): `kept` is
        (filtered document, dropped names) when fields were dropped."""
        trailers = resp.trailers.fields if resp.trailers else ()
        for name, value in tuple(resp.headers.fields) + tuple(trailers):
            hname = name.decode("latin-1").lower()
            text = value.decode("latin-1")
            if CREDENTIAL_KEY.search(hname) or find_minted(text) or URL_USERINFO.search(text):
                return "credential-named header or token-shaped value", hname, None
        try:
            raw = resp.get_content(strict=True) or b""
        except ValueError:
            return "response is not strict JSON", None, None
        if not raw:
            return None, None, None
        try:
            doc = parse_strict(raw)
        except StrictJSONError:
            return "response is not strict JSON", None, None
        if not isinstance(doc, dict):
            return "response is not a JSON object", None, None
        # Fields that are always dropped never reach the tab, so they are removed before the
        # scan: a credential inside them (an OTLP header) must not block the rest (review 11c-1).
        drop = exc.drop_fields if exc is not None else frozenset()
        dropped = sorted(k for k in doc if k in drop)
        doc = {k: v for k, v in doc.items() if k not in drop}
        stack: list = [("$", doc)]
        while stack:
            path, node = stack.pop()
            if isinstance(node, dict):
                for k, v in node.items():
                    kp = f"{path}.{k}"
                    if CREDENTIAL_KEY.search(k) and not (exc is not None and exc.is_benign(kp)):
                        return "credential-named field", kp, None
                    if find_minted(k):
                        return "token-shaped key", path, None
                    stack.append((kp, v))
            elif isinstance(node, list):
                stack += [(f"{path}[{i}]", v) for i, v in enumerate(node)]
            elif isinstance(node, str) and (find_minted(node) or URL_USERINFO.search(node)):
                return "token-shaped value", path, None
        if exc is None or (exc.response_fields is None and not dropped):
            return None, None, None
        # Every status (review 11b-1): the upstream chooses the status, so an error body is
        # held to the same allowlist; error shapes that should pass are listed in it.
        if exc.response_fields is not None:
            unlisted = sorted(k for k in doc if k not in exc.response_fields)
            if unlisted and exc.strict_fields:
                return "field outside the allowlist", ",".join(unlisted)[:512], None
            dropped += unlisted
            doc = {k: v for k, v in doc.items() if k in exc.response_fields}
        if not dropped:
            return None, None, None
        return None, None, (doc, dropped)

    def _derivations(self, flow: http.HTTPFlow, view: RequestView | None) -> list:
        if view is None:
            return []
        out = []
        for cid in flow.metadata.get("seclab.injected") or []:
            cred = self.b.creds.get(cid)
            if cred is not None and cred.confirmed:
                out += [(cred, r) for r in cred.derive_rules if r.matches(view)]
        return out

    def _derive(self, flow: http.HTTPFlow, view: RequestView, derivations: list,
                body: bytes) -> tuple[bytes, str | None]:
        """Structural, never pattern-based: the declared field of a strict JSON object is the
        minted token. Anything else on this route fails closed."""
        try:
            doc = parse_strict(body)
        except StrictJSONError as e:
            return body, f"response is not strict JSON ({e})"
        if not isinstance(doc, dict):
            return body, "response is not a JSON object"
        for parent, rule in derivations:
            token = doc.get(rule.field)
            if not isinstance(token, str):
                return body, f"no string field {rule.field!r}"
            try:
                child = self.b.creds.derive_trusted(parent, rule, token)
            except PolicyError as e:
                return body, str(e)
            doc[rule.field] = child.sentinel
            self.b.audit("credential.derived", credentialId=child.id, parentId=parent.id,
                         rule=f"derive:{rule.id}", location="body", **view.summary())
            self.b.notify("credential.derived", {"id": child.id, "parentId": parent.id,
                                                 "rule": f"derive:{rule.id}", "sentinel": child.sentinel})
        return json.dumps(doc, ensure_ascii=False).encode("utf-8"), None

    # ------------------------------------------------------------ websockets
    @fail_closed
    def websocket_message(self, flow: http.HTTPFlow) -> None:
        assert flow.websocket is not None
        msg = flow.websocket.messages[-1]
        view = flow.metadata.get("seclab.view")
        if flow.metadata.get("seclab.ws_dead"):
            # mitmproxy cannot close a WebSocket from this hook (flow.kill() is not applied
            # in transit, mitmproxy#4711), so a killed connection relays nothing more.
            msg.drop()
            return
        blocked = self.b.policy.deny_match(view) if view is not None else None
        if blocked is not None:
            # A destination blocked while the socket was open relays nothing more (revision 5).
            flow.metadata["seclab.ws_dead"] = True
            self.b.audit("request.denied", status=403, reason=f"denied by rule {blocked.id}",
                         ruleId=blocked.id, **view.summary())
            msg.drop()
            return
        if msg.from_client:
            hits = self.b.creds.find_sentinels(msg.content)
            if hits:
                for cid in {h[0] for h in hits}:
                    self.b.audit("sentinel.misplaced", credentialId=cid, location="websocket",
                                 action=self.b.policy.sentinel_mismatch,
                                 **(view.summary() if view else {}))
                if self.b.policy.sentinel_mismatch == "block":
                    msg.drop()
            return
        content, why = self._scrub_real(msg.content, msg.is_text)
        if why:
            self.b.audit("response.blocked", reason=f"websocket {why}", **(view.summary() if view else {}))
            msg.drop()
            return
        if flow.metadata.get("seclab.injected") or self._bound_host(view):
            # Decide on what the tab sees (the concatenated stream), not on one message.
            carry: bytes = flow.metadata.get("seclab.ws_carry", b"")
            enc = "utf-8" if msg.is_text else "latin-1"
            context = carry.decode(enc, "surrogateescape")
            text = content.decode(enc, "surrogateescape")
            n = len(context)
            # Any match starting in bytes the tab already has (split across messages, or only
            # recognisable once its terminator arrived) cannot be recalled: deliver no more.
            spans = [h for h in self.b.creds.find_real(carry + content) if h[2] < len(carry) < h[3]]
            spans += [h for h in self._minted_hits(context + text) if h[2] < n]
            if spans:
                self.b.audit("response.blocked", reason="websocket token split across messages",
                             **(view.summary() if view else {}))
                msg.drop()
                flow.metadata["seclab.ws_dead"] = True
                return
            if msg.is_text:
                content = self._scrub_minted(text, flow, "websocket", context).encode("utf-8", "surrogateescape")
            elif [h for h in self._minted_hits(context + text) if h[2] >= n]:
                self.b.audit("response.blocked", reason="websocket token-like binary frame",
                             **(view.summary() if view else {}))
                msg.drop()
                return
            flow.metadata["seclab.ws_carry"] = (carry + content)[-WS_WINDOW:]
        if content != msg.content:
            msg.content = content

    # ------------------------------------------------------------ non-HTTP
    def tcp_start(self, flow: tcp.TCPFlow) -> None:
        self.b.audit("tcp.blocked", server=str(flow.server_conn.address))
        flow.kill()

    def udp_start(self, flow: udp.UDPFlow) -> None:
        self.b.audit("udp.blocked", server=str(flow.server_conn.address))
        flow.kill()

    # ------------------------------------------------------------ upstream guard
    @fail_closed
    async def server_connect(self, data: server_hooks.ServerConnectionHookData) -> None:
        server = data.server
        if server.address is None:
            server.error = "seclab: no upstream address"
            return
        host, port = server.address[0], server.address[1]
        ip = normalize_ip(host)
        ips = [ip] if ip is not None else []
        if not ips:
            try:
                infos = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(
                    host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP), DNS_TIMEOUT)
            except (OSError, asyncio.TimeoutError):
                server.error = "seclab: upstream name resolution failed"
                self.b.audit("upstream.dns_failed", host=host, port=port)
                return
            for info in infos:
                cand = normalize_ip(info[4][0])
                if cand is not None and cand not in ips:
                    ips.append(cand)
        if not ips:
            server.error = "seclab: no upstream address"
            return
        for cand in ips:
            reason = deny_reason(cand, self.local_ips)
            if reason:
                server.error = f"seclab: upstream address not permitted ({reason})"
                self.b.audit("upstream.blocked", host=host, port=port, ip=str(cand), reason=reason)
                return
        # Pin the vetted address so the connect cannot re-resolve (DNS rebinding).
        # SNI was already set from the hostname by the HTTP layer.
        server.address = (str(ips[0]), port)
