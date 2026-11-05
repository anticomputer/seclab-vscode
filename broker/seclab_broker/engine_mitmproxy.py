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
from .policy import (METHOD_OVERRIDE_HEADERS, Binding, PolicyError, RequestView, backstop_denies,
                     canonical_path, normalize_host, normalize_ip, query_has_method_override,
                     validate_fragment)
from .scanner import find_minted
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
        return {"scheme": r.scheme, "host": display_host(r.pretty_host), "port": r.port,
                "method": display_host(r.method)[:16], "path": display_path(r.path.split("?", 1)[0])}

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
        return RequestView(r.scheme, host, port, method, path, query), ""

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

    @fail_closed
    async def request(self, flow: http.HTTPFlow) -> None:
        view: RequestView | None = flow.metadata.get("seclab.view")
        if flow.response is not None:
            return
        if view is None:
            self._deny(flow, 403, "request was not classified")
            return
        planned: dict[str, tuple[Credential, Binding]] = {}
        unbound: list[tuple[Credential, str, str]] = []
        misplaced: list[tuple[str, str]] = []
        for cid, where, hname, hvalue in self._sentinel_locations(flow):
            cred = self.b.creds.get(cid)
            if cred is None:
                continue
            binding = None
            if hname is not None and header_has_sentinel(hvalue or "", cred.sentinel):
                binding = next((b for b in cred.bindings if b.matches(view)
                                and b.inject and b.inject.header.lower() == hname.lower()), None)
                if binding is None and not cred.confirmed and view.scheme == "https":
                    unbound.append((cred, hname, hvalue or ""))
                    continue
            if binding is not None:
                if cid in planned:
                    misplaced.append((cid, where))
                else:
                    planned[cid] = (cred, binding)
            else:
                misplaced.append((cid, where))

        if misplaced:
            for cid, where in misplaced:
                self.b.audit("sentinel.misplaced", credentialId=cid, location=where,
                             action=self.b.policy.sentinel_mismatch, **view.summary())
            if self.b.policy.sentinel_mismatch == "block":
                self._deny(flow, 403, "credential sentinel used outside its binding")
                return

        for cred, _b in list(planned.values()) + [(c, None) for c, _h, _v in unbound]:
            entry = backstop_denies(view, cred.provider)
            if entry is not None:
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
                binding = next((b for b in cred.bindings if b.matches(view) and b.inject
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
        textual = _textual(resp.headers)
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
            for name, value in resp.trailers.fields:
                if self.b.creds.find_real(value) or (scan_minted and find_minted(value.decode("latin-1"))):
                    return self._block_response(flow, "credential material in trailers")

        raw = resp.raw_content or b""
        try:
            body = resp.get_content(strict=True) or b""
        except ValueError:
            if self.b.creds.find_real(raw) or injected:
                return self._block_response(flow, "undecodable response body on a credentialed flow")
            return
        body2, why = self._scrub_real(body, textual)
        if why:
            return self._block_response(flow, why)
        if scan_minted and body2:
            if textual:
                body2 = self._scrub_minted(body2.decode("utf-8", "surrogateescape"), flow,
                                           "body").encode("utf-8", "surrogateescape")
            elif injected and find_minted(body2.decode("latin-1")):
                return self._block_response(flow, "token-like material in a non-text credentialed response")
        if body2 != body:
            resp.content = body2

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
