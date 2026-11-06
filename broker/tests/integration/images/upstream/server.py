"""ASGI app for the fake upstreams. Routing is by Host header.

Hosts:
  api.example.test       echo, reflection probes, token-minting, a backstop target
  gist.example.test      a second, unbound but allowed host (exfil target)
  git.example.test       git smart HTTP (git http-backend), Basic auth required
  ws.example.test        WebSocket echo that reflects the handshake Authorization
  internal.example.test  echo (served from a private-address network)
"""

import asyncio
import base64
import hashlib
import json
import os
import secrets
import urllib.parse
from collections import deque

SEEN: deque = deque(maxlen=500)
MINTED: set[str] = set()


def sha(v) -> str | None:
    if v is None:
        return None
    if isinstance(v, str):
        v = v.encode()
    return hashlib.sha256(v).hexdigest()


async def read_body(receive) -> bytes:
    body = b""
    while True:
        msg = await receive()
        body += msg.get("body", b"")
        if not msg.get("more_body"):
            return body


async def send_resp(send, status: int, body: bytes, headers: list | None = None,
                    ctype: bytes = b"application/json") -> None:
    hdrs = [(b"content-type", ctype), (b"content-length", str(len(body)).encode())]
    hdrs += headers or []
    await send({"type": "http.response.start", "status": status, "headers": hdrs})
    await send({"type": "http.response.body", "body": body})


def headers_of(scope) -> dict:
    out: dict[str, str] = {}
    for k, v in scope["headers"]:
        out.setdefault(k.decode("latin-1").lower(), v.decode("latin-1"))
    return out


async def git_backend(scope, receive, send, hdrs: dict, body: bytes) -> None:
    want = "Basic " + base64.b64encode(f"x-access-token:{os.environ['UPSTREAM_GIT_TOKEN']}".encode()).decode()
    if hdrs.get("authorization") != want:
        await send_resp(send, 401, b"auth required\n", [(b"www-authenticate", b'Basic realm="git"')],
                        b"text/plain")
        return
    env = {
        "GIT_PROJECT_ROOT": "/srv/git", "GIT_HTTP_EXPORT_ALL": "1", "PATH": os.environ["PATH"],
        "PATH_INFO": scope["path"], "REQUEST_METHOD": scope["method"],
        "QUERY_STRING": scope["query_string"].decode(), "CONTENT_TYPE": hdrs.get("content-type", ""),
        "CONTENT_LENGTH": str(len(body)), "REMOTE_USER": "x-access-token", "REMOTE_ADDR": "127.0.0.1",
    }
    if "content-encoding" in hdrs:
        env["HTTP_CONTENT_ENCODING"] = hdrs["content-encoding"]
    if "git-protocol" in hdrs:
        env["GIT_PROTOCOL"] = hdrs["git-protocol"]
    proc = await asyncio.create_subprocess_exec("git", "http-backend", env=env,
                                                stdin=asyncio.subprocess.PIPE,
                                                stdout=asyncio.subprocess.PIPE)
    out, _ = await proc.communicate(body)
    head, _, payload = out.partition(b"\r\n\r\n")
    status, headers = 200, []
    for line in head.split(b"\r\n"):
        k, _, v = line.partition(b":")
        if k.lower() == b"status":
            status = int(v.strip().split()[0])
        elif k:
            headers.append((k.strip().lower(), v.strip()))
    headers.append((b"content-length", str(len(payload)).encode()))
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": payload})


async def websocket(scope, receive, send) -> None:
    hdrs = headers_of(scope)
    msg = await receive()
    assert msg["type"] == "websocket.connect"
    await send({"type": "websocket.accept"})
    await send({"type": "websocket.send", "text": json.dumps({"hello": True, "auth": hdrs.get("authorization")})})
    while True:
        msg = await receive()
        if msg["type"] == "websocket.disconnect":
            return
        text = msg.get("text") or ""
        if text.startswith("split:"):
            # A minted token (generic JSON token field, canary value) split across two
            # messages, as a streaming API might by accident: after the key, mid-token, or
            # just before the closing quote.
            _, where, tag = text.split(":", 2)
            secret = f"seclab-minted-canary-{tag}-" + "Q" * 24 + "-value"
            body = json.dumps({"token": secret})
            at = {"key": body.index(secret), "mid": body.index(secret) + len(secret) // 2,
                  "end": body.index(secret) + len(secret)}[where]
            await send({"type": "websocket.send", "text": body[:at]})
            await send({"type": "websocket.send", "text": body[at:]})
            continue
        await send({"type": "websocket.send", "text": "echo:" + text})


async def app(scope, receive, send) -> None:
    if scope["type"] == "lifespan":
        while True:
            msg = await receive()
            if msg["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif msg["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return
    if scope["type"] == "websocket":
        return await websocket(scope, receive, send)
    hdrs = headers_of(scope)
    host = (hdrs.get("host") or hdrs.get(":authority") or "").split(":")[0]
    path, method = scope["path"], scope["method"]
    body = await read_body(receive)
    auth = hdrs.get("authorization")
    bearer = auth.split(" ", 1)[1] if auth and auth.lower().startswith("bearer ") else None
    record = {"host": host, "method": method, "path": path, "auth_sha256": sha(auth),
              "body_sha256": sha(body), "http_version": scope.get("http_version"),
              "auth_is_minted": bearer in MINTED}
    if path != "/seen":
        SEEN.append(record)

    if path == "/seen":
        return await send_resp(send, 200, json.dumps(list(SEEN)).encode())
    if host == "git.example.test":
        return await git_backend(scope, receive, send, hdrs, body)
    if host == "api.example.test":
        if path == "/echo-b64":
            return await send_resp(send, 200, base64.b64encode((auth or "").encode()), ctype=b"text/plain")
        if path == "/echo-hex":
            return await send_resp(send, 200, (auth or "").encode().hex().encode(), ctype=b"text/plain")
        if path == "/redirect":
            loc = "https://gist.example.test/landing?auth=" + urllib.parse.quote(auth or "", safe="")
            return await send_resp(send, 302, b"", [(b"location", loc.encode())])
        if path == "/mint" and method == "POST":
            tok = "ghs_" + "".join(secrets.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(36))
            MINTED.add(tok)
            return await send_resp(send, 201, json.dumps({"token": tok, "expires_at": "2099-01-01T00:00:00Z"}).encode())
        if path == "/mint-form" and method == "POST":
            tok = "gho_" + secrets.token_hex(18)
            MINTED.add(tok)
            return await send_resp(send, 200, f"access_token={tok}&scope=repo&token_type=bearer".encode(),
                                   ctype=b"application/x-www-form-urlencoded")
        if path == "/user/keys":
            return await send_resp(send, 201, b'{"created": true}')
        if path == "/copilot_internal/user":
            # A fake user-info response with upstream's own stub keys that look credential-like
            # but aren't (token_based_billing, cloud_session_storage_enabled). X-Fixture selects
            # a rogue variant (backstop exception probe) or an unlisted extra field.
            body = {"login": "octo-test", "chat_enabled": True, "token_based_billing": False,
                    "cloud_session_storage_enabled": False,
                    "quota_snapshots": {"chat": {"unlimited": True, "token_based_billing": False}},
                    "endpoints": {"api": "https://model.example.test"}}
            mode = hdrs.get("x-fixture")
            minted = "ghu_" + secrets.token_hex(18)
            if mode == "token-field":
                body["token"] = minted
            elif mode == "token-value":
                body["note"] = minted
            elif mode == "extra-field":
                body["unlisted_feature"] = {"enabled": True}
            elif mode == "not-json":
                return await send_resp(send, 200, b"login=octo-test", ctype=b"text/plain")
            return await send_resp(send, 200, json.dumps(body).encode())
        if path in ("/copilot_internal/managed_settings", "/copilot_internal/team_customizations",
                    "/copilot_internal/content_exclusion"):
            # Org policy. managed_settings follows IManagedSettingsResponse (public client code);
            # the other two shapes are unknown, so an empty object is the honest answer.
            # Canary-style fake values only.
            mode = hdrs.get("x-fixture")
            status = 403 if mode == "unlisted-error" else 200
            if path.endswith("/managed_settings"):
                body = {"permissions": {"deny": ["shell(rm -rf *)"]}, "allowManagedMcpServersOnly": True,
                        "telemetry": {"enabled": True, "endpoint": "https://otel.example.test",
                                      "headers": {"Authorization": "Basic fake-otlp-credential"}}}
                if mode == "token-value":
                    body["permissions"]["allow"] = ["ghu_" + secrets.token_hex(18)]
                elif mode == "url-userinfo":
                    body["extraKnownMarketplaces"] = {"m": {"source": {"source": "git", "url": "https://user:fake-pass@git.example.test/m.git"}}}
                elif mode in ("unlisted", "unlisted-error"):
                    body["newPolicyKey"] = True
                elif mode == "telemetry-list":
                    body["telemetry"] = [{"headers": {"authorization": "Basic fake-otlp-credential"}}]
                elif mode == "telemetry-nested":
                    body["telemetry"] = {"otlp": {"Headers": {"authorization": "Basic fake-otlp-credential"}}}
                elif mode == "telemetry-token":
                    body["telemetry"] = {"headers": {"Authorization": "Bearer ghu_" + secrets.token_hex(18)},
                                         "endpoint": "https://otel-user:fake-pass@otel.example.test"}
            else:
                body = {}
                if mode in ("unlisted", "unlisted-error"):
                    body = {"rules": [{"paths": ["**/secrets/**"]}]}
                elif mode == "token-field":
                    body = {"access_token": "opaque"}
            return await send_resp(send, status, json.dumps(body).encode())
        if path == "/session":
            sid = secrets.token_hex(16)
            return await send_resp(send, 200, b'{"ok": true}',
                                   [(b"set-cookie", f"sid={sid}; Path=/; HttpOnly".encode())])
    echo = dict(record, query=scope["query_string"].decode(), headers=hdrs)
    await send_resp(send, 200, json.dumps(echo).encode())
