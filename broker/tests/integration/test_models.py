"""Model hosts through the tab's broker (secure-agentic plan 4.3/4.4): probes A9 (budget)
and A22 (body policy), and sealed agent-host tokens never forwarded (A25, broker side).
The fake model API is the test upstream at model.example.test; credentials are canaries."""

import base64
import hashlib
import json
import os


def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


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


def test_backstop_exception_copilot_user_is_narrow_and_its_response_is_checked(pod, ctl):
    """Coordinator-approved exception (ADR broker-model-access): exactly GET
    /copilot_internal/user, no body, no query, under provider github. A normal response
    passes; a rogue upstream returning a credential-named field, a token-shaped value, or
    non-JSON is blocked and audited as a finding, so no real minted value reaches the tab.
    Measured shape is from fake responses (the spike ran with no real credential)."""
    gh = {"id": "gh", "provider": "github", "inject": {"header": "Authorization", "fmt": "Bearer {value}"},
          "bind": [{"host": "api.example.test", "path": "/copilot_internal/**", "methods": ["GET", "POST"]}]}
    s = pod.load({"allow": [{"host": "api.example.test"}], "credentials": [gh], "prompt": {"enabled": False}})["gh"]
    ctl.call("credential.provide", {"id": "gh", "value": pod.canaries["git"]})
    auth = ["-H", f"Authorization: Bearer {s}"]
    r = pod.curl("https://api.example.test/copilot_internal/user", *auth)
    assert r.code == 200 and r.json()["login"] == "octo-test"
    mark = ctl.mark()
    for mode in ("token-field", "token-value", "not-json"):
        r = pod.curl("https://api.example.test/copilot_internal/user", *auth, "-H", f"X-Fixture: {mode}")
        assert r.code == 502 and "ghu_" not in r.body, (mode, r.body)
    found = [e for e in ctl.notes_since(mark, "audit.event") if e["type"] == "credential.backstop_exception_blocked"]
    assert len(found) == 3
    # Everything else on /copilot_internal stays behind the backstop.
    for args in ([], ["-X", "POST", "-d", "{}"]):
        assert pod.curl("https://api.example.test/copilot_internal/user?x=1", *auth, *args).code == 403
    assert pod.curl("https://api.example.test/copilot_internal/user", *auth, "-X", "POST", "-d", "{}").code == 403
    assert pod.curl("https://api.example.test/copilot_internal/User", *auth).code == 403
    assert pod.curl("https://api.example.test/copilot_internal/v2/token", *auth).code == 403


# ---- user decisions on the measured traffic (2026-11-05; policy schema revision 4) --------

# The built-in copilot provider's measured endpoints, re-hosted onto the fixture (the unit
# tests check the built-in data itself).
CAPI = {"id": "copilot-fixture", "hosts": ["model.example.test"], "fields": [], "toolTypes": [], "endpoints": [
    {"path": "/models", "methods": ["GET"]},
    {"path": "/responses", "methods": ["POST"], "toolTypes": ["function", "custom"],
     "fields": ["include", "input", "instructions", "model", "parallel_tool_calls", "reasoning", "store", "stream", "text", "tools"]},
    {"path": "/chat/completions", "methods": ["POST"], "toolTypes": ["function", "custom"],
     "fields": ["messages", "model", "reasoning_effort", "snippy", "stream", "stream_options", "temperature", "tools"]},
    {"path": "/v1/messages", "methods": ["POST"], "toolTypes": ["custom"], "untypedTool": "custom",
     "fields": ["max_tokens", "messages", "model", "stream", "system", "temperature", "thinking", "tools"]},
    {"id": "github-mcp-readonly", "path": "/mcp/readonly", "methods": ["POST"], "requiresGrant": True,
     "fields": ["id", "jsonrpc", "method", "params"], "toolTypes": []}]}
ORG = ("managed_settings", "team_customizations", "content_exclusion")


def gh_parent(extra_bind=()):
    """The GitHub token as the agent host uses it (amended D7): Bearer, bound to the four
    /copilot_internal GETs and the measured CAPI model routes by exact path and method."""
    bind = [{"host": "api.example.test", "path": f"/copilot_internal/{p}", "methods": ["GET"]} for p in ("user",) + ORG]
    bind += [{"host": "model.example.test", "path": "/models", "methods": ["GET"]}]
    bind += [{"host": "model.example.test", "path": p, "methods": ["POST"]}
             for p in ("/responses", "/chat/completions", "/v1/messages")]
    return {"id": "gh", "provider": "github", "inject": {"header": "Authorization", "fmt": "Bearer {value}"},
            "bind": bind + list(extra_bind)}


def load_gh(pod, ctl, grants=(), extra_bind=()):
    s = pod.load({"allow": [{"host": "api.example.test"}, {"host": "model.example.test"}],
                  "credentials": [gh_parent(extra_bind)], "prompt": {"enabled": False},
                  "models": {"providers": [CAPI], "grants": list(grants)}})["gh"]
    ctl.call("credential.provide", {"id": "gh", "value": pod.canaries["git"]})
    return s


def capi(pod, s, path, body):
    return pod.curl(f"https://model.example.test{path}", "-X", "POST", "-H", f"Authorization: Bearer {s}",
                    "-H", "Content-Type: application/json", "--data-binary", json.dumps(body))


def test_d7_amended_github_token_reaches_the_measured_capi_routes_only(pod, ctl):
    """Amended D7 (user-accepted): the GitHub token itself is injected on the CAPI model
    routes, by exact path and method, with the measured body shapes; the tab only ever holds
    the sentinel. Anything else on the model host is denied before the upstream."""
    s = load_gh(pod, ctl)
    fn = {"type": "function", "name": "view", "parameters": {"type": "object"}}
    custom = {"type": "custom", "name": "apply_patch", "format": {"type": "grammar", "syntax": "lark", "definition": "start: /.+/"}}
    ok = [("/responses", {"model": "m", "input": "hi", "stream": True, "tools": [fn, custom]}),
          ("/chat/completions", {"model": "m", "messages": [], "snippy": {"enabled": True}, "tools": [fn]}),
          ("/v1/messages", {"model": "m", "messages": [], "max_tokens": 1, "system": "s",
                            "thinking": {"type": "enabled", "budget_tokens": 1024}, "tools": [{"name": "view", "input_schema": {}}]})]
    for path, body in ok:
        r = capi(pod, s, path, body)
        assert r.code == 200 and r.json()["path"] == path, (path, r.code, r.body)
        pod.assert_no_canary(r.body)
    r = pod.curl("https://model.example.test/models", "-H", f"Authorization: Bearer {s}")
    assert r.code == 200
    got = [x for x in pod.seen() if x["host"] == "model.example.test" and x["path"] in ("/models",) + tuple(p for p, _ in ok)]
    assert len(got) == 4 and {x["auth_sha256"] for x in got} == {sha("Bearer " + pod.canaries["git"])}
    before = len(pod.seen())
    for path, body in [("/embeddings", {"model": "m", "input": "x"}),
                       ("/responses", {"model": "m", "input": "x", "snippy": {"enabled": True}}),
                       ("/responses", {"model": "m", "input": "x", "tools": [{"type": "web_search"}]}),
                       ("/mcp/readonly", {"id": 1, "jsonrpc": "2.0", "method": "tools/list", "params": {}})]:
        assert capi(pod, s, path, body).code == 403, path
    assert len(pod.seen()) == before


def test_github_remote_mcp_is_denied_until_a_tab_grant(pod, ctl):
    """Coordinator decision: POST <capi>/mcp/readonly (GitHub's remote MCP server acting on
    the user's GitHub) is denied by default; a per-tab Tier C grant plus a binding opens it."""
    rpc = {"id": 1, "jsonrpc": "2.0", "method": "tools/list", "params": {}}
    s = load_gh(pod, ctl)
    mark = ctl.mark()
    assert capi(pod, s, "/mcp/readonly", rpc).code == 403
    denied = ctl.wait_note("audit.event", lambda e: e["type"] == "model.denied", since=mark, timeout=10)
    assert "grant" in denied["reason"] and denied["detail"] == "github-mcp-readonly"
    mcp = {"host": "model.example.test", "path": "/mcp/readonly", "methods": ["POST"]}
    s = load_gh(pod, ctl, grants=[{"provider": "copilot-fixture", "endpoint": "github-mcp-readonly"}], extra_bind=[mcp])
    r = capi(pod, s, "/mcp/readonly", rpc)
    assert r.code == 200 and r.json()["auth_sha256"] == sha("Bearer " + pod.canaries["git"])


def test_org_policy_gets_are_narrow_and_their_responses_checked(pod, ctl):
    """User decision: exactly GET /copilot_internal/{managed_settings,team_customizations,
    content_exclusion}, with the same checks as /user, and (secure-agentic review) strict
    allowlists: any unlisted top-level key blocks. managed_settings passes in its public shape
    with the OTLP headers map dropped; the other two pass only as {} until their shapes are
    known. A token-shaped value, a credential-named key or URL userinfo is blocked and audited;
    the tab never sees it."""
    s = load_gh(pod, ctl)
    auth = ["-H", f"Authorization: Bearer {s}"]
    url = "https://api.example.test/copilot_internal/managed_settings"
    mark = ctl.mark()
    r = pod.curl(url, *auth)
    doc = r.json()
    assert r.code == 200 and doc["permissions"]["deny"] and doc["telemetry"]["endpoint"], r.body
    assert "headers" not in doc["telemetry"] and "fake-otlp-credential" not in r.body
    e = ctl.wait_note("audit.event", lambda e: e["type"] == "credential.backstop_exception_filtered", since=mark, timeout=10)
    assert e["detail"] == "telemetry.headers"
    mark = ctl.mark()
    for mode in ("token-value", "url-userinfo", "unlisted"):
        r = pod.curl(url, *auth, "-H", f"X-Fixture: {mode}")
        assert r.code == 502 and "ghu_" not in r.body and "fake-pass" not in r.body, (mode, r.body)
    for name in ORG[1:]:
        u = f"https://api.example.test/copilot_internal/{name}"
        r = pod.curl(u, *auth)
        assert r.code == 200 and r.json() == {}, (name, r.body)
        for mode in ("unlisted", "token-field"):
            r = pod.curl(u, *auth, "-H", f"X-Fixture: {mode}")
            assert r.code == 502 and "opaque" not in r.body, (name, mode)
    found = [e for e in ctl.notes_since(mark, "audit.event") if e["type"] == "credential.backstop_exception_blocked"]
    assert len(found) == 7
    for name in ORG:
        u = f"https://api.example.test/copilot_internal/{name}"
        assert pod.curl(u + "?org=x", *auth).code == 403
        assert pod.curl(u, *auth, "-X", "POST", "-d", "{}").code == 403
    assert pod.curl("https://api.example.test/copilot_internal/v2/token", *auth).code == 403


def test_copilot_user_benign_keys_pass_and_unlisted_fields_are_dropped(pod, ctl):
    """The /user response's measured field allowlist: upstream's own stub keys that look like
    credentials (token_based_billing, cloud_session_storage_enabled) pass; a field outside
    the allowlist is dropped and audited as a finding; a token-shaped value still blocks."""
    s = load_gh(pod, ctl)
    auth = ["-H", f"Authorization: Bearer {s}"]
    r = pod.curl("https://api.example.test/copilot_internal/user", *auth)
    doc = r.json()
    assert r.code == 200 and doc["token_based_billing"] is False and doc["quota_snapshots"]["chat"]["unlimited"]
    mark = ctl.mark()
    r = pod.curl("https://api.example.test/copilot_internal/user", *auth, "-H", "X-Fixture: extra-field")
    assert r.code == 200 and "unlisted_feature" not in r.json() and r.json()["login"] == "octo-test"
    e = ctl.wait_note("audit.event", lambda e: e["type"] == "credential.backstop_exception_filtered", since=mark, timeout=10)
    assert e["detail"] == "unlisted_feature"
    r = pod.curl("https://api.example.test/copilot_internal/user", *auth, "-H", "X-Fixture: token-value")
    assert r.code == 502 and "ghu_" not in r.body
