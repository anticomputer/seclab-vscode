"""Model-host body policy and budget (policy schema revision 3; secure-agentic plan 4.3/4.4,
probe A22). Every case here is a denial the broker must make before forwarding."""

import json

import pytest

from seclab_broker.models import (Budget, ModelPolicy, StrictJSONError, check_request, is_model_host,
                                  parse_strict)
from seclab_broker.policy import Policy, PolicyError

POL = ModelPolicy.from_json({"providers": ["openai", "anthropic", {
    "id": "fake", "hosts": ["model.example.test"], "endpoints": [{"path": "/v1/chat", "methods": ["POST"]}],
    "fields": ["model", "messages", "tools"], "toolTypes": ["function"]}]})
JSON = {"content-type": ["application/json"]}


def check(host, path, body, method="POST", headers=JSON, upgrade=None, policy=POL):
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    return check_request(policy, host, method, path, headers, raw, upgrade)


@pytest.mark.parametrize("raw", [
    b'{"a":1,"a":2}', b'{"\\u0074ools":[]}', b'{"a":NaN}', b'{"a":1} x', b'{"a":"\\ud800"}',
    b"\xef\xbb\xbf{}", b'{"a":1,}', b"{'a':1}", b"[" * 70 + b"]" * 70, b'{"a":"x\x01"}', b"\xff",
])
def test_strict_json_rejects(raw):
    with pytest.raises(StrictJSONError):
        parse_strict(raw)


def test_strict_json_accepts_normal_documents():
    doc = {"model": "m", "messages": [{"role": "user", "content": "caf\u00e9 \"q\" \\ \n"}], "n": -1.5e3,
           "ok": True, "x": None, "e": {}}
    assert parse_strict(json.dumps(doc).encode()) == doc
    assert parse_strict(json.dumps(doc, ensure_ascii=False).encode()) == doc


def test_allowed_request_passes_and_reports_tools():
    v = check("api.openai.com", "/v1/chat/completions",
              {"model": "m", "messages": [], "tools": [{"type": "function", "function": {"name": "f"}}]})
    assert v.ok and v.provider == "openai" and v.tools == ["function"]
    assert check("api.anthropic.com", "/v1/messages",
                 {"model": "m", "messages": [], "max_tokens": 1, "tools": [{"name": "f", "input_schema": {}}]}).ok
    assert check("api.openai.com", "/v1/models", b"", method="GET", headers={}).ok


@pytest.mark.parametrize("host,path,body,why", [
    ("api.openai.com", "/v1/responses", {"model": "m", "input": "x", "tools": [{"type": "mcp", "server_url": "https://x.example.test"}]}, "tool type"),
    ("api.openai.com", "/v1/responses", {"model": "m", "input": "x", "tools": [{"type": "web_search"}]}, "tool type"),
    ("api.openai.com", "/v1/chat/completions", {"model": "m", "messages": [], "web_search_options": {}}, "field"),
    ("api.openai.com", "/v1/responses", {"model": "m", "prompt": {"id": "pmpt_1"}}, "field"),
    ("api.anthropic.com", "/v1/messages", {"model": "m", "messages": [], "max_tokens": 1, "mcp_servers": [{"url": "https://x.example.test"}]}, "field"),
    ("api.anthropic.com", "/v1/messages", {"model": "m", "messages": [], "max_tokens": 1, "tools": [{"type": "web_fetch_20250910", "name": "web_fetch"}]}, "tool type"),
    ("api.anthropic.com", "/v1/messages", {"model": "m", "messages": [], "max_tokens": 1, "tools": "x"}, "array"),
    ("api.openai.com", "/v1/files", {"x": 1}, "endpoint"),
    ("api.groq.com", "/openai/v1/chat/completions", {"model": "m"}, "no declared provider"),
])
def test_body_policy_denials(host, path, body, why):
    v = check(host, path, body)
    assert not v.ok and why in v.reason


def test_a22_smuggling_shapes_are_denied():
    base = b'{"model":"m","input":"x","tools":[{"type":"function"}]%s}'
    dup = base % b',"tools":[{"type":"mcp","server_url":"https://x.example.test"}]'
    assert "strict JSON" in check("api.openai.com", "/v1/responses", dup).reason
    esc = b'{"model":"m","input":"x","\\u0074ools":[{"type":"mcp"}]}'
    assert "strict JSON" in check("api.openai.com", "/v1/responses", esc).reason
    gz = check("api.openai.com", "/v1/responses", {"model": "m"},
               headers={**JSON, "content-encoding": ["gzip"]})
    assert "encoding" in gz.reason
    for ct in (["text/plain"], ["application/json", "application/json"], [], ["application/x-www-form-urlencoded"]):
        assert not check("api.openai.com", "/v1/responses", {"model": "m"}, headers={"content-type": ct}).ok
    assert "upgrade" in check("api.openai.com", "/v1/responses", b"", method="GET", headers={},
                              upgrade="websocket").reason


def test_tab_chosen_names_stay_out_of_reason():
    v = check("api.openai.com", "/v1/chat/completions", {"model": "m", "IGNORE-ME": 1})
    assert v.reason == "field not allowed for this provider" and v.detail == "IGNORE-ME"


def test_grant_allows_one_server_tool_for_one_provider():
    granted = ModelPolicy.from_json({"providers": ["openai", "anthropic"],
                                     "grants": [{"provider": "openai", "toolType": "web_search"}]})
    assert check("api.openai.com", "/v1/responses", {"model": "m", "tools": [{"type": "web_search"}]},
                 policy=granted).ok
    assert not check("api.openai.com", "/v1/responses", {"model": "m", "tools": [{"type": "mcp"}]},
                     policy=granted).ok
    with pytest.raises(PolicyError):
        ModelPolicy.from_json({"providers": ["openai"], "grants": [{"provider": "nope", "toolType": "x"}]})


def test_known_model_hosts_are_model_hosts_without_a_provider():
    empty = ModelPolicy.from_json(None)
    assert is_model_host("api.openai.com", empty) and is_model_host("x.openai.azure.com", empty)
    assert not is_model_host("api.example.test", empty)
    assert is_model_host("model.example.test", POL)


def test_budget_and_policy_wiring():
    p = Policy.from_json({"version": 1, "models": {"providers": ["copilot"], "budget": {"requests": 2, "bytes": 10}}})
    b = Budget()
    assert b.exhausted(p.models) is None
    b.requests = 2
    assert "request" in b.exhausted(p.models)
    b.requests, b.bytes = 0, 10
    assert "byte" in b.exhausted(p.models)
    with pytest.raises(PolicyError):
        Policy.from_json({"version": 1, "models": {"providers": ["nope"]}})


# ---- security review round 7 regressions ------------------------------------------------

@pytest.mark.parametrize("host,path,body", [
    ("api.openai.com", "/v1/chat/completions", {"model": "m", "messages": [{"role": "user", "content": [
        {"type": "image_url", "image_url": {"url": "https://exfil.example.test/c.png?d=x"}}]}]}),
    ("api.openai.com", "/v1/responses", {"model": "m", "input": [{"role": "user", "content": [
        {"type": "input_file", "file_url": "https://exfil.example.test/f.pdf"}]}]}),
    ("api.openai.com", "/v1/responses", {"model": "m", "input": [{"role": "user", "content": [
        {"type": "input_image", "image_url": "https://exfil.example.test/i.png"}]}]}),
    ("api.anthropic.com", "/v1/messages", {"model": "m", "max_tokens": 1, "messages": [{"role": "user", "content": [
        {"type": "image", "source": {"type": "url", "url": "https://exfil.example.test/c.png?d=x"}}]}]}),
    ("api.anthropic.com", "/v1/messages", {"model": "m", "max_tokens": 1, "messages": [{"role": "user", "content": [
        {"type": "document", "source": {"type": "url", "url": "https://exfil.example.test/d.pdf"}}]}]}),
    ("api.anthropic.com", "/v1/messages", {"model": "m", "max_tokens": 1, "messages": [{"role": "user", "content": [
        {"type": "image", "source": {"type": "URL", "URL": "https://exfil.example.test/c.png"}}]}]}),
])
def test_r7_remote_content_the_provider_would_fetch_is_denied(host, path, body):
    v = check(host, path, body)
    assert not v.ok and "remote content" in v.reason and v.detail.startswith("$.")


def test_r7_inline_content_and_client_tool_calls_pass():
    assert check("api.openai.com", "/v1/chat/completions", {"model": "m", "messages": [{"role": "user", "content": [
        {"type": "text", "text": "see https://docs.example.test/page"},
        {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}}]}]}).ok
    assert check("api.anthropic.com", "/v1/messages", {"model": "m", "max_tokens": 1, "messages": [
        {"role": "assistant", "content": [{"type": "tool_use", "id": "t", "name": "fetch",
                                           "input": {"url": "https://docs.example.test/"}}]},
        {"role": "user", "content": [{"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"}}]}],
        "tools": [{"name": "fetch", "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}}}]}).ok
    granted = ModelPolicy.from_json({"providers": ["anthropic"],
                                     "grants": [{"provider": "anthropic", "toolType": "remote-content"}]})
    assert check("api.anthropic.com", "/v1/messages", {"model": "m", "max_tokens": 1, "messages": [{"role": "user", "content": [
        {"type": "image", "source": {"type": "url", "url": "https://img.example.test/c.png"}}]}]}, policy=granted).ok


def test_r7_case_variant_keys_are_refused():
    with pytest.raises(StrictJSONError):
        parse_strict(b'{"tools":[{"type":"function","Type":"mcp"}]}')
    v = check("api.openai.com", "/v1/chat/completions", {"model": "m", "messages": [], "tools": [{"TYPE": "mcp"}]})
    assert not v.ok


def test_r7_every_credential_location_is_found():
    from seclab_broker.models import Provider, credential_values
    gemini = Provider.from_json({"id": "g", "hosts": ["gen.example.test"], "endpoints": [{"path": "/**", "methods": ["POST"]}],
                                 "fields": ["contents"], "authHeaders": ["X-Custom-Key"], "authQueryParams": ["k2"]})
    hdrs = {"x-goog-api-key": ["a"], "ocp-apim-subscription-key": ["b"], "x-custom-key": ["c"], "cookie": ["d"],
            "user-agent": ["not-a-credential"]}
    found = dict(credential_values(gemini, hdrs, "key=e&KEY=f&subscription-key=g&k2=h&alt=sse"))
    assert set(found) == {"header:x-goog-api-key", "header:ocp-apim-subscription-key", "header:x-custom-key",
                          "header:cookie", "query:key", "query:subscription-key", "query:k2"}


# ---- measured copilot provider (policy schema revision 4) ---------------------------------
# Shapes are the top-level fields and tool types the shipped agent host and Copilot runtime
# sent from a real tab (secure-agentic B2 run, 2026-11-05); content is made up.

COP = ModelPolicy.from_json({"providers": ["copilot"]})
GRANTED = ModelPolicy.from_json({"providers": ["copilot"],
                                 "grants": [{"provider": "copilot", "endpoint": "github-mcp-readonly"}]})
CAPI = "api.individual.githubcopilot.com"
FN = {"type": "function", "name": "view", "parameters": {"type": "object"}}
CUSTOM = {"type": "custom", "name": "apply_patch", "format": {"type": "grammar", "syntax": "lark", "definition": "start: /.+/"}}


def test_measured_copilot_requests_pass():
    responses = {"include": [], "input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": "hi"}]},
                                          {"type": "function_call", "call_id": "c", "name": "view", "arguments": "{}"},
                                          {"type": "function_call_output", "call_id": "c", "output": "ok"}],
                 "instructions": "x", "model": "m", "parallel_tool_calls": True, "reasoning": {"effort": "low", "summary": "auto"},
                 "store": False, "stream": True, "text": {"verbosity": "low"}, "tools": [FN, CUSTOM]}
    v = check(CAPI, "/responses", responses, policy=COP)
    assert v.ok and v.tools == ["function", "custom"]
    chat = {"messages": [{"role": "user", "content": "hi"}], "model": "m", "reasoning_effort": "low",
            "snippy": {"enabled": True}, "stream": True, "stream_options": {"include_usage": True}, "temperature": 0,
            "tools": [{"type": "function", "function": {"name": "view"}}, {"type": "custom", "custom": {"name": "apply_patch", "format": {"type": "grammar"}}}]}
    assert check(CAPI, "/chat/completions", chat, policy=COP).ok
    messages = {"max_tokens": 1, "messages": [{"role": "user", "content": [{"type": "text", "text": "hi", "cache_control": {"type": "ephemeral"}}]}],
                "model": "m", "stream": True, "system": [{"type": "text", "text": "s"}], "temperature": 0,
                "thinking": {"type": "enabled", "budget_tokens": 1024, "display": "summarized"},
                "tools": [{"name": "view", "input_schema": {"type": "object"}}]}
    v = check(CAPI, "/v1/messages", messages, policy=COP)
    assert v.ok and v.tools == ["custom"]
    assert check("api.githubcopilot.com", "/models", b"", method="GET", headers={}, policy=COP).ok


@pytest.mark.parametrize("path,body,why", [
    ("/responses", {"model": "m", "input": "x", "snippy": {"enabled": True}}, "field"),      # chat-only field
    ("/chat/completions", {"model": "m", "messages": [], "system": "s"}, "field"),          # messages-only field
    ("/v1/messages", {"model": "m", "messages": [], "max_tokens": 1, "reasoning_effort": "low"}, "field"),
    ("/responses", {"model": "m", "input": "x", "previous_response_id": "r"}, "field"),       # draft field, never sent
    ("/responses", {"model": "m", "input": "x", "tools": [{"name": "untyped"}]}, "tool type"),  # untyped only on /v1/messages
    ("/responses", {"model": "m", "input": "x", "tools": [{"type": "web_search"}]}, "tool type"),
    ("/responses", {"model": "m", "input": "x", "tools": [{"type": "mcp", "server_url": "https://x.example.test"}]}, "tool type"),
    ("/v1/messages", {"model": "m", "messages": [], "max_tokens": 1, "tools": [{"type": "function", "name": "f"}]}, "tool type"),
    ("/v1/messages", {"model": "m", "messages": [], "max_tokens": 1, "tools": [{"type": "web_fetch_20250910", "name": "w"}]}, "tool type"),
    ("/embeddings", {"model": "m", "input": "x"}, "endpoint"),                                # draft endpoint, never called
    ("/mcp/readonly", {"id": 1, "jsonrpc": "2.0", "method": "tools/list", "params": {}}, "needs a grant"),
])
def test_measured_copilot_denials(path, body, why):
    v = check(CAPI, path, body, policy=COP)
    assert not v.ok and why in v.reason, v


def test_github_remote_mcp_needs_a_per_tab_endpoint_grant():
    rpc = {"id": 1, "jsonrpc": "2.0", "method": "tools/call", "params": {"name": "get_me", "arguments": {}}}
    assert check(CAPI, "/mcp/readonly", rpc, policy=COP).detail == "github-mcp-readonly"
    assert check(CAPI, "/mcp/readonly", rpc, policy=GRANTED).ok
    # The grant opens that endpoint only, with its own field list and no tools.
    assert "field" in check(CAPI, "/mcp/readonly", dict(rpc, tools=[FN]), policy=GRANTED).reason
    assert "endpoint" in check(CAPI, "/mcp", rpc, policy=GRANTED).reason
    # A tool-type grant is not an endpoint grant, and the reverse.
    assert not check(CAPI, "/mcp/readonly", rpc, policy=ModelPolicy.from_json(
        {"providers": ["copilot"], "grants": [{"provider": "copilot", "toolType": "github-mcp-readonly"}]})).ok
    assert "tool type" in check(CAPI, "/responses", {"model": "m", "tools": [{"type": "mcp"}]}, policy=GRANTED).reason


def test_endpoint_grants_are_validated():
    for bad in ({"provider": "copilot", "endpoint": "nope"}, {"provider": "openai", "endpoint": "github-mcp-readonly"},
                {"provider": "missing", "endpoint": "github-mcp-readonly"}):
        with pytest.raises(PolicyError):
            ModelPolicy.from_json({"providers": ["copilot", "openai"], "grants": [bad]})
    with pytest.raises(PolicyError):  # requiresGrant needs an id to be grantable at all
        ModelPolicy.from_json({"providers": [{"id": "p", "hosts": ["p.example.test"], "fields": [],
                                              "endpoints": [{"path": "/x", "methods": ["POST"], "requiresGrant": True}]}]})
    # A plain (non-grantable) endpoint can't be opened by naming its id.
    with pytest.raises(PolicyError):
        ModelPolicy.from_json({"providers": [{"id": "p", "hosts": ["p.example.test"], "fields": [],
                                              "endpoints": [{"id": "e", "path": "/x", "methods": ["POST"]}]}],
                               "grants": [{"provider": "p", "endpoint": "e"}]})


def test_revision4_policy_shapes_validate():
    ok = Policy.from_json({"version": 1, "models": {"providers": ["copilot"], "grants": [
        {"provider": "copilot", "endpoint": "github-mcp-readonly"}, {"provider": "copilot", "toolType": "remote-content"}]}})
    assert ok.models.endpoint_grants == {("copilot", "github-mcp-readonly")}
    for bad in ({"provider": "copilot", "endpoint": "github-mcp-readonly", "toolType": "x"}, {"provider": "copilot"}):
        with pytest.raises(PolicyError):
            Policy.from_json({"version": 1, "models": {"providers": ["copilot"], "grants": [bad]}})
