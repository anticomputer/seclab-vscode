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
