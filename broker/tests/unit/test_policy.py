"""Matcher invariants. Each test here guards a bypass class; none may regress."""

import json
from pathlib import Path

import pytest

from seclab_broker.policy import (Binding, Inject, Policy, PolicyError, RequestView, Rule,
                                  backstop_denies, canonical_path, normalize_host,
                                  query_has_method_override)

EXAMPLES = Path(__file__).resolve().parents[2] / "examples"


def req(host="api.example.com", path="/", method="GET", scheme="https", port=None, query=""):
    return RequestView(scheme, host, port or (443 if scheme == "https" else 80), method, path, query)


@pytest.mark.parametrize("raw,expected", [
    ("API.Example.COM", "api.example.com"),
    ("api.example.com.", "api.example.com"),
    ("[::ffff:1.2.3.4]", "1.2.3.4"),
    ("::ffff:127.0.0.1", "127.0.0.1"),
    ("[2001:db8::1]", "2001:db8::1"),
    ("bücher.example", "xn--bcher-kva.example"),
])
def test_host_normalisation(raw, expected):
    assert normalize_host(raw) == expected


@pytest.mark.parametrize("raw", [
    "", "2130706433", "0x7f000001", "0x7f.1", "127.1", "1.2.3", "evil.com%2f", "a..b",
    "-a.com", "a_b.com", "fe80::1%eth0", "a.com:443", "a b.com", "a.123",
])
def test_host_rejects(raw):
    assert normalize_host(raw) is None


@pytest.mark.parametrize("raw,expected", [
    ("/repos/o/r", ("/repos/o/r", "")),
    ("/repos/o/r?x=1", ("/repos/o/r", "x=1")),
    ("/a%20b", ("/a b", "")),
    ("/", ("/", "")),
])
def test_canonical_path_ok(raw, expected):
    assert canonical_path(raw) == expected


@pytest.mark.parametrize("raw", [
    "/repos/../user/keys", "/repos/./x", "/repos/%2e%2e/user/keys", "/repos/%2E%2E/user",
    "/repos%2fo", "/a%5cb", "/a\\b", "/a;b", "/a%3bb", "//user/keys", "/user//keys",
    "/a%00", "/a%25", "*", "http://x.test/", "/a#b", "/%ff", "/a\tb",
])
def test_canonical_path_rejects(raw):
    assert canonical_path(raw) is None


def test_method_override_query():
    assert query_has_method_override("_method=DELETE")
    assert query_has_method_override("a=1&_METHOD=put")
    assert not query_has_method_override("method=x")


def test_rule_defaults_https_443_any_method():
    r = Rule.from_json({"host": "api.example.com"})
    assert r.matches(req())
    assert r.matches(req(method="POST", path="/x/y"))
    assert not r.matches(req(scheme="http"))
    assert not r.matches(req(port=8443))
    assert not r.matches(req(host="evil.api.example.com"))


def test_rule_wildcard_is_strict_subdomain():
    r = Rule.from_json({"host": "*.example.com"})
    assert r.matches(req(host="a.example.com"))
    assert r.matches(req(host="a.b.example.com"))
    assert not r.matches(req(host="example.com"))
    assert not r.matches(req(host="badexample.com"))


def test_rule_path_glob():
    r = Rule.from_json({"host": "h.example", "methods": ["GET"], "path": "/repos/*/x"})
    assert r.matches(req(host="h.example", path="/repos/a/x"))
    assert not r.matches(req(host="h.example", path="/repos/a/b/x"))
    assert not r.matches(req(host="h.example", path="/REPOS/a/x"))
    assert not r.matches(req(host="h.example", path="/repos/a/x", method="POST"))


def test_rule_rejects_non_canonical_hosts():
    with pytest.raises(PolicyError):
        Rule.from_json({"host": "API.example.com"})
    with pytest.raises(PolicyError):
        Rule.from_json({"host": "*.1.2.3.4"})


def test_binding_never_matches_cleartext_and_needs_explicit_methods():
    inj = {"header": "Authorization", "fmt": "Bearer {value}"}
    b = Binding.from_json({"host": "api.example.com", "path": "/repos/**", "methods": ["GET"], "inject": inj})
    assert b.matches(req(path="/repos/a/b"))
    assert not b.matches(req(path="/repos/a/b", scheme="http", port=443))
    assert not b.matches(req(path="/gists", method="POST"))
    with pytest.raises(PolicyError):
        Binding.from_json({"host": "api.example.com", "path": "/**", "methods": ["*"], "inject": inj})


def test_binding_websocket_opt_in():
    """Revision 2: upgrades get a credential only from a binding with websocket: true, and
    only for the WebSocket protocol."""
    inj = {"header": "Authorization", "fmt": "Bearer {value}"}
    plain = Binding.from_json({"host": "api.example.com", "path": "/ws", "methods": ["GET"], "inject": inj})
    ws = Binding.from_json({"host": "api.example.com", "path": "/ws", "methods": ["GET"], "inject": inj,
                            "websocket": True})
    r = req(path="/ws")
    assert plain.matches(r) and ws.matches(r)
    assert not plain.matches(r, "websocket") and ws.matches(r, "websocket")
    for other in ("h2c", "connect", "websocket, h2c", ""):
        assert not ws.matches(r, other)
    assert "websocket" not in plain.to_json() and ws.to_json()["websocket"] is True
    assert Binding.from_json(ws.to_json()).websocket
    with pytest.raises(PolicyError):
        Binding.from_json({"host": "api.example.com", "path": "/ws", "methods": ["GET"], "inject": inj,
                           "websocket": "yes"})


@pytest.mark.parametrize("header", ["Host", "content-length", "Proxy-Authorization", "Proxy-Foo", "Transfer-Encoding"])
def test_inject_forbidden_headers(header):
    with pytest.raises(PolicyError):
        Inject.from_json({"header": header, "fmt": "{value}"})


def test_inject_render():
    assert Inject.from_json({"header": "Authorization", "fmt": "Bearer {value}"}).render("abc") == "Bearer abc"
    basic = Inject.from_json({"header": "Authorization", "fmt": "Basic {base64:x-access-token:{value}}"})
    assert basic.render("tok") == "Basic eC1hY2Nlc3MtdG9rZW46dG9r"
    with pytest.raises(PolicyError):
        Inject.from_json({"header": "Authorization", "fmt": "Bearer {other}"})
    with pytest.raises(PolicyError):
        Inject.from_json({"header": "Authorization", "fmt": "Bearer static"})


def test_examples_validate():
    for f in EXAMPLES.glob("*.json"):
        Policy.from_json(json.loads(f.read_text()))


def test_policy_schema_rejects_unknown_fields_and_versions():
    with pytest.raises(PolicyError):
        Policy.from_json({"version": 2})
    with pytest.raises(PolicyError):
        Policy.from_json({"version": 1, "allow": [{"host": "a.com", "extra": 1}]})
    with pytest.raises(PolicyError):
        Policy.from_json({"version": 1, "credentials": [{"id": "x", "bind": {"host": "a.com", "path": "/", "methods": ["GET"]}}]})


def test_default_deny_and_baseline():
    p = Policy.from_json({"version": 1})
    assert p.allow_match(req(host="example.com")) is None
    assert p.allow_match(req(host="open-vsx.org", path="/api/x")) is not None
    assert p.allow_match(req(host="open-vsx.org", path="/api/x", method="POST")) is None
    assert Policy.from_json({"version": 1, "baseline": False}).allow_match(req(host="open-vsx.org")) is None


@pytest.mark.parametrize("method,path", [
    ("POST", "/user/keys"), ("POST", "/USER/KEYS"), ("POST", "/user/keys/"),
    ("POST", "/repos/o/r/keys"), ("POST", "/app/installations/1/access_tokens"),
    ("POST", "/repos/o/r/actions/runners/registration-token"),
    ("POST", "/orgs/o/actions/runners/generate-jitconfig"),
    ("GET", "/authorizations"), ("DELETE", "/authorizations/1"),
    ("GET", "/copilot_internal/v2/token"), ("POST", "/api/v3/user/keys"),
    ("POST", "/user/codespaces"), ("PATCH", "/applications/abc/token"),
])
def test_github_backstop(method, path):
    assert backstop_denies(req(host="api.github.com", method=method, path=path)) is not None


@pytest.mark.parametrize("method,path,host", [
    ("GET", "/user/keys", "api.github.com"),
    ("GET", "/repos/o/r", "api.github.com"),
    ("POST", "/user/keys", "api.example.com"),
])
def test_github_backstop_negative(method, path, host):
    assert backstop_denies(req(host=host, method=method, path=path)) is None


def test_backstop_by_provider_name_for_other_hosts():
    assert backstop_denies(req(host="ghe.corp.example", method="POST", path="/api/v3/user/keys"), "github")


def test_backstop_exception_is_exact():
    """Coordinator-approved: only GET /copilot_internal/user (and its /api/v3 form), exact
    case, no query. The deny still matches it; the exception is checked separately."""
    from seclab_broker.policy import backstop_exception
    ok = req(host="api.github.com", method="GET", path="/copilot_internal/user")
    assert backstop_denies(ok) is not None and backstop_exception(ok) is not None
    assert backstop_exception(req(host="api.github.com", method="GET", path="/api/v3/copilot_internal/user"))
    for bad in (dict(method="POST"), dict(path="/copilot_internal/User"), dict(path="/copilot_internal/user/x"),
                dict(path="/copilot_internal/v2/token"), dict(host="api.example.com")):
        assert backstop_exception(req(**{"host": "api.github.com", "method": "GET",
                                         "path": "/copilot_internal/user", **bad})) is None
    from seclab_broker.policy import RequestView
    assert backstop_exception(RequestView("https", "api.github.com", 443, "GET", "/copilot_internal/user", "x=1")) is None


@pytest.mark.parametrize("name", ["managed_settings", "team_customizations", "content_exclusion"])
def test_org_policy_backstop_exceptions_are_exact(name):
    """User-approved 2026-11-05 ('Allow exactly those three GETs, with the same strict checks
    as /user'): GET only, exact case, no query, both path forms, any GitHub host by provider;
    every other /copilot_internal path stays denied."""
    from seclab_broker.policy import backstop_exception
    path = f"/copilot_internal/{name}"
    for host, p in (("api.github.com", path), ("ghe.corp.example", "/api/v3" + path), ("api.acme.ghe.example", path)):
        exc = backstop_exception(req(host=host, method="GET", path=p), "github")
        assert exc is not None and exc.response_fields is None and not exc.benign_keys
    for bad in (dict(method="POST"), dict(method="PUT"), dict(path=path.upper()), dict(path=path + "/x"),
                dict(path=path + "s"), dict(query="org=x")):
        assert backstop_exception(req(**{"host": "api.github.com", "method": "GET", "path": path, **bad})) is None
    for other in ("/copilot_internal/v2/token", "/copilot_internal/settings", "/copilot_internal/mcp_registry"):
        assert backstop_denies(req(host="api.github.com", method="GET", path=other)) is not None
        assert backstop_exception(req(host="api.github.com", method="GET", path=other)) is None


def test_copilot_user_exception_has_the_measured_field_allowlist():
    from seclab_broker.policy import backstop_exception
    exc = backstop_exception(req(host="api.github.com", method="GET", path="/copilot_internal/user"))
    assert {"login", "endpoints", "copilotignore_enabled", "quota_snapshots"} <= exc.response_fields
    assert "token" not in exc.response_fields
    assert exc.benign_keys == {"token_based_billing", "cloud_session_storage_enabled"}
