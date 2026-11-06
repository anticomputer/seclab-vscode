"""Matcher invariants. Each test here guards a bypass class; none may regress."""

import json
import re
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
        # Strict allowlists (secure-agentic review): any unlisted top-level key blocks.
        assert exc is not None and exc.strict_fields and exc.response_fields is not None and not exc.benign_keys
    if name == "managed_settings":
        assert {"permissions", "allowedMcpServers", "deniedMcpServers"} <= exc.response_fields
        assert exc.drop_fields == {"telemetry"} and "telemetry" not in exc.response_fields
    else:
        assert exc.response_fields == {"message", "documentation_url", "status"} and exc.drop_fields == frozenset()
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
    assert "token" not in exc.response_fields and not exc.strict_fields
    # Benign names only at their measured JSON paths (review 11-3).
    assert exc.is_benign("$.token_based_billing") and exc.is_benign("$.quota_snapshots.chat.token_based_billing")
    for p in ("$.endpoints.token_based_billing", "$.quota_snapshots.token_based_billing",
              "$.quota_snapshots.a.b.token_based_billing", "$.x.cloud_session_storage_enabled", "$.token"):
        assert not exc.is_benign(p), p


def test_r11_shipped_provider_data_is_validated(tmp_path, monkeypatch):
    """Review 11-1: a misspelt key in shipped data fails at load instead of silently
    disabling a check (here the grant gate on remote MCP, and the /user field filter)."""
    import seclab_broker.models as models
    import seclab_broker.policy as policy
    data = json.loads((policy.DATA_DIR / "model-providers.v1.json").read_text())
    ep = next(e for e in data["providers"][0]["endpoints"] if e.get("requiresGrant"))
    ep["requireGrant"] = ep.pop("requiresGrant")
    (tmp_path / "model-providers.v1.json").write_text(json.dumps(data))
    monkeypatch.setattr(models, "DATA_DIR", tmp_path)
    models.builtin_providers.cache_clear()
    try:
        with pytest.raises(PolicyError):
            models.builtin_providers()
    finally:
        models.builtin_providers.cache_clear()
    gh = json.loads((policy.DATA_DIR / "providers" / "github.json").read_text())
    for mutate in (lambda d: d["exceptions"][0].update(responseField=d["exceptions"][0].pop("responseFields")),
                   lambda d: d["exceptions"][1].pop("responseFields"),
                   lambda d: d["deny"][0].update(method="POST")):
        d = json.loads(json.dumps(gh))
        mutate(d)
        with pytest.raises(PolicyError):
            policy._check_backstop_file("github.json", d)
    policy._check_backstop_file("github.json", gh)


def test_r11_request_summary_carries_query_key_names_only():
    s = req(host="api.github.com", path="/copilot_internal/content_exclusion", query="repository=o%2Fr&b=2&b=3&x").summary()
    assert s["queryKeys"] == ["b", "repository", "x"] and "o%2Fr" not in json.dumps(s)
    assert "queryKeys" not in req(host="api.github.com").summary()
    # Review 11b-7: no split %XX escape; a sealed agent-host token never exported.
    long = req(query="%C3%A9" * 40 + "=1").summary()["queryKeys"][0]
    assert len(long) <= 64 and not re.search(r"%[0-9A-F]?$", long)
    assert req(query="copilot-sealed.v1.BBBB=1").summary()["queryKeys"] == ["[sealed]"]
    # The marker can't be forged (review 11c-4), and a sealed token in the path isn't exported (11c-5).
    assert req(query="[sealed]=1").summary()["queryKeys"] == ["%5Bsealed%5D"]
    assert req(path="/x/copilot-sealed.v1.AAAA/y").summary()["path"] == "/x/[sealed]/y"
    assert "[sealed]" not in req(path="/[sealed]").summary()["path"]


def test_r11_url_userinfo_pattern():
    from seclab_broker.engine_mitmproxy import URL_USERINFO
    for bad in ("https://user:fake-pass@git.example.test/m.git", "https://abcdefghijklmnop1234@h.example.test/",
                "ssh://git:x@h.example.test/r", "https://user%3Afake@h.example.test/", "//user:fake@h.example.test/",
                "HTTPS://u:p@h.example.test/", "see //user:fake@h.example.test/ ok"):
        assert URL_USERINFO.search(bad), bad
    for ok in ("ssh://git@h.example.test/r.git", "https://h.example.test/a@b", "mailto:a@b.example.test",
               "git@h.example.test:o/r", "https://h.example.test/x%40y", "a//b:c@d", "x://y:z@ "):
        assert not URL_USERINFO.search(ok), ok


def test_r11b_backstop_data_is_checked_when_a_policy_loads(monkeypatch):
    import seclab_broker.policy as policy
    called = []
    monkeypatch.setattr(policy, "providers", lambda: called.append(1) or {})
    Policy.from_json({"version": 1})
    assert called
    for bad in ({"dropFields": ["telemetry.headers"]}, {"dropFields": ["*"]}, {"benignKeys": ["token"]},
                {"responseFields": ["a.b"]}):
        gh = json.loads((policy.DATA_DIR / "providers" / "github.json").read_text())
        gh["exceptions"][1].update(bad)
        with pytest.raises(PolicyError):
            policy._check_backstop_file("github.json", gh)


def test_deny_rules_are_every_port_and_scheme_and_validated():
    """Revision 5: a block can't be sidestepped by a non-default port or scheme, and it wins
    over allow rules and the baseline (the engine checks deny_match first)."""
    p = Policy.from_json({"version": 1, "allow": [{"host": "evil.example.test"}],
                          "deny": [{"id": "b", "host": "*.evil.example.test"}, {"id": "c", "host": "evil.example.test",
                                                                               "ports": [443], "schemes": ["https"]}]})
    for r in (req(host="evil.example.test"), req(host="a.evil.example.test", port=8443),
              req(host="x.y.evil.example.test", scheme="http", port=8080)):
        assert p.deny_match(r) is not None, r
    # `*.x` on a deny rule also blocks the apex (review 12-2).
    apex = Policy.from_json({"version": 1, "allow": [{"host": "evil.example.test"}],
                             "deny": [{"id": "b", "host": "*.evil.example.test"}]})
    assert apex.deny_match(req(host="evil.example.test")) is not None
    assert apex.deny_match(req(host="notevil.example.test")) is None
    assert p.deny_match(req(host="evil.example.test", port=8443)).id == "b"  # apex covered by `*.`
    narrow = Policy.from_json({"version": 1, "allow": [{"host": "evil.example.test"}],
                               "deny": [{"id": "c", "host": "evil.example.test", "ports": [443], "schemes": ["https"]}]})
    assert narrow.deny_match(req(host="evil.example.test", port=8443)) is None
    assert narrow.allow_match(req(host="evil.example.test")) is not None and narrow.deny_match(req(host="evil.example.test")).id == "c"
    assert p.to_json()["deny"][0] == {"id": "b", "host": "*.evil.example.test", "schemes": ["http", "https"]}
    for bad in ([{"host": "x.example.test"}], [{"id": "d", "host": "x.example.test", "path": "/x"}],
                [{"id": "d", "host": "x.example.test"}, {"id": "d", "host": "y.example.test"}],
                [{"id": "d", "host": "X.Example.test"}]):
        with pytest.raises(PolicyError):
            Policy.from_json({"version": 1, "deny": bad})
    assert "deny" not in Policy.from_json({"version": 1}).to_json()


def test_request_summary_carries_client_port():
    v = RequestView("https", "api.example.com", 443, "GET", "/", "", client_port=50123)
    assert v.summary()["clientPort"] == 50123 and "clientPort" not in req().summary()
    assert v == req(host="api.example.com")  # not part of request identity


def test_credential_budget_is_validated_and_counts_parent():
    """Revision 6: a per-credential budget over the tab's lifetime; derived use counts
    against the parent; counters survive policy.load."""
    from seclab_broker.core import Broker
    cred = {"id": "cfs", "inject": {"header": "Authorization", "fmt": "Basic {base64:cfs:{value}}"},
            "bind": [{"host": "pkgs.example.test", "path": "/feed/**", "methods": ["GET"]}],
            "budget": {"requests": 2, "bytes": 100}}
    b = Broker()
    b.rpc_policy_load({"policy": {"version": 1, "credentials": [cred]}})
    c = b.creds.get("cfs")
    assert c.budget == (2, 100) and b.credential_budget_exceeded(c) is None
    b.charge_credential(c, requests=1, nbytes=10)
    child = b.creds.derive(c, "seclab-canary-derived-0000000000000000", "pattern")
    assert b.credential_budget_exceeded(child) is None
    b.charge_credential(child, requests=1)
    assert b.credential_budget_exceeded(c) == ("cfs", "request budget exhausted")
    assert b.credential_budget_exceeded(child) == ("cfs", "request budget exhausted")
    # Review 13-2: a grandchild charges the root too.
    grandchild = b.creds.derive(child, "seclab-canary-derived-1111111111111111", "pattern")
    assert b.credential_budget_exceeded(grandchild) == ("cfs", "request budget exhausted")
    b.charge_credential(grandchild, requests=5)
    assert b.credential_usage["cfs"].requests == 7
    health = b.dispatch("health", {})["credentialBudgets"]
    assert health == [{"id": "cfs", "requests": 7, "bytes": 10, "maxRequests": 2, "maxBytes": 100}]
    b.rpc_policy_load({"policy": {"version": 1, "credentials": [dict(cred, budget={"bytes": 100})]}})
    assert b.credential_budget_exceeded(c) is None  # the request cap was lifted; usage kept
    b.charge_credential(c, nbytes=90)
    assert b.credential_budget_exceeded(c) == ("cfs", "byte budget exhausted")
    ws = dict(cred, bind=[{"host": "pkgs.example.test", "path": "/feed/**", "methods": ["GET"], "websocket": True}])
    with pytest.raises(PolicyError):  # review 13-10
        Policy.from_json({"version": 1, "credentials": [ws]})
    Policy.from_json({"version": 1, "credentials": [dict(ws, budget={"requests": 5})]})
    for bad in ({"requests": -1}, {"requests": 1, "other": 1}, {"bytes": "1"}):
        with pytest.raises(PolicyError):
            Policy.from_json({"version": 1, "credentials": [dict(cred, budget=bad)]})


@pytest.mark.parametrize("method,path,denied", [
    ("GET", "/example-org/ExampleProject/_packaging/example-npm-feed/npm/registry/left-pad", False),
    ("GET", "/example-org/ExampleProject/_packaging/example-pypi-feed/pypi/download/x/1.0/x-1.0-py3-none-any.whl", False),
    ("PUT", "/example-org/ExampleProject/_packaging/example-npm-feed/npm/registry/left-pad", True),
    ("POST", "/example-org/ExampleProject/_packaging/example-pypi-feed/pypi/upload", True),
    ("DELETE", "/example-org/ExampleProject/_packaging/example-npm-feed/npm/registry/left-pad/-rev/1", True),
    ("PATCH", "/example-org/_packaging/feed/npm/registry/x", True),
    ("GET", "/example-org/_apis/tokens/pats", True),
    ("POST", "/example-org/ExampleProject/_apis/packaging/feeds", True),
    ("GET", "/_apis/token/sessiontokens", True),
    ("GET", "/EXAMPLE-ORG/_APIS/Tokens/Pats", True),
    # Review 13-1/13-4/13-9: any depth, organisation in the hostname, trailing dots.
    ("PUT", "/_packaging/example-npm-feed/npm/registry/left-pad", True),
    ("GET", "/a/b/team/_apis/tokens/pats", True),
    ("GET", "/_apis.", True),
    ("GET", "/org/_apis. /tokens", True),
    ("GET", "/_packaging/example-npm-feed/npm/registry/left-pad", False),
])
def test_azure_devops_backstop(method, path, denied):
    for host, provider in (("pkgs.dev.azure.com", None), ("vssps.dev.azure.com", None), ("feeds.dev.azure.com", None),
                           ("myorg.pkgs.visualstudio.com", None), ("visualstudio.com", None),
                           ("feed.example.test", "azure-devops")):
        assert (backstop_denies(req(host=host, method=method, path=path), provider) is not None) == denied, (host, method, path)
    assert backstop_denies(req(host="feed.example.test", method="PUT", path="/o/p/_packaging/f")) is None  # not by host
