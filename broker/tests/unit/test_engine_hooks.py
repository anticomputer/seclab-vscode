"""Engine hooks driven with mitmproxy's own test flows, for paths the pod harness can't reach:
response trailers (the hypercorn upstream can't send them), a hook whose audit also fails, an
unclassified flow, and a spent credential arriving on the first-use binding prompt path.
Regression tests for broker findings m2-m3 #6 and #8, 11-2 and 13-8."""

import asyncio

from mitmproxy import http
from mitmproxy.test import tflow

from seclab_broker.core import Broker
from seclab_broker.engine_mitmproxy import SeclabAddon
from seclab_broker.policy import RequestView

CANARY = "seclab-test-canary-" + "T" * 24 + "-value"
MINTED = "ghs_" + "a1B2" * 9
HOST = "api.example.test"


def _broker(**policy):
    b = Broker(tab_id="t1")
    b.dispatch("policy.load", {"policy": {"version": 1, "credentials": [{
        "id": "c1", "bind": {"host": HOST, "path": "/**", "methods": ["GET"]},
        "inject": {"header": "Authorization", "fmt": "Bearer {value}"}}], **policy}})
    b.dispatch("credential.provide", {"id": "c1", "value": CANARY})
    events = []
    b.add_sink(lambda m, p: events.append((m, p)))
    return b, events


def _view(path="/x", host=HOST):
    return RequestView("https", host, 443, "GET", path, "")


def _credentialed_response(trailers, body=b"{}", ctype="application/json"):
    b, events = _broker()
    addon = SeclabAddon(b, frozenset())
    f = tflow.tflow(resp=True)
    f.request.host = HOST
    f.metadata["seclab.view"] = _view()
    f.metadata["seclab.injected"] = ["c1"]
    f.response.status_code = 200
    f.response.headers["content-type"] = ctype
    f.response.content = body
    f.response.trailers = http.Headers(trailers)
    asyncio.run(addon.response(f))
    blocked = [p for m, p in events if m == "audit.event" and p.get("type") == "response.blocked"]
    return f, blocked


def test_m2m3_6_response_trailers_are_scanned():
    """m2-m3 #6: a minted token or the real value in a response trailer blocks the response,
    a benign trailer passes, and a sentinel in a request trailer is located (so it's never
    forwarded outside its binding)."""
    f, blocked = _credentialed_response([(b"x-trace", b"ok")])
    assert f.response.status_code == 200 and not blocked
    assert f.response.trailers.fields == ((b"x-trace", b"ok"),)
    for value in (MINTED, CANARY):
        f, blocked = _credentialed_response([(b"x-trace", value.encode())])
        assert f.response.status_code == 502, value[:4]
        assert [p["reason"] for p in blocked] == ["credential material in trailers"]
        assert value.encode() not in (f.response.content or b"")

    b, _ = _broker()
    addon = SeclabAddon(b, frozenset())
    f = tflow.tflow()
    f.request.trailers = http.Headers([(b"x-sig", b.creds.get("c1").sentinel.encode())])
    assert [(cid, where) for cid, where, _n, _v in addon._sentinel_locations(f)] == [("c1", "trailer")]


def test_11_2_trailers_get_the_exception_check_and_session_stripping():
    """11-2: the backstop-exception response check reads trailers as well as headers, and a
    session trailer on a credentialed flow is stripped like a session header."""
    b, _ = _broker()
    addon = SeclabAddon(b, frozenset())
    resp = http.Response.make(200, b"{}", {"content-type": "application/json"})
    resp.trailers = http.Headers([(b"x-request-id", b"r1")])
    assert addon._exception_response_check(resp)[0] is None
    resp.trailers = http.Headers([(b"x-session-token", b"r1")])
    assert addon._exception_response_check(resp)[:2] == (
        "credential-named header or token-shaped value", "x-session-token")

    f, blocked = _credentialed_response([(b"set-cookie", b"sid=1"), (b"x-trace", b"ok")])
    assert f.response.status_code == 200 and not blocked
    assert f.response.trailers.fields == ((b"x-trace", b"ok"),)


def test_m2m3_8_a_failing_audit_never_lets_a_failed_hook_pass():
    """m2-m3 #8: when a hook fails and the audit fails too, the flow is still answered with
    502 (contained before auditing), and request() denies a flow nothing classified."""
    b, _ = _broker()
    addon = SeclabAddon(b, frozenset())

    def broken(*_a, **_k):
        raise RuntimeError("audit sink down")

    b.audit = broken
    f = tflow.tflow()
    f.metadata["seclab.view"] = _view()
    f.request.headers["authorization"] = "Bearer x"

    def explode(*_a, **_k):
        raise RuntimeError("hook bug")

    addon._sentinel_locations = explode
    asyncio.run(addon.request(f))
    assert f.response is not None and f.response.status_code == 502

    b2, _ = _broker()
    f = tflow.tflow()
    asyncio.run(SeclabAddon(b2, frozenset()).request(f))
    assert f.response is not None and f.response.status_code == 403


def test_13_8_a_spent_credential_is_never_prompted_for():
    """13-8: an unconfirmed (bindless) import whose budget is spent gets 429 on the first-use
    binding path, and no binding prompt is raised; with budget left, the prompt is raised."""
    sentinel = "SECLAB_SNTL_" + "p" * 40

    def run(spent):
        b, events = _broker(allow=[{"host": "pkgs.example.test"}],
                            prompt={"timeoutSeconds": 0.2})
        b.dispatch("credential.import", {"id": "imp", "value": CANARY + "2", "sentinel": sentinel,
                                         "budget": {"requests": 1}})
        if spent:
            b.charge_credential(b.creds.get("imp"), requests=1)
        f = tflow.tflow()
        f.request.host = "pkgs.example.test"
        f.request.path = "/feed/x"
        f.request.headers["authorization"] = f"Bearer {sentinel}"
        f.metadata["seclab.view"] = _view("/feed/x", "pkgs.example.test")
        asyncio.run(SeclabAddon(b, frozenset()).request(f))
        prompts = [p for m, p in events if m == "approval.requested"]
        return f.response.status_code if f.response else None, prompts

    status, prompts = run(spent=True)
    assert status == 429 and prompts == []
    status, prompts = run(spent=False)
    assert len(prompts) == 1 and prompts[0]["kind"] == "credential-binding"


def _connect(deny_rule):
    b, events = _broker(deny=[deny_rule] if deny_rule else [])
    b.dispatch("proxy.auth.set", {"username": "seclab", "password": "P" * 22})
    import base64
    f = tflow.tflow()
    f.request.method = "CONNECT"
    f.request.host = "blocked.example.test"
    f.request.port = 443
    f.request.headers["Proxy-Authorization"] = "Basic " + base64.b64encode(b"seclab:" + b"P" * 22).decode()
    SeclabAddon(b, frozenset()).http_connect(f)
    denied = [p for m, p in events if m == "audit.event" and p.get("type") == "request.denied"]
    return f, denied


def test_12_7_and_12b_2_a_blocked_host_is_refused_at_connect():
    """12-7: a CONNECT to a blocked host is refused with 403 at CONNECT time and audited with
    the rule id, before any inner request. 12b-2: a deny rule narrowed to http still refuses the
    tunnel, which could carry either scheme. Control: no rule, the tunnel opens."""
    for rule in ({"id": "blk", "host": "blocked.example.test"},
                 {"id": "blk", "host": "blocked.example.test", "schemes": ["http"]}):
        f, denied = _connect(rule)
        assert f.response is not None and f.response.status_code == 403, rule
        assert [d.get("ruleId") for d in denied] == ["blk"], rule
        assert denied[0]["method"] == "CONNECT"
    f, denied = _connect(None)
    assert f.response is None and denied == []


def test_11_7_a_bodiless_exception_response_passes_and_error_bodies_are_checked():
    """11-7: a bodiless 204/304 on a backstop-exception route passes once its headers are
    clean (it isn't "not strict JSON"); a header with a credential-named field still blocks."""
    b, _ = _broker()
    addon = SeclabAddon(b, frozenset())
    for status in (204, 304):
        resp = http.Response.make(status, b"", {})
        assert addon._exception_response_check(resp) == (None, None, None), status
        resp.headers["x-session-token"] = "r1"
        assert addon._exception_response_check(resp)[0] == "credential-named header or token-shaped value"
    resp = http.Response.make(404, b'{"message":"not found","token":"x"}', {"content-type": "application/json"})
    assert addon._exception_response_check(resp)[:2] == ("credential-named field", "$.token")
