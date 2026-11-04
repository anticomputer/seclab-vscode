import asyncio
import base64
import ipaddress
import json

import pytest

from seclab_broker.core import Broker, RpcError
from seclab_broker.credentials import (CredentialStore, b64_cores, encoded_variants,
                                       header_has_sentinel, infer_inject, new_sentinel)
from seclab_broker.netguard import deny_reason
from seclab_broker.policy import Binding, Policy, PolicyError, RequestView
from seclab_broker.scanner import find_minted

# Canary: deliberately NOT shaped like any real provider token.
CANARY = "seclab-test-canary-" + "Q" * 24 + "-value"


def store_with(value=CANARY):
    s = CredentialStore()
    p = Policy.from_json({"version": 1, "credentials": [{
        "id": "c1", "bind": {"host": "api.example.com", "path": "/**", "methods": ["GET"]},
        "inject": {"header": "Authorization", "fmt": "Bearer {value}"}}]})
    s.apply_policy(p.credentials)
    s.provide("c1", value, None)
    return s


def test_sentinels_are_unique_and_long():
    a, b = new_sentinel(), new_sentinel()
    assert a != b and len(a) >= 43


def test_sentinel_stable_across_policy_reload():
    s = store_with()
    before = s.get("c1").sentinel
    p = Policy.from_json({"version": 1, "credentials": [{
        "id": "c1", "bind": {"host": "api.example.com", "path": "/x/**", "methods": ["GET"]},
        "inject": {"header": "Authorization", "fmt": "Bearer {value}"}}]})
    s.apply_policy(p.credentials)
    assert s.get("c1").sentinel == before and s.get("c1").has_value()


def test_sentinel_found_raw_and_in_basic_auth_and_base64_any_alignment():
    s = store_with()
    sent = s.get("c1").sentinel
    assert s.find_sentinels(f"token {sent}".encode())
    basic = base64.b64encode(f"x-access-token:{sent}".encode())
    assert s.find_sentinels(b"Basic " + basic)
    for pad in ("", "a", "ab"):
        assert s.find_sentinels(base64.b64encode((pad + sent).encode()))
    assert header_has_sentinel("Basic " + basic.decode(), sent)
    assert not header_has_sentinel("Bearer nothing", sent)


@pytest.mark.parametrize("encode", [
    lambda v: v.encode(),
    lambda v: base64.b64encode(v.encode()),
    lambda v: base64.urlsafe_b64encode(("xx" + v).encode()),
    lambda v: v.encode().hex().encode(),
    lambda v: v.encode().hex().upper().encode(),
    lambda v: json.dumps({"t": v}).encode(),
])
def test_real_value_found_in_every_encoding(encode):
    s = store_with("pa$$/word+with=specials&more-chars")
    assert s.find_real(b"prefix " + encode("pa$$/word+with=specials&more-chars") + b" suffix")


def test_scrub_removes_values_and_sentinels():
    s = store_with()
    sent = s.get("c1").sentinel
    out = s.scrub(f"a {CANARY} b {sent} c")
    assert CANARY not in out and sent not in out


def test_revoke_drops_value_and_can_rotate():
    s = store_with()
    old = s.get("c1").sentinel
    s.revoke("c1", rotate=True)
    assert not s.get("c1").has_value() and s.get("c1").sentinel != old
    assert not s.find_real(CANARY.encode())


def test_infer_inject():
    sent = new_sentinel()
    i = infer_inject("Authorization", f"Bearer {sent}", sent)
    assert i.fmt == "Bearer {value}"
    b = "Basic " + base64.b64encode(f"user:{sent}".encode()).decode()
    i = infer_inject("Authorization", b, sent)
    assert i.render("X") == "Basic " + base64.b64encode(b"user:X").decode()


def test_import_validation():
    s = CredentialStore()
    with pytest.raises(PolicyError):
        s.import_credential("x", "short", None, [], [], None, {})
    with pytest.raises(PolicyError):
        s.import_credential("x", CANARY, "bad sentinel!", [], [], None, {})
    with pytest.raises(PolicyError):
        s.import_credential("x", CANARY + "\udcff", None, [], [], None, {})
    c = s.import_credential("x", CANARY, "S" * 40, [], [], None, {"kind": "workspace-scan"})
    assert not c.confirmed and c.sentinel == "S" * 40


def test_derive_rejects_bad_values_and_store_survives():
    """Regression (security review 2026-11-04 #4): an unencodable minted value
    poisoned the store and disabled reflection scanning for later credentials."""
    s = store_with()
    parent = s.get("c1")
    with pytest.raises(PolicyError):
        s.derive(parent, "x" * 20 + "\udcff", "json-token-field")
    s.provide("c1", "another-canary-value-123", None)
    assert s.find_real(b"another-canary-value-123")


def test_derived_credentials_are_capped():
    s = store_with()
    parent = s.get("c1")
    for i in range(64):
        s.derive(parent, f"minted-token-value-{i:04d}", "r")
    with pytest.raises(PolicyError):
        s.derive(parent, "minted-token-value-9999", "r")


@pytest.mark.parametrize("ip", [
    "127.0.0.1", "10.1.2.3", "172.17.0.1", "192.168.65.254", "169.254.169.254", "100.64.0.1",
    "0.0.0.0", "::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::127.0.0.1", "64:ff9b::a00:1",
    "2002:a00:1::", "fe80::1", "fc00::1", "224.0.0.1", "240.0.0.1", "255.255.255.255",
    "2001:0:4136:e378:8000:63bf:f5ff:fffe",
])
def test_netguard_denies(ip):
    assert deny_reason(ipaddress.ip_address(ip)) is not None


@pytest.mark.parametrize("ip", ["1.1.1.1", "140.82.112.3", "2606:4700::1111", "11.200.0.5"])
def test_netguard_allows_public(ip):
    assert deny_reason(ipaddress.ip_address(ip)) is None


def test_netguard_local_extra():
    ip = ipaddress.ip_address("11.200.0.1")
    assert deny_reason(ip, frozenset({ip})) == "broker-local"


def test_minted_token_rules():
    tok = "ghs_" + "a1B2" * 9
    hits = find_minted(json.dumps({"token": tok, "expires_at": "x"}))
    assert [h[1] for h in hits] == [tok]
    assert find_minted("access_token=" + "z" * 30 + "&scope=repo")[0][1] == "z" * 30
    assert not find_minted('{"name": "hello"}')


# ---------------------------------------------------------------- approvals

def rv(host="new.example.com"):
    return RequestView("https", host, 443, "GET", "/x", "")


def mk_broker(timeout=0.3, **prompt):
    b = Broker(tab_id="t1")
    b.rpc_policy_load({"policy": {"version": 1, "prompt": {"timeoutSeconds": timeout, **prompt}}})
    events = []
    b.add_sink(lambda m, p: events.append((m, p)))
    return b, events


def test_no_controller_denies_without_holding():
    async def go():
        b = Broker()
        d = await b.ask_egress(rv())
        assert not d.allow and d.reason == "no-controller" and b.held == 0
    asyncio.run(go())


def test_allow_once_resolves_all_waiters_for_origin():
    async def go():
        b, ev = mk_broker(timeout=5)
        t1 = asyncio.create_task(b.ask_egress(rv()))
        t2 = asyncio.create_task(b.ask_egress(rv()))
        await asyncio.sleep(0.05)
        reqs = [p for m, p in ev if m == "approval.requested"]
        assert len(reqs) == 1 and b.held == 2
        b.rpc_approval_decide({"approvalId": reqs[0]["approvalId"], "decision": "allow-once"})
        assert (await t1).allow and (await t2).allow
        assert b.allowed(rv()) is None  # once is not remembered
    asyncio.run(go())


def test_allow_tab_adds_rule():
    async def go():
        b, ev = mk_broker(timeout=5)
        t = asyncio.create_task(b.ask_egress(rv()))
        await asyncio.sleep(0.05)
        aid = [p for m, p in ev if m == "approval.requested"][0]["approvalId"]
        b.rpc_approval_decide({"approvalId": aid, "decision": "allow-tab"})
        assert (await t).allow
        assert b.allowed(rv()) is not None
        assert any(m == "policy.changed" for m, _ in ev)
    asyncio.run(go())


def test_deny_and_cooldown():
    async def go():
        b, ev = mk_broker(timeout=5, denyCooldownSeconds=60)
        t = asyncio.create_task(b.ask_egress(rv()))
        await asyncio.sleep(0.05)
        aid = [p for m, p in ev if m == "approval.requested"][0]["approvalId"]
        b.rpc_approval_decide({"approvalId": aid, "decision": "deny"})
        assert not (await t).allow
        d = await b.ask_egress(rv())
        assert not d.allow and d.reason == "deny-cooldown"
    asyncio.run(go())


def test_hold_times_out_to_deny():
    async def go():
        b, ev = mk_broker(timeout=0.2)
        d = await b.ask_egress(rv())
        assert not d.allow and "timeout" in d.reason
        assert ("approval.resolved", {"approvalId": [p for m, p in ev if m == "approval.requested"][0]["approvalId"],
                                      "decision": "deny", "by": "timeout"}) in ev
    asyncio.run(go())


def test_pending_queue_is_bounded():
    async def go():
        b, ev = mk_broker(timeout=5, maxPending=2)
        tasks = [asyncio.create_task(b.ask_egress(rv(f"h{i}.example.com"))) for i in range(3)]
        await asyncio.sleep(0.05)
        d3 = await tasks[2]
        assert not d3.allow and d3.reason == "approval-queue-full"
        for a in list(b.approvals):
            b.rpc_approval_decide({"approvalId": a, "decision": "deny"})
        await asyncio.gather(*tasks[:2])
    asyncio.run(go())


def test_decide_unknown_and_bad_decision():
    b, _ = mk_broker()
    with pytest.raises(RpcError):
        b.rpc_approval_decide({"approvalId": "nope", "decision": "allow-once"})
    with pytest.raises(RpcError):
        b.dispatch("approval.decide", {"approvalId": "nope", "decision": "yes"})


# ---------------------------------------------------------------- proxy auth / custody

def test_proxy_auth():
    b = Broker()
    assert not b.check_proxy_auth("seclab", "x" * 22)[0]  # nothing configured: reject all
    with pytest.raises(RpcError):
        b.dispatch("proxy.auth.set", {"username": "seclab", "password": "tooshort"})
    b.dispatch("proxy.auth.set", {"username": "seclab", "password": "A" * 22})
    assert b.check_proxy_auth("seclab", "A" * 22)[0]
    assert not b.check_proxy_auth("seclab", "A" * 21 + "B")[0]
    assert not b.check_proxy_auth("other", "A" * 22)[0]
    assert not b.check_proxy_auth(None, None)[0]


def test_audit_never_contains_value_or_sentinel():
    b = Broker()
    b.dispatch("policy.load", {"policy": {"version": 1, "credentials": [{
        "id": "c1", "bind": {"host": "api.example.com", "path": "/**", "methods": ["GET"]},
        "inject": {"header": "Authorization", "fmt": "Bearer {value}"}}]}})
    b.dispatch("credential.provide", {"id": "c1", "value": CANARY})
    sent = b.creds.get("c1").sentinel
    b.audit("test", path=f"/x/{CANARY}/{sent}", nested={"v": [CANARY]})
    dumped = json.dumps(b.dispatch("audit.tail", {"limit": 100}))
    assert CANARY not in dumped and sent not in dumped
    listed = json.dumps(b.dispatch("credential.list", {}))
    assert CANARY not in listed


def test_invalid_params_never_echo_value():
    b = Broker()
    try:
        b.dispatch("credential.provide", {"id": "missing", "value": CANARY})
    except RpcError as e:
        assert CANARY not in e.message
    try:
        b.dispatch("credential.import", {"id": "x", "value": CANARY + "\n"})
    except RpcError as e:
        assert CANARY not in e.message


def test_shutdown_clears_credentials():
    async def go():
        b = Broker()
        b.dispatch("policy.load", {"policy": {"version": 1, "credentials": [{
            "id": "c1", "bind": {"host": "api.example.com", "path": "/**", "methods": ["GET"]},
            "inject": {"header": "Authorization", "fmt": "Bearer {value}"}}]}})
        b.dispatch("credential.provide", {"id": "c1", "value": CANARY})
        b.dispatch("broker.shutdown", {})
        assert not b.creds.all()
    asyncio.run(go())


def test_b64_cores_minimum():
    assert all(len(c) >= 12 for c in b64_cores(b"x" * 40))
    assert "raw" in encoded_variants("abcdefgh").values()


def test_binding_from_import_proposed():
    inj = {"header": "X-Api-Key", "fmt": "{value}"}
    b = Binding.from_json({"host": "api.example.com", "path": "/v1/**", "methods": ["POST"], "inject": inj})
    assert b.inject.header == "X-Api-Key"
