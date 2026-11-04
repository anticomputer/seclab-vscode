"""The code conforms to schema/protocol.v1.json: every method's result validates,
params are enforced, and validation errors never echo values."""

import asyncio

import pytest

from seclab_broker import protocol
from seclab_broker.core import Broker, RpcError

CANARY = "seclab-test-canary-" + "R" * 24 + "-value"
POLICY = {"version": 1, "tabId": "t1", "allow": [{"id": "a", "host": "api.example.com"}],
          "credentials": [{"id": "c1", "bind": {"host": "api.example.com", "path": "/**", "methods": ["GET"]},
                           "inject": {"header": "Authorization", "fmt": "Bearer {value}"}}]}


def call(b: Broker, method: str, params: dict | None = None):
    result = b.dispatch(method, params or {})
    err = protocol.check("result", method, result)
    assert err is None, f"{method} result does not match protocol.v1.json: {err}"
    return result


def test_method_sets_match():
    assert set(Broker.METHODS) == protocol.method_names()


def test_every_method_result_matches_definition():
    async def go():
        b = Broker(tab_id="t1")
        b.ca_pem = "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n"
        notes = []
        b.add_sink(lambda m, p: notes.append((m, p)))
        seen = set()

        def c(m, p=None):
            seen.add(m)
            return call(b, m, p)

        c("broker.hello")
        c("health")
        c("proxy.auth.set", {"username": "seclab", "password": "A" * 22})
        c("policy.load", {"policy": POLICY})
        c("policy.get")
        c("policy.update", {"addAllow": [{"id": "b", "host": "b.example.com", "methods": ["GET"]}],
                            "removeAllow": ["a"]})
        c("credential.provide", {"id": "c1", "value": CANARY, "expiresAt": None})
        c("credential.import", {"id": "imp", "value": CANARY + "2", "source": {"kind": "workspace-scan"}})
        c("credential.list")
        c("credential.revoke", {"id": "c1", "rotateSentinel": True})
        c("ca.get")
        task = asyncio.create_task(b.ask_egress(
            __import__("seclab_broker.policy", fromlist=["RequestView"]).RequestView(
                "https", "new.example.com", 443, "GET", "/x", "")))
        await asyncio.sleep(0.01)
        approvals = c("approval.list")["approvals"]
        c("approval.decide", {"approvalId": approvals[0]["approvalId"], "decision": "allow-tab"})
        await task
        c("audit.tail", {"limit": 2000})
        c("broker.shutdown", {"reason": "test"})
        assert seen == protocol.method_names()
        for method, params in notes:
            err = protocol.check("notification", method, params)
            assert err is None, f"notification {method}: {err}"
        assert {m for m, _ in notes} >= {"audit.event", "approval.requested", "approval.resolved",
                                         "policy.changed"}
        for _, p in [n for n in notes if n[0] == "audit.event"]:
            assert p["type"] in protocol.audit_types()
    asyncio.run(go())


@pytest.mark.parametrize("method,params", [
    ("health", {"unexpected": 1}),
    ("proxy.auth.set", {"username": "seclab"}),
    ("audit.tail", {"limit": 0}),
    ("approval.decide", {"approvalId": "x", "decision": "maybe"}),
    ("credential.import", {"id": "x", "value": CANARY, "source": {"kind": "elsewhere"}}),
])
def test_params_are_enforced(method, params):
    with pytest.raises(RpcError) as e:
        Broker().dispatch(method, params)
    assert e.value.code == -32602


@pytest.mark.parametrize("method,params", [
    ("proxy.auth.set", {"username": "seclab", "password": CANARY + "!"}),
    ("credential.provide", {"id": "c", "value": CANARY + "\n"}),
    ("credential.import", {"id": "x", "value": CANARY, "sentinel": CANARY + "!"}),
])
def test_validation_errors_never_echo_values(method, params):
    with pytest.raises(RpcError) as e:
        Broker().dispatch(method, params)
    assert CANARY not in e.value.message


def test_definition_never_fetches():
    # $refs are local only; the merged definition carries the policy schema.
    d = protocol.definition()
    assert "policy" in d["definitions"] and "rule" in d["definitions"]
