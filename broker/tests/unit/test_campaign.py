"""Controls against folder-open loaders and beacons (DPRK "Contagious Interview"
tasks.json campaign; see docs/adr/20261104-defeat-folder-open-loaders.md).
No sockets are opened here; hostnames are classifier inputs only."""

import asyncio
import json
from pathlib import Path

import pytest

from seclab_broker.core import Broker, RpcError
from seclab_broker.policy import Policy, RequestView, baseline_rules, risky_category, risk_flags

EXAMPLES = Path(__file__).resolve().parents[2] / "examples"
CAMPAIGN_HOSTS = ["vscode-setup.vercel.app", "ip-api-check-nine.vercel.app", "api.npoint.io",
                  "api.ipify.org", "ipify.org", "pastebin.com", "gist.githubusercontent.com",
                  "raw.githubusercontent.com", "x.netlify.app", "x.pages.dev", "x.workers.dev"]


def rv(host, scheme="https", port=None, path="/x"):
    return RequestView(scheme, host, port or (443 if scheme == "https" else 80), "GET", path, "")


@pytest.mark.parametrize("host", CAMPAIGN_HOSTS)
def test_campaign_hosts_are_risky(host):
    assert risky_category(host) is not None


def test_baseline_and_examples_exclude_risky_destinations():
    for host in CAMPAIGN_HOSTS:
        assert not any(r.matches(rv(host)) for r in baseline_rules()), host
        for f in EXAMPLES.glob("*.json"):
            p = Policy.from_json(json.loads(f.read_text()))
            assert p.allow_match(rv(host)) is None, (f.name, host)


def test_risk_flags():
    assert risk_flags(rv("146.70.41.188", "http", 1224)) == ["raw-ip", "cleartext", "nonstandard-port"]  # fixture-lint: ignore
    assert risk_flags(rv("api.npoint.io")) == ["risky-destination:paste"]
    assert risk_flags(rv("api.example.com")) == []


def mk(user_action=True, **prompt):
    b = Broker(tab_id="t1")
    b.rpc_policy_load({"policy": {"version": 1, "prompt": {"timeoutSeconds": 5, **prompt}}})
    notes = []
    b.add_sink(lambda m, p: notes.append((m, p)))
    if user_action:
        b.dispatch("tab.event", {"kind": "userAction"})
    return b, notes


def prompts(notes):
    return [p for m, p in notes if m == "approval.requested"]


def run(coro):
    return asyncio.run(coro)


def test_raw_ip_denied_without_prompt_by_default():
    async def go():
        b, notes = mk()
        d = await b.ask_egress(rv("192.0.2.10", "http", 1224))
        assert not d.allow and d.reason == "raw-ip-destination" and prompts(notes) == []
    run(go())


def test_raw_ip_prompt_once_offers_no_allow_tab():
    async def go():
        b, notes = mk(rawIpDestinations="prompt-once")
        t = asyncio.create_task(b.ask_egress(rv("192.0.2.10", "http", 1224)))
        await asyncio.sleep(0.01)
        p = prompts(notes)[0]
        assert "allow-tab" not in p["decisions"] and "raw-ip" in p["risk"]["flags"]
        with pytest.raises(RpcError):
            b.dispatch("approval.decide", {"approvalId": p["approvalId"], "decision": "allow-tab"})
        b.dispatch("approval.decide", {"approvalId": p["approvalId"], "decision": "allow-once"})
        assert (await t).allow
    run(go())


def test_risky_destination_never_offers_allow_tab():
    async def go():
        b, notes = mk()
        t = asyncio.create_task(b.ask_egress(rv("loader.vercel.app")))
        await asyncio.sleep(0.01)
        p = prompts(notes)[0]
        assert p["decisions"] == ["allow-once", "deny"]
        assert "risky-destination:hosting" in p["risk"]["flags"]
        b.dispatch("approval.decide", {"approvalId": p["approvalId"], "decision": "deny"})
        assert not (await t).allow
    run(go())


def test_risky_auto_denied_before_user_action():
    async def go():
        b, notes = mk(user_action=False)
        b.dispatch("tab.event", {"kind": "opened"})
        for host in ("loader.vercel.app", "api.ipify.org", "api.npoint.io"):
            d = await b.ask_egress(rv(host))
            assert not d.allow and d.reason == "risky-before-user-action"
        assert prompts(notes) == []
        # An ordinary host still prompts, flagged as early and unprompted by the user.
        t = asyncio.create_task(b.ask_egress(rv("api.example.com"), origin="task:env"))
        await asyncio.sleep(0.01)
        p = prompts(notes)[0]
        assert {"early-after-open", "no-user-action-yet"} <= set(p["risk"]["flags"])
        assert p["risk"]["origin"] == {"label": "task:env", "verified": False}
        b.dispatch("approval.decide", {"approvalId": p["approvalId"], "decision": "deny"})
        await t
        # After the user acts, risky destinations prompt (without allow-tab).
        b.dispatch("tab.event", {"kind": "userAction"})
        t = asyncio.create_task(b.ask_egress(rv("loader.vercel.app")))
        await asyncio.sleep(0.01)
        assert len(prompts(notes)) == 2
        b.dispatch("approval.decide", {"approvalId": prompts(notes)[1]["approvalId"], "decision": "deny"})
        await t
        denied = [p for m, p in notes if m == "audit.event" and p["type"] == "request.denied_unprompted"]
        assert len(denied) == 3 and all(e["risk"]["flags"] for e in denied)
    run(go())


def test_policy_risky_destinations_extend_the_list():
    async def go():
        b, notes = mk(user_action=False)
        b.rpc_policy_load({"policy": {"version": 1, "riskyDestinations": [
            {"host": "*.drop.example.com", "category": "hosting"}]}})
        d = await b.ask_egress(rv("a.drop.example.com"))
        assert d.reason == "risky-before-user-action"
    run(go())


def test_prompt_rate_limit():
    async def go():
        b, notes = mk(maxPerMinute=3, offerDenyNewAfter=100)
        tasks = [asyncio.create_task(b.ask_egress(rv(f"h{i}.example.com"))) for i in range(5)]
        await asyncio.sleep(0.05)
        assert len(prompts(notes)) == 3
        limited = [t for t in tasks if t.done()]
        assert len(limited) == 2 and all(t.result().reason == "prompt-rate-limited" for t in limited)
        for p in prompts(notes):
            b.dispatch("approval.decide", {"approvalId": p["approvalId"], "decision": "deny"})
        await asyncio.gather(*tasks)
        b.dispatch("prompt.reset", {})
        t = asyncio.create_task(b.ask_egress(rv("h9.example.com")))
        await asyncio.sleep(0.01)
        assert len(prompts(notes)) == 4
        b.dispatch("approval.decide", {"approvalId": prompts(notes)[3]["approvalId"], "decision": "deny"})
        await t
    run(go())


def test_deny_new_destinations_offered_after_denials_and_enforced():
    async def go():
        b, notes = mk(offerDenyNewAfter=2)
        for i in range(2):
            t = asyncio.create_task(b.ask_egress(rv(f"d{i}.example.com")))
            await asyncio.sleep(0.01)
            p = prompts(notes)[-1]
            assert "deny-new-destinations" not in p["decisions"]
            b.dispatch("approval.decide", {"approvalId": p["approvalId"], "decision": "deny"})
            await t
        pending = asyncio.create_task(b.ask_egress(rv("other.example.com")))
        t = asyncio.create_task(b.ask_egress(rv("d2.example.com")))
        await asyncio.sleep(0.01)
        p = prompts(notes)[-1]
        assert "deny-new-destinations" in p["decisions"]
        b.dispatch("approval.decide", {"approvalId": p["approvalId"], "decision": "deny-new-destinations"})
        assert not (await t).allow and not (await pending).allow  # other pending prompt denied too
        n = len(prompts(notes))
        d = await b.ask_egress(rv("d3.example.com"))
        assert d.reason == "deny-new-destinations" and len(prompts(notes)) == n
        assert b.dispatch("health", {})["prompt"]["denyNewDestinations"] is True
    run(go())


def test_proxy_auth_origin_label():
    b = Broker()
    b.dispatch("proxy.auth.set", {"username": "seclab", "password": "A" * 22})
    assert b.check_proxy_auth("seclab+task:env", "A" * 22) == (True, "task:env")
    assert b.check_proxy_auth("seclab", "A" * 22) == (True, None)
    assert b.check_proxy_auth("seclab+bad label", "A" * 22) == (False, None)
    assert b.check_proxy_auth("other+task:env", "A" * 22) == (False, None)
