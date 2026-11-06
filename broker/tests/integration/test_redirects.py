"""Broker-followed redirects (revision 8): a CFS package download answers with a redirect to
a signed storage URL, which the broker follows itself. The tab never gets the Location or
the signature, can't make the broker follow anything else, and can't reach storage itself."""

import base64
import json
import secrets
import shlex
import urllib.parse

from conftest import STORAGE_HOST

FEED = "/github-cfs/GitHubCFS/_packaging/github-cfs-oss/npm/registry"
PYPI = ("/github-cfs/00000000-0000-4000-8000-000000000001/_packaging/"
        "00000000-0000-4000-8000-000000000002/pypi/download")
STORAGE_HEADERS = {"host", "user-agent", "accept", "accept-encoding", "connection"}


def _cfs(pod, ctl, cid: str, budget: dict | None = None) -> str:
    """Load a CFS-shaped policy on the fixture host (the provider applies by name) and
    return the tab's Basic header carrying the sentinel."""
    value = "seclab-canary-cfs-" + secrets.token_hex(16)
    pod.canaries[cid] = value
    cred = {"id": cid, "provider": "azure-devops",
            "inject": {"header": "Authorization", "fmt": "Basic {base64:cfs:{value}}"},
            "bind": [{"host": "api.example.test", "path": FEED + "/**", "methods": ["GET"]},
                     {"host": "api.example.test", "path": PYPI + "/**", "methods": ["GET"]}],
            **({"budget": budget} if budget else {})}
    s = pod.load({"allow": [{"id": "feed", "host": "api.example.test", "methods": ["GET"], "path": FEED + "/**"},
                            {"id": "pypi", "host": "api.example.test", "methods": ["GET"], "path": PYPI + "/**"}],
                  "credentials": [cred], "prompt": {"timeoutSeconds": 10}})[cid]
    ctl.call("credential.provide", {"id": cid, "value": value})
    return "Authorization: Basic " + base64.b64encode(f"cfs:{s}".encode()).decode()


def _location(pod, path: str) -> str:
    """The Location the fixture answered the latest request for `path` with."""
    return [x for x in pod.seen() if x["path"] == path and "location" in x][-1]["location"]


def _sig(pod, loc: str) -> str:
    """The Location's signature, registered as a canary: the final sweep then proves it never
    reached the tab, the audit or the broker's logs."""
    sig = urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query)["sig"][0]
    pod.canaries["sas-" + sig[-12:]] = sig
    return sig


def _storage_hits(pod, sig: str) -> list[dict]:
    return [x for x in pod.seen() if x["host"] == STORAGE_HOST and x.get("query", "").endswith("sig=" + sig)]


def _tab_saw_nothing(r, sig: str) -> None:
    seen = r.headers + r.body
    assert sig not in seen and "vsblobprodcus" not in seen and "sig=" not in seen
    assert "\nlocation:" not in r.headers.lower()


def test_cfs_download_redirect_is_followed_by_the_broker(pod, ctl):
    basic = _cfs(pod, ctl, "cfs-follow", {"requests": 50, "bytes": 1 << 20})
    blobs = 0
    for path, mode, extra in ((FEED + "/left-pad/-/left-pad-1.0.0.tgz", "303", ()),
                              (PYPI + "/six/1.0/six-1.0-py3-none-any.whl", "303", ("--http1.1",)),
                              (FEED + "/is-odd/-/is-odd-1.0.0.tgz", "302", ()),
                              (FEED + "/is-even/-/is-even-1.0.0.tgz", "307", ())):
        mark = ctl.mark()
        r = pod.curl(f"https://api.example.test{path}", "-H", basic, "-H", f"X-Fixture: {mode}",
                     "-H", "X-Tab-Probe: seclab-tab-header", *extra)
        loc = _location(pod, path)
        sig = _sig(pod, loc)
        assert r.code == 200 and r.body.startswith("seclab-fixture-blob /b-"), (mode, r.code, r.body[:200])
        _tab_saw_nothing(r, sig)
        # One hop, no credential and no client header (not even the tab's own probe header).
        hits = _storage_hits(pod, sig)
        assert len(hits) == 1 and hits[0]["auth_sha256"] is None and hits[0]["method"] == "GET"
        assert set(hits[0]["header_names"]) <= STORAGE_HEADERS, hits[0]["header_names"]
        ev = ctl.wait_note("audit.event", lambda e: e["type"] == "credential.redirect_followed", since=mark)
        assert ev["credentialId"] == "cfs-follow" and ev["status"] == int(mode)
        assert ev["redirectHost"] == STORAGE_HOST and ev["redirectPath"] == urllib.parse.urlsplit(loc).path
        assert ev["respBytes"] == len(r.body) and {"redirectHost", "redirectPath"} <= set(ev["untrusted"])
        assert sig not in json.dumps(ctl.notes_since(mark))
        blobs += len(r.body)
    used = [x for x in ctl.call("health", {})["credentialBudgets"] if x["id"] == "cfs-follow"][0]
    assert used["requests"] == 4 and used["bytes"] >= blobs


def test_cfs_redirect_refusals_never_reach_the_tab(pod, ctl):
    basic = _cfs(pod, ctl, "cfs-refuse")
    cases = [("301", "status 301 is not followed"), ("308", "status 308 is not followed"),
             ("off-pattern", "host not declared by the provider"), ("http", "Location is not https"),
             ("port", "port is not 443"), ("userinfo", "userinfo in Location"),
             ("private", "target address not permitted"), ("chain", "target answered 302"),
             ("missing", "target answered 404"), ("deny", "denied by rule blk-storage")]
    for n, (mode, why) in enumerate(cases):
        if mode == "deny":
            ctl.call("policy.update", {"addDeny": [{"id": "blk-storage", "host": STORAGE_HOST}]})
        path = f"{FEED}/refuse-{n}/-/refuse-{n}-1.0.0.tgz"
        mark = ctl.mark()
        r = pod.curl(f"https://api.example.test{path}", "-H", basic, "-H", f"X-Fixture: {'303' if mode == 'deny' else mode}")
        if mode == "deny":
            ctl.call("policy.update", {"removeDeny": ["blk-storage"]})
        loc = _location(pod, path)
        sig = _sig(pod, loc)
        assert r.code == 502 and "credentialed redirect not followed" in r.body and why in r.body, (mode, r.code, r.body)
        _tab_saw_nothing(r, sig)
        ev = ctl.wait_note("audit.event", lambda e: e["type"] == "credential.redirect_refused", since=mark)
        assert ev["reason"] == why and ev["credentialId"] == "cfs-refuse"
        assert sig not in json.dumps(ctl.notes_since(mark))
        hits = _storage_hits(pod, sig)
        if mode == "chain":
            # The target's own redirect is never followed: one hop only.
            assert len(hits) == 1
            second = _sig(pod, hits[0]["location"])
            assert not _storage_hits(pod, second) and second not in r.headers + r.body
        elif mode == "missing":
            assert len(hits) == 1  # its error body, which echoes the signature, is dropped
        else:
            assert not hits, mode
        if mode == "private":
            ctl.wait_note("audit.event", lambda e: e["type"] == "upstream.blocked", since=mark)


def test_tab_cannot_trigger_the_follow_itself(pod, ctl):
    basic = _cfs(pod, ctl, "cfs-direct")
    # Straight to storage, with or without the sentinel: denied (a prompt the user declines),
    # and never reached.
    ctl.handlers["approval.requested"] = lambda p: ctl.call(
        "approval.decide", {"approvalId": p["approvalId"], "decision": "deny"})
    for opts in ((), ("-H", basic)):
        r = pod.curl(f"https://{STORAGE_HOST}/b-0/tab.blob?sig=tab-chosen", *opts)
        assert r.code == 403, (opts, r.code)
    ctl.handlers.clear()
    assert not [x for x in pod.seen() if x["host"] == STORAGE_HOST and x["path"] == "/b-0/tab.blob"]
    # A redirect answering an uncredentialed feed request is the tab's own: relayed, not followed.
    path = FEED + "/plain/-/plain-1.0.0.tgz"
    mark = ctl.mark()
    r = pod.curl(f"https://api.example.test{path}")
    loc = _location(pod, path)
    sig = urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query)["sig"][0]
    assert r.code == 303 and not _storage_hits(pod, sig)
    assert not [e for e in ctl.notes_since(mark, "audit.event") if e["type"].startswith("credential.redirect_")]
    # A credentialed redirect under a provider that declares no redirects: not followed either.
    value = "seclab-canary-plain-" + secrets.token_hex(16)
    pod.canaries["plain-redirect"] = value
    s = pod.load({"allow": [{"id": "api", "host": "api.example.test", "methods": ["GET"]}],
                  "credentials": [{"id": "plain", "inject": {"header": "Authorization", "fmt": "Bearer {value}"},
                                   "bind": [{"host": "api.example.test", "path": "/redirect-storage",
                                             "methods": ["GET"]}]}]})["plain"]
    ctl.call("credential.provide", {"id": "plain", "value": value})
    mark = ctl.mark()
    r = pod.curl("https://api.example.test/redirect-storage", "-H", f"Authorization: Bearer {s}")
    loc = _location(pod, "/redirect-storage")
    sig = urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query)["sig"][0]
    assert r.code == 303 and not _storage_hits(pod, sig)
    assert not [e for e in ctl.notes_since(mark, "audit.event") if e["type"].startswith("credential.redirect_")]


def test_followed_redirect_is_bounded_by_the_byte_budget(pod, ctl):
    basic = _cfs(pod, ctl, "cfs-bytes", {"requests": 50, "bytes": 4000})
    r = pod.curl(f"https://api.example.test{FEED}/small/-/small-1.0.0.tgz", "-H", basic, "-H", "X-Fixture: big-1000")
    _sig(pod, _location(pod, f"{FEED}/small/-/small-1.0.0.tgz"))
    assert r.code == 200 and len(r.body) == 1000
    mark = ctl.mark()
    path = f"{FEED}/large/-/large-1.0.0.tgz"
    r = pod.curl(f"https://api.example.test{path}", "-H", basic, "-H", "X-Fixture: big-5000")
    sig = _sig(pod, _location(pod, path))
    assert r.code == 429 and "byte budget exhausted" in r.body
    _tab_saw_nothing(r, sig)
    ev = ctl.wait_note("audit.event", lambda e: e["type"] == "credential.budget_exceeded", since=mark)
    assert ev["budgetId"] == "cfs-bytes"
    assert not ctl.notes_since(mark, "approval.requested")
    used = [x for x in ctl.call("health", {})["credentialBudgets"] if x["id"] == "cfs-bytes"][0]
    assert 1000 <= used["bytes"] < 4000


def test_concurrent_followed_redirects_cannot_overspend_the_byte_budget(pod, ctl):
    """Review 15-2: each body chunk is checked and charged with no await between, so parallel
    downloads (npm and pip fetch several at once) share one byte budget rather than each
    seeing all of it."""
    basic = _cfs(pod, ctl, "cfs-parallel", {"requests": 50, "bytes": 12000})
    paths = [f"{FEED}/par{i}/-/par{i}-1.0.0.tgz" for i in range(6)]
    cmd = " ".join(f"(curl -sS --max-time 30 -o /dev/null -w '%{{http_code}}\\n' -H {shlex.quote(basic)} "
                   f"-H 'X-Fixture: big-5000' https://api.example.test{p}) &" for p in paths) + " wait"
    codes = sorted(pod.ws(cmd).stdout.decode().split())
    for p in paths:
        _sig(pod, _location(pod, p))
    assert len(codes) == 6 and set(codes) <= {"200", "429"}, codes
    assert 1 <= codes.count("200") <= 2 and "429" in codes, codes
    used = [x for x in ctl.call("health", {})["credentialBudgets"] if x["id"] == "cfs-parallel"][0]
    # Followed bodies never overspend; only the redirects' own small bodies (counted as
    # every credentialed response is) can sit on top.
    assert used["bytes"] <= 12000 + 6 * 512, used
