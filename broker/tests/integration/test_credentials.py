"""Sentinel credentials: placement-only injection, misplacement, response
scanning, minted tokens, backstop, JIT, import, WebSocket, git over HTTPS."""

import hashlib
import json
import secrets
import time

ALLOW = [{"id": "api", "host": "api.example.test"}, {"id": "gist", "host": "gist.example.test"},
         {"id": "git", "host": "git.example.test"}, {"id": "ws", "host": "ws.example.test"}]
BEARER = {"header": "Authorization", "fmt": "Bearer {value}"}
API_CRED = {
    "id": "api", "provider": "github", "inject": BEARER,
    "bind": [
        {"host": "api.example.test", "path": "/echo/repos/**", "methods": ["GET"]},
        {"host": "api.example.test", "path": "/echo-b64", "methods": ["GET"]},
        {"host": "api.example.test", "path": "/echo-hex", "methods": ["GET"]},
        {"host": "api.example.test", "path": "/redirect", "methods": ["GET"]},
        {"host": "api.example.test", "path": "/mint", "methods": ["POST"]},
        {"host": "api.example.test", "path": "/mint-form", "methods": ["POST"]},
        {"host": "api.example.test", "path": "/user/keys", "methods": ["POST"]},
        {"host": "api.example.test", "path": "/session", "methods": ["GET"]},
        {"host": "ws.example.test", "path": "/ws", "methods": ["GET"]},
    ],
}
GIT_CRED = {
    "id": "git", "inject": {"header": "Authorization", "fmt": "Basic {base64:x-access-token:{value}}"},
    "bind": [
        {"host": "git.example.test", "path": "/demo.git/info/refs", "methods": ["GET"]},
        {"host": "git.example.test", "path": "/demo.git/git-upload-pack", "methods": ["POST"]},
    ],
}


def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def setup(pod, ctl, mismatch="block", creds=(API_CRED, GIT_CRED), provide=True):
    sentinels = pod.load({"allow": ALLOW, "credentials": list(creds), "sentinelMismatch": mismatch,
                          "prompt": {"enabled": False}})
    if provide:
        ctl.call("credential.provide", {"id": "api", "value": pod.canaries["api"]})
        if "git" in sentinels:
            ctl.call("credential.provide", {"id": "git", "value": pod.canaries["git"]})
    return sentinels


def test_swap_only_on_binding_match(pod, ctl):
    s = setup(pod, ctl)["api"]
    r = pod.curl("https://api.example.test/echo/repos/o/r", "-H", f"Authorization: Bearer {s}")
    assert r.code == 200
    echo = r.json()
    assert echo["auth_sha256"] == sha("Bearer " + pod.canaries["api"])  # upstream got the real value
    assert echo["headers"]["authorization"] == "Bearer " + s  # the echo came back re-sentinelised
    assert any(e["type"] == "credential.injected" for e in pod.audit())


def test_no_swap_on_wrong_path_or_method(pod, ctl):
    s = setup(pod, ctl)["api"]
    r = pod.curl("https://api.example.test/echo/other", "-H", f"Authorization: Bearer {s}")
    assert r.code == 403 and "outside its binding" in r.body
    r = pod.curl("https://api.example.test/echo/repos/o/r", "-X", "POST", "-H", f"Authorization: Bearer {s}")
    assert r.code == 403


def test_sentinel_to_unbound_allowed_host_not_swapped(pod, ctl):
    s = setup(pod, ctl)["api"]
    body = json.dumps({"files": {"x.txt": {"content": f"token={s}"}}})
    r = pod.curl("https://gist.example.test/gists", "-X", "POST", "-d", body)
    assert r.code == 403
    r = pod.curl("https://gist.example.test/gists", "-H", f"Authorization: Bearer {s}")
    assert r.code == 403
    events = [e for e in pod.audit() if e["type"] == "sentinel.misplaced"]
    assert {e["location"] for e in events} >= {"body", "header:authorization"}


def test_sentinel_to_unbound_host_in_log_mode_reaches_upstream_unswapped(pod, ctl):
    s = setup(pod, ctl, mismatch="log")["api"]
    body = f"token={s}"
    r = pod.curl("https://gist.example.test/gists", "-X", "POST", "-d", body,
                 "-H", f"Authorization: Bearer {s}")
    assert r.code == 200
    echo = r.json()
    assert echo["body_sha256"] == sha(body)  # the sentinel, not the real value, went out
    assert echo["auth_sha256"] == sha("Bearer " + s)


def test_sentinel_in_query_of_bound_host_not_swapped(pod, ctl):
    s = setup(pod, ctl)["api"]
    assert pod.curl(f"https://api.example.test/echo/repos/o/r?t={s}").code == 403


def test_sentinel_in_other_header_of_bound_request(pod, ctl):
    s = setup(pod, ctl)["api"]
    r = pod.curl("https://api.example.test/echo/repos/o/r", "-H", f"X-Token: {s}")
    assert r.code == 403


def test_reflection_in_other_encodings_blocked(pod, ctl):
    s = setup(pod, ctl)["api"]
    for path in ("/echo-b64", "/echo-hex"):
        r = pod.curl(f"https://api.example.test{path}", "-H", f"Authorization: Bearer {s}")
        assert r.code == 502, path
        assert "response blocked" in r.body
    # A raw echo in a redirect Location is rewritten back to the sentinel.
    r = pod.curl("https://api.example.test/redirect", "-H", f"Authorization: Bearer {s}")
    assert r.code == 302
    location = [h for h in r.headers.splitlines() if h.lower().startswith("location:")][0]
    assert s in location
    pod.assert_no_canary("\n".join(pod.tab_output))


def test_minted_token_is_resentinelised(pod, ctl):
    s = setup(pod, ctl)["api"]
    mark = ctl.mark()
    r = pod.curl("https://api.example.test/mint", "-X", "POST", "-H", f"Authorization: Bearer {s}")
    assert r.code == 201
    token = r.json()["token"]
    assert token.startswith("SECLAB_SNTL_") and "ghs_" not in r.body
    derived = ctl.wait_note("credential.derived", since=mark)
    assert derived["parentId"] == "api" and derived["sentinel"] == token
    # The derived sentinel works through the same bindings, and only there.
    r = pod.curl("https://api.example.test/echo/repos/o/r", "-H", f"Authorization: Bearer {token}")
    assert r.code == 200 and r.json()["auth_is_minted"] is True
    r = pod.curl("https://gist.example.test/x", "-H", f"Authorization: Bearer {token}")
    assert r.code == 403
    r = pod.curl("https://api.example.test/mint-form", "-X", "POST", "-H", f"Authorization: Bearer {s}")
    assert r.code == 200 and r.body.startswith("access_token=SECLAB_SNTL_") and "gho_" not in r.body


def test_session_cookies_from_credentialed_requests_are_stripped(pod, ctl):
    """Regression (security review 2026-11-04 round 1b #1): a session cookie issued in
    answer to a credentialed request is a derived credential."""
    s = setup(pod, ctl)["api"]
    r = pod.curl("https://api.example.test/session", "-H", f"Authorization: Bearer {s}")
    assert r.code == 200 and "set-cookie" not in r.headers.lower()
    # Control: without an injected credential the cookie is not derived from our secret.
    r = pod.curl("https://api.example.test/session")
    assert r.code == 200 and "set-cookie" in r.headers.lower()
    assert any(e["type"] == "session.stripped" for e in pod.audit())


def test_provider_backstop_beats_binding(pod, ctl):
    s = setup(pod, ctl)["api"]
    r = pod.curl("https://api.example.test/user/keys", "-X", "POST", "-H", f"Authorization: Bearer {s}",
                 "-d", "{}")
    assert r.code == 403 and "backstop" in r.body
    assert not [x for x in pod.seen() if x["path"] == "/user/keys" and x["auth_sha256"]]


def test_jit_credential_from_host(pod, ctl):
    jit = dict(API_CRED, id="jit")
    s = pod.load({"allow": ALLOW, "credentials": [jit], "prompt": {"timeoutSeconds": 10}})["jit"]
    value = "seclab-canary-jit-" + secrets.token_hex(16)
    pod.canaries["jit"] = value
    ctl.handlers["credential.needed"] = lambda p: ctl.call("credential.provide", {"id": p["id"], "value": value})
    r = pod.curl("https://api.example.test/echo/repos/o/r", "-H", f"Authorization: Bearer {s}")
    assert r.code == 200 and r.json()["auth_sha256"] == sha("Bearer " + value)


def test_revoked_credential_is_not_injected(pod, ctl):
    s = setup(pod, ctl)["api"]
    pod.load({"allow": ALLOW, "credentials": [API_CRED], "prompt": {"timeoutSeconds": 1}})
    ctl.call("credential.revoke", {"id": "api"})
    r = pod.curl("https://api.example.test/echo/repos/o/r", "-H", f"Authorization: Bearer {s}")
    assert r.code == 503
    rotated = ctl.call("credential.revoke", {"id": "api", "rotateSentinel": True})["sentinel"]
    assert rotated != s


def test_imported_credential_binding_confirmed_on_first_use(pod, ctl):
    pod.load({"allow": ALLOW, "prompt": {"timeoutSeconds": 10, "denyCooldownSeconds": 0}})
    sentinel = "IMPORTED_" + secrets.token_urlsafe(32).replace("-", "a").replace("_", "b")
    res = ctl.call("credential.import", {"id": "dotenv-api", "value": pod.canaries["imported"],
                                          "sentinel": sentinel,
                                          "source": {"kind": "workspace-scan", "path": ".env"}})
    assert res == {"id": "dotenv-api", "sentinel": sentinel, "confirmed": False}
    mark = ctl.mark()
    ctl.handlers["approval.requested"] = lambda p: ctl.call(
        "approval.decide", {"approvalId": p["approvalId"], "decision": "allow-tab"})
    r = pod.curl("https://api.example.test/echo/svc", "-H", f"Authorization: Token {sentinel}")
    assert r.code == 200 and r.json()["auth_sha256"] == sha("Token " + pod.canaries["imported"])
    req = ctl.notes_since(mark, "approval.requested")
    assert len(req) == 1 and req[0]["kind"] == "credential-binding"
    assert req[0]["suggestedBinding"]["inject"] == {"header": "Authorization", "fmt": "Token {value}"}
    # Notifications travel on the control channel, the response on a separate exec: wait for it.
    confirmed = ctl.wait_note("credential.bindingConfirmed", since=mark, timeout=10)
    assert confirmed["binding"]["path"] == "/echo/svc"
    r = pod.curl("https://api.example.test/echo/svc", "-H", f"Authorization: Token {sentinel}")
    assert r.code == 200
    assert len(ctl.notes_since(mark, "approval.requested")) == 1
    # Confirmed binding is exact: another path is a misplacement.
    assert pod.curl("https://api.example.test/echo/other", "-H", f"Authorization: Token {sentinel}").code == 403


def test_allow_once_binding_still_scans_minted_tokens(pod, ctl):
    """Regression (security review 2026-11-04 #1): with an allow-once binding for an
    imported credential, the response was not scanned and a minted token reached the tab."""
    pod.load({"allow": ALLOW, "prompt": {"timeoutSeconds": 10, "denyCooldownSeconds": 0}})
    s = ctl.call("credential.import", {"id": "imp-a1", "value": pod.canaries["imported"],
                                        "source": {"kind": "password-input"}})["sentinel"]
    ctl.handlers["approval.requested"] = lambda p: ctl.call(
        "approval.decide", {"approvalId": p["approvalId"], "decision": "allow-once"})
    r = pod.curl("https://api.example.test/mint", "-X", "POST", "-H", f"Authorization: Bearer {s}")
    assert r.code == 201, r.body
    assert r.json()["token"].startswith("SECLAB_SNTL_") and "ghs_" not in r.body


def test_binding_approvals_are_not_coalesced_across_requests(pod, ctl):
    """Regression (security review 2026-11-04 #2): a second request joined the first
    request's binding approval and got the real value on an unapproved path/method/header."""
    pod.load({"allow": ALLOW, "prompt": {"timeoutSeconds": 10, "denyCooldownSeconds": 0}})
    s = ctl.call("credential.import", {"id": "imp-a2", "value": pod.canaries["imported"],
                                        "source": {"kind": "workspace-scan"}})["sentinel"]
    mark = ctl.mark()

    def decide(p):
        time.sleep(1.0)
        ok = p["request"]["path"] == "/echo/a2-ok" and p["request"]["method"] == "GET"
        ctl.call("approval.decide", {"approvalId": p["approvalId"],
                                     "decision": "allow-once" if ok else "deny"})

    ctl.handlers["approval.requested"] = decide
    out = pod.ws(
        f"(curl -s -o /dev/null -w 'A=%{{http_code}}' -H 'Authorization: Bearer {s}' "
        f"https://api.example.test/echo/a2-ok > /tmp/a.out &) ; sleep 0.3; "
        f"curl -s -o /dev/null -w 'B=%{{http_code}}' -X DELETE -H 'X-Smuggle: {s}' "
        f"https://api.example.test/echo/a2-bad; sleep 2; echo; cat /tmp/a.out").stdout.decode()
    assert "B=403" in out and "A=200" in out, out
    assert len(ctl.notes_since(mark, "approval.requested")) == 2
    assert not [x for x in pod.seen() if x["path"] == "/echo/a2-bad"]


def test_unbound_credential_never_offers_a_wildcard_binding(pod, ctl):
    """Regression (self-review 2026-11-04): a literal '*' in the tab-chosen path became a
    glob in suggestedBinding, so 'allow-tab' would have confirmed a wildcard binding."""
    pod.load({"allow": ALLOW, "prompt": {"timeoutSeconds": 10, "denyCooldownSeconds": 0}})
    s = ctl.call("credential.import", {"id": "imp-glob", "value": pod.canaries["imported"],
                                        "source": {"kind": "workspace-scan"}})["sentinel"]
    mark = ctl.mark()
    ctl.handlers["approval.requested"] = lambda p: ctl.call(
        "approval.decide", {"approvalId": p["approvalId"], "decision": "allow-tab"})
    r = pod.curl("https://api.example.test/echo/**", "-H", f"Authorization: Bearer {s}")
    assert r.code == 403 and "exact binding" in r.body
    assert ctl.notes_since(mark, "approval.requested") == []


def _ws_split(pod, s, where):
    p = pod.ws(f"python3 /usr/local/bin/wsclient.py wss://ws.example.test/ws split:{where}:{where} after",
               env={"WS_AUTH": "Bearer " + s, "WS_COLLECT": "1"})
    assert p.returncode == 0, p.stderr.decode()
    return json.loads(p.stdout)[-1]["messages"], f"seclab-minted-canary-{where}-" + "Q" * 24 + "-value"


def test_websocket_token_split_across_messages(pod, ctl):
    """A minted token split across WebSocket messages matches no single message. Each
    server message is scanned with a window of what the tab already received on the
    connection (decide on what the tab sees, not on one message)."""
    s = setup(pod, ctl)["api"]
    # Key in one message, token in the next: re-sentinelised, connection unaffected.
    got, canary = _ws_split(pod, s, "key")
    joined = "".join(got[:-1])
    assert canary not in joined and json.loads(joined)["token"].startswith("SECLAB_SNTL_")
    assert got[-1] == "echo:after"
    # Token split mid-way: the second half never goes out, and the connection is dead.
    mark = ctl.mark()
    got, canary = _ws_split(pod, s, "mid")
    assert len(got) == 1 and canary not in got[0] and canary[:16] in got[0]
    ctl.wait_note("audit.event", lambda e: e["type"] == "response.blocked"
                  and "split across" in e["reason"], since=mark, timeout=10)
    # Residual (ADR no-real-secret, Consequences): a token whose match completes only on
    # its terminator was delivered before it could be recognised. It is detected and the
    # connection killed, but not prevented.
    mark = ctl.mark()
    got, canary = _ws_split(pod, s, "end")
    assert len(got) == 1 and canary in got[0]
    ctl.wait_note("audit.event", lambda e: e["type"] == "response.blocked"
                  and "split across" in e["reason"], since=mark, timeout=10)


def test_websocket_handshake_injection_and_message_scanning(pod, ctl):
    s = setup(pod, ctl)["api"]
    p = pod.ws(f"python3 /usr/local/bin/wsclient.py wss://ws.example.test/ws hello {s}",
               env={"WS_AUTH": f"Bearer {s}"})
    assert p.returncode == 0, p.stderr.decode()
    hello, echo, leaked = json.loads(p.stdout)
    assert hello["auth"] == "Bearer " + s  # upstream saw the real value; reflection was scrubbed
    assert echo == "echo:hello"
    assert leaked is None  # client message carrying the sentinel was dropped


def test_git_clone_and_fetch_with_sentinel(pod, ctl):
    s = setup(pod, ctl)["git"]
    helper = "!f() { echo username=x-access-token; echo password=$GIT_SENTINEL; }; f"
    pod.ws(f"git config --global credential.helper '{helper}'")
    p = pod.ws("rm -rf demo && git clone -q https://git.example.test/demo.git demo && cat demo/README",
               env={"GIT_SENTINEL": s})
    assert p.returncode == 0, p.stderr.decode()
    assert b"hello from the test upstream" in p.stdout
    # Advance upstream, then fetch.
    from conftest import docker
    docker("exec", pod.name("upstream"), "sh", "-c",
           "d=$(mktemp -d) && git clone -q /srv/git/demo.git $d && cd $d && echo two > TWO && git add TWO && "
           "git -c user.name=t -c user.email=t@example.test commit -q -m two && git push -q origin main")
    p = pod.ws("cd demo && git fetch -q && git log --oneline origin/main | wc -l", env={"GIT_SENTINEL": s})
    assert p.returncode == 0 and p.stdout.strip() == b"2", p.stderr.decode()
    # Control: anything that is not the sentinel is not swapped, so upstream refuses it.
    p = pod.ws("rm -rf demo2 && git clone -q https://git.example.test/demo.git demo2",
               env={"GIT_SENTINEL": "not-the-sentinel-" + secrets.token_hex(8)})
    assert p.returncode != 0
    cfg = pod.ws("cat demo/.git/config; git config --global --list").stdout.decode()
    pod.assert_no_canary(cfg)
