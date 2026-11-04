"""Egress: proxy auth, default deny, hold-and-prompt, matcher bypasses, HTTP/2."""

import time

ALLOW_API = [{"id": "api", "host": "api.example.test"}, {"id": "gist", "host": "gist.example.test"}]
RAW_CONNECT = r'''
import base64, os, socket, sys
host, port, auth, payload = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4].encode().decode("unicode_escape").encode()
s = socket.create_connection(("broker", 8080), timeout=10)
req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
if auth != "-":
    req += "Proxy-Authorization: Basic " + base64.b64encode(auth.encode()).decode() + "\r\n"
s.sendall((req + "\r\n").encode())
first = s.recv(4096).decode("latin-1")
print(first.split("\r\n")[0])
if payload:
    s.sendall(payload)
    try:
        print("AFTER:" + s.recv(4096).decode("latin-1").split("\r\n")[0])
    except Exception as e:
        print("AFTER:" + type(e).__name__)
'''


def raw_connect(pod, host, port, auth, payload=""):
    return pod.ws(f"python3 - {host} {port} '{auth}' '{payload}' <<'EOF'\n{RAW_CONNECT}\nEOF").stdout.decode()


def test_proxy_auth_required_and_never_prompts(pod, ctl):
    pod.load({"allow": [], "prompt": {"enabled": True, "timeoutSeconds": 5}})
    mark = ctl.mark()
    assert raw_connect(pod, "blocked.example.test", 443, "-").startswith("HTTP/1.1 407")
    assert raw_connect(pod, "blocked.example.test", 443, "seclab:wrong-password-xxxxxxxx").startswith("HTTP/1.1 407")
    assert raw_connect(pod, "blocked.example.test", 443, f"other:{pod.proxy_password}").startswith("HTTP/1.1 407")
    plain = pod.ws("env -u HTTP_PROXY -u http_proxy curl -s -o /dev/null -w '%{http_code}' "
                   "-x http://broker:8080 http://blocked.example.test/").stdout.decode()
    assert plain == "407"
    time.sleep(0.5)
    assert ctl.notes_since(mark, "approval.requested") == []
    assert any(e["type"] == "proxy.auth_failed" for e in pod.audit())


def test_default_deny(pod, ctl):
    pod.load({"allow": ALLOW_API, "prompt": {"enabled": False}})
    r = pod.curl("https://blocked.example.test/echo/x")
    assert r.code == 403 and "x-seclab-broker: denied" in r.headers.lower()
    assert pod.curl("https://api.example.test/echo/x").code == 200
    # Default port only: 8443 on an allowed host is still denied.
    assert pod.curl("https://api.example.test:8443/echo/x").code == 403
    # Cleartext is not implied by an https rule.
    assert pod.curl("http://api.example.test/echo/x").code == 403


def test_prompt_allow_once(pod, ctl):
    pod.load({"allow": [], "prompt": {"timeoutSeconds": 10, "denyCooldownSeconds": 0}})
    ctl.handlers["approval.requested"] = lambda p: ctl.call(
        "approval.decide", {"approvalId": p["approvalId"], "decision": "allow-once"})
    mark = ctl.mark()
    assert pod.curl("https://blocked.example.test/echo/once").code == 200
    assert pod.curl("https://blocked.example.test/echo/once").code == 200
    reqs = ctl.notes_since(mark, "approval.requested")
    assert len(reqs) == 2
    assert reqs[0]["request"]["host"] == "blocked.example.test"
    assert reqs[0]["suggestedRule"]["host"] == "blocked.example.test"


def test_prompt_allow_tab_persists_for_tab(pod, ctl):
    pod.load({"allow": [], "prompt": {"timeoutSeconds": 10, "denyCooldownSeconds": 0}})
    ctl.handlers["approval.requested"] = lambda p: ctl.call(
        "approval.decide", {"approvalId": p["approvalId"], "decision": "allow-tab"})
    mark = ctl.mark()
    assert pod.curl("https://blocked.example.test/echo/a").code == 200
    assert pod.curl("https://blocked.example.test/echo/b").code == 200
    assert len(ctl.notes_since(mark, "approval.requested")) == 1
    changed = ctl.notes_since(mark, "policy.changed")
    assert changed and changed[0]["added"][0]["host"] == "blocked.example.test"


def test_prompt_deny(pod, ctl):
    pod.load({"allow": [], "prompt": {"timeoutSeconds": 10, "denyCooldownSeconds": 0}})
    ctl.handlers["approval.requested"] = lambda p: ctl.call(
        "approval.decide", {"approvalId": p["approvalId"], "decision": "deny"})
    r = pod.curl("https://blocked.example.test/echo/deny")
    assert r.code == 403 and "egress denied" in r.body


def test_hold_times_out_to_deny(pod, ctl):
    pod.load({"allow": [], "prompt": {"timeoutSeconds": 1.5, "denyCooldownSeconds": 0}})
    mark = ctl.mark()
    t0 = time.time()
    r = pod.curl("https://blocked.example.test/echo/timeout")
    assert r.code == 403 and time.time() - t0 >= 1.4
    resolved = ctl.notes_since(mark, "approval.resolved")
    assert resolved and resolved[0]["by"] == "timeout" and resolved[0]["decision"] == "deny"


def test_held_request_resumes_without_retry(pod, ctl):
    pod.load({"allow": [], "prompt": {"timeoutSeconds": 10, "denyCooldownSeconds": 0}})

    def slow_allow(p):
        time.sleep(1.0)
        ctl.call("approval.decide", {"approvalId": p["approvalId"], "decision": "allow-once"})

    ctl.handlers["approval.requested"] = slow_allow
    before = [s for s in pod.seen() if s["path"] == "/echo/held"]
    r = pod.curl("https://blocked.example.test/echo/held", "--retry", "0")
    assert r.code == 200
    after = [s for s in pod.seen() if s["path"] == "/echo/held"]
    assert len(after) - len(before) == 1


def test_approval_queue_is_bounded(pod, ctl):
    pod.load({"allow": [], "prompt": {"timeoutSeconds": 3, "maxPending": 1, "denyCooldownSeconds": 0}})
    # Two different origins: the second cannot open a second prompt.
    p = pod.ws("(curl -s -o /dev/null -w '%{http_code}\\n' https://blocked.example.test/echo/q1 &) ; sleep 0.5; "
               "curl -s -o /dev/null -w '%{http_code}' https://gist.example.test/echo/q2; wait")
    assert p.stdout.decode().strip().splitlines()[-1] == "403"
    assert any(e["type"] == "approval.queue_full" for e in pod.audit())


def test_http2_end_to_end(pod, ctl):
    pod.load({"allow": ALLOW_API, "prompt": {"enabled": False}})
    r = pod.curl("https://api.example.test/echo/h2", "--http2")
    assert r.code == 200 and r.http_version == "2"
    assert r.json()["http_version"] == "2"


def test_authority_confusion_rejected(pod, ctl):
    pod.load({"allow": ALLOW_API, "prompt": {"enabled": False}})
    # Host header differs from the CONNECT target / SNI.
    assert pod.curl("https://api.example.test/echo/x", "-H", "Host: gist.example.test").code == 421
    assert pod.curl("https://api.example.test/echo/x", "--http2", "-H", "Host: gist.example.test").code == 421
    # CONNECT goes to gist while SNI and Host say api.
    assert pod.curl("https://api.example.test/echo/x",
                    "--connect-to", "api.example.test:443:gist.example.test:443").code == 421


def test_method_override_and_path_tricks_rejected(pod, ctl):
    pod.load({"allow": ALLOW_API, "prompt": {"enabled": False}})
    assert pod.curl("https://api.example.test/echo/x", "-H", "X-HTTP-Method-Override: DELETE").code == 400
    assert pod.curl("https://api.example.test/echo/x?_method=DELETE").code == 400
    assert pod.curl("https://api.example.test/echo/../user/keys", "--path-as-is").code == 400
    assert pod.curl("https://api.example.test/echo/%2e%2e/user/keys", "--path-as-is").code == 400
    assert pod.curl("https://api.example.test/echo/a;b").code == 400
    assert pod.curl("https://api.example.test//echo/x", "--path-as-is").code == 400


def test_absolute_form_inside_tunnel_rejected(pod, ctl):
    """Regression (security review 2026-11-04 #3): an HTTP/1 absolute-form target inside
    a CONNECT tunnel was forwarded verbatim, so the origin could route on a different
    authority from the one the policy checked."""
    pod.load({"allow": ALLOW_API, "prompt": {"enabled": False}})
    script = r'''
import base64, socket, ssl, sys
pw = sys.argv[1]
s = socket.create_connection(("broker", 8080), timeout=10)
auth = base64.b64encode(f"seclab:{pw}".encode()).decode()
s.sendall(f"CONNECT api.example.test:443 HTTP/1.1\r\nHost: api.example.test:443\r\nProxy-Authorization: Basic {auth}\r\n\r\n".encode())
assert s.recv(4096).startswith(b"HTTP/1.1 200")
t = ssl.create_default_context().wrap_socket(s, server_hostname="api.example.test")
t.sendall(b"GET https://gist.example.test/echo/a3 HTTP/1.1\r\nHost: api.example.test\r\nConnection: close\r\n\r\n")
print(t.recv(4096).split(b"\r\n")[0].decode())
'''
    out = pod.ws(f"python3 - '{pod.proxy_password}' <<'EOF'\n{script}\nEOF").stdout.decode().strip()
    assert out.startswith("HTTP/1.1 421"), out
    assert not [s for s in pod.seen() if s["path"] == "/echo/a3"]


def test_non_http_inside_tunnel_is_not_forwarded(pod, ctl):
    pod.load({"allow": ALLOW_API, "prompt": {"enabled": False}})
    out = raw_connect(pod, "api.example.test", 22, f"seclab:{pod.proxy_password}", "SSH-2.0-probe\\r\\n")
    assert out.startswith("HTTP/1.1 200")
    after = out.split("AFTER:", 1)[1]
    assert "SSH" not in after
    assert not [s for s in pod.seen() if s["path"] == "SSH-2.0-probe"]
