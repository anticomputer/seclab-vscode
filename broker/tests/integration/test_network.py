"""Network containment: proxy-unaware clients fail closed, no DNS exfiltration
through Docker's embedded resolver, upstream address guard, broker isolation."""

import json
import secrets
import time

from conftest import WORKSPACE_IMAGE, docker


def ip_on(pod, container: str, network: str) -> str:
    out = docker("inspect", "-f", "{{json .NetworkSettings.Networks}}", container).stdout
    return json.loads(out)[network]["IPAddress"]


def test_proxy_unaware_clients_fail_closed(pod, ctl):
    pod.load({"allow": [{"host": "api.example.test"}], "prompt": {"enabled": False}})
    unset = "env -u HTTPS_PROXY -u https_proxy -u HTTP_PROXY -u http_proxy"
    p = pod.ws(f"{unset} curl -sS --max-time 5 https://api.example.test/echo/x")
    assert p.returncode != 0 and b"Could not resolve host" in p.stderr
    upstream_ip = ip_on(pod, pod.name("upstream"), pod.name("inet"))
    p = pod.ws(f"{unset} curl -sS --max-time 5 -k https://{upstream_ip}/echo/x")
    assert p.returncode != 0
    # TEST-NET-1 (RFC 5737): reserved for documentation, never a real host.
    p = pod.ws(f"{unset} curl -sS --max-time 5 http://192.0.2.1/")
    assert p.returncode != 0
    assert pod.ws("getent hosts api.example.test").returncode != 0
    # Only the default route-less internal network: no default gateway.
    routes = pod.ws("cat /proc/net/route").stdout.decode().splitlines()[1:]
    assert all(line.split()[1] != "00000000" for line in routes if line.strip())


def test_no_dns_exfiltration_via_embedded_resolver(pod, ctl):
    dns_ip = ip_on(pod, pod.name("dns"), pod.name("inet"))
    tag = secrets.token_hex(4)
    names = {k: f"{k}-{tag}.exfil.test" for k in ("control", "default", "direct", "dnsflag", "tcp")}
    # Positive control: a container on a normal (non-internal) network with --dns reaches the logger.
    ctl_dns_ip = ip_on(pod, pod.name("dns"), pod.name("ctl"))
    docker("run", "--rm", "--network", pod.name("ctl"), "--dns", ctl_dns_ip, "--entrypoint", "getent",
           WORKSPACE_IMAGE, "hosts", names["control"], check=False)
    # 1. The workspace's default resolver (Docker embedded DNS, 127.0.0.11).
    pod.ws(f"getent hosts {names['default']}; dig +time=2 +tries=1 @127.0.0.11 {names['default']}")
    # 2. Direct to the logger's IP: no route.
    pod.ws(f"dig +time=2 +tries=1 @{dns_ip} {names['direct']}; dig +tcp +time=2 +tries=1 @{dns_ip} {names['tcp']}")
    # 3. A container on the internal network that is *configured* to use the logger as its
    #    upstream resolver: the embedded resolver must not forward for internal-only containers
    #    (CVE-2024-29018 class, GHSA-mq39-4gv4-mvpx).
    docker("run", "--rm", "--network", pod.name("int"), "--dns", dns_ip, "--entrypoint", "sh",
           WORKSPACE_IMAGE, "-c", f"getent hosts {names['dnsflag']}; dig +time=2 +tries=1 @127.0.0.11 {names['dnsflag']}",
           check=False)
    time.sleep(1)
    log = docker("exec", pod.name("dns"), "sh", "-c", "cat /srv/dns.log 2>/dev/null || true").stdout.decode()
    assert names["control"] in log, "positive control failed: the DNS logger is not observing queries"
    for k in ("default", "direct", "dnsflag", "tcp"):
        assert names[k] not in log, f"DNS query escaped the internal network via {k}"


def test_upstream_address_guard(pod, ctl):
    """Every probe targets something this test owns (the private-network upstream, the
    broker itself), so a broken guard can never reach a real host service. Link-local and
    metadata addresses (169.254.169.254) are covered by unit tests instead of live probes."""  # fixture-lint: ignore
    broker_ip = ip_on(pod, pod.name("broker"), pod.name("inet"))
    pod.load({"allow": [
        {"host": "internal.example.test"},
        {"host": broker_ip, "schemes": ["http"], "ports": [8080]},
        {"host": "localhost", "schemes": ["http"], "ports": [8080]},
        {"host": "127.0.0.1", "schemes": ["http"], "ports": [8080]},
    ], "prompt": {"enabled": False}})
    for url in ("https://internal.example.test/echo/x", f"http://{broker_ip}:8080/",
                "http://localhost:8080/", "http://[::ffff:127.0.0.1]:8080/"):
        r = pod.curl(url, "--noproxy", "")
        assert r.code in (502, 503), (url, r.code, r.body[:200])
    events = [e for e in pod.audit() if e["type"] in ("upstream.blocked", "upstream.dns_failed")]
    reasons = {e.get("reason") for e in events if e["type"] == "upstream.blocked"}
    assert {"non-global", "loopback", "broker-local"} <= reasons, reasons
    assert not [s for s in pod.seen() if s["host"] == "internal.example.test"]


def test_brokers_are_isolated_from_each_other(pod, ctl):
    """Mechanism the supervisor relies on: a per-broker network with ICC disabled,
    and no route between different brokers' networks."""
    tag = secrets.token_hex(3)
    net_a, net_b = f"seclab-it-{tag}-a", f"seclab-it-{tag}-b"
    try:
        docker("network", "create", "-o", "com.docker.network.bridge.enable_icc=false", net_a)
        docker("network", "create", "-o", "com.docker.network.bridge.enable_icc=false", net_b)
        for n, net in (("a1", net_a), ("a2", net_a), ("b1", net_b)):
            docker("run", "-d", "--name", f"seclab-it-{tag}-{n}", "--network", net, "--entrypoint",
                   "python3", WORKSPACE_IMAGE, "-m", "http.server", "8080")
        time.sleep(1.5)
        a2 = ip_on(pod, f"seclab-it-{tag}-a2", net_a)
        b1 = ip_on(pod, f"seclab-it-{tag}-b1", net_b)
        for target in (a2, b1):
            p = docker("exec", f"seclab-it-{tag}-a1", "curl", "-sS", "--max-time", "3",
                       f"http://{target}:8080/", check=False)
            assert p.returncode != 0, f"reached {target}"
    finally:
        for n in ("a1", "a2", "b1"):
            docker("rm", "-f", f"seclab-it-{tag}-{n}", check=False)
        docker("network", "rm", net_a, net_b, check=False)
