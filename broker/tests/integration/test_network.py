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
    p = pod.ws(f"{unset} curl -sS --max-time 5 http://1.1.1.1/")
    assert p.returncode != 0
    assert pod.ws("getent hosts api.example.test").returncode != 0
    # Only the default route-less internal network: no default gateway.
    routes = pod.ws("cat /proc/net/route").stdout.decode().splitlines()[1:]
    assert all(line.split()[1] != "00000000" for line in routes if line.strip())


def test_no_dns_exfiltration_via_embedded_resolver(pod, ctl):
    dns_ip = ip_on(pod, pod.name("dns"), pod.name("inet"))
    tag = secrets.token_hex(4)
    names = {k: f"{k}-{tag}.exfil.test" for k in ("control", "default", "direct", "dnsflag", "tcp")}
    # Positive control: a container on a normal network with --dns reaches the logger.
    docker("run", "--rm", "--network", pod.name("inet"), "--dns", dns_ip, "--entrypoint", "getent",
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
    gateway = json.loads(docker("network", "inspect", pod.name("inet")).stdout)[0]["IPAM"]["Config"][0]["Gateway"]
    pod.load({"allow": [
        {"host": "internal.example.test"},
        {"host": "host.docker.internal", "schemes": ["http", "https"]},
        {"host": "169.254.169.254", "schemes": ["http"]},
        {"host": gateway, "schemes": ["http", "https"]},
        {"host": "localhost", "schemes": ["http"], "ports": [8080]},
    ], "prompt": {"enabled": False}})
    for url in ("https://internal.example.test/echo/x", "http://host.docker.internal/",
                "http://169.254.169.254/latest/meta-data/", "http://[::ffff:169.254.169.254]/",
                f"http://{gateway}/", "http://localhost:8080/"):
        r = pod.curl(url, "--noproxy", "")
        assert r.code in (502, 503), (url, r.code, r.body[:200])
    events = [e for e in pod.audit() if e["type"] in ("upstream.blocked", "upstream.dns_failed")]
    reasons = {e.get("reason") for e in events if e["type"] == "upstream.blocked"}
    assert "non-global" in reasons and "link-local" in reasons and "loopback" in reasons
    assert "broker-local" in reasons
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
