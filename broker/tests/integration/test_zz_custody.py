"""Custody checks and the canary sweep. Runs last (file name sorts last)."""

import json

from conftest import docker
from controller import RpcFailure


def test_control_protocol_errors(pod, ctl):
    with_bad = pod.controller()
    try:
        with_bad.send_raw(b"not json\n")
        with_bad.send_raw(b'{"jsonrpc":"2.0","id":7,"method":"no.such"}\n')
        with_bad.send_raw(b'[{"jsonrpc":"2.0","id":8,"method":"health"}]\n')
        try:
            with_bad.call("credential.provide", {"id": "nope", "value": pod.canaries["api"]})
        except RpcFailure as e:
            assert e.error["code"] == -32602
        import time
        time.sleep(0.5)
        raw = b"".join(with_bad.raw_lines)
        assert b'"code":-32700' in raw and b'"code":-32601' in raw and b'"code":-32600' in raw
        pod.assert_no_canary(raw.decode())
    finally:
        with_bad.close()


def test_broker_process_custody(pod, ctl):
    b = pod.name("broker")
    # Not dumpable: same-uid processes (e.g. a docker exec) cannot read its environment or memory.
    p = docker("exec", b, "cat", "/proc/1/environ", check=False)
    assert p.returncode != 0
    p = docker("exec", b, "sh", "-c", "head -c 16 /proc/1/mem", check=False)
    assert p.returncode != 0
    limits = docker("exec", b, "cat", "/proc/1/limits").stdout.decode()
    core = [line for line in limits.splitlines() if line.startswith("Max core file size")][0]
    assert core.split()[4:6] == ["0", "0"]
    # The CA private key lives only on the broker's tmpfs, owner-only; no exportable bundles.
    ls = docker("exec", b, "ls", "-l", "/run/seclab/ca").stdout.decode()
    key_line = [line for line in ls.splitlines() if line.endswith("mitmproxy-ca.pem")][0]
    assert key_line.startswith("-rw-------")
    assert ".p12" not in ls
    mounts = docker("exec", b, "cat", "/proc/mounts").stdout.decode()
    assert any(" /run/seclab tmpfs " in line for line in mounts.splitlines())
    # The workspace only ever sees the public certificate.
    ws_ca = pod.ws("cat /usr/local/share/ca-certificates/seclab-tab.crt").stdout.decode()
    assert "PRIVATE KEY" not in ws_ca and ws_ca.strip() == ctl.call("ca.get")["certPem"].strip()
    # The real credential is not in the broker's environment or filesystem.
    p = docker("exec", b, "sh", "-c", "grep -rl seclab-canary / --exclude-dir=proc --exclude-dir=sys 2>/dev/null",
               check=False)
    assert p.stdout.strip() == b""


def test_all_control_traffic_matched_protocol_definition(pod, ctl):
    """Every result and notification seen during the suite validated against
    schema/protocol.v1.json (drift guard between code, definition and docs)."""
    assert ctl.violations == []
    assert len(ctl.notes) > 50


def test_canary_sweep(pod, ctl):
    """No canary, in any encoding, in anything the tab saw, in audit, or in broker logs."""
    pod.assert_no_canary("\n".join(pod.tab_output))
    pod.assert_no_canary(json.dumps(pod.audit()))
    pod.assert_no_canary("\n".join(json.dumps(n) for n in ctl.notes))
    logs = docker("logs", pod.name("broker"))
    pod.assert_no_canary(logs.stdout.decode("utf-8", "replace") + logs.stderr.decode("utf-8", "replace"))
    env = docker("exec", pod.name("ws"), "env").stdout.decode()
    pod.assert_no_canary(env)


def test_shutdown_drops_credentials(pod, ctl):
    ctl.call("broker.shutdown", {"reason": "tab closed"})
    import time
    for _ in range(50):
        state = docker("inspect", "-f", "{{.State.Running}}", pod.name("broker")).stdout.strip()
        if state == b"false":
            break
        time.sleep(0.2)
    assert state == b"false"
