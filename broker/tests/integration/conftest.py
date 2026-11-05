"""Pod-shaped harness: workspace container on an --internal network whose
only peer is the broker; the broker also sits on a fake "internet" network
(public-range subnet) and a private-range network (to prove the upstream
address guard). Driven by a fake host controller over stdio.
"""

from __future__ import annotations

import base64
import json
import os
import random
import secrets
import shlex
import subprocess
import time
import urllib.parse
from dataclasses import dataclass, field

import pytest

from controller import Controller

BROKER_IMAGE = os.environ.get("BROKER_IMAGE", "seclab-broker:test")
UPSTREAM_IMAGE = os.environ.get("UPSTREAM_IMAGE", "seclab-broker-it-upstream:test")
WORKSPACE_IMAGE = os.environ.get("WORKSPACE_IMAGE", "seclab-broker-it-workspace:test")
UPSTREAM_HOSTS = ["api.example.test", "gist.example.test", "git.example.test", "ws.example.test",
                  "blocked.example.test", "model.example.test"]
HARDENING = ["--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
             "--pids-limit", "256"]


def docker(*args: str, check: bool = True, input: bytes | None = None,
           timeout: float = 120) -> subprocess.CompletedProcess:
    p = subprocess.run(["docker", *args], input=input, capture_output=True, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args[:3])} failed: {p.stderr.decode()[-2000:]}")
    return p


def b64_cores(data: bytes) -> list[bytes]:
    out = []
    for k, start in ((0, 0), (1, 2), (2, 3)):
        enc = base64.b64encode(b"\0" * k + data)
        core = enc[start:4 * ((len(data) + k) // 3)]
        out += [core, core.translate(bytes.maketrans(b"+/", b"-_"))]
    return out


def encodings(value: str) -> list[bytes]:
    raw = value.encode()
    return [raw, raw.hex().encode(), raw.hex().upper().encode(),
            urllib.parse.quote(value, safe="").encode()] + b64_cores(raw)


@dataclass
class Result:
    code: int
    http_version: str
    headers: str
    body: str

    def json(self):
        return json.loads(self.body)


@dataclass
class Pod:
    ident: str
    canaries: dict[str, str] = field(default_factory=dict)
    tab_output: list[str] = field(default_factory=list)
    proxy_password: str = ""
    upstream_ca: str = ""
    inet_subnet: str = ""

    def name(self, part: str) -> str:
        return f"seclab-it-{self.ident}-{part}"

    # ---------------------------------------------------------------- lifecycle
    def up(self) -> None:
        third = random.randint(1, 254)
        self.inet_subnet = f"11.250.{third}.0/24"
        # Every network the broker sits on is --internal: the fake "internet" and the
        # private network have no route out, so even a broken guard cannot reach a real
        # host during tests. `ctl` (not internal) exists only for the DNS test's positive
        # control and never carries the broker or the workspace.
        docker("network", "create", "--internal", self.name("int"))
        docker("network", "create", "--internal", "--subnet", self.inet_subnet, self.name("inet"))
        docker("network", "create", "--internal", self.name("priv"))
        docker("network", "create", self.name("ctl"))
        self.canaries = {
            "api": "seclab-canary-api-" + secrets.token_hex(16),
            "git": "seclab-canary-git-" + secrets.token_hex(16),
            "imported": "seclab-canary-imp-" + secrets.token_hex(16),
        }
        aliases = sum((["--network-alias", h] for h in UPSTREAM_HOSTS), [])
        docker("run", "-d", "--name", self.name("upstream"), "--network", self.name("inet"), *aliases,
               "-e", f"UPSTREAM_GIT_TOKEN={self.canaries['git']}", UPSTREAM_IMAGE)
        docker("run", "-d", "--name", self.name("internal"), "--network", self.name("priv"),
               "--network-alias", "internal.example.test", "-e", "UPSTREAM_GIT_TOKEN=unused", UPSTREAM_IMAGE)
        docker("run", "-d", "--name", self.name("dns"), "--network", self.name("inet"),
               UPSTREAM_IMAGE, "dns")
        docker("network", "connect", self.name("ctl"), self.name("dns"))
        self.upstream_ca = self._wait_file(self.name("upstream"), "/srv/tls/ca.pem")
        self._wait_file(self.name("internal"), "/srv/tls/ca.pem")

        docker("create", "--name", self.name("broker"), "--network", self.name("int"),
               "--network-alias", "broker", *HARDENING,
               "--tmpfs", "/run/seclab:rw,nosuid,nodev,noexec,size=16m,uid=1000,gid=1000,mode=0700",
               "-e", f"SECLAB_TAB_ID=it-{self.ident}",
               "-e", f"SECLAB_EXTRA_UPSTREAM_CA_PEM={self.upstream_ca}",
               BROKER_IMAGE)
        docker("network", "connect", self.name("inet"), self.name("broker"))
        docker("network", "connect", self.name("priv"), self.name("broker"))
        docker("start", self.name("broker"))
        self.ctl = self._connect_controller()
        self.proxy_password = secrets.token_urlsafe(16)
        self.ctl.call("proxy.auth.set", {"username": "seclab", "password": self.proxy_password})

        proxy = f"http://seclab:{self.proxy_password}@broker:8080"
        env = []
        for k in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
            env += ["-e", f"{k}={proxy}"]
        env += ["-e", "NO_PROXY=localhost,127.0.0.1,::1", "-e", "no_proxy=localhost,127.0.0.1,::1",
                "-e", "NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/seclab-tab.crt",
                "-e", "REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt",
                "-e", "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
                "-e", "GIT_TERMINAL_PROMPT=0"]
        docker("run", "-d", "--name", self.name("ws"), "--network", self.name("int"),
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges", *env, WORKSPACE_IMAGE)
        ca = self.ctl.call("ca.get")["certPem"]
        docker("exec", "-u", "0", "-i", self.name("ws"), "sh", "-c",
               "cat > /usr/local/share/ca-certificates/seclab-tab.crt && update-ca-certificates >/dev/null",
               input=ca.encode())

    def _connect_controller(self) -> Controller:
        deadline = time.time() + 30
        while True:
            ctl = self.controller()
            try:
                if ctl.call("health", timeout=3)["status"] == "ok":
                    return ctl
            except Exception:
                if time.time() > deadline:
                    logs = docker("logs", self.name("broker"), check=False)
                    raise RuntimeError("broker never became healthy: " + logs.stderr.decode()[-3000:])
            ctl.close()
            time.sleep(0.3)

    def _wait_file(self, container: str, path: str) -> str:
        for _ in range(100):
            p = docker("exec", container, "cat", path, check=False)
            if p.returncode == 0 and p.stdout:
                return p.stdout.decode()
            time.sleep(0.2)
        raise RuntimeError(f"{container}:{path} never appeared")

    def controller(self) -> Controller:
        return Controller(self.name("broker"))

    def down(self) -> None:
        try:
            self.ctl.close()
        except Exception:
            pass
        if os.environ.get("KEEP_POD"):
            return
        for part in ("ws", "broker", "upstream", "internal", "dns"):
            docker("rm", "-f", self.name(part), check=False)
        for part in ("int", "inet", "priv", "ctl"):
            docker("network", "rm", self.name(part), check=False)

    # ---------------------------------------------------------------- helpers
    def load(self, policy: dict) -> dict:
        policy = {"version": 1, "baseline": False, **policy}
        return self.ctl.call("policy.load", {"policy": policy})["sentinels"]

    def ws(self, cmd: str, env: dict | None = None, timeout: float = 60) -> subprocess.CompletedProcess:
        args = ["exec"]
        for k, v in (env or {}).items():
            args += ["-e", f"{k}={v}"]
        p = docker(*args, self.name("ws"), "sh", "-c", cmd, check=False, timeout=timeout)
        self.tab_output.append(p.stdout.decode("utf-8", "replace") + p.stderr.decode("utf-8", "replace"))
        return p

    def curl(self, url: str, *opts: str, env: dict | None = None) -> Result:
        quoted = " ".join(shlex.quote(o) for o in opts)
        cmd = (f"curl -sS --max-time 30 -D /tmp/h -o /tmp/b -w '%{{http_code}} %{{http_version}}' "
               f"{quoted} {shlex.quote(url)}; echo; echo ---HEADERS---; cat /tmp/h; echo ---BODY---; cat /tmp/b; "
               f"rm -f /tmp/h /tmp/b")
        p = self.ws(cmd, env=env)
        out = p.stdout.decode("utf-8", "replace")
        status_line, _, rest = out.partition("\n")
        headers, _, body = rest.partition("---BODY---\n")
        code, _, ver = status_line.strip().partition(" ")
        return Result(int(code or 0), ver, headers.replace("---HEADERS---\n", ""), body)

    def seen(self) -> list[dict]:
        p = docker("exec", self.name("upstream"), "python", "-c",
                   "import urllib.request,ssl,json;"
                   "c=ssl.create_default_context(cafile='/srv/tls/ca.pem');c.check_hostname=False;"
                   "print(urllib.request.urlopen('https://127.0.0.1/seen',context=c).read().decode())")
        return json.loads(p.stdout)

    def audit(self) -> list[dict]:
        return self.ctl.call("audit.tail", {"limit": 2000})["events"]

    def assert_no_canary(self, text: str) -> None:
        data = text.encode("utf-8", "replace")
        for name, value in self.canaries.items():
            for enc in encodings(value):
                assert enc not in data, f"canary {name} leaked ({enc[:12]!r}...)"


@pytest.fixture(scope="session")
def pod():
    p = Pod(ident=secrets.token_hex(3))
    try:
        p.up()
        yield p
    finally:
        p.down()


@pytest.fixture
def ctl(pod):
    """Each test starts from a fresh prompt session in a tab the user has interacted
    with; tests about pre-interaction behaviour send `tab.event opened` themselves."""
    pod.ctl.handlers.clear()
    pod.ctl.call("prompt.reset")
    pod.ctl.call("tab.event", {"kind": "userAction"})
    yield pod.ctl
    pod.ctl.handlers.clear()
