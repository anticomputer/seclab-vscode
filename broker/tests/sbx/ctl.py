"""Control-channel helper for the sbx validation script. Runs in the harness
image (docker CLI + Python) so nothing executes on the macOS host except
docker and sbx.

  ctl.py setup <broker> <outdir>   reads SECLAB_PW, API_CANARY, GIT_CANARY from env;
                                   writes <outdir>/ca.pem and <outdir>/env
  ctl.py audit <broker> <outdir>   writes <outdir>/audit.json
"""

import json
import os
import subprocess
import sys
import time


class Ctl:
    def __init__(self, container: str):
        self.p = subprocess.Popen(["docker", "exec", "-i", container, "seclab-broker", "control"],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.n = 0

    def call(self, method, params=None):
        self.n += 1
        msg = {"jsonrpc": "2.0", "id": self.n, "method": method}
        if params is not None:
            msg["params"] = params
        self.p.stdin.write(json.dumps(msg) + "\n")
        self.p.stdin.flush()
        while True:
            line = self.p.stdout.readline()
            if not line:
                raise RuntimeError("control channel closed")
            resp = json.loads(line)
            if resp.get("id") == self.n:
                if "error" in resp:
                    raise RuntimeError(resp["error"])
                return resp["result"]

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=10)


def connect(container: str) -> Ctl:
    for _ in range(60):
        try:
            c = Ctl(container)
            if c.call("health")["status"] == "ok":
                return c
        except Exception:
            pass
        time.sleep(0.5)
    raise SystemExit("broker never became healthy")


POLICY = {
    "version": 1, "tabId": "sbx-validation", "baseline": False,
    "prompt": {"enabled": False}, "sentinelMismatch": "block",
    "allow": [{"host": "api.example.test"}, {"host": "gist.example.test"},
              {"host": "git.example.test"}],
    "credentials": [
        {"id": "api", "inject": {"header": "Authorization", "fmt": "Bearer {value}"},
         "bind": {"host": "api.example.test", "path": "/echo/repos/**", "methods": ["GET"]}},
        {"id": "git", "inject": {"header": "Authorization", "fmt": "Basic {base64:x-access-token:{value}}"},
         "bind": [{"host": "git.example.test", "path": "/demo.git/info/refs", "methods": ["GET"]},
                  {"host": "git.example.test", "path": "/demo.git/git-upload-pack", "methods": ["POST"]}]},
    ],
}


def main() -> int:
    cmd, container, outdir = sys.argv[1:4]
    c = connect(container)
    try:
        if cmd == "setup":
            c.call("proxy.auth.set", {"username": "seclab", "password": os.environ["SECLAB_PW"]})
            sentinels = c.call("policy.load", {"policy": POLICY})["sentinels"]
            c.call("credential.provide", {"id": "api", "value": os.environ["API_CANARY"]})
            c.call("credential.provide", {"id": "git", "value": os.environ["GIT_CANARY"]})
            with open(os.path.join(outdir, "ca.pem"), "w") as f:
                f.write(c.call("ca.get")["certPem"])
            with open(os.path.join(outdir, "env"), "w") as f:
                f.write(f"API_SENTINEL={sentinels['api']}\nGIT_SENTINEL={sentinels['git']}\n")
        elif cmd == "audit":
            with open(os.path.join(outdir, "audit.json"), "w") as f:
                json.dump(c.call("audit.tail", {"limit": 2000})["events"], f, indent=1)
    finally:
        c.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
