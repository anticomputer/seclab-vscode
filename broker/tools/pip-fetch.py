"""Fetch the hash-locked wheels for one requirements file into /wheels, in the token-holding
`wheels` stage of a broker image build. The final stage installs from /wheels with
--no-index and never sees a token or the network.

    python3 /opt/pipfetch/pip-fetch.py /opt/pipfetch/requirements.txt

The index is chosen explicitly by the build arg PIP_SOURCE, never by whether a secret is
present, so a local build can't silently fall back to public PyPI:
  cfs     GitHub's CFS PyPI feed. Needs the BuildKit secret `cfs_feed_token` (supplied by
          `gh cfs -- docker build`) and a tmpfs at /run/cfs-auth. The token goes into a
          0600 netrc on that tmpfs, never into argv, the environment of pip's index URL,
          a layer or a log, and the build fails if it appears in a downloaded file.
  public  pypi.org (hosted CI, which can't use CFS). Same --require-hashes.
Modelled on `gh cfs generate docker-helper` (gh-cfs v0.3.1) and the Fork-build session's
CFS local-build recipe (EDR 20261105-cfs-local-builds).
"""

from __future__ import annotations

import os
import pathlib
import re
import subprocess
import sys

CFS_INDEX = "https://pkgs.dev.azure.com/github-cfs/GitHubCFS/_packaging/github-cfs-pypi/pypi/simple/"
PUBLIC_INDEX = "https://pypi.org/simple/"
SECRET = pathlib.Path("/run/secrets/cfs_feed_token")
AUTH_DIR = pathlib.Path("/run/cfs-auth")
OUT = pathlib.Path("/wheels")


def fail(msg: str) -> None:
    sys.exit(f"pip-fetch: {msg}")


def tmpfs_at(path: str) -> bool:
    for line in pathlib.Path("/proc/self/mountinfo").read_text().splitlines():
        before, _, after = line.partition(" - ")
        fields, fs = before.split(), after.split()
        if len(fields) >= 5 and fields[4] == path:
            return bool(fs) and fs[0] == "tmpfs"
    return False


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: pip-fetch.py REQUIREMENTS")
    req = sys.argv[1]
    source = os.environ.get("PIP_SOURCE", "")
    # An allowlist, not "everything but PIP_*": nothing from the build can hook the child
    # (PYTHONPATH, sitecustomize, NETRC, ...). The child also runs isolated (-I).
    keep = ("PATH", "HOME", "LANG", "LC_ALL", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
            "NO_PROXY", "no_proxy", "SSL_CERT_FILE")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env.update(PIP_CONFIG_FILE="/dev/null", PIP_NO_INPUT="1", PIP_KEYRING_PROVIDER="disabled",
               PIP_DISABLE_PIP_VERSION_CHECK="1", PIP_NO_CACHE_DIR="1")
    cmd = [sys.executable, "-I", "-m", "pip", "download", "--require-hashes", "--only-binary=:all:", "--no-deps",
           "--dest", str(OUT), "-r", req]
    token = None
    netrc = AUTH_DIR / "netrc"
    if source == "cfs":
        if not tmpfs_at(str(AUTH_DIR)):
            fail("PIP_SOURCE=cfs needs a tmpfs mount at /run/cfs-auth")
        try:
            raw = SECRET.read_bytes()[:65537]
        except OSError:
            fail("PIP_SOURCE=cfs needs the cfs_feed_token secret: build with `gh cfs -- docker build`")
        if not 0 < len(raw) <= 65536 or not re.fullmatch(rb"[A-Za-z0-9._~+/=\-]+", raw):
            fail("malformed cfs_feed_token secret")
        token = raw.decode("ascii")
        old = os.umask(0o077)
        try:
            netrc.write_text(f"machine pkgs.dev.azure.com\n  login cfs\n  password {token}\n")
        finally:
            os.umask(old)
        env["NETRC"] = str(netrc)
        cmd += ["--index-url", CFS_INDEX]
    elif source == "public":
        cmd += ["--index-url", PUBLIC_INDEX]
    else:
        fail("set the build arg PIP_SOURCE to cfs or public")
    try:
        rc = subprocess.run(cmd, env=env).returncode
    finally:
        if token is not None:
            netrc.unlink(missing_ok=True)
    if rc != 0:
        fail(f"pip download failed ({rc})")
    if token is not None:
        needle = token.encode()
        for f in OUT.rglob("*"):
            if f.is_file() and needle in f.read_bytes():
                fail("the feed token appears in a downloaded file")


if __name__ == "__main__":
    main()
