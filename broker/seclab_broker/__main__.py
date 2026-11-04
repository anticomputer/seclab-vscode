"""Entrypoint: `seclab-broker run | control | selftest-hardening`."""

from __future__ import annotations

import argparse
import asyncio
import ctypes
import logging
import os
import resource
import secrets
import sys
from pathlib import Path

from . import VERSION
from .control import DEFAULT_SOCKET, bridge, serve

PR_SET_DUMPABLE = 4


def harden() -> None:
    """No core dumps; not ptrace-able or /proc/<pid>/mem-readable by same-uid processes."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_DUMPABLE, 0) failed")


def make_ca(confdir: Path, tab_id: str | None) -> str:
    from mitmproxy import certs

    confdir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(confdir, 0o700)
    if not (confdir / "mitmproxy-ca.pem").exists():
        label = tab_id or secrets.token_hex(4)
        certs.CertStore.create_store(confdir, "mitmproxy", 2048,
                                     organization="seclab-vscode broker",
                                     cn=f"seclab-vscode tab CA {label}")
    # Only the public certificate leaves this directory.
    for name in ("mitmproxy-ca.p12", "mitmproxy-ca-cert.p12", "mitmproxy-ca-cert.cer"):
        (confdir / name).unlink(missing_ok=True)
    return (confdir / "mitmproxy-ca-cert.pem").read_text()


def upstream_trust(workdir: Path) -> str | None:
    """Optional extra upstream CA (tests). Added to certifi, never replaces it."""
    extra = os.environ.get("SECLAB_EXTRA_UPSTREAM_CA_PEM")
    if not extra:
        return None
    import certifi

    bundle = workdir / "upstream-ca.pem"
    bundle.write_text(Path(certifi.where()).read_text() + "\n" + extra.strip() + "\n")
    return str(bundle)


async def run(args: argparse.Namespace) -> int:
    from mitmproxy import options, version
    from mitmproxy.tools.dump import DumpMaster

    from .core import Broker
    from .engine_mitmproxy import SeclabAddon
    from .netguard import local_addresses

    tab_id = os.environ.get("SECLAB_TAB_ID") or None
    local_ips = local_addresses()
    harden()

    run_dir = Path(os.environ.get("SECLAB_RUN_DIR", "/run/seclab"))
    confdir = run_dir / "ca"
    ca_pem = make_ca(confdir, tab_id)
    export = os.environ.get("SECLAB_CA_EXPORT_DIR")
    if export:
        p = Path(export) / "ca.pem"
        p.write_text(ca_pem)
        os.chmod(p, 0o644)

    broker = Broker(tab_id=tab_id, engine="mitmproxy", engine_version=version.VERSION)
    broker.ca_pem = ca_pem

    opts = options.Options(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        confdir=str(confdir),
        mode=["regular"],
    )
    master = DumpMaster(opts, with_termlog=False, with_dumper=False)
    trusted = upstream_trust(run_dir)
    opts.update(
        connection_strategy="lazy",
        http2=True,
        websocket=True,
        rawtcp=False,
        ssl_insecure=False,
        upstream_cert=False,
        block_global=False,
        block_private=False,
        showhost=False,
        body_size_limit=os.environ.get("SECLAB_BODY_SIZE_LIMIT", "512m"),
        stream_large_bodies=None,
        save_stream_file=None,
        **({"ssl_verify_upstream_trusted_ca": trusted} if trusted else {}),
    )
    master.addons.add(SeclabAddon(broker, local_ips))

    server = await serve(broker, Path(os.environ.get("SECLAB_CONTROL_SOCKET", str(DEFAULT_SOCKET))))
    broker.on_shutdown = master.shutdown
    broker.audit("broker.started", version=VERSION, engine=f"mitmproxy {version.VERSION}",
                 listen=f"{args.listen_host}:{args.listen_port}")
    try:
        await master.run()
    finally:
        broker.creds.clear()
        server.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="seclab-broker")
    parser.add_argument("--version", action="version", version=VERSION)
    sub = parser.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run the proxy and the control socket")
    r.add_argument("--listen-host", default="0.0.0.0")
    r.add_argument("--listen-port", type=int, default=8080)
    sub.add_parser("control", help="bridge stdio to the control socket (docker exec -i target)")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr,
                        format="%(levelname)s %(name)s: %(message)s")
    if args.cmd == "control":
        return bridge(Path(os.environ.get("SECLAB_CONTROL_SOCKET", str(DEFAULT_SOCKET))))
    return asyncio.run(run(args))


if __name__ == "__main__":
    sys.exit(main())
