"""Control channel: JSON-RPC 2.0, newline-delimited, over a private Unix socket.

The host never connects to the socket directly. It runs
``docker exec -i <broker> seclab-broker control`` (or the sbx/kubectl
equivalent), whose stdio is bridged to this socket, so nothing listens on the
host or on any network. See docs/broker-protocol.md.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import sys
import threading
from pathlib import Path
from typing import Any

from .core import Broker, RpcError

log = logging.getLogger("seclab.control")
MAX_LINE = 1 << 20
DEFAULT_SOCKET = Path(os.environ.get("SECLAB_CONTROL_SOCKET", "/run/seclab/control/control.sock"))


class Session:
    def __init__(self, broker: Broker, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.broker, self.reader, self.writer = broker, reader, writer

    def send(self, obj: dict) -> None:
        if self.writer.is_closing():
            return
        self.writer.write(json.dumps(obj, separators=(",", ":")).encode() + b"\n")

    def notify(self, method: str, params: dict) -> None:
        self.send({"jsonrpc": "2.0", "method": method, "params": params})

    async def run(self) -> None:
        self.broker.add_sink(self.notify)
        self.broker.audit("control.connected", controllers=self.broker.controllers)
        try:
            while True:
                try:
                    line = await self.reader.readuntil(b"\n")
                except asyncio.IncompleteReadError:
                    break
                except asyncio.LimitOverrunError:
                    self.send(_error(None, -32700, "message too large"))
                    break
                if not line.strip():
                    continue
                self.handle(line)
                await self.writer.drain()
        finally:
            self.broker.remove_sink(self.notify)
            self.writer.close()
            self.broker.audit("control.disconnected", controllers=self.broker.controllers)

    def handle(self, line: bytes) -> None:
        try:
            msg = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            self.send(_error(None, -32700, "parse error"))
            return
        if isinstance(msg, list):
            self.send(_error(None, -32600, "batches are not supported"))
            return
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
            if isinstance(msg, dict) and "method" not in msg and ("result" in msg or "error" in msg):
                return  # stray response; the broker never sends requests
            self.send(_error(msg.get("id") if isinstance(msg, dict) else None, -32600, "invalid request"))
            return
        mid = msg.get("id")
        if mid is not None and not isinstance(mid, (str, int)):
            self.send(_error(None, -32600, "id must be a string or integer"))
            return
        try:
            result = self.broker.dispatch(msg["method"], msg.get("params"))
        except RpcError as e:
            if mid is not None:
                err = _error(mid, e.code, e.message)
                if e.data is not None:
                    err["error"]["data"] = e.data
                self.send(err)
            return
        except Exception:
            log.exception("control method failed: %s", msg["method"])
            if mid is not None:
                self.send(_error(mid, -32603, "internal error"))
            return
        if mid is not None:
            self.send({"jsonrpc": "2.0", "id": mid, "result": result})


def _error(mid: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


async def serve(broker: Broker, path: Path = DEFAULT_SOCKET) -> asyncio.base_events.Server:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    if path.exists():
        path.unlink()
    old = os.umask(0o177)
    try:
        server = await asyncio.start_unix_server(
            lambda r, w: Session(broker, r, w).run(), path=str(path), limit=MAX_LINE)
    finally:
        os.umask(old)
    return server


def bridge(path: Path = DEFAULT_SOCKET) -> int:
    """stdio <-> control socket. Used as the `docker exec -i` target."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(str(path))
    except OSError as e:
        print(json.dumps(_error(None, -32002, f"broker control socket unavailable: {e.strerror}")),
              flush=True)
        return 2
    stdin, stdout = sys.stdin.buffer, sys.stdout.buffer

    def up() -> None:
        try:
            while chunk := stdin.read1(65536):
                sock.sendall(chunk)
        except OSError:
            pass
        finally:
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    threading.Thread(target=up, daemon=True).start()
    try:
        while chunk := sock.recv(65536):
            stdout.write(chunk)
            stdout.flush()
    except OSError:
        pass
    return 0
