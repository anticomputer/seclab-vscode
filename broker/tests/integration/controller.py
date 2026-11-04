"""Fake host side of the broker control protocol (docs/broker-protocol.md).

Speaks newline-delimited JSON-RPC 2.0 over the stdio of
`docker exec -i <broker> seclab-broker control`, exactly as the tab
supervisor does.
"""

from __future__ import annotations

import itertools
import json
import queue
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from seclab_broker import protocol


class RpcFailure(Exception):
    def __init__(self, error: dict):
        super().__init__(error.get("message"))
        self.error = error


class Controller:
    def __init__(self, container: str):
        self.proc = subprocess.Popen(
            ["docker", "exec", "-i", container, "seclab-broker", "control"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
        self._ids = itertools.count(1)
        self._pending: dict[int, queue.Queue] = {}
        self._methods: dict[int, str] = {}
        self.violations: list[str] = []
        self._lock = threading.Lock()
        self.notes: list[dict] = []
        self._cv = threading.Condition()
        self.handlers: dict[str, Callable[[dict], None]] = {}
        self._pool = ThreadPoolExecutor(max_workers=4)
        self.raw_lines: list[bytes] = []
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self.raw_lines.append(line)
            msg = json.loads(line)
            if "id" in msg and ("result" in msg or "error" in msg) and msg["id"] is not None:
                method = self._methods.get(msg["id"])
                if method and "result" in msg:
                    err = protocol.check("result", method, msg["result"])
                    if err:
                        self.violations.append(f"result of {method}: {err}")
                q = self._pending.get(msg["id"])
                if q:
                    q.put(msg)
                continue
            if msg.get("method") not in protocol.notification_names():
                self.violations.append(f"unknown notification {msg.get('method')}")
            else:
                err = protocol.check("notification", msg["method"], msg.get("params"))
                if err:
                    self.violations.append(f"notification {msg['method']}: {err}")
                elif msg["method"] == "audit.event" and msg["params"]["type"] not in protocol.audit_types():
                    self.violations.append(f"unknown audit type {msg['params']['type']}")
            with self._cv:
                self.notes.append(msg)
                self._cv.notify_all()
            handler = self.handlers.get(msg.get("method"))
            if handler:
                self._pool.submit(handler, msg.get("params", {}))

    def send_raw(self, data: bytes) -> None:
        assert self.proc.stdin is not None
        with self._lock:
            self.proc.stdin.write(data)

    def call(self, method: str, params: dict | None = None, timeout: float = 15) -> Any:
        mid = next(self._ids)
        q: queue.Queue = queue.Queue()
        self._pending[mid] = q
        self._methods[mid] = method
        msg = {"jsonrpc": "2.0", "id": mid, "method": method}
        if params is not None:
            msg["params"] = params
        self.send_raw(json.dumps(msg).encode() + b"\n")
        try:
            resp = q.get(timeout=timeout)
        finally:
            self._pending.pop(mid, None)
        if "error" in resp:
            raise RpcFailure(resp["error"])
        return resp["result"]

    def mark(self) -> int:
        with self._cv:
            return len(self.notes)

    def notes_since(self, mark: int, method: str | None = None) -> list[dict]:
        with self._cv:
            return [n.get("params", {}) for n in self.notes[mark:]
                    if method is None or n.get("method") == method]

    def wait_note(self, method: str, pred: Callable[[dict], bool] = lambda p: True,
                  since: int = 0, timeout: float = 15) -> dict:
        deadline = time.time() + timeout
        with self._cv:
            while True:
                for n in self.notes[since:]:
                    if n.get("method") == method and pred(n.get("params", {})):
                        return n["params"]
                left = deadline - time.time()
                if left <= 0:
                    raise TimeoutError(f"no {method} notification")
                self._cv.wait(left)

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()
        self._pool.shutdown(wait=False)
