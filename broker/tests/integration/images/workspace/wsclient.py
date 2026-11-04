"""WebSocket probe run inside the workspace: connects through HTTPS_PROXY,
prints every message received as one JSON line."""

import asyncio
import json
import os
import sys

import aiohttp


async def main(url: str, auth: str | None, send: list[str]) -> None:
    proxy = os.environ["HTTPS_PROXY"]
    headers = {"Authorization": auth} if auth else {}
    async with aiohttp.ClientSession(trust_env=False) as s:
        async with s.ws_connect(url, proxy=proxy, headers=headers, timeout=10) as ws:
            out = [json.loads((await ws.receive(timeout=10)).data)]
            for m in send:
                await ws.send_str(m)
                try:
                    msg = await ws.receive(timeout=2)
                    out.append(msg.data)
                except asyncio.TimeoutError:
                    out.append(None)
            print(json.dumps(out))


if __name__ == "__main__":
    auth = os.environ.get("WS_AUTH") or None
    asyncio.run(main(sys.argv[1], auth, sys.argv[2:]))
