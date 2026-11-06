"""Engine-level upgrade guards (policy schema revision 2): which requests count as
upgrades, and a protocol switch on a credentialed request that was not approved as a
WebSocket is never relayed. Uses mitmproxy's own test flows."""

import asyncio

from mitmproxy.test import tflow
from mitmproxy.websocket import WebSocketData

from seclab_broker.core import Broker
from seclab_broker.engine_mitmproxy import SeclabAddon, _upgrade_token


def _req(**headers):
    f = tflow.tflow()
    for k, v in headers.items():
        f.request.headers[k.replace("_", "-")] = v
    return f.request


def test_every_upgrade_signal_counts():
    assert _upgrade_token(_req()) is None
    assert _upgrade_token(_req(Upgrade=" WebSocket ")) == "websocket"
    assert _upgrade_token(_req(Upgrade="websocket, h2c")) == "websocket, h2c"
    # mitmproxy switches on the 101 response plus the request's Sec-WebSocket-Version.
    assert _upgrade_token(_req(Sec_WebSocket_Version="13")) == "malformed-upgrade"
    assert _upgrade_token(_req(Connection="keep-alive, Upgrade")) == "malformed-upgrade"
    r = _req()
    r.headers.add("Upgrade", "websocket")
    r.headers.add("Upgrade", "websocket")
    assert _upgrade_token(r) == "malformed-upgrade"
    r = _req()
    r.method = "CONNECT"
    assert _upgrade_token(r) == "connect"


def _switched(ws_ok: bool):
    addon = SeclabAddon(Broker(), frozenset())
    f = tflow.tflow(resp=True)
    f.response.status_code = 101
    f.response.headers["Upgrade"] = "websocket"
    f.websocket = WebSocketData()
    f.metadata["seclab.injected"] = ["api"]
    if ws_ok:
        f.metadata["seclab.ws_ok"] = True
    asyncio.run(addon.response(f))
    return f


def test_protocol_switch_on_credentialed_request_needs_approval():
    f = _switched(ws_ok=False)
    assert f.response.status_code == 502 and f.websocket is None
    f = _switched(ws_ok=True)
    assert f.response.status_code == 101 and f.websocket is not None
