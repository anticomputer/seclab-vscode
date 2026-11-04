from pathlib import Path

from seclab_broker.netguard import local_addresses

ROUTE = """Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth1\t00000000\t0100FA0B\t0003\t0\t0\t0\t00000000\t0\t0\t0
eth1\t0000FA0B\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0
eth0\t000012AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0
"""


def test_local_addresses_from_procfs(tmp_path: Path):
    (tmp_path / "route").write_text(ROUTE)
    found = {str(ip) for ip in local_addresses(tmp_path)}
    # default gateway, and the conventional gateway of each directly connected subnet
    assert {"11.250.0.1", "172.18.0.1"} <= found
