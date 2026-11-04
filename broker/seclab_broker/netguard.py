"""Upstream address guard: the broker never connects to non-public addresses.

Applied after DNS resolution on every upstream connect, whatever the policy
says, so an allowed hostname that resolves (or rebinds) to loopback, RFC1918,
link-local, CGNAT, the Docker gateway or the broker itself is refused.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

IP = ipaddress.IPv4Address | ipaddress.IPv6Address
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL = ipaddress.ip_network("64:ff9b:1::/48")


def _embedded_v4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip.teredo is not None:
        return ip.teredo[1]
    if ip in _NAT64:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    packed = ip.packed
    # IPv4-compatible (deprecated) ::a.b.c.d, excluding :: and ::1.
    if packed[:12] == b"\0" * 12 and int(ip) > 1:
        return ipaddress.IPv4Address(packed[12:])
    return None


def deny_reason(ip: IP, extra: frozenset[IP] = frozenset()) -> str | None:
    if isinstance(ip, ipaddress.IPv6Address):
        if ip in _NAT64_LOCAL:
            return "nat64-local"
        v4 = _embedded_v4(ip)
        if v4 is not None:
            inner = deny_reason(v4, extra)
            return f"embedded-ipv4:{inner}" if inner else None
    if ip in extra:
        return "broker-local"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_multicast:
        return "multicast"
    if ip.is_reserved:
        return "reserved"
    if not ip.is_global:
        return "non-global"
    return None


def local_addresses(proc: Path = Path("/proc/net")) -> frozenset[IP]:
    """The broker's own addresses and its gateways, read from procfs."""
    found: set[IP] = set()
    try:
        for line in (proc / "route").read_text().splitlines()[1:]:
            cols = line.split()
            if len(cols) > 2 and cols[2] != "00000000":
                found.add(ipaddress.IPv4Address(bytes.fromhex(cols[2])[::-1]))
    except OSError:
        pass
    try:
        lines = (proc / "fib_trie").read_text().splitlines()
        for i, line in enumerate(lines[:-1]):
            if "/32 host LOCAL" in lines[i + 1]:
                found.add(ipaddress.IPv4Address(line.split()[-1]))
    except (OSError, ValueError):
        pass
    try:
        for line in (proc / "ipv6_route").read_text().splitlines():
            cols = line.split()
            if len(cols) >= 5 and cols[4] != "0" * 32:
                found.add(ipaddress.IPv6Address(bytes.fromhex(cols[4])))
    except (OSError, ValueError):
        pass
    try:
        for line in (proc / "if_inet6").read_text().splitlines():
            found.add(ipaddress.IPv6Address(bytes.fromhex(line.split()[0])))
    except (OSError, ValueError):
        pass
    return frozenset(found)
