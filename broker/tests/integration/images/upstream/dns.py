"""Logging DNS responder for the DNS exfiltration test. Answers NXDOMAIN and
appends every query name to /srv/dns.log."""

import socket
import sys


def qname(packet: bytes) -> str:
    labels, i = [], 12
    while i < len(packet) and packet[i]:
        n = packet[i]
        labels.append(packet[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += 1 + n
    return ".".join(labels)


def main() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 53))
    t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    t.bind(("0.0.0.0", 53))
    t.listen()
    t.setblocking(False)
    print("dns ready", flush=True)
    while True:
        try:
            conn, _ = t.accept()
            conn.settimeout(2)
            data = conn.recv(4096)
            with open("/srv/dns.log", "a") as f:
                f.write("tcp " + qname(data[2:]) + "\n")
            conn.close()
        except BlockingIOError:
            pass
        s.settimeout(0.2)
        try:
            data, addr = s.recvfrom(4096)
        except socket.timeout:
            continue
        with open("/srv/dns.log", "a") as f:
            f.write("udp " + qname(data) + "\n")
        # NXDOMAIN reply with the question echoed.
        reply = data[:2] + b"\x81\x83" + data[4:6] + b"\x00\x00\x00\x00\x00\x00" + data[12:]
        s.sendto(reply, addr)


if __name__ == "__main__":
    sys.exit(main())
