"""Stub of a CFS PyPI feed for the local-build path test (tests/cfs-path/run.sh). Serves one
hash-pinned wheel under the example feed paths (tools/cfs-config.vectors.json), over TLS as the
feed host, and only to Basic auth cfs:<the stub token>. Records each request (path, whether the
auth matched) to /srv/requests.log. Example values only; it runs on an --internal network.

    python3 stub_index.py INDEX_PATH DOWNLOAD_PATH TOKEN
    python3 stub_index.py --hash        the wheel's sha256
"""

import base64
import hashlib
import http.server
import io
import ssl
import sys
import zipfile

NAME, VERSION = "seclab_cfs_probe", "1.0"
WHEEL = f"{NAME}-{VERSION}-py3-none-any.whl"


def wheel() -> bytes:
    """A minimal, byte-stable wheel (fixed timestamps), so its hash is reproducible."""
    files = {
        f"{NAME}/__init__.py": b"",
        f"{NAME}-{VERSION}.dist-info/METADATA": f"Metadata-Version: 2.1\nName: {NAME}\nVersion: {VERSION}\n".encode(),
        f"{NAME}-{VERSION}.dist-info/WHEEL": b"Wheel-Version: 1.0\nGenerator: seclab-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    record = "".join(f"{p},sha256={base64.urlsafe_b64encode(hashlib.sha256(b).digest()).rstrip(b'=').decode()},{len(b)}\n"
                     for p, b in files.items()) + f"{NAME}-{VERSION}.dist-info/RECORD,,\n"
    files[f"{NAME}-{VERSION}.dist-info/RECORD"] = record.encode()
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for p, b in files.items():
            z.writestr(zipfile.ZipInfo(p, date_time=(2020, 1, 1, 0, 0, 0)), b)
    return out.getvalue()


def main() -> None:
    if sys.argv[1:2] == ["--hash"]:
        print(hashlib.sha256(wheel()).hexdigest())
        return
    index_path, download_path, token = sys.argv[1:4]
    data = wheel()
    digest = hashlib.sha256(data).hexdigest()
    want = "Basic " + base64.b64encode(f"cfs:{token}".encode()).decode()
    project = index_path + "seclab-cfs-probe/"
    file_path = f"{download_path}seclab-cfs-probe/{VERSION}/{WHEEL}"

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            auth = self.headers.get("Authorization")
            ok = auth == want
            with open("/srv/requests.log", "a") as f:
                f.write(f"{self.path} auth={'ok' if ok else 'none' if not auth else 'bad'}\n")
            if not ok:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="stub"')
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if self.path in (project, project.rstrip("/")):
                # Absolute file URL on the feed's GUID path, as the real index links files.
                link = "https://" + self.headers.get("Host", "") + file_path
                body = f'<html><body><a href="{link}#sha256={digest}">{WHEEL}</a></body></html>'.encode()
                ctype = "text/html"
            elif self.path == file_path:
                body, ctype = data, "application/octet-stream"
            else:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a) -> None:
            pass

    srv = http.server.ThreadingHTTPServer(("0.0.0.0", 443), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/srv/tls/server.pem", "/srv/tls/server.key")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print("stub index ready", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
