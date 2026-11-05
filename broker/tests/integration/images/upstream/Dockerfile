# Fake "internet" for the broker integration tests: one HTTPS server (HTTP/1.1,
# HTTP/2, WebSocket) answering for several test hostnames, a git smart-HTTP
# backend, and a logging DNS server used by the DNS-exfiltration test.
FROM python:3.13-slim-trixie@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1
RUN apt-get update \
 && apt-get install -y --no-install-recommends git openssl \
 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /opt/upstream/requirements.txt
RUN pip install --no-cache-dir --no-deps --require-hashes --only-binary=:all: -r /opt/upstream/requirements.txt
COPY server.py dns.py entrypoint.sh /opt/upstream/
RUN chmod 0755 /opt/upstream/entrypoint.sh
ENTRYPOINT ["/opt/upstream/entrypoint.sh"]
