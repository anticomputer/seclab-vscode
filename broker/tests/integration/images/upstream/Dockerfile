# Fake "internet" for the broker integration tests: one HTTPS server (HTTP/1.1,
# HTTP/2, WebSocket) answering for several test hostnames, a git smart-HTTP
# backend, and a logging DNS server used by the DNS-exfiltration test.
# Build context: broker/ (wheels are fetched as in broker/Dockerfile).
FROM python:3.13-slim-trixie@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1 AS wheels
ARG PIP_SOURCE
COPY tools/pip-fetch.py /opt/pipfetch/pip-fetch.py
COPY tests/integration/images/upstream/requirements.txt /opt/pipfetch/requirements.txt
RUN --mount=type=secret,id=cfs_feed_token,required=false --mount=type=tmpfs,target=/run/cfs-auth python3 -I /opt/pipfetch/pip-fetch.py /opt/pipfetch/requirements.txt

FROM python:3.13-slim-trixie@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1
RUN apt-get update \
 && apt-get install -y --no-install-recommends git openssl \
 && rm -rf /var/lib/apt/lists/*
COPY tests/integration/images/upstream/requirements.txt /opt/upstream/requirements.txt
RUN --mount=type=bind,from=wheels,source=/wheels,target=/opt/wheels pip install --no-cache-dir --no-deps --require-hashes --only-binary=:all: --no-index --find-links /opt/wheels -r /opt/upstream/requirements.txt
COPY tests/integration/images/upstream/server.py tests/integration/images/upstream/dns.py tests/integration/images/upstream/entrypoint.sh /opt/upstream/
RUN chmod 0755 /opt/upstream/entrypoint.sh
ENTRYPOINT ["/opt/upstream/entrypoint.sh"]
