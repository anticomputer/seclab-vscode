# Stand-in for the tab's workspace sandbox in the OCI pod. Proxy-aware clients
# (curl, git, python/aiohttp) plus a non-root user. It has no route out: it is
# attached only to the tab's --internal network, whose only peer is the broker.
FROM debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git python3 python3-aiohttp dnsutils \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -u 1000 dev
COPY wsclient.py /usr/local/bin/wsclient.py
USER dev
WORKDIR /home/dev
CMD ["sleep", "infinity"]
