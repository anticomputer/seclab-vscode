# Stand-in for the tab's workspace sandbox in the OCI pod. Proxy-aware clients
# (curl, git, python/aiohttp) plus a non-root user. It has no route out: it is
# attached only to the tab's --internal network, whose only peer is the broker.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git python3 python3-aiohttp dnsutils \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -u 1000 dev
COPY wsclient.py /usr/local/bin/wsclient.py
USER dev
WORKDIR /home/dev
CMD ["sleep", "infinity"]
