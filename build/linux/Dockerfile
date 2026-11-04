# Builder image for the Linux editor + REH. Node version tracks upstream .nvmrc
# (checked by build/linux/build.sh); bump together with upstream.lock.
# trixie: Electron 43 headers need gcc >= 13 (bookworm's gcc 12 fails on native-keymap),
# and its glibc 2.41 matches the sbx shell kit (DHI Debian 13), so REH native modules load there.
FROM node:24.22.1-trixie

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential pkg-config python3 git jq ca-certificates \
      libx11-dev libxkbfile-dev libsecret-1-dev libkrb5-dev \
 && rm -rf /var/lib/apt/lists/*

# Non-root build user; the source/caches live in named volumes owned by it.
RUN useradd -m -u 1001 builder && mkdir -p /work /out && chown builder:builder /work /out
USER builder
WORKDIR /work
