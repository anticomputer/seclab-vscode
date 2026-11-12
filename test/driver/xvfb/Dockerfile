# Headless editor runner (EDR headless-driver): the Linux editor under Xvfb, driven over its CDP
# pipe (test/driver/). No host display, no OS permissions. Same pinned base as the builder, so the
# editor's native modules (built against trixie's glibc) load.
FROM node:24.22.1-trixie@sha256:f1e034976f948cf212ef1f659c12e5dd58ac7eab947831813e81a62401ca38be

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      xvfb xauth fonts-dejavu-core \
      libnss3 libgtk-3-0t64 libasound2t64 libgbm1 libxss1 libxkbfile1 libsecret-1-0 \
      libxshmfence1 libdrm2 libxtst6 \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1001 runner
USER runner
WORKDIR /repo
