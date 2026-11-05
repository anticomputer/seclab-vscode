# Pinned tools, verified before use (build/tools/tools.json; ./seclab tool NAME). One target per
# tool. Release artifacts are downloaded and verified by build/tools/tool.sh (sha256 pin plus the
# publisher's signature or attestation) and passed in as the build context; the sha256 is checked
# again here. Source tools are built here from a pinned commit in pinned toolchain images.
# apt: Debian's signed archive without version pins (recorded exception, EDR
# 20261105-supply-chain-exceptions).

FROM debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4 AS base
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

# ---- cosign (release binary; sigstore bundle verified by tool.sh with sigstore-python) ----------
FROM base AS cosign
ARG SHA256
COPY artifact /usr/local/bin/cosign
RUN echo "$SHA256  /usr/local/bin/cosign" | sha256sum -c - && chmod 0755 /usr/local/bin/cosign
ENTRYPOINT ["cosign"]

# ---- actionlint (release archive; GitHub attestation verified by tool.sh) -------------------------
FROM base AS actionlint
ARG SHA256
RUN apt-get update && apt-get install -y --no-install-recommends shellcheck && rm -rf /var/lib/apt/lists/*
COPY artifact /tmp/actionlint.tar.gz
RUN echo "$SHA256  /tmp/actionlint.tar.gz" | sha256sum -c - && tar -xzf /tmp/actionlint.tar.gz -C /usr/local/bin actionlint && rm /tmp/actionlint.tar.gz
ENTRYPOINT ["actionlint"]

# ---- gitleaks (built from source; reproducible, binary sha256 pinned and attested in CI) -----------
FROM golang:1.27.3-trixie@sha256:2336eda24930976591abea806d9b7d99eeae38238f19755c5deec02facdc1594 AS gitleaks-build
ARG GIT
ARG TAG
ARG COMMIT
ENV CGO_ENABLED=0 GOFLAGS=-mod=readonly GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
RUN git clone -q --depth 1 --branch "$TAG" "$GIT" /src && test "$(git -C /src rev-parse HEAD)" = "$COMMIT"
WORKDIR /src
# Both arches from one build (Go cross-compiles reproducibly), so either host can check both pins.
RUN for a in arm64 amd64; do GOARCH=$a go build -trimpath -buildvcs=false \
      -ldflags "-s -w -buildid= -X=github.com/zricethezav/gitleaks/v8/version.Version=$TAG" -o /out/gitleaks-linux-$a . ; done \
    && cd /out && sha256sum gitleaks-linux-* > SHA256SUMS

FROM scratch AS gitleaks-bins
COPY --from=gitleaks-build /out/ /

FROM base AS gitleaks
ARG TARGETARCH
ARG BIN_SHA256
# The pre-mount scan script (tabd/src/scan.ts) needs bash, git, and tar with bzip2/xz.
RUN apt-get update && apt-get install -y --no-install-recommends git bzip2 xz-utils && rm -rf /var/lib/apt/lists/*
COPY --from=gitleaks-build /out/gitleaks-linux-${TARGETARCH} /usr/bin/gitleaks
# The binary shipped is the pinned one (TT-2), whatever the build cache held.
RUN echo "$BIN_SHA256  /usr/bin/gitleaks" | sha256sum -c -
ENTRYPOINT ["gitleaks"]

# ---- lychee (built from source; Cargo.lock --locked, crates checksum-verified) ---------------------
FROM rust:1.99.1-slim-trixie@sha256:7eab7ce19273ce785e0ca7578bdf7bc1fcbae621775a8197379a04c9f6e03cd5 AS lychee-build
ARG GIT
ARG TAG
ARG COMMIT
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates cmake && rm -rf /var/lib/apt/lists/*
RUN git clone -q --depth 1 --branch "$TAG" "$GIT" /src && test "$(git -C /src rev-parse HEAD)" = "$COMMIT"
WORKDIR /src
RUN cargo build -q --locked --release -p lychee && cp target/release/lychee /lychee

FROM base AS lychee
COPY --from=lychee-build /lychee /usr/local/bin/lychee
ENTRYPOINT ["lychee"]
