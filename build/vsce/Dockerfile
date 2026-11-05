# syntax=docker/dockerfile:1
# vsce for packaging the containment fixtures (EDR cfs-local-builds). Local only, built with
#   gh cfs -- docker build -t seclab-vsce:3.9.2 build/vsce
# The CFS token is a BuildKit secret and a tmpfs npmrc for one RUN that installs vsce with no
# install scripts; the RUN fails if the token appears in what it keeps. vsce then runs from the
# final image with no token and no network.
FROM node:24.22.1-trixie@sha256:f1e034976f948cf212ef1f659c12e5dd58ac7eab947831813e81a62401ca38be AS fetch
RUN --mount=type=secret,id=cfs_feed_token,required=true \
    --mount=type=tmpfs,target=/run/cfs-auth \
    set +x; set -eu; umask 077; \
    token="$(cat /run/secrets/cfs_feed_token)"; test -n "$token"; \
    registry=https://pkgs.dev.azure.com/github-cfs/GitHubCFS/_packaging/github-cfs-oss/npm/registry/; \
    auth_path=//pkgs.dev.azure.com/github-cfs/GitHubCFS/_packaging/github-cfs-oss/npm; \
    printf 'registry=%s\nreplace-registry-host=npmjs\n%s/registry/:_authToken=%s\n%s/:_authToken=%s\n' "$registry" "$auth_path" "$token" "$auth_path" "$token" > /run/cfs-auth/npmrc; \
    : > /run/cfs-auth/global-npmrc; \
    export NPM_CONFIG_USERCONFIG=/run/cfs-auth/npmrc NPM_CONFIG_GLOBALCONFIG=/run/cfs-auth/global-npmrc \
      NPM_CONFIG_CACHE=/run/cfs-auth/cache NPM_CONFIG_LOGS_DIR=/run/cfs-auth/logs NPM_CONFIG_REGISTRY="$registry" \
      NPM_CONFIG_REPLACE_REGISTRY_HOST=npmjs NPM_CONFIG_UPDATE_NOTIFIER=false NPM_CONFIG_IGNORE_SCRIPTS=true; \
    npm install --global --prefix /opt/vsce --ignore-scripts --no-audit --no-fund --loglevel=error @vscode/vsce@3.9.2 >/dev/null; \
    if grep -rqF -- "$token" /opt/vsce; then echo "CFS token found in the vsce install; refusing" >&2; exit 1; fi; \
    unset token; chmod -R a+rX /opt/vsce; /opt/vsce/bin/vsce --version

FROM node:24.22.1-trixie@sha256:f1e034976f948cf212ef1f659c12e5dd58ac7eab947831813e81a62401ca38be
COPY --from=fetch /opt/vsce /opt/vsce
ENV PATH=/opt/vsce/bin:$PATH
USER node
