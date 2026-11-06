#!/bin/sh
# Generates a throwaway CA and a server certificate at start (never stored in
# the repo), seeds a git repository, then serves.
set -eu
mode="${1:-https}"
if [ "$mode" = "dns" ]; then
  exec python /opt/upstream/dns.py
fi
mkdir -p /srv/tls /srv/git
cd /srv/tls
if [ ! -f ca.pem ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=seclab test upstream CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout ca.key -out ca.pem 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -subj "/CN=example.test" -keyout server.key -out server.csr 2>/dev/null
  printf 'subjectAltName=DNS:*.example.test,DNS:example.test,DNS:*.blob.core.windows.net\nextendedKeyUsage=serverAuth\n' > ext.cnf
  openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 \
    -extfile ext.cnf -out server.pem 2>/dev/null
fi
if [ ! -d /srv/git/demo.git ]; then
  git init -q --bare -b main /srv/git/demo.git
  git -C /srv/git/demo.git config http.receivepack true
  tmp=$(mktemp -d)
  git -C "$tmp" init -q -b main
  echo "hello from the test upstream" > "$tmp/README"
  git -C "$tmp" add README
  git -C "$tmp" -c user.name=t -c user.email=t@example.test commit -q -m init
  git -C "$tmp" push -q /srv/git/demo.git main
  rm -rf "$tmp"
fi
exec python -m hypercorn --bind 0.0.0.0:443 --certfile /srv/tls/server.pem --keyfile /srv/tls/server.key \
  --log-level warning /opt/upstream/server:app
