#!/usr/bin/env bash
# Pulls a certificate from CertStore and installs it if it changed.
# Run from cron/systemd timer on each server, e.g. every hour:
#   0 * * * * CERTSTORE_URL=https://certs.example.com CERTSTORE_KEY=cs_... DOMAIN=api.example.com \
#             DEST=/etc/ssl/api.example.com RELOAD_CMD="systemctl reload nginx" /usr/local/bin/certstore-sync.sh
#
# Requires: bash, curl, openssl. Writes $DEST/fullchain.pem, $DEST/privkey.pem, $DEST/cert.pem, $DEST/chain.pem
set -euo pipefail

: "${CERTSTORE_URL:?set CERTSTORE_URL}"
: "${CERTSTORE_KEY:?set CERTSTORE_KEY}"
: "${DOMAIN:?set DOMAIN}"
: "${DEST:?set DEST}"
RELOAD_CMD="${RELOAD_CMD:-}"

umask 077
mkdir -p "$DEST"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fetch() { # $1 = file name
  curl -fsS --retry 3 --max-time 30 \
    -H "Authorization: Bearer ${CERTSTORE_KEY}" \
    "${CERTSTORE_URL%/}/api/v1/certs/${DOMAIN}/$1" -o "$tmp/$1"
}

fetch fullchain.pem
if [[ -f "$DEST/fullchain.pem" ]] && cmp -s "$tmp/fullchain.pem" "$DEST/fullchain.pem"; then
  exit 0 # unchanged
fi

fetch privkey.pem
fetch cert.pem
fetch chain.pem

# Make sure the key matches the certificate (guards against a renewal between requests).
cert_pub="$(openssl x509 -in "$tmp/cert.pem" -noout -pubkey | openssl sha256)"
key_pub="$(openssl pkey -in "$tmp/privkey.pem" -pubout | openssl sha256)"
if [[ "$cert_pub" != "$key_pub" ]]; then
  echo "certstore-sync: key/cert mismatch for $DOMAIN, will retry next run" >&2
  exit 1
fi

for f in privkey.pem cert.pem chain.pem fullchain.pem; do
  mv -f "$tmp/$f" "$DEST/$f.new"
  mv -f "$DEST/$f.new" "$DEST/$f"
done
chmod 600 "$DEST/privkey.pem"
echo "certstore-sync: installed new certificate for $DOMAIN (expires $(openssl x509 -in "$DEST/cert.pem" -noout -enddate | cut -d= -f2))"

if [[ -n "$RELOAD_CMD" ]]; then
  eval "$RELOAD_CMD"
fi
