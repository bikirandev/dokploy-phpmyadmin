#!/bin/sh
# Writes the client-address and Cloudflare allow-list includes before nginx starts.
set -eu

OUT=/etc/nginx/conf.d
CF_ONLY="$(echo "${CLOUDFLARE_ONLY:-false}" | tr '[:upper:]' '[:lower:]')"

case "$CF_ONLY" in
  true|1|yes)
    # Only Cloudflare may connect; the visitor's address comes from CF-Connecting-IP.
    echo 'map $http_cf_connecting_ip $client_ip { "" $remote_addr; default $http_cf_connecting_ip; }' > "$OUT/client-ip.inc"
    {
      grep -E '^[0-9a-fA-F:.]+/[0-9]+$' /etc/nginx/cloudflare-ips.txt | while read -r cidr; do
        echo "allow $cidr;"
      done
      echo "deny all;"
    } > "$OUT/cloudflare-allow.inc"
    echo "[dbportal] Cloudflare-only mode: direct connections are refused"
    ;;
  *)
    echo 'map $remote_addr $client_ip { default $remote_addr; }' > "$OUT/client-ip.inc"
    : > "$OUT/cloudflare-allow.inc"
    ;;
esac
