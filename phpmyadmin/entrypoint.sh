#!/bin/sh
# Replaces the image's entrypoint: nothing it does is needed here (configuration is baked into
# the image, the filesystem is read-only, and secrets come from the portal per request).
set -eu

mkdir -p /run/dbportal/tunnels /run/dbportal/ca /run/dbportal/probe 2>/dev/null || true
chmod 0700 /run/dbportal /run/dbportal/tunnels /run/dbportal/ca /run/dbportal/probe 2>/dev/null || true

# SSH tunnel service: the only process allowed to start programs (restarted if it stops).
(
  while true; do
    php -d disable_functions= -d memory_limit=64M /opt/dbportal/bin/tunneld.php || true
    sleep 1
  done
) &

exec "$@"
