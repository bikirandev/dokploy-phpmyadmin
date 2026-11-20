#!/bin/sh
# Replaces pgAdmin's entrypoint. The filesystem is read-only, configuration is baked into the
# image, and secrets come from the portal per request.
set -eu
umask 077

PY=/venv/bin/python3
mkdir -p /run/pgadmin/sessions /run/dbportal/tunnels /run/dbportal/ca /var/lib/pgadmin/storage

# First start: create pgAdmin's configuration database. pgAdmin's setup insists on an initial
# internal account; it gets a random password nobody knows and can't sign in anyway
# (only the portal-backed "webserver" sign-in is enabled).
if [ ! -f /var/lib/pgadmin/pgadmin4.db ]; then
  PGADMIN_SETUP_EMAIL="setup@dbportal.invalid" \
  PGADMIN_SETUP_PASSWORD="$("$PY" -c 'import secrets; print(secrets.token_urlsafe(32))')" \
    "$PY" /pgadmin4/setup.py setup-db >/dev/null
fi

# SSH tunnel service and the portal's internal API (connection tests), restarted if they stop.
(
  while true; do
    "$PY" -m dbportal.tunneld || true
    sleep 1
  done
) &
(
  while true; do
    "$PY" -m dbportal.internal_api || true
    sleep 1
  done
) &

# Files people leave in pgAdmin's Storage Manager (backups, uploads) are deleted after a day.
(
  while true; do
    find /var/lib/pgadmin/storage -mindepth 2 -type f -mmin +1440 ! -path '*/.dbportal/*' -delete 2>/dev/null || true
    find /var/lib/pgadmin/storage -mindepth 2 -type d -empty ! -name .dbportal -delete 2>/dev/null || true
    sleep 900
  done
) &

cd /pgadmin4
exec "$PY" /venv/bin/gunicorn -c /pgadmin4/gunicorn_dbportal.py dbportal_wsgi:app
