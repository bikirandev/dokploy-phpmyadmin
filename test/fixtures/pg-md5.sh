#!/bin/sh
# Test only (docker-entrypoint-initdb.d): a role whose login asks for an MD5 password, which
# "Not encrypted" connections must refuse (they accept only SCRAM-SHA-256).
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -c "SET password_encryption = 'md5'" -c "CREATE ROLE md5_user LOGIN PASSWORD 'Md5Pg-2026!'"
# pg_hba.conf takes the first matching line: put this one before the image's own.
{ echo 'host all md5_user all md5'; cat "$PGDATA/pg_hba.conf"; } > /tmp/pg_hba.conf
cat /tmp/pg_hba.conf > "$PGDATA/pg_hba.conf"
