#!/bin/sh
# Test only: starts PostgreSQL with TLS, using the certificate named in PG_CERT (from the fixtures).
# PostgreSQL refuses a key file others can read, so it is copied with the right owner and mode.
set -eu
install -o postgres -g postgres -m 0600 "/certs/$PG_CERT.key" /var/lib/postgresql/server.key
install -o postgres -g postgres -m 0644 "/certs/$PG_CERT.pem" /var/lib/postgresql/server.crt
cp /fixtures/pg-app.sh /docker-entrypoint-initdb.d/app.sh
exec docker-entrypoint.sh postgres -c ssl=on \
  -c ssl_cert_file=/var/lib/postgresql/server.crt -c ssl_key_file=/var/lib/postgresql/server.key
