#!/bin/sh
# Test only (docker-entrypoint-initdb.d): a limited role that owns the database named in APP_DB.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres -c "CREATE ROLE app_user LOGIN PASSWORD 'AppPg-2026!'"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres -c "CREATE DATABASE $APP_DB OWNER app_user"
