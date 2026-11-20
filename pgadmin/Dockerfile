# syntax=docker/dockerfile:1
# pgAdmin, hardened for DB Portal. Pinned to the latest stable release.
FROM dpage/pgadmin4:9.19

USER root
RUN set -eux; \
    # SSH tunnels (OpenSSH with a pinned host key; sshpass for password logins)
    apk add --no-cache openssh-client-default openssh-keygen sshpass; \
    # The official entrypoint writes config files and starts a mail server: neither is used here.
    rm -f /entrypoint.sh

COPY config_local.py /pgadmin4/config_local.py
COPY gunicorn_dbportal.py /pgadmin4/gunicorn_dbportal.py
COPY dbportal /opt/dbportal/dbportal
COPY dbportal_wsgi.py /opt/dbportal/dbportal_wsgi.py
COPY entrypoint.sh /usr/local/bin/dbportal-entrypoint
RUN set -eux; \
    chmod 0755 /usr/local/bin/dbportal-entrypoint; \
    chmod -R a+rX,go-w /opt/dbportal /pgadmin4/config_local.py /pgadmin4/gunicorn_dbportal.py; \
    # Compiled once here: the container's filesystem is read-only.
    /venv/bin/python3 -m compileall -q /pgadmin4 /opt/dbportal >/dev/null

ENV PYTHONPATH=/pgadmin4:/opt/dbportal \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/run/pgadmin

USER 5050
EXPOSE 8080 8081
ENTRYPOINT ["/usr/local/bin/dbportal-entrypoint"]
