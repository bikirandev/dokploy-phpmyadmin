# syntax=docker/dockerfile:1
# phpMyAdmin, hardened for DB Portal. Pinned to the latest stable release.
FROM phpmyadmin:5.2.3-apache

USER root
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends openssh-client sshpass; \
    rm -rf /var/lib/apt/lists/*; \
    # phpMyAdmin on 8080 and the portal's internal API on 8081, both as an unprivileged user
    sed -ri 's/^Listen 80$/Listen 8080\nListen 8081/' /etc/apache2/ports.conf; \
    sed -ri 's/<VirtualHost \*:80>/<VirtualHost *:8080>/' /etc/apache2/sites-enabled/000-default.conf; \
    # The real blowfish secret is set in config.user.inc.php; this stops the entrypoint writing one.
    echo '<?php // blowfish_secret is set in config.user.inc.php' > /etc/phpmyadmin/config.secret.inc.php; \
    mkdir -p /run/dbportal; \
    chown www-data:www-data /run/dbportal

COPY apache/security.conf /etc/apache2/conf-enabled/zz-dbportal-security.conf
COPY apache/internal.conf /etc/apache2/sites-enabled/010-dbportal-internal.conf
COPY php/dbportal.ini /usr/local/etc/php/conf.d/zz-dbportal.ini
COPY config.user.inc.php /etc/phpmyadmin/config.user.inc.php
COPY dbportal /opt/dbportal
COPY entrypoint.sh /usr/local/bin/dbportal-entrypoint
RUN chmod 0755 /usr/local/bin/dbportal-entrypoint && chmod -R a+rX,go-w /opt/dbportal /etc/phpmyadmin/config.user.inc.php

USER www-data
EXPOSE 8080 8081
ENTRYPOINT ["/usr/local/bin/dbportal-entrypoint"]
CMD ["apache2-foreground"]
