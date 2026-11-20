# syntax=docker/dockerfile:1

# Dependencies (firebase/php-jwt), installed in a throwaway stage.
FROM composer:2 AS vendor
WORKDIR /app
COPY composer.json composer.lock ./
COPY src ./src
RUN composer install --no-dev --no-interaction --no-progress --prefer-dist --optimize-autoloader --classmap-authoritative

FROM php:8.3-apache

RUN set -eux; \
    docker-php-ext-enable opcache; \
    a2enmod headers remoteip >/dev/null; \
    rm -f /etc/apache2/sites-enabled/000-default.conf; \
    sed -ri 's/^Listen 80$/# Listen 80 (see portal.conf)/' /etc/apache2/ports.conf; \
    mkdir -p /data; \
    chown www-data:www-data /data

COPY docker/apache.conf /etc/apache2/sites-enabled/portal.conf
COPY docker/php.ini /usr/local/etc/php/conf.d/zz-portal.ini
COPY --from=vendor /app/vendor /app/vendor
COPY src /app/src
COPY templates /app/templates
COPY public /app/public
COPY bin /app/bin

# Run Apache as an unprivileged user on port 8080.
USER www-data
WORKDIR /app
EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/healthz >/dev/null || exit 1

CMD ["apache2-foreground"]
