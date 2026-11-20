# syntax=docker/dockerfile:1
# Gateway: the only container Traefik (Dokploy) talks to. Runs nginx as an unprivileged user.
FROM nginxinc/nginx-unprivileged:1.28-alpine

USER root
RUN rm -f /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/nginx.conf
COPY proxy-base.inc /etc/nginx/proxy-base.inc
COPY templates/ /etc/nginx/templates/
COPY cloudflare-ips.txt /etc/nginx/cloudflare-ips.txt
COPY 40-dbportal.sh /docker-entrypoint.d/40-dbportal.sh
RUN chmod 0755 /docker-entrypoint.d/40-dbportal.sh && chown -R nginx:nginx /etc/nginx/conf.d
USER nginx

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1
