# syntax=docker/dockerfile:1
# Firewall for the network namespace phpMyAdmin shares (network_mode: service:egress-guard).
FROM alpine:3.22
RUN apk add --no-cache iptables ip6tables iproute2 musl-utils
COPY guard.sh /usr/local/bin/guard.sh
RUN chmod 0755 /usr/local/bin/guard.sh
HEALTHCHECK --interval=10s --timeout=3s --start-period=60s --retries=3 CMD test -f /run/guard-ready
ENTRYPOINT ["/usr/local/bin/guard.sh"]
