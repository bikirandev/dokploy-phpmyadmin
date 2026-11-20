#!/bin/sh
# Network guard for phpMyAdmin. phpMyAdmin joins this container's network namespace, so these
# rules decide what phpMyAdmin can reach:
#   in:  only the gateway and portal, on ports 8080 (phpMyAdmin) and 8081 (internal API)
#   out: the portal's internal API, databases on the pma-databases network, and the public internet.
#        Everything private (Dokploy, other apps, cloud metadata, your LAN) is blocked.
set -eu

log() { echo "[egress-guard] $*"; }

PORTAL_HOST="${PORTAL_HOST:-portal}"
PORTAL_PORT="${PORTAL_PORT:-8080}"
ALLOW="$(echo "${EGRESS_ALLOW_CIDRS:-}" | tr ',' ' ')"
BLOCK="$(echo "${EGRESS_BLOCK_CIDRS:-}" | tr ',' ' ')"
rm -f /run/guard-ready

# Find the portal (it lives only on the internal network) to identify that network.
PORTAL_IP=""
i=0
while [ "$i" -lt 90 ]; do
  PORTAL_IP="$(getent hosts "$PORTAL_HOST" | awk '{print $1; exit}')" || true
  [ -n "$PORTAL_IP" ] && break
  i=$((i + 1))
  sleep 1
done
[ -n "$PORTAL_IP" ] || { log "cannot resolve $PORTAL_HOST"; exit 1; }

BACKEND_IF="$(ip -4 route get "$PORTAL_IP" | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i + 1); exit}}')"
EGRESS_IF="$(ip -4 route show default | awk '{print $5; exit}')"
[ -n "$BACKEND_IF" ] || { log "cannot find the internal network interface"; exit 1; }
[ -n "$EGRESS_IF" ] || { log "no default route (is the pma-egress network attached?)"; exit 1; }
[ "$BACKEND_IF" != "$EGRESS_IF" ] || { log "internal and egress networks share an interface"; exit 1; }
DB_NETS="$(ip -4 -o addr show | awk -v b="$BACKEND_IF" -v e="$EGRESS_IF" '$2 != "lo" && $2 != b && $2 != e {print $4}')"

log "internal: $BACKEND_IF ($PORTAL_IP), egress: $EGRESS_IF, database networks: ${DB_NETS:-none}"

apply_v4() {
  iptables -P INPUT ACCEPT
  iptables -P OUTPUT ACCEPT
  iptables -F INPUT
  iptables -F OUTPUT

  # Inbound: replies, loopback, and the gateway/portal on the internal network only.
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -A INPUT -i "$BACKEND_IF" -p tcp -m multiport --dports 8080,8081 -j ACCEPT
  iptables -A INPUT -j DROP

  # Outbound
  iptables -A OUTPUT -o lo -j ACCEPT
  iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -A OUTPUT -o "$BACKEND_IF" -d "$PORTAL_IP" -p tcp --dport "$PORTAL_PORT" -j ACCEPT
  iptables -A OUTPUT -o "$BACKEND_IF" -j REJECT
  for net in $DB_NETS; do
    iptables -A OUTPUT -d "$net" -p tcp -j ACCEPT
  done
  for cidr in $BLOCK; do
    iptables -A OUTPUT -d "$cidr" -j REJECT
  done
  for cidr in $ALLOW; do
    iptables -A OUTPUT -d "$cidr" -j ACCEPT
  done
  for cidr in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 \
              192.0.0.0/24 192.0.2.0/24 192.88.99.0/24 192.168.0.0/16 198.18.0.0/15 \
              198.51.100.0/24 203.0.113.0/24 224.0.0.0/3; do
    iptables -A OUTPUT -d "$cidr" -j REJECT
  done
}

apply_v6() {
  ip6tables -P INPUT ACCEPT
  ip6tables -P OUTPUT ACCEPT
  ip6tables -F INPUT
  ip6tables -F OUTPUT
  ip6tables -A INPUT -i lo -j ACCEPT
  ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ip6tables -A INPUT -j DROP
  ip6tables -A OUTPUT -o lo -j ACCEPT
  ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  for cidr in ::/128 ::1/128 ::ffff:0:0/96 64:ff9b::/96 100::/64 2001:db8::/32 fc00::/7 fe80::/10 ff00::/8; do
    ip6tables -A OUTPUT -d "$cidr" -j REJECT
  done
}

apply_v4
if ip6tables -L >/dev/null 2>&1; then
  apply_v6
else
  log "IPv6 filtering unavailable (no IPv6 in this network namespace)"
fi

touch /run/guard-ready
log "rules applied"

trap 'exit 0' TERM INT
while :; do
  sleep 3600 &
  wait $!
done
