#!/usr/bin/env bash
# Runs the whole stack locally (imitating a Dokploy server) and tests it end to end.
#   test/run-e2e.sh          run, then remove everything
#   KEEP=1 test/run-e2e.sh   keep the stack running afterwards (https://db.localhost:8443)
set -euo pipefail
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1

PROJECT=dbportal-test
COMPOSE=(docker compose -p "$PROJECT" --env-file test/.env.test -f docker-compose.yml -f test/docker-compose.test.yml)
FAILED=0
CREATED_DOKPLOY_NETWORK=0

cleanup() {
  if [ "${KEEP:-0}" != "1" ]; then
    "${COMPOSE[@]}" --profile test down -v --remove-orphans >/dev/null 2>&1 || true
    docker network rm pma-databases-test >/dev/null 2>&1 || true
    # Only remove dokploy-network if this script created it (never a real Dokploy's).
    if [ "$CREATED_DOKPLOY_NETWORK" = "1" ]; then docker network rm dokploy-network >/dev/null 2>&1 || true; fi
  fi
}
trap cleanup EXIT

echo "== Test certificates and keys"
mkdir -p test/.fixtures
if [ ! -f test/.fixtures/ca.pem ]; then
  docker run --rm -v "$PWD/test/.fixtures:/out" -v "$PWD/test/fixtures/gen.sh:/gen.sh:ro" alpine:3.22 sh /gen.sh
fi

echo "== Networks Dokploy would provide"
if ! docker network inspect dokploy-network >/dev/null 2>&1; then
  docker network create --attachable dokploy-network >/dev/null
  CREATED_DOKPLOY_NETWORK=1
fi
docker network inspect pma-databases-test >/dev/null 2>&1 || docker network create --internal --attachable pma-databases-test >/dev/null

echo "== Starting the stack"
"${COMPOSE[@]}" up -d --build --wait --wait-timeout 300

echo "== End-to-end tests (browser-like, through Traefik)"
"${COMPOSE[@]}" --profile test run --rm tester || FAILED=1

pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1  --  $2"; FAILED=1; }

echo
echo "== Network guard (from inside phpMyAdmin's container)"
probe() { "${COMPOSE[@]}" exec -T pma php -r "\$f=@fsockopen('$1', $2, \$e, \$s, 4); echo \$f ? 'OPEN' : 'BLOCKED';"; }
GATEWAY_IP=$(docker network inspect "${PROJECT}_pma-egress" --format '{{(index .IPAM.Config 0).Gateway}}')
[ "$(probe portal 8080)" = "OPEN" ] && pass "portal internal API reachable" || fail "portal internal API reachable" "blocked"
[ "$(probe gateway 8080)" = "BLOCKED" ] && pass "gateway not reachable from phpMyAdmin" || fail "gateway not reachable" "open"
[ "$(probe "$GATEWAY_IP" 8443)" = "BLOCKED" ] && pass "Docker host ($GATEWAY_IP) not reachable" || fail "Docker host not reachable" "open"
[ "$(probe 169.254.169.254 80)" = "BLOCKED" ] && pass "cloud metadata address blocked" || fail "cloud metadata blocked" "open"
[ "$(probe 192.168.1.1 80)" = "BLOCKED" ] && pass "private LAN addresses blocked" || fail "private LAN blocked" "open"
[ "$(probe local-db 3306)" = "OPEN" ] && pass "databases on pma-databases reachable" || fail "pma-databases reachable" "blocked"
if [ "$(probe 1.1.1.1 443)" = "OPEN" ]; then pass "public internet reachable (for remote databases)"; else echo "SKIP  public internet (no internet access here?)"; fi
DISABLED=$("${COMPOSE[@]}" exec -T pma sh -c "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/ && php -r 'echo function_exists(\"proc_open\") ? \" proc_open-available\" : \" proc_open-disabled\";'")
case "$DISABLED" in *proc_open-disabled*) pass "program execution disabled for PHP in phpMyAdmin" ;; *) fail "program execution disabled" "$DISABLED" ;; esac
LOCAL_INFILE=$("${COMPOSE[@]}" exec -T pma php -r 'echo ini_get("mysqli.allow_local_infile") ? "on" : "off";')
[ "$LOCAL_INFILE" = "off" ] && pass "LOAD DATA LOCAL INFILE disabled" || fail "LOCAL INFILE disabled" "$LOCAL_INFILE"
USER_PMA=$("${COMPOSE[@]}" exec -T pma id -u)
[ "$USER_PMA" != "0" ] && pass "phpMyAdmin runs as a non-root user (uid $USER_PMA)" || fail "non-root phpMyAdmin" "root"
USER_PORTAL=$("${COMPOSE[@]}" exec -T portal id -u)
[ "$USER_PORTAL" != "0" ] && pass "portal runs as a non-root user (uid $USER_PORTAL)" || fail "non-root portal" "root"
if "${COMPOSE[@]}" exec -T pma sh -c 'touch /var/www/html/x 2>/dev/null'; then fail "read-only phpMyAdmin filesystem" "writable"; else pass "phpMyAdmin filesystem is read-only"; fi

echo
echo "== Emergency sign-in link (created on the server)"
# curl with normal path handling (Git Bash on Windows maps /dev/null only when conversion is on)
http() { env -u MSYS_NO_PATHCONV curl -sk "$@" || true; }
LINK=$("${COMPOSE[@]}" exec -T portal php /app/bin/emergency-link.php --subject alice | sed -n 1p)
TOKEN_PATH="${LINK#https://db.localhost:8443}"
CODE=$(http -o /dev/null -w '%{http_code}' "https://db.localhost:8443$TOKEN_PATH")
[ "$CODE" = "200" ] && pass "emergency link shows a confirm page" || fail "emergency link page" "$CODE"
RESP=$(http -o /dev/null -D - -X POST "https://db.localhost:8443$TOKEN_PATH")
echo "$RESP" | grep -qi '^location: /servers' && echo "$RESP" | grep -qi '__Host-dbp_session' \
  && pass "emergency link signs the admin in" || fail "emergency sign-in" "$(echo "$RESP" | head -3)"
CODE=$(http -o /dev/null -w '%{http_code}' -X POST "https://db.localhost:8443$TOKEN_PATH")
[ "$CODE" = "404" ] && pass "emergency link works only once" || fail "emergency link one-time" "$CODE"
if "${COMPOSE[@]}" exec -T portal php /app/bin/emergency-link.php --subject bob >/dev/null 2>&1; then
  fail "emergency links only for admins" "created for bob"
else
  pass "emergency links only for admins"
fi

echo
if [ "$FAILED" = "0" ]; then echo "ALL CHECKS PASSED"; else echo "SOME CHECKS FAILED"; fi
[ "${KEEP:-0}" = "1" ] && echo "Stack kept running: https://db.localhost:8443 (stop with: KEEP=0 and docker compose -p $PROJECT down -v)"
exit "$FAILED"
