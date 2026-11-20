#!/usr/bin/env python3
"""End-to-end tests for DB Portal. Runs in the tester container (see test/run-e2e.sh).

Everything goes through Traefik and the gateway, exactly like a browser would.
"""
import html
import json
import os
import re
import sys

import requests
import urllib3

urllib3.disable_warnings()

PORTAL = os.environ.get("PORTAL", "https://db.localhost:8443")
PMA = os.environ.get("PMA", "https://pma.localhost:8443")
FIXTURES = "/fixtures"

LIMIT_DEFAULTS = {
    "servers_per_account": "25", "tests_per_minute": "10", "failures_before_lock": "5",
    "lock_minutes": "15", "sessions_per_account": "3", "import_mb": "64", "signins_per_ip_minute": "10",
}

results = []


def check(name, condition, detail=""):
    ok = bool(condition)
    results.append((name, ok))
    line = ("PASS  " if ok else "FAIL  ") + name
    if not ok:
        line += "  --  " + str(detail)[:400]
    print(line, flush=True)
    return ok


def server_data(**overrides):
    data = {
        "name": "Test server", "environment": "Development", "location": "remote", "method": "tls",
        "host": "", "port": "3306", "internal_host": "", "internal_port": "3306",
        "ssh_host": "", "ssh_port": "22", "ssh_user": "", "ssh_auth": "key", "ssh_key": "", "ssh_password": "",
        "ssh_db_host": "", "ssh_db_port": "3306", "db_user": "", "db_password": "", "cred_mode": "saved",
        "pin_token": "",
    }
    data.update(overrides)
    return data


class User:
    def __init__(self, name):
        self.name = name
        self.session = requests.Session()
        self.session.verify = False
        self.csrf = ""

    def get(self, url, **kw):
        kw.setdefault("allow_redirects", False)
        kw.setdefault("timeout", 60)
        return self.session.get(url, **kw)

    def post(self, url, **kw):
        kw.setdefault("allow_redirects", False)
        kw.setdefault("timeout", 120)
        return self.session.post(url, **kw)

    def login(self):
        """Signs in through the stand-in identity provider. Returns the callback response."""
        r = self.get(PORTAL + "/auth/login")
        if r.status_code != 302:
            return r
        authorize = r.headers["Location"]
        self.session.get(authorize, timeout=30)
        r = self.session.post(authorize, data={"username": self.name, "claims": ""}, allow_redirects=False, timeout=30)
        return self.get(r.headers.get("Location", PORTAL + "/signin"))

    def agree(self):
        r = self.get(PORTAL + "/welcome")
        m = re.search(r'name="_csrf" value="([^"]+)"', r.text)
        self.csrf = m.group(1) if m else ""
        return self.form("/welcome", {"agree": "1"})

    def refresh_csrf(self, page="/servers"):
        r = self.get(PORTAL + page)
        m = re.search(r'name="csrf-token" content="([^"]+)"', r.text)
        self.csrf = m.group(1) if m else ""
        return r

    def form(self, path, data, files=None):
        payload = dict(data)
        payload["_csrf"] = self.csrf
        return self.post(PORTAL + path, data=payload, files=files)

    def test_server(self, data, files=None):
        r = self.post(PORTAL + "/servers/test", data=data, files=files,
                      headers={"X-CSRF-Token": self.csrf, "Accept": "application/json"})
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, {"raw": r.text[:300]}

    def server_ids(self):
        r = self.get(PORTAL + "/servers")
        pairs = re.findall(r'href="/servers/(\d+)/edit" aria-label="Edit ([^"]+)"', r.text)
        return {html.unescape(name): int(sid) for sid, name in pairs}

    def open(self, server_id, extra=None):
        """Opens a server and follows the hand-over to phpMyAdmin. Returns (response, slot, cookie header)."""
        data = {"_csrf": self.csrf}
        data.update(extra or {})
        r = self.post(f"{PORTAL}/servers/{server_id}/open", data=data)
        if r.status_code != 303 or "/__dbportal/enter" not in r.headers.get("Location", ""):
            return r, None, ""
        enter = self.get(r.headers["Location"])
        location = enter.headers.get("Location", "")
        m = re.search(r"server=(\d+)", location)
        page = self.get(PMA + location if location.startswith("/") else location)
        return page, (int(m.group(1)) if m else None), enter.headers.get("Set-Cookie", "")


def main():
    anon = User("anonymous")

    print("\n== Edge and headers")
    r = anon.get(PORTAL + "/signin")
    check("sign-in page loads with only the Bikiran button", r.status_code == 200 and "Continue with Bikiran" in r.text
          and 'type="password"' not in r.text, r.status_code)
    h = r.headers
    check("HSTS header", "max-age=" in h.get("Strict-Transport-Security", ""), h)
    csp = h.get("Content-Security-Policy", "")
    check("strict CSP (no inline or eval)", "script-src 'self'" in csp and "unsafe" not in csp, csp)
    check("X-Frame-Options: DENY", h.get("X-Frame-Options") == "DENY")
    check("X-Content-Type-Options: nosniff", h.get("X-Content-Type-Options") == "nosniff")
    check("no software versions in Server header", not re.search(r"\d", h.get("Server", "")), h.get("Server"))
    check("no X-Powered-By header", "X-Powered-By" not in h)
    r = anon.get(PORTAL + "/", headers={"Host": "evil.localhost"})
    check("unknown host names get nothing", r.status_code == 404, r.status_code)

    print("\n== Nothing works without signing in")
    r = anon.get(PORTAL + "/servers")
    check("My servers needs sign-in", r.status_code == 303 and "/signin" in r.headers.get("Location", ""), r.status_code)
    for path in ["/", "/index.php", "/index.php?route=/server/databases", "/favicon.ico", "/js/dist/shared.js"]:
        r = anon.get(PMA + path)
        check(f"phpMyAdmin {path} needs a session", r.status_code == 302
              and r.headers.get("Location", "").startswith(PORTAL + "/servers"), f"{r.status_code} {r.headers.get('Location')}")
    r = anon.get(PORTAL + "/internal/pma-auth")
    check("internal auth endpoint hidden on the portal host", r.status_code == 404, r.status_code)
    r = anon.post(PORTAL + "/internal/descriptors", json={})
    check("internal descriptors endpoint hidden", r.status_code == 404, r.status_code)
    r = anon.get(PMA + "/_dbp_auth")
    check("gateway auth location hidden", r.status_code == 404, r.status_code)
    anon.session.cookies.set("__Host-dbp_s1", "A" * 43 + "." + "B" * 43, domain="pma.localhost", path="/")
    r = anon.get(PMA + "/index.php")
    check("a forged phpMyAdmin session cookie is refused", r.status_code == 302, r.status_code)

    print("\n== Sign-in (alice is a platform admin)")
    alice = User("alice")
    r = alice.login()
    check("first sign-in goes to the rules", r.status_code == 303 and r.headers.get("Location") == "/welcome",
          f"{r.status_code} {r.headers.get('Location')} {r.text[:200]}")
    cookie = r.headers.get("Set-Cookie", "").lower()
    check("session cookie is __Host-, Secure, HttpOnly, SameSite=Lax",
          "__host-dbp_session=" in cookie and "secure" in cookie and "httponly" in cookie and "samesite=lax" in cookie, cookie)
    r = alice.get(PORTAL + "/servers")
    check("rules must be accepted before anything else", r.status_code == 303 and r.headers.get("Location") == "/welcome")
    r = alice.get(PORTAL + "/welcome")
    m = re.search(r'name="_csrf" value="([^"]+)"', r.text)
    alice.csrf = m.group(1) if m else ""
    r = alice.form("/welcome", {})
    check("the rules need the checkbox", r.status_code == 422, r.status_code)
    r = alice.form("/welcome", {"agree": "1"})
    check("accepting the rules continues to My servers", r.status_code == 303 and r.headers.get("Location") == "/servers")
    r = alice.refresh_csrf()
    check("empty My servers page", r.status_code == 200 and "No servers yet" in r.text, r.status_code)
    r = alice.form("/admin/limits", dict(LIMIT_DEFAULTS, tests_per_minute="100", signins_per_ip_minute="100"))
    check("admin raises limits for the test run", r.status_code == 303, r.status_code)

    print("\n== Forms are protected")
    r = alice.post(PORTAL + "/servers", data={"name": "x"})
    check("POST without a CSRF token is refused", r.status_code == 403, r.status_code)
    r = alice.post(PORTAL + "/servers", data={"name": "x", "_csrf": alice.csrf}, headers={"Origin": "https://evil.example"})
    check("cross-site POST is refused", r.status_code == 403, r.status_code)

    print("\n== On this server (pma-databases network)")
    local = server_data(name="Shop – Production", environment="Production", location="local",
                        internal_host="local-db", db_user="shop_admin", db_password="ShopPass-2026!", cred_mode="saved")
    code, j = alice.test_server(local)
    check("test reaches the local database", code == 200 and j.get("ok"), j)
    check("test shows the version", any("MariaDB 11.4" in c for c in j.get("checks", [])), j.get("checks"))
    check("test shows limited privileges", any("ON `shop`.*" in g for g in j.get("grants", [])) and not j.get("superuser"), j)
    code, j = alice.test_server(dict(local, db_user="root", db_password="RootPass-2026!"))
    check("root is blocked", not j.get("ok") and "root" in json.dumps(j).lower(), j)
    code, j = alice.test_server(dict(local, db_user="super_admin", db_password="SuperPass-2026!"))
    check("an all-privileges user is flagged", j.get("ok") and j.get("superuser"), j)
    for host, port in [("internal-svc", "80"), ("portal", "8080"), ("gateway", "8080"), ("traefik", "80")]:
        code, j = alice.test_server(dict(local, internal_host=host, internal_port=port))
        check(f"can't use '{host}' as a database (Dokploy and portal internals)", not j.get("ok"), j)
    r = alice.form("/servers", local)
    check("local server saved", r.status_code == 303 and "notice=added" in r.headers.get("Location", ""), r.status_code)
    ids = alice.server_ids()
    shop = ids.get("Shop – Production")
    check("server appears in My servers", shop is not None, ids)

    print("\n== Open in phpMyAdmin (own host name)")
    page, slot, ticket_cookie = alice.open(shop)
    check("open hands over to phpMyAdmin's host", slot is not None, getattr(page, "status_code", page))
    tc = ticket_cookie.lower()
    check("phpMyAdmin session cookie is __Host-, Secure, HttpOnly", "__host-dbp_s" in tc and "secure" in tc and "httponly" in tc, tc)
    check("phpMyAdmin opens already signed in", page.status_code == 200 and "phpMyAdmin" in page.text
          and "pma_username" not in page.text, page.status_code)
    check("phpMyAdmin doesn't reveal the PHP version", "X-Powered-By" not in page.headers)
    check("phpMyAdmin shows no setup warnings", "configuration storage is not completely configured" not in page.text
          and "blowfish_secret" not in page.text and "TempDir" not in page.text)
    check("phpMyAdmin sends HSTS too", "max-age=" in page.headers.get("Strict-Transport-Security", ""))
    r = alice.get(f"{PMA}/index.php?route=/database/structure&db=shop&server={slot}")
    check("phpMyAdmin shows the database's tables", r.status_code == 200 and "products" in r.text, r.status_code)
    check("portal session cookie never reaches phpMyAdmin's host",
          not any(c.name == "__Host-dbp_session" and c.domain.startswith("pma") for c in alice.session.cookies))

    print("\n== Each account sees only its own servers")
    bob = User("bob")
    bob.login()
    bob.agree()
    bob.refresh_csrf()
    r = bob.get(f"{PORTAL}/servers/{shop}/edit")
    check("bob can't see alice's server", r.status_code == 404, r.status_code)
    r = bob.form(f"/servers/{shop}/open", {})
    check("bob can't open alice's server", r.status_code == 404, r.status_code)
    r = bob.form(f"/servers/{shop}/delete", {})
    check("bob can't delete alice's server", r.status_code == 404, r.status_code)
    r = bob.get(PMA + "/index.php")
    check("bob has no phpMyAdmin access", r.status_code == 302, r.status_code)
    r = bob.get(PORTAL + "/servers")
    check("bob's list doesn't show alice's server", "Shop – Production" not in r.text)
    guess = server_data(name="x", location="local", internal_host="other-db", db_user="crm_admin", cred_mode="saved")
    last = {}
    for i in range(5):
        _, last = bob.test_server(dict(guess, db_password=f"wrong-{i}"))
    check("5 wrong passwords lock the target", "locked" in (last.get("error") or "").lower(), last)
    code, j = bob.test_server(dict(guess, db_password="CrmPass-2026!"))
    check("it stays locked even with the right password", code == 423 and not j.get("ok"), (code, j))

    print("\n== Remote: TLS with a verified certificate, ask every time")
    with open(FIXTURES + "/ca.pem", "rb") as f:
        ca = f.read()
    tls = server_data(name="Analytics – Primary", environment="Production", method="tls", host="remote-tls.test",
                      db_user="report_ro", db_password="ReportPass-2026!", cred_mode="ask")
    code, j = alice.test_server(tls)
    check("without its CA the certificate is rejected", not j.get("ok") and "certificate" in (j.get("error") or "").lower(), j)
    code, j = alice.test_server(tls, files={"ca_file": ("ca.pem", ca, "application/x-pem-file")})
    check("with its CA the certificate is verified", j.get("ok") and any("certificate verified" in c for c in j.get("checks", [])), j)
    check("connection uses TLS 1.2 or 1.3", any("TLS 1.3" in c or "TLS 1.2" in c for c in j.get("checks", [])), j.get("checks"))
    r = alice.form("/servers", tls, files={"ca_file": ("ca.pem", ca, "application/x-pem-file")})
    check("TLS server saved without its password", r.status_code == 303, r.status_code)
    tls_id = alice.server_ids().get("Analytics – Primary")
    r = alice.get(f"{PORTAL}/servers/{tls_id}/open")
    check("ask-every-time shows a password form", 'name="db_password"' in r.text)
    page, slot, _ = alice.open(tls_id, {"db_user": "report_ro", "db_password": "nope"})
    check("a wrong password is rejected", slot is None and page.status_code == 422, page.status_code)
    page, slot, _ = alice.open(tls_id, {"db_user": "report_ro", "db_password": "ReportPass-2026!"})
    check("the right password opens phpMyAdmin", slot is not None and page.status_code == 200, page.status_code)
    r = alice.get(f"{PMA}/index.php?route=/server/databases&server={slot}")
    check("remote database is listed", "analytics" in r.text, r.status_code)

    print("\n== Remote: self-signed certificate (fingerprint checked before connecting)")
    pinned = server_data(name="Legacy CRM", method="pinned", host="selfsigned.test", db_user="legacy_admin",
                         db_password="LegacyPass-2026!")
    code, j = alice.test_server(pinned)
    pin = j.get("pin") or {}
    check("fingerprint offered for trust", j.get("ok") and pin.get("kind") == "tls" and pin.get("token") and pin.get("strict") is False, j)
    r = alice.form("/servers", pinned)
    check("can't save before trusting the certificate", r.status_code == 422, r.status_code)
    r = alice.form("/servers", dict(pinned, name="Wrong pin", host="strict.test", pin_token=pin.get("token", "")))
    check("a fingerprint trusted for another server is refused", r.status_code == 422, r.status_code)
    r = alice.form("/servers", dict(pinned, pin_token=pin.get("token", "")))
    check("saved after trusting", r.status_code == 303, r.status_code)
    legacy = alice.server_ids().get("Legacy CRM")
    page, slot, _ = alice.open(legacy)
    check("pinned server opens", slot is not None and page.status_code == 200, getattr(page, "status_code", page))
    r = alice.get(f"{PMA}/index.php?route=/server/databases&server={slot}")
    check("its database is listed", "legacy" in r.text, r.status_code)

    print("\n== Remote: self-signed certificate with a matching name (strict pinning)")
    strict = server_data(name="Strict server", method="pinned", host="strict.test", db_user="strict_user",
                         db_password="StrictPass-2026!")
    code, j = alice.test_server(strict)
    pin = j.get("pin") or {}
    check("certificate is pinned strictly", j.get("ok") and pin.get("strict") is True, j)
    r = alice.form("/servers", dict(strict, pin_token=pin.get("token", "")))
    check("strict server saved", r.status_code == 303, r.status_code)
    page, slot, _ = alice.open(alice.server_ids().get("Strict server"))
    check("strict server opens", slot is not None and page.status_code == 200, getattr(page, "status_code", page))

    print("\n== Remote: SSH tunnel through a bastion")
    with open(FIXTURES + "/deploy_ed25519") as f:
        key = f.read()
    ssh = server_data(name="Office reports", method="ssh", ssh_host="bastion.test", ssh_user="deploy", ssh_auth="key",
                      ssh_key=key, ssh_db_host="private-db", ssh_db_port="3306", db_user="reports_dev",
                      db_password="ReportsDev-2026!")
    code, j = alice.test_server(ssh)
    pin = j.get("pin") or {}
    check("SSH tunnel test passes", j.get("ok") and any("SSH connected" in c for c in j.get("checks", [])), j)
    check("SSH host key offered for trust", pin.get("kind") == "ssh" and pin.get("fingerprint", "").startswith("SHA256:"), pin)
    code, j = alice.test_server(dict(ssh, ssh_auth="password", ssh_key="", ssh_password="BastionPass-2026!"))
    check("SSH password sign-in works", j.get("ok"), j)
    code, j = alice.test_server(dict(ssh, ssh_auth="password", ssh_key="", ssh_password="wrong"))
    check("wrong SSH password is rejected", not j.get("ok"), j)
    code, j = alice.test_server(dict(ssh, ssh_db_host="local-db"))
    check("database host unreachable from the bastion is reported", not j.get("ok"), j)
    r = alice.form("/servers", dict(ssh, pin_token=pin.get("token", "")))
    check("SSH server saved", r.status_code == 303, r.status_code)
    page, slot, _ = alice.open(alice.server_ids().get("Office reports"))
    check("SSH server opens in phpMyAdmin", slot is not None and page.status_code == 200, getattr(page, "status_code", page))
    r = alice.get(f"{PMA}/index.php?route=/server/databases&server={slot}")
    check("database behind the bastion is listed", "reports" in r.text, r.status_code)

    print("\n== This server's own address (EGRESS_IP=203.0.113.10) and blocked addresses")
    code, j = alice.test_server(dict(pinned, host="203.0.113.10"))
    check("this server's IP as a remote host points to \"On this server\"",
          code == 422 and "On this server" in (j.get("errors") or {}).get("host", ""), (code, j))
    code, j = alice.test_server(dict(pinned, host="this-server.test"))
    check("a host name pointing at this server gets the same advice",
          not j.get("ok") and "is this Dokploy server" in (j.get("error") or ""), j)
    code, j = alice.test_server(dict(ssh, ssh_host="203.0.113.10"))
    check("this server's IP as an SSH host points to \"On this server\"",
          code == 422 and "On this server" in (j.get("errors") or {}).get("ssh_host", ""), (code, j))
    code, j = alice.test_server(dict(local, internal_host="203.0.113.10"))
    check("this server's IP as an internal host asks for the Internal Host",
          code == 422 and "Internal Host" in (j.get("errors") or {}).get("host", ""), (code, j))
    code, j = alice.test_server(dict(tls, host="10.250.250.250"))
    check("an address in EGRESS_BLOCK_CIDRS says it's blocked",
          not j.get("ok") and "blocked by this portal's settings" in (j.get("error") or ""), j)

    print("\n== Admin")
    r = bob.get(PORTAL + "/admin")
    check("non-admins can't open Admin", r.status_code == 404, r.status_code)
    r = alice.get(PORTAL + "/admin")
    check("Admin page loads for admins", r.status_code == 200 and "Abuse limits" in r.text, r.status_code)
    m = re.search(r"bob@example\.com.*?/admin/accounts/(\d+)/suspend", r.text, re.S)
    bob_id = int(m.group(1)) if m else 0
    m = re.search(r"alice@example\.com.*?</li>", r.text, re.S)
    check("admins can't suspend themselves (no button)", m is not None and "/suspend" not in m.group(0))

    r = alice.form("/admin/limits", dict(LIMIT_DEFAULTS, tests_per_minute="2", signins_per_ip_minute="100"))
    codes = [alice.test_server(local)[0] for _ in range(3)]
    check("connection tests are rate limited per account", 429 in codes, codes)

    r = alice.form("/admin/limits", dict(LIMIT_DEFAULTS, import_mb="1", signins_per_ip_minute="100"))
    try:
        big = alice.post(f"{PMA}/index.php?route=/import&server={slot}", files={"import_file": ("big.sql", b"x" * (2 * 1024 * 1024))})
        status = big.status_code
    except requests.RequestException as exc:
        status = str(exc)
    check("uploads over the import limit are refused before phpMyAdmin", status == 413, status)
    r = alice.form("/admin/limits", dict(LIMIT_DEFAULTS, signins_per_ip_minute="100"))
    check("limits saved", r.status_code == 303, r.status_code)

    r = alice.form(f"/admin/accounts/{bob_id}/suspend", {"reason": "Test suspension"})
    check("admin suspends an account", r.status_code == 303, r.status_code)
    r = bob.get(PORTAL + "/servers")
    check("suspended account is signed out at once", r.status_code == 303 and "/signin" in r.headers.get("Location", ""), r.status_code)
    r = User("bob").login()
    check("suspended account can't sign in", r.status_code == 403 and "suspended" in r.text.lower(), r.status_code)
    r = alice.form(f"/admin/accounts/{bob_id}/reactivate", {})
    check("admin reactivates the account", r.status_code == 303, r.status_code)
    bob = User("bob")
    r = bob.login()
    check("reactivated account can sign in", r.status_code == 303, r.status_code)

    print("\n== Activity log")
    r = alice.get(PORTAL + "/activity")
    check("alice's activity shows opens, changes and tests",
          all(s in r.text for s in ["Opened phpMyAdmin", "Server added", "Connection tested"]), r.status_code)
    r = bob.get(PORTAL + "/activity?filter=problems")
    check("bob's activity shows his lockout", "Server locked" in r.text, r.status_code)
    check("bob's activity doesn't show alice's servers", "Shop – Production" not in r.text)

    print("\n== Closing and signing out")
    r = alice.get(f"{PMA}/__dbportal/close?slot={slot}")
    check("phpMyAdmin 'Log out' closes that session and returns to the portal",
          r.status_code == 303 and r.headers.get("Location", "").startswith(PORTAL + "/servers"), r.status_code)
    alice.refresh_csrf()
    r = alice.form("/auth/logout", {})
    check("sign out", r.status_code == 303 and "/signin" in r.headers.get("Location", ""), r.status_code)
    r = alice.get(f"{PMA}/index.php?route=/server/databases&server=1")
    check("every phpMyAdmin session ends with sign-out", r.status_code == 302, r.status_code)
    r = alice.form("/admin/limits", LIMIT_DEFAULTS)
    check("signed-out session can't change anything", r.status_code in (303, 403) and "/signin" in r.headers.get("Location", "/signin"), r.status_code)

    passed = sum(1 for _, ok in results if ok)
    print(f"\n{passed}/{len(results)} checks passed", flush=True)
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
