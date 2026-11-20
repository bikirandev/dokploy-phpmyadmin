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
PGA = os.environ.get("PGA", "https://pga.localhost:8443")
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
        "name": "Test server", "environment": "Development", "kind": "mysql", "db_name": "",
        "location": "remote", "method": "tls",
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

    def open_pg(self, server_id, extra=None):
        """Opens a PostgreSQL server and follows the hand-over into pgAdmin. Returns (page, cookie header)."""
        data = {"_csrf": self.csrf}
        data.update(extra or {})
        r = self.post(f"{PORTAL}/servers/{server_id}/open", data=data)
        if r.status_code != 303 or not r.headers.get("Location", "").startswith(PGA + "/__dbportal/enter"):
            return r, ""
        enter = self.get(r.headers["Location"])
        location = enter.headers.get("Location", "")
        page = self.get(PGA + location if location.startswith("/") else location)
        for _ in range(3):  # pgAdmin signs in (portal-backed), then shows its main page
            if page.status_code not in (301, 302, 303) or "Location" not in page.headers:
                break
            nxt = page.headers["Location"]
            page = self.get(PGA + nxt if nxt.startswith("/") else nxt)
        return page, enter.headers.get("Set-Cookie", "")


class PgAdmin:
    """Talks to pgAdmin's JSON API the way its own page does."""

    def __init__(self, user):
        self.user = user
        self.token = ""

    def load(self):
        r = self.user.get(PGA + "/browser/js/utils.js")
        m = re.search(r"pgAdmin\['csrf_token'\] = '([^']+)'", r.text)
        self.token = m.group(1) if m else ""
        return r

    def call(self, method, path, body=None, timeout=90):
        headers = {"X-pgA-CSRFToken": self.token, "Referer": PGA + "/browser/", "Accept": "application/json",
                   "X-Requested-With": "XMLHttpRequest"}
        kw = {"headers": headers, "allow_redirects": False, "timeout": timeout}
        if body is not None:
            kw["json"] = body
        r = self.user.session.request(method, PGA + path, **kw)
        try:
            data = r.json()
        except ValueError:
            data = {"raw": r.text[:300]}
        return r.status_code, data

    def nodes(self, path):
        code, data = self.call("GET", path)
        # pgAdmin answers tree requests in "data" or, for some nodes, in "result"
        items = (data.get("data") or data.get("result")) if isinstance(data, dict) else None
        return {n.get("label"): n.get("_id") for n in items or [] if isinstance(n, dict)} if code == 200 else {}

    def group(self):
        return self.nodes("/browser/server_group/nodes/").get("DB Portal")

    def databases(self, gid, sid):
        return self.nodes(f"/browser/database/nodes/{gid}/{sid}/")


def pga_cookie(user):
    for c in user.session.cookies:
        if c.name == "__Host-pga_session" and "pga" in (c.domain or ""):
            return c.value
    return ""


def pga_home(user):
    """Loads pgAdmin's page like a browser tab does (following its sign-in redirects)."""
    r = user.get(PGA + "/", headers={"Accept": "text/html"})
    for _ in range(3):
        if r.status_code not in (301, 302, 303) or "Location" not in r.headers:
            break
        nxt = r.headers["Location"]
        r = user.get(PGA + nxt if nxt.startswith("/") else nxt, headers={"Accept": "text/html"})
    return r


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
    for path in ["/", "/browser/", "/misc/ping", "/static/js/generated/app.bundle.js", "/socket.io/?EIO=4&transport=polling"]:
        r = anon.get(PGA + path)
        check(f"pgAdmin {path} needs a session", r.status_code == 302
              and r.headers.get("Location", "").startswith(PORTAL + "/servers"), f"{r.status_code} {r.headers.get('Location')}")
    for path in ["/internal/pga-auth", "/internal/pga-session", "/internal/pga-alive"]:
        r = anon.post(PORTAL + path, json={}) if path != "/internal/pga-auth" else anon.get(PORTAL + path)
        check(f"internal endpoint {path} hidden", r.status_code == 404, r.status_code)
    anon.session.cookies.set("__Host-dbp_g1", "A" * 43 + "." + "B" * 43, domain="pga.localhost", path="/")
    r = anon.get(PGA + "/browser/")
    check("a forged pgAdmin session cookie is refused", r.status_code == 302, r.status_code)
    r = anon.get(PGA + "/browser/", headers={"Remote-User": "dbp-" + "0" * 24, "X-Dbp-Assertion": "x.y"})
    check("pgAdmin ignores identity headers sent by the browser", r.status_code == 302, r.status_code)

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

    print("\n== PostgreSQL on this server, opened in pgAdmin (own host name)")
    pglocal = server_data(kind="postgres", name="Shop PG", environment="Production", location="local",
                          internal_host="pg-local", internal_port="", db_user="shop_owner",
                          db_password="ShopPg-2026!", db_name="shop", cred_mode="saved")
    code, j = alice.test_server(pglocal)
    check("PostgreSQL test reaches the local database", code == 200 and j.get("ok"), j)
    check("test shows the PostgreSQL version", any(c.startswith("PostgreSQL 17") for c in j.get("checks", [])), j.get("checks"))
    check("test shows what the role may do, not a superuser",
          any("Owns databases: shop" in g for g in j.get("grants", [])) and not j.get("superuser"), j)
    code, j = alice.test_server(dict(pglocal, db_user="postgres", db_password="PgRoot-2026!"))
    check("the postgres superuser is blocked", not j.get("ok") and "postgres is blocked" in json.dumps(j), j)
    code, j = alice.test_server(dict(pglocal, db_user="boss_admin", db_password="BossPg-2026!"))
    check("another superuser role is flagged", j.get("ok") and j.get("superuser"), j)
    code, j = alice.test_server(dict(pglocal, db_password="wrong"))
    check("a wrong PostgreSQL password is reported", not j.get("ok") and "rejected" in (j.get("error") or ""), j)
    code, j = alice.test_server(dict(pglocal, db_name="nope"))
    check("a missing database is explained", not j.get("ok") and "doesn't exist" in (j.get("error") or ""), j)
    for host, port in [("internal-svc", "80"), ("portal", "8080"), ("gateway", "8080"), ("pma", "8080")]:
        code, j = alice.test_server(dict(pglocal, internal_host=host, internal_port=port))
        check(f"pgAdmin can't use '{host}' as a database", not j.get("ok"), j)
    r = alice.form("/servers", pglocal)
    check("PostgreSQL server saved", r.status_code == 303 and "notice=added" in r.headers.get("Location", ""), r.status_code)
    pg_shop = alice.server_ids().get("Shop PG")
    r = alice.get(PORTAL + "/servers")
    check("the list shows it as PostgreSQL, opened in pgAdmin", "PostgreSQL" in r.text and "Open in pgAdmin" in r.text)

    page, cookie = alice.open_pg(pg_shop)
    lc = cookie.lower()
    check("open hands over to pgAdmin's host with a __Host-, Secure, HttpOnly cookie",
          "__host-dbp_g" in lc and "secure" in lc and "httponly" in lc, cookie)
    check("pgAdmin opens already signed in", page.status_code == 200 and "pgAdmin" in page.text,
          f"{page.status_code} {page.headers.get('Location')} {page.text[:200]}")
    check("pgAdmin sends HSTS", "max-age=" in page.headers.get("Strict-Transport-Security", ""))
    check("pgAdmin's session cookie is __Host-", pga_cookie(alice) != "")
    pga = PgAdmin(alice)
    r = pga.load()
    check("pgAdmin hands its page a CSRF token", pga.token != "", r.status_code)
    gid = pga.group()
    servers = pga.nodes(f"/browser/server/nodes/{gid}/") if gid else {}
    check("the server opened in the portal is listed in a 'DB Portal' group", gid and "Shop PG" in servers, servers)
    sid = servers.get("Shop PG")
    code, j = pga.call("POST", f"/browser/server/connect/{gid}/{sid}", {})
    check("pgAdmin connects without asking for the password", code == 200 and j.get("success") == 1, (code, j))
    dbs = pga.databases(gid, sid)
    check("pgAdmin lists the database", "shop" in dbs, dbs)
    schemas = pga.nodes(f"/browser/schema/nodes/{gid}/{sid}/{dbs.get('shop')}/") if dbs.get("shop") else {}
    tables = pga.nodes(f"/browser/table/nodes/{gid}/{sid}/{dbs.get('shop')}/{schemas.get('public')}/") if schemas.get("public") else {}
    check("pgAdmin shows the database's tables", "products" in tables, (schemas, tables))
    code, j = pga.call("POST", f"/sqleditor/initialize/sqleditor/{4242}/{gid}/{sid}/{dbs.get('shop')}",
                       {"dbname": "shop", "user": "boss_admin", "password": "BossPg-2026!", "role": ""})
    check("the Query Tool can't switch to another database user", "another database user" in json.dumps(j), (code, j))
    code, j = pga.call("POST", f"/sqleditor/initialize/sqleditor/{4243}/{gid}/{sid}/{dbs.get('shop')}", {"dbname": "shop"})
    check("the Query Tool opens as the portal's user", code == 200 and j.get("success") == 1, (code, j))
    code, j = pga.call("POST", f"/browser/server/obj/{gid}/", {"name": "x", "host": "10.250.250.200", "port": 3306,
                                                              "username": "legacy_admin", "db": "postgres"})
    check("registering a server in pgAdmin is refused", code == 403 and "managed in DB Portal" in json.dumps(j), (code, j))
    code, j = pga.call("PUT", f"/browser/server/obj/{gid}/{sid}", {"host": "internal-svc"})
    check("changing a server's connection in pgAdmin is refused", code == 403, (code, j))
    code, j = pga.call("DELETE", f"/browser/server/obj/{gid}/{sid}")
    check("deleting a server in pgAdmin is refused", code == 403, (code, j))
    code, j = pga.call("POST", "/misc/workspace/adhoc_connect_server", {"server_name": "x", "did": 0, "host": "pg-tls.test",
                                                                        "port": 5432, "user": "app_user"})
    check("ad hoc connections are refused", code == 403, (code, j))
    code, j = pga.call("GET", "/llm/status")
    check("pgAdmin reports its AI assistant as off", code == 200 and (j.get("data") or {}).get("system_enabled") is False, (code, j))
    for path in ["/cloud/", "/import_export_servers/get_servers", "/llm/models/anthropic", "/user_management/user/"]:
        code, j = pga.call("GET", path)
        check(f"pgAdmin feature {path} is turned off", code == 403, (code, j))
    r = alice.get(PGA + "/socket.io/?EIO=4&transport=polling")
    check("Socket.IO (ERD, Schema Diff) works in the user's own session", r.status_code == 200, r.status_code)
    alice.refresh_csrf()

    print("\n== PostgreSQL: each account sees only its own pgAdmin")
    bob.refresh_csrf()
    r = bob.get(PGA + "/browser/")
    check("bob has no pgAdmin access", r.status_code == 302, r.status_code)
    bob_pg = server_data(kind="postgres", name="Bob PG", location="local", internal_host="pg-local", internal_port="5432",
                         db_user="shop_owner", db_password="ShopPg-2026!", cred_mode="saved")
    r = bob.form("/servers", bob_pg)
    check("bob saves his own PostgreSQL server", r.status_code == 303, r.status_code)
    page, _ = bob.open_pg(bob.server_ids().get("Bob PG"))
    check("bob opens pgAdmin", page.status_code == 200, page.status_code)
    # Same computer: bob's browser still holds alice's pgAdmin session cookie.
    bob.session.cookies.set("__Host-pga_session", pga_cookie(alice), domain="pga.localhost", path="/")
    bpga = PgAdmin(bob)
    code, j = bpga.call("GET", "/browser/server_group/nodes/")
    check("someone else's pgAdmin session is signed out, not reused", code in (401, 403), (code, j))
    page = pga_home(bob)
    check("pgAdmin then signs bob in as himself", page.status_code == 200, page.status_code)
    bpga.load()
    bgid = bpga.group()
    bservers = bpga.nodes(f"/browser/server/nodes/{bgid}/") if bgid else {}
    check("bob then sees only his own servers", "Bob PG" in bservers and "Shop PG" not in bservers, bservers)
    code, j = bpga.call("POST", f"/browser/server/connect/{gid}/{sid}", {})
    check("bob can't connect alice's server", code != 200 or j.get("success") != 1, (code, j))
    # alice's own tab: pgAdmin checks again who she is and signs her back in.
    pga_home(alice)
    pga.load()
    check("alice keeps her own pgAdmin", "Shop PG" in pga.nodes(f"/browser/server/nodes/{pga.group()}/"))

    print("\n== PostgreSQL remote: TLS (private CA), pinned certificates, SSH, unencrypted")
    pgtls = server_data(kind="postgres", name="Analytics PG", environment="Production", method="tls", host="pg-tls.test",
                        port="5432", db_user="app_user", db_password="AppPg-2026!", db_name="analytics", cred_mode="ask")
    code, j = alice.test_server(pgtls)
    check("without its CA the certificate is rejected", not j.get("ok") and "certificate" in (j.get("error") or "").lower(), j)
    code, j = alice.test_server(pgtls, files={"ca_file": ("ca.pem", ca, "application/x-pem-file")})
    check("with its CA the certificate is verified (TLS 1.3)", j.get("ok")
          and any("TLS 1.3, certificate verified" in c for c in j.get("checks", [])), j)
    r = alice.form("/servers", pgtls, files={"ca_file": ("ca.pem", ca, "application/x-pem-file")})
    check("TLS PostgreSQL server saved", r.status_code == 303, r.status_code)
    page, _ = alice.open_pg(alice.server_ids().get("Analytics PG"), {"db_user": "app_user", "db_password": "nope"})
    check("a wrong typed password doesn't open pgAdmin", page.status_code == 422, page.status_code)
    page, _ = alice.open_pg(alice.server_ids().get("Analytics PG"), {"db_user": "app_user", "db_password": "AppPg-2026!"})
    check("the typed password opens pgAdmin", page.status_code == 200, page.status_code)

    def pga_open_and_list(name, database):
        pga.load()
        g = pga.group()
        s = pga.nodes(f"/browser/server/nodes/{g}/").get(name)
        c, res = pga.call("POST", f"/browser/server/connect/{g}/{s}", {})
        ok = c == 200 and res.get("success") == 1
        return ok and database in pga.databases(g, s), (c, res)

    ok, detail = pga_open_and_list("Analytics PG", "analytics")
    check("pgAdmin connects with the verified certificate and lists the database", ok, detail)

    pinned_pg = server_data(kind="postgres", name="Pinned PG", method="pinned", host="pg-pinned.test", port="5432",
                            db_user="app_user", db_password="AppPg-2026!")
    code, j = alice.test_server(pinned_pg)
    pin = j.get("pin") or {}
    check("a CA-signed certificate for another name is pinned by fingerprint", j.get("ok") and pin.get("strict") is False
          and pin.get("token"), j)
    r = alice.form("/servers", dict(pinned_pg, pin_token=pin.get("token", "")))
    check("pinned PostgreSQL server saved", r.status_code == 303, r.status_code)
    page, _ = alice.open_pg(alice.server_ids().get("Pinned PG"))
    ok, detail = pga_open_and_list("Pinned PG", "pinned")
    check("pgAdmin connects after checking the fingerprint", page.status_code == 200 and ok, detail)

    self_pg = server_data(kind="postgres", name="Selfsigned PG", method="pinned", host="pg-selfsigned.test", port="5432",
                          db_user="app_user", db_password="AppPg-2026!")
    code, j = alice.test_server(self_pg)
    pin = j.get("pin") or {}
    check("a self-signed certificate is pinned strictly (by PostgreSQL's client)", j.get("ok") and pin.get("strict") is True, j)
    r = alice.form("/servers", dict(self_pg, pin_token=pin.get("token", "")))
    page, _ = alice.open_pg(alice.server_ids().get("Selfsigned PG"))
    ok, detail = pga_open_and_list("Selfsigned PG", "legacy")
    check("pgAdmin connects with the pinned certificate", page.status_code == 200 and ok, detail)

    code, j = alice.test_server(server_data(kind="postgres", method="tls", host="pg-plain.test", port="5432",
                                            db_user="app_user", db_password="AppPg-2026!"))
    check("a PostgreSQL server without TLS is refused", not j.get("ok") and "doesn't offer TLS" in (j.get("error") or ""), j)
    code, j = alice.test_server(server_data(kind="postgres", method="pinned", host="pg-plain.test", port="5432",
                                            db_user="app_user", db_password="AppPg-2026!"))
    check("…also when pinning", not j.get("ok") and "doesn't offer TLS" in (j.get("error") or ""), j)

    ssh_pg = server_data(kind="postgres", name="Office PG", method="ssh", ssh_host="bastion.test", ssh_user="deploy",
                         ssh_auth="key", ssh_key=key, ssh_db_host="private-pg", ssh_db_port="5432", db_user="app_user",
                         db_password="AppPg-2026!", db_name="reports")
    code, j = alice.test_server(ssh_pg)
    pin = j.get("pin") or {}
    check("PostgreSQL through the SSH tunnel passes", j.get("ok") and any("SSH connected" in c for c in j.get("checks", [])), j)
    r = alice.form("/servers", dict(ssh_pg, pin_token=pin.get("token", "")))
    check("SSH PostgreSQL server saved", r.status_code == 303, r.status_code)
    page, _ = alice.open_pg(alice.server_ids().get("Office PG"))
    ok, detail = pga_open_and_list("Office PG", "reports")
    check("pgAdmin connects through the SSH tunnel", page.status_code == 200 and ok, detail)
    alice.refresh_csrf()

    print("\n== This server's own address (EGRESS_IP=10.250.250.200) and blocked addresses")
    code, j = alice.test_server(dict(pinned, host="10.250.250.200"))
    check("a database on this server can be added as a remote server (its public IP)", j.get("ok"), j)
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
    try:
        big = alice.post(f"{PGA}/file_manager/filemanager/1/", files={"newfile": ("big.sql", b"x" * (2 * 1024 * 1024))})
        status = big.status_code
    except requests.RequestException as exc:
        status = str(exc)
    check("uploads over the limit are refused before pgAdmin", status == 413, status)
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
          all(s in r.text for s in ["Opened phpMyAdmin", "Opened pgAdmin", "Server added", "Connection tested"]), r.status_code)
    r = bob.get(PORTAL + "/activity?filter=problems")
    check("bob's activity shows his lockout", "Server locked" in r.text, r.status_code)
    check("bob's activity doesn't show alice's servers", "Shop – Production" not in r.text)

    print("\n== Closing and signing out")
    r = alice.get(f"{PMA}/__dbportal/close?slot={slot}")
    check("phpMyAdmin 'Log out' closes that session and returns to the portal",
          r.status_code == 303 and r.headers.get("Location", "").startswith(PORTAL + "/servers"), r.status_code)
    r = alice.get(PGA + "/logout", headers={"Accept": "text/html"})
    check("pgAdmin 'Log out' goes to the portal's close page", r.status_code == 303
          and r.headers.get("Location", "") == PGA + "/__dbportal/close", f"{r.status_code} {r.headers.get('Location')}")
    r = alice.get(r.headers.get("Location", PGA + "/__dbportal/close"))
    check("…which closes this browser's pgAdmin sessions", r.status_code == 303
          and "notice=pga-closed" in r.headers.get("Location", ""), f"{r.status_code} {r.headers.get('Location')}")
    r = alice.get(PGA + "/browser/")
    check("pgAdmin needs a newly opened server after that", r.status_code == 302, r.status_code)
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
