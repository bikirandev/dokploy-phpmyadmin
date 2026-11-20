# DB Portal for Dokploy

A secure, multi-user front door for **phpMyAdmin** and **pgAdmin**, deployed on [Dokploy](https://dokploy.com).

- **Sign in with Bikiran** (OpenID Connect). No portal passwords to steal or reset.
- **MySQL / MariaDB servers open in phpMyAdmin, PostgreSQL servers in pgAdmin.** Same server list, vault and rules for both.
- **Each account sees only its own servers.** Add databases on this server or anywhere else.
- **Saved passwords are encrypted** (XChaCha20-Poly1305) and never sent to the browser, or choose **Ask every time**.
- **Remote servers over TLS, a pinned self-signed certificate, or an SSH tunnel.** Unencrypted connections are refused.
- **phpMyAdmin and pgAdmin are each locked in a box**: each runs on its own host name, holds no secrets, and a firewall stops it reaching anything private (Dokploy itself, other apps, cloud metadata, your LAN).
- **Abuse limits, lockouts, suspension and an activity log**, managed from an Admin page.

## How it works

```
Browser ──HTTPS──▶ Traefik (Dokploy) ──▶ gateway (nginx)
                                          │  per-IP rate limits, security headers,
                                          │  optional Cloudflare-only mode
                         db.example.com   ├──▶ portal       sign-in, My servers, vault, activity, admin
                     pma.db.example.com   ├──▶ phpMyAdmin   every request checked with the portal first
                      pg.db.example.com   └──▶ pgAdmin      every request checked with the portal first
                                                  │
                                 egress-guard / pga-guard (a firewall for each tool's network)
                                                  ├── pma-databases network ──▶ your Dokploy databases
                                                  └── public internet ───────▶ remote databases (TLS / SSH)
```

| Container | Job | Holds secrets? |
|---|---|---|
| `gateway` | The only thing Traefik talks to. Routes the three host names, rate-limits, sets security headers, and asks the portal before letting a request reach phpMyAdmin or pgAdmin. | Only the token it uses to ask the portal |
| `portal` | Sign-in, server list, password vault, activity log, admin. Never connects to databases itself. | The vault key |
| `pma` | phpMyAdmin 5.2.3 (pinned) plus the MySQL connection tester and SSH tunnel service. | No. Credentials arrive per request, encrypted with a key that only the user's browser cookie carries. |
| `pga` | pgAdmin 9.19 (pinned) with DB Portal's layer in front of it, plus the PostgreSQL connection tester and SSH tunnel service. | No, same as `pma`. pgAdmin's own database holds settings and history, never passwords. |
| `egress-guard`, `pga-guard` | Firewalls for the network namespaces phpMyAdmin and pgAdmin share. | No |

**Opening a server**: the portal checks the login with the database, then creates a ticket: the connection details are encrypted with a fresh random key, the portal keeps the ciphertext and forgets the key, and the key goes to the user's browser as a cookie for the tool's host name only. On each request, the tool's container fetches the ciphertext from the portal (only if the user's portal session is still valid) and decrypts it with the key from the cookie. A breach of a tool's container therefore cannot read anyone else's credentials.

**pgAdmin specifically**: DB Portal's layer signs each person in as their own pgAdmin user (pgAdmin's "webserver" sign-in, fed only by the layer, never by a request header) and checks on every request that pgAdmin's session belongs to the person the portal vouches for. pgAdmin lists only the servers opened in the portal, in a "DB Portal" group; adding or editing servers there is turned off. Every connection pgAdmin opens, including Backup and Restore, takes its address, user, TLS settings and password from the open ticket of that request, so pgAdmin never stores a password, can't connect as another database user, and stops connecting within a minute after the portal session ends.

## Requirements

- Dokploy **v0.31 or later** (it needs Dokploy's *Networks* feature).
- Three DNS names pointing at your Dokploy server, for example `db.example.com` (portal), `pma.db.example.com` (phpMyAdmin) and `pg.db.example.com` (pgAdmin). Each tool is kept on its own host name so its pages can never act on the portal or on the other tool.
- An OpenID Connect client at Bikiran (issuer URL, client ID, client secret).

## Deploy on Dokploy

### 1. DNS

Create `A` (and `AAAA` if you use IPv6) records for all three host names, pointing at the Dokploy server.

### 2. The `pma-databases` network

phpMyAdmin and pgAdmin can reach **only** Dokploy databases attached to this network (MySQL, MariaDB and PostgreSQL alike).

In Dokploy, open **Networks** and create a network:

| Setting | Value |
|---|---|
| Name | `pma-databases` |
| Driver | `overlay` |
| Attachable | on |
| Internal | on (databases don't need the internet) |

Then, for each database that should be reachable "on this server", open the database in Dokploy, find **Networks** (Advanced tab) and add `pma-databases`. Keep `dokploy-network` attached as well if your apps use it.

Attach it to the databases only, not to DB Portal's own services: `docker-compose.yml` already connects phpMyAdmin and pgAdmin to it.

A database on this server can also be added as a "Remote server", through the server's public IP and the database's external port. "On this server" is safer: nothing is exposed to the internet. PostgreSQL databases created by Dokploy have TLS turned off, so for them "Remote server" only works after you turn TLS on (or through an SSH tunnel).

### 3. Register the portal with Bikiran

- Redirect URI: `https://db.example.com/auth/callback`
- Scopes: `openid email profile`
- Grant type: authorization code (the portal uses PKCE)

### 4. Generate secrets

```sh
sh scripts/generate-secrets.sh          # Linux / macOS
pwsh scripts/generate-secrets.ps1       # Windows
```

**Store `VAULT_KEY` in a password manager.** Without it, saved database passwords cannot be decrypted after a restore.

### 5. Create the service

1. In your Dokploy project: **Create Service → Compose**, provider **Git** (this repository), compose path `./docker-compose.yml`, type **Docker Compose**.
2. **Environment** tab: paste the values from [.env.example](.env.example) and fill them in.
3. Leave the **Domains** tab empty. Routing and certificates are set by labels in `docker-compose.yml`.
4. **Advanced** tab: leave **Networks** empty for every service (no networks added, *Detach dokploy-network* off) and **Isolated Deployment** off. `docker-compose.yml` sets up all networks itself. If Dokploy adds a network to `pma` or `pga`, the deploy fails with ``service pma declares mutually exclusive `network_mode` and `networks` ``.
5. **Deploy.**

### 6. Make yourself an admin

Sign in once at `https://db.example.com`, then on the server:

```sh
docker exec $(docker ps -qf name=portal) php /app/bin/users.php
```

Copy your user ID into `ADMIN_SUBJECTS` (comma-separated for several people) and redeploy.

## Configuration

| Variable | Required | Meaning |
|---|---|---|
| `PORTAL_DOMAIN` | yes | Portal host name, e.g. `db.example.com` |
| `PMA_DOMAIN` | yes | phpMyAdmin host name, e.g. `pma.db.example.com` (must differ) |
| `PGA_DOMAIN` | yes | pgAdmin host name, e.g. `pg.db.example.com` (must differ from both) |
| `OIDC_ISSUER` | yes | Bikiran's issuer URL (its `/.well-known/openid-configuration` must exist) |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | yes | The client registered in step 3 |
| `OIDC_PROVIDER_NAME` | no | Shown on the sign-in button (default `Bikiran`) |
| `OIDC_USER_ID_CLAIM` | no | The permanent user ID claim (default `sub`) |
| `OIDC_REQUIRED_AMR` | no | E.g. `mfa`: only accept sign-ins whose token says 2-step verification was used |
| `OIDC_REQUIRE_EMAIL_VERIFIED` | no | `true` to require `email_verified` |
| `OIDC_TOKEN_AUTH` | no | `basic` (default) or `post` for the token endpoint |
| `VAULT_KEY` | yes | 32 random bytes, base64. Encrypts saved passwords and signs internal tokens |
| `GATEWAY_TOKEN`, `PMA_TOKEN`, `PGA_TOKEN` | yes | Random, all different, 32+ characters. Authenticate internal calls |
| `ADMIN_SUBJECTS` | no | User IDs of platform admins |
| `EGRESS_IP` | no | This server's public IP, shown to users for their firewall rules |
| `EGRESS_BLOCK_CIDRS` | no | Extra addresses phpMyAdmin and pgAdmin must never reach, comma-separated. Leave this server's own IP out of it: users may add databases published on this server as "Remote server" |
| `EGRESS_ALLOW_CIDRS` | no | Private ranges phpMyAdmin and pgAdmin may treat as "remote". Leave empty unless you know you need it |
| `CLOUDFLARE_ONLY` | no | `true`: accept traffic only from Cloudflare and take the visitor IP from `CF-Connecting-IP` |
| `PORTAL_NAME` | no | Product name in the UI (default `DB Portal`) |
| `PMA_DATABASES_NETWORK` | no | Name of the databases network (default `pma-databases`) |
| `CERT_RESOLVER` | no | Traefik certificate resolver (default `letsencrypt`, Dokploy's default) |

Abuse limits (servers per account, tests per minute, lockouts, sessions, import size, sign-in attempts per IP) are **not** environment variables: admins change them on the **Admin** page, and they are stored in the portal's own database.

## Security model

| Threat | Protection |
|---|---|
| Stolen or guessed portal password | There is none: sign-in is delegated to Bikiran (and its 2-step verification). |
| Login CSRF, token replay, mix-up | Authorization code + PKCE, `state` bound to a cookie, `nonce`, issuer and audience checks, RFC 9207 `iss` check. |
| One user reaching another's servers | Every query is scoped to the owner; tickets are bound to the user, their live session and the tool. pgAdmin checks on every request that its session belongs to the person the portal vouches for. |
| phpMyAdmin or pgAdmin bug (XSS) acting on the portal | Each tool runs on its own host name; portal cookies are `__Host-` and never sent there; strict CSP and CSRF tokens on the portal. |
| Using phpMyAdmin or pgAdmin to attack internal systems | `egress-guard` and `pga-guard` firewalls: only the portal API, `pma-databases`, and public addresses. Address checks before every connection as well. In pgAdmin, adding servers, ad hoc connections, the PSQL terminal, cloud deployment and the AI assistant are turned off. |
| pgAdmin keeping or reusing passwords | Every pgAdmin connection (Backup and Restore included) gets its password from the open ticket of that request: pgAdmin saves none, can't switch to another database user, and stops connecting within a minute after the portal session ends. |
| A malicious "database server" | `LOAD DATA LOCAL INFILE` disabled; no program execution in phpMyAdmin's PHP; pgAdmin reads certificate and key files only from the user's own folder; read-only filesystems; no secrets in either container. |
| Password guessing through the portal | Lockout per account and target after repeated failures; tests per minute limit; per-IP limits at the gateway. |
| Eavesdropping between portal and remote databases | TLS with certificate verification (the system CAs are always passed explicitly; PHP's MySQL driver otherwise skips the check), pinned self-signed certificates, or SSH with a pinned host key. Plain connections are refused. |
| Vault data stolen from a backup | Passwords are encrypted with `VAULT_KEY`, which is not stored on the data volume. |
| Root access | `root` (MySQL) and `postgres` (PostgreSQL) can't be saved, tested or used. Users are warned when an account or role has administrator-level privileges. |

Hardening: all containers run with `no-new-privileges`, all Linux capabilities dropped, read-only root filesystems, CPU and memory limits and no published ports. The gateway, portal, phpMyAdmin and pgAdmin run as non-root users; the guards run as root with only `NET_ADMIN`, which they need to set the firewall rules.

**Known limits, be aware:**
- phpMyAdmin wasn't designed for many untrusted users sharing one installation. A future phpMyAdmin bug that lets a signed-in user run code could expose other users' **currently open** sessions. The design limits this (no stored secrets, read-only filesystem, no internal network access), but **keep phpMyAdmin updated quickly**.
- "TLS, self-signed certificate" with a certificate whose name doesn't match the host (for example MySQL's auto-generated one) is checked by fingerprint **before** each connection, because PHP's MySQL driver can't pin a certificate inside the connection. If the certificate's name matches the host, the driver enforces the pin itself ("strict").
- If a server's SSH host key changes, connections stop until the owner runs a test and trusts the new key.
- pgAdmin is built for several users, but it is one shared process (it can only run as one). A pgAdmin bug that lets a signed-in user run code could expose other users' **currently open** sessions, as with phpMyAdmin. pgAdmin fixed several such bugs in 2024 and 2025: **keep it updated quickly**.
- DB Portal's layer in pgAdmin hooks into pgAdmin's internals. Before deploying a new pgAdmin version, run `test/run-e2e.sh`.
- For PostgreSQL, "TLS, self-signed certificate" pins a self-signed certificate inside the connection itself (PostgreSQL's client trusts exactly that certificate). A certificate from an authority you didn't upload is checked by fingerprint before each new connection instead.
- A PostgreSQL server opened in two browsers is listed once in pgAdmin, and connects only in a browser that has it open.
- pgAdmin still shows some menu entries for features DB Portal turns off (such as *Register → Server* and *Import/Export Servers*); using them shows a short message instead. pgAdmin's user menu shows each person as a `dbp-…` name: a stable alias of their Bikiran account.

## Operating it

- **Backups**: back up the `portal-data` volume (Dokploy → Volume backups) and keep `VAULT_KEY` separately. The `pga-data` volume holds pgAdmin's settings, query history and Storage Manager files (no passwords); back it up only if you want to keep those. Files in pgAdmin's Storage Manager, such as backups made there, are deleted after 24 hours.
- **Updates**: phpMyAdmin is pinned in `phpmyadmin/Dockerfile`, pgAdmin in `pgadmin/Dockerfile`. Update the tag when a new release comes out (watch [phpMyAdmin security announcements](https://www.phpmyadmin.net/security/) and [pgAdmin releases](https://www.pgadmin.org/news/)), run `test/run-e2e.sh`, and redeploy.
- **Emergency access** (Bikiran sign-in down): on the server,
  `docker exec -it $(docker ps -qf name=portal) php /app/bin/emergency-link.php --subject <your-user-id>`
  prints a one-time link valid for 10 minutes. Only works for admins; it is logged.
- **Cloudflare**: proxy all three host names (orange cloud), SSL mode **Full (strict)**, then set `CLOUDFLARE_ONLY=true`. If the first certificate can't be issued while proxied, switch to DNS-only until it is, then turn the proxy back on.
- **Logs**: `docker logs` of each container; user-facing events are on each user's Activity page (kept 90 days).

## Testing locally

`test/run-e2e.sh` builds everything and runs it next to a stand-in identity provider, Traefik (as Dokploy runs it), local and remote MySQL, MariaDB and PostgreSQL test databases (private CA, self-signed, SSH bastion), then runs about 200 browser-level and network checks. Needs Docker with Compose v2.33+.

```sh
test/run-e2e.sh            # run and clean up
KEEP=1 test/run-e2e.sh     # keep it running at https://db.localhost:8443
```

## Not done yet

- **Bikiran's real settings**: the sign-in is standard OpenID Connect and was tested against a stand-in provider. Set `OIDC_ISSUER`, `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET` when Bikiran's client is registered.
- **A 2-step verification step inside the portal**, in case Bikiran's login doesn't enforce one. If Bikiran reports it in the ID token's `amr` claim, `OIDC_REQUIRED_AMR` already enforces it.
- **Vault key rotation** (re-encrypting saved passwords under a new key).

## License

MIT, see [LICENSE](LICENSE).
