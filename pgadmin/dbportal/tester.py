"""
Connection test for PostgreSQL servers, used by the portal (full test, and the quick check
before opening pgAdmin). Mirrors the MySQL tester in phpMyAdmin's container.
"""
import hmac
import secrets
import time

import psycopg

from . import net, probe, tunnels
from .common import PLAIN_PARAMS, RUN_DIR, SYSTEM_CA, AuthFailed, UserError, write_pem

BLOCKED_USER = 'postgres'
CA_DIR = RUN_DIR + '/ca'
# Predefined roles that reach the server's files or programs: as risky as a superuser.
RISKY_ROLES = {'pg_execute_server_program', 'pg_read_server_files', 'pg_write_server_files'}


def blocked(user):
    return user == '' or user.lower() == BLOCKED_USER


def connect(host, port, user, password, database, params):
    conninfo = {
        'host': host, 'port': port, 'user': user, 'dbname': database,
        'connect_timeout': 8, 'application_name': 'DB Portal connection test',
        'gssencmode': 'disable',
    }
    if password:
        conninfo['password'] = password
    conninfo.update(params)
    try:
        return psycopg.connect(autocommit=True, **conninfo)
    except psycopg.OperationalError as error:
        message = str(error)
        if getattr(error, 'sqlstate', None) == '28P01' or 'password authentication failed' in message \
                or 'authentication failed for user' in message:
            raise AuthFailed(message) from None
        raise


def version(conn):
    number = conn.info.server_version
    if number >= 100000:
        return 'PostgreSQL %d.%d' % (number // 10000, number % 10000)
    return 'PostgreSQL %d.%d.%d' % (number // 10000, number // 100 % 100, number % 100)


def tls_version(conn):
    if not conn.pgconn.ssl_in_use:
        return ''
    try:
        row = conn.execute('SELECT version FROM pg_catalog.pg_stat_ssl WHERE pid = pg_catalog.pg_backend_pid()').fetchone()
    except psycopg.Error:
        row = None
    return str(row[0]) if row and row[0] else 'TLS'


def privileges(conn):
    """What the role may do, for the owner to review. Returns (lines, superuser, user)."""
    user, superuser, createdb, createrole, replication, bypassrls = conn.execute(
        'SELECT r.rolname, r.rolsuper, r.rolcreatedb, r.rolcreaterole, r.rolreplication, r.rolbypassrls '
        'FROM pg_catalog.pg_roles r WHERE r.rolname = current_user').fetchone()
    member_of = [row[0] for row in conn.execute(
        'SELECT b.rolname FROM pg_catalog.pg_auth_members m '
        'JOIN pg_catalog.pg_roles b ON b.oid = m.roleid '
        'JOIN pg_catalog.pg_roles u ON u.oid = m.member '
        'WHERE u.rolname = current_user ORDER BY 1').fetchall()]
    owns = [row[0] for row in conn.execute(
        'SELECT d.datname FROM pg_catalog.pg_database d '
        'JOIN pg_catalog.pg_roles r ON r.oid = d.datdba '
        'WHERE r.rolname = current_user AND NOT d.datistemplate ORDER BY 1 LIMIT 20').fetchall()]
    can_connect = [row[0] for row in conn.execute(
        "SELECT datname FROM pg_catalog.pg_database WHERE NOT datistemplate "
        "AND pg_catalog.has_database_privilege(datname, 'CONNECT') ORDER BY 1 LIMIT 20").fetchall()]

    lines = []
    if superuser:
        lines.append('Superuser (can do anything on this server)')
    if createrole:
        lines.append('Can create roles')
    if createdb:
        lines.append('Can create databases')
    if replication:
        lines.append('Can use replication')
    if bypassrls:
        lines.append('Bypasses row-level security')
    if member_of:
        lines.append('Member of ' + ', '.join(member_of[:8]))
    if owns:
        lines.append('Owns databases: ' + ', '.join(owns))
    if can_connect:
        lines.append('Can connect to: ' + ', '.join(can_connect))
    risky = bool(superuser or createrole or replication or bypassrls or RISKY_ROLES & set(member_of))
    return lines[:12], risky, str(user)


def friendly(error, target, database, via_ssh):
    """A connection error explained for the owner, without internal details."""
    message = ' '.join(str(error).split())
    if 'authentication method requirement' in message:
        # "Not encrypted" accepts only SCRAM logins (require_auth).
        if 'hashed password' in message:
            asked = 'asked for the password as MD5'
        elif 'cleartext password' in message:
            asked = 'asked for the password in clear text'
        elif 'did not complete authentication' in message:
            asked = 'let this user in without a password'
        else:
            asked = "doesn't use SCRAM-SHA-256 for this login"
        return ('%s %s. Without encryption only SCRAM-SHA-256 logins are allowed. Set password_encryption = '
                'scram-sha-256 on the server and reset the password, or use TLS.' % (target, asked))
    if 'no pg_hba.conf entry' in message and 'no encryption' in message:
        return ('%s only accepts encrypted connections. Choose "TLS, self-signed certificate" instead.' % target)
    if 'certificate verify failed' in message:
        return ("TLS failed: the certificate of %s couldn't be verified. Upload its CA certificate, "
                'or choose "TLS, self-signed certificate".' % target)
    if 'does not match host name' in message:
        return ('TLS failed: the certificate of %s is for another name. Connect with the name in the '
                'certificate, or choose "TLS, self-signed certificate".' % target)
    if 'server does not support SSL' in message or 'SSL is not enabled' in message:
        return ("%s doesn't offer TLS. Turn on TLS (ssl = on) on the database server, or use an "
                'SSH tunnel.' % target)
    if 'no pg_hba.conf entry' in message:
        return ("%s doesn't let this login in (pg_hba.conf). Allow this portal's address, the user "
                'and the database there.' % target)
    if 'database "' in message and 'does not exist' in message:
        return "The database %s doesn't exist on %s. Enter another database." % (database, target)
    if 'too many connections' in message or 'remaining connection slots' in message:
        return '%s has too many connections right now. Try again later.' % target
    if 'Connection refused' in message:
        return ('The SSH tunnel works, but nothing is listening on %s.' % target if via_ssh
                else "Can't reach %s. Check the address, the port and the firewall." % target)
    if 'server closed the connection unexpectedly' in message or 'invalid response to SSL negotiation' in message \
            or 'received invalid response' in message or 'SSL SYSCALL error: EOF' in message:
        return ("The SSH tunnel works, but %s isn't reachable from the SSH server." % target if via_ssh
                else "%s accepted the connection but didn't answer like PostgreSQL." % target)
    if 'timeout expired' in message or 'timed out' in message or 'No route' in message \
            or 'unreachable' in message:
        return "Can't reach %s. Check the address, the port and the firewall." % target
    if 'could not translate host name' in message:
        return "Can't find %s. Check the host name." % target
    return 'Could not connect: ' + message[:160]


def run(d, full):
    out = {'ok': False, 'auth_failed': False, 'checks': [], 'grants': [], 'superuser': False,
           'pin': None, 'error': None, 'version': '', 'latency_ms': None}
    user = str(d.get('user') or '')
    password = str(d.get('password') or '')
    method = str(d.get('method') or '')
    host = str(d.get('host') or '')
    database = str(d.get('database') or '') or 'postgres'
    try:
        port = int(d.get('port') or 5432)
    except (TypeError, ValueError):
        port = 5432
    target = '%s:%d' % (host, port)
    if blocked(user):
        out['error'] = 'postgres is blocked. Use a role with only the privileges it needs.'
        return out

    tunnel_key = None
    transport = ''
    conn = None
    try:
        connect_host, connect_port = host, port
        params = {'sslmode': 'prefer'}
        encrypted = False
        if method == 'internal':
            net.check_internal(host)
            transport = 'Internal network, nothing exposed to the internet'
        elif method == 'tls':
            net.check_remote(host)
            ca_pem = str(d.get('ca_pem') or '')
            params = {'sslmode': 'verify-full',
                      'sslrootcert': write_pem(CA_DIR, ca_pem) if ca_pem.strip() else SYSTEM_CA}
            transport = 'certificate verified'
            encrypted = True
        elif method == 'pinned':
            net.check_remote(host)
            seen = probe.certificate(host, port)
            pinned = str(d.get('pin_sha256') or '')
            if pinned and not hmac.compare_digest(pinned, seen['sha256']):
                out['pin'] = {'kind': 'tls', 'fingerprint': seen['sha256'], 'value': seen['pem'],
                              'strict': seen['strict'], 'mismatch': True}
                out['error'] = ('The certificate of %s changed since you trusted it. Connections are '
                                'blocked until you confirm the new one.' % target)
                return out
            if not pinned:
                out['pin'] = {'kind': 'tls', 'fingerprint': seen['sha256'], 'value': seen['pem'],
                              'strict': seen['strict'], 'mismatch': False}
            strict = bool(d.get('pin_strict')) if pinned else seen['strict']
            pem = str(d.get('pin_pem') or '') if pinned else seen['pem']
            if strict:
                params = {'sslmode': 'verify-ca', 'sslrootcert': write_pem(CA_DIR, pem)}
            else:
                params = {'sslmode': 'require'}
            transport = ('self-signed certificate (trust it below)' if not pinned
                         else 'pinned certificate verified' if strict else 'certificate fingerprint matched')
            encrypted = True
        elif method == 'plain':
            net.check_remote(host)
            params = dict(PLAIN_PARAMS)
        elif method == 'ssh':
            ssh = d.get('ssh') if isinstance(d.get('ssh'), dict) else {}
            ssh_host = str(ssh.get('host') or '')
            net.check_remote(ssh_host)
            pinned = str(ssh.get('hostkey') or '')
            tunnel_key = 'test-' + secrets.token_hex(6)
            try:
                # No separate key scan: OpenSSH penalises connections that never log in.
                tunnel = tunnels.open_tunnel(tunnel_key, ssh, pinned, host, port, learn=pinned == '')
            except UserError as error:
                if pinned and "doesn't match" in str(error):
                    scanned = tunnels.scan(ssh_host, int(ssh.get('port') or 22))
                    out['pin'] = {'kind': 'ssh', 'fingerprint': scanned['fingerprint'], 'value': scanned['line'],
                                  'strict': True, 'mismatch': True}
                    out['error'] = ('The host key of %s changed since you trusted it. Connections are '
                                    'blocked until you confirm the new one.' % ssh_host)
                    return out
                raise
            if not pinned:
                out['pin'] = {'kind': 'ssh', 'fingerprint': tunnel['fingerprint'], 'value': tunnel['hostkey'],
                              'strict': True, 'mismatch': False}
            connect_host, connect_port = '127.0.0.1', tunnel['port']
            out['checks'].append('SSH connected to %s as %s' % (ssh_host, ssh.get('user') or ''))
            out['checks'].append('Tunnel open to %s' % target)
            transport = 'encrypted by the SSH tunnel'
        else:
            raise UserError('Unknown connection method.')

        started = time.monotonic()
        conn = connect(connect_host, connect_port, user, password, database, params)
        out['latency_ms'] = int(round((time.monotonic() - started) * 1000))
        out['version'] = version(conn)
        tls = tls_version(conn)
        if encrypted and not tls:
            raise UserError('The connection to %s is not encrypted. Turn on TLS on the database server.' % target)
        if tls and encrypted:
            transport = tls.replace('TLSv', 'TLS ') + ', ' + transport
        if method != 'ssh':
            out['checks'].insert(0, 'Reached the server in %d ms' % out['latency_ms'])
        out['checks'].append(out['version'] + ', ' + transport if method == 'ssh' else out['version'])
        if method == 'plain':
            out['checks'].append({'text': 'Not encrypted. Queries and results travel in clear text.', 'warn': True})
            out['checks'].append('Password checked with SCRAM-SHA-256, never sent')
        elif method != 'ssh':
            out['checks'].append(transport[:1].upper() + transport[1:])
        if full:
            lines, risky, current = privileges(conn)
            out['checks'].append('Signed in as ' + current)
            out['grants'] = lines
            out['superuser'] = risky
            if not risky:
                out['checks'].append('Not a superuser, postgres is not used')
            if method == 'plain' and probe.offers_tls(host, port):
                # The owner could encrypt this connection: the portal suggests it.
                out['tls_offered'] = True
        out['ok'] = True
    except AuthFailed:
        out['auth_failed'] = True
        out['error'] = 'The database rejected this user name or password.'
    except UserError as error:
        out['error'] = str(error)
    except psycopg.Error as error:
        out['error'] = friendly(error, target, database, method == 'ssh')
    except Exception as error:  # noqa: BLE001 (report, never crash the API)
        out['error'] = friendly(error, target, database, method == 'ssh')
    finally:
        if conn is not None:
            try:
                conn.close()
            except psycopg.Error:
                pass
        if tunnel_key is not None:
            tunnels.close(tunnel_key)
    return out
