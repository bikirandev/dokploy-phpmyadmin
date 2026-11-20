"""
DB Portal's layer inside pgAdmin.

Who is this? The gateway lets a request through only after the portal confirmed the person's
portal session, and adds the portal's signed assertion. Gate (the outermost WSGI layer) sends the
assertion and the ticket ids from the person's cookies to the portal, which answers who they are
and returns their open PostgreSQL sessions, encrypted; the keys come from the same cookies.
pgAdmin's own "webserver" sign-in then logs that person in from REMOTE_USER, which only Gate sets.

Before each request: the signed-in pgAdmin user must be the one the portal vouches for (pgAdmin
doesn't check this again by itself); the servers opened in the portal are mirrored into a
"DB Portal" group and everything else is removed; features that would bypass the portal are
refused.

Connections: every connection pgAdmin opens is built by ServerManager.create_connection_string,
and its database tools get their password from ServerManager.export_password_env. Both take the
host, port, user, TLS settings and password from the open session in the current request, never
from pgAdmin's database. pgAdmin stores no database passwords.

A background thread closes connections and SSH tunnels within a minute after their portal
session ends.
"""
import hashlib
import html
import json
import logging
import os
import re
import threading
import time
from types import SimpleNamespace

from werkzeug.http import parse_cookie

from . import common, net, probe, tunnels
from .common import UserError

log = logging.getLogger('dbportal')

GROUP_NAME = 'DB Portal'
ROW_PREFIX = 'dbportal:'
USER_RE = re.compile(r'^dbp-[a-f0-9]{24}$')
ROW_RE = re.compile(r'^[a-f0-9]{40}$')
KEY_RE = re.compile(r'^[a-f0-9]{64}$')
SESSION_COOKIE = '__Host-pga_session'  # SESSION_COOKIE_NAME in config_local.py
COMMENT = 'Opened from DB Portal. Its connection settings and password are managed there.'
ENV_TAGS = {'Production': '#ff8c8c', 'Staging': '#f2b33d', 'Development': '#7ea8ff'}
CONNECTION_FIELDS = {'host', 'port', 'maintenance_db', 'username', 'connection_params'}

# Variables and headers a client must never be able to set.
STRIP = ('REMOTE_USER', 'HTTP_REMOTE_USER', 'HTTP_X_SCRIPT_NAME', 'HTTP_X_SCHEME', 'HTTP_X_FORWARDED_HOST',
         'HTTP_X_FORWARDED_PORT', 'HTTP_X_FORWARDED_PREFIX', 'HTTP_X_PGADMIN_WEBSERVER_SECRET')

MSG_NOT_OPEN = 'This server is not open in DB Portal in this browser. Open it again from DB Portal.'
MSG_OTHER_USER = ('DB Portal opened this server as %s. To use another database user, open the server '
                  'from DB Portal with that user.')
MSG_SERVERS = 'Servers are managed in DB Portal. Add or change them there, then open them.'
MSG_PASSWORD = 'Change the password with ALTER ROLE in the Query Tool, then update it in DB Portal.'
MSG_FEATURE = 'This pgAdmin feature is turned off in DB Portal.'
MSG_SESSION = 'DB Portal could not confirm your session. Open the server again from DB Portal.'

BLOCKED_BLUEPRINTS = {'cloud', 'azure', 'rds', 'google', 'starfleet', 'import_export_servers', 'psql',
                      'llm', 'kerberos', 'oauth2', 'mfa', 'user_management'}
# Read-only answers pgAdmin's page needs even with those features off ("who am I", "AI is off").
ALLOWED_ENDPOINTS = {'user_management.current_user_info', 'llm.status'}
BLOCKED_ENDPOINTS = {
    ('NODE-server.obj', 'POST'): MSG_SERVERS,
    ('NODE-server.obj_id', 'PUT'): MSG_SERVERS,
    ('NODE-server.obj_id', 'DELETE'): MSG_SERVERS,
    ('NODE-server_group.obj', 'POST'): MSG_SERVERS,
    ('NODE-server_group.obj_id', 'PUT'): MSG_SERVERS,
    ('NODE-server_group.obj_id', 'DELETE'): MSG_SERVERS,
    ('NODE-server.change_password_id', 'POST'): MSG_PASSWORD,
    ('NODE-server.clear_saved_password_id', 'PUT'): MSG_SERVERS,
    ('NODE-server.clear_sshtunnel_password_id', 'PUT'): MSG_SERVERS,
    ('workspace.adhoc_connect_server', 'POST'): MSG_SERVERS,
}

_local = threading.local()
_lock = threading.Lock()
_sessions = {}      # pgAdmin session id -> {'user', 'seen', 'servers': {server id: ticket key}}
_tunnel_users = {}  # tunnel key -> ticket keys using it
_user_locks = {}
_system_ca = []


# ---------------------------------------------------------------------------------------------
# Who is this? (WSGI)
# ---------------------------------------------------------------------------------------------

def _looks_static(path):
    return path == '/favicon.ico' or path.startswith('/static/') or '/static/' in path


class Gate:
    """Outermost WSGI layer: asks the portal who sent this request and what they opened."""

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        for key in STRIP:
            environ.pop(key, None)
        path = environ.get('PATH_INFO') or '/'
        if path == '/misc/ping' or _looks_static(path):
            return self.app(environ, start_response)
        ctx = _load_context(environ)
        if ctx is not None:
            environ['REMOTE_USER'] = ctx.user
            environ['dbportal.ctx'] = ctx
        if path.startswith('/socket.io'):
            # Socket.IO events don't pass through Flask's request hooks: check the session here.
            if ctx is None or not _session_belongs_to(environ, ctx.user):
                return _plain(start_response, '403 Forbidden', MSG_SESSION)
        return self.app(environ, start_response)


def _load_context(environ):
    assertion = environ.get('HTTP_X_DBP_ASSERTION') or ''
    if not assertion or len(assertion) > 4096:
        return None
    cookies = parse_cookie(environ.get('HTTP_COOKIE') or '')
    tickets, keys = {}, {}
    for slot in range(1, common.MAX_SLOTS + 1):
        value = cookies.get(common.COOKIE_PREFIX + str(slot))
        if isinstance(value, str) and value.count('.') == 1:
            tickets[slot], keys[slot] = value.split('.', 1)
    answer = common.post_json('/internal/pga-session', {
        'assertion': assertion,
        'tickets': {str(slot): ticket for slot, ticket in tickets.items()},
    })
    if not answer or not USER_RE.match(str(answer.get('user') or '')):
        return None
    by_row = {}
    for item in answer.get('servers') or []:
        if not isinstance(item, dict):
            continue
        try:
            slot = int(item.get('slot'))
        except (TypeError, ValueError):
            continue
        if slot not in keys:
            continue
        descriptor = common.open_ticket(common.b64d(tickets[slot]), common.b64d(keys[slot]),
                                        common.b64d(str(item.get('c') or '')), common.b64d(str(item.get('n') or '')))
        if descriptor is None or descriptor.get('kind') != 'postgres' \
                or not ROW_RE.match(str(descriptor.get('row') or '')):
            continue
        by_row[descriptor['row']] = descriptor
    open_rows = {row for row in answer.get('open_rows') or [] if isinstance(row, str) and ROW_RE.match(row)}
    return SimpleNamespace(user=answer['user'], by_row=by_row, open_rows=open_rows | set(by_row), sid_cache={})


def _session_belongs_to(environ, user):
    value = parse_cookie(environ.get('HTTP_COOKIE') or '').get(SESSION_COOKIE) or ''
    sid = value.split('!', 1)[0]
    with _lock:
        entry = _sessions.get(sid)
    return bool(sid) and entry is not None and entry['user'] == user


def _plain(start_response, status, text):
    body = text.encode()
    start_response(status, [('Content-Type', 'text/plain; charset=utf-8'), ('Content-Length', str(len(body))),
                            ('Cache-Control', 'no-store')])
    return [body]


# ---------------------------------------------------------------------------------------------
# Before each request (Flask)
# ---------------------------------------------------------------------------------------------

def _skip(endpoint):
    return endpoint == 'static' or endpoint.endswith('.static') or endpoint == 'misc.ping'


def _guard():
    """Runs first: right person, sign-out goes to the portal, no feature that bypasses the portal."""
    from flask import redirect, request, session
    from flask_login import current_user
    from flask_security.utils import logout_user

    endpoint = request.endpoint or ''
    if _skip(endpoint):
        return None
    ctx = request.environ.get('dbportal.ctx')
    if ctx is None:
        return _refuse(403, MSG_SESSION)
    if current_user.is_authenticated and (current_user.username != ctx.user
                                          or current_user.auth_source != 'webserver'):
        # Someone else's pgAdmin session, for example after a sign-out on a shared computer.
        _forget_session(session.sid)
        logout_user()
        session.clear()
        return _relogin()
    if endpoint == 'webserver.login':
        # pgAdmin's own sign-in page would only sign the user out: sign in from the portal instead.
        return redirect('/', 303)
    if endpoint in ('security.logout', 'webserver.logout'):
        # pgAdmin's "Log out" (or its inactivity timeout) closes the pgAdmin sessions in the portal.
        _forget_session(session.sid)
        if current_user.is_authenticated:
            logout_user()
        session.clear()
        return redirect(common.PGA_URL + '/__dbportal/close', 303)
    reason = _blocked(endpoint, request.method, getattr(request, 'blueprints', None) or [request.blueprint or ''])
    if reason:
        return _refuse(403, reason)
    if current_user.is_authenticated:
        _remember_session(session.sid, ctx.user)
    return None


def _blocked(endpoint, method, blueprints):
    if endpoint in ALLOWED_ENDPOINTS:
        return None
    names = {endpoint.split('.', 1)[0]}
    for name in blueprints:
        names.update(name.split('.'))
    if names & BLOCKED_BLUEPRINTS:
        return MSG_FEATURE
    return BLOCKED_ENDPOINTS.get((endpoint, method))


def _relogin():
    from flask import redirect, request
    if request.method == 'GET' and 'text/html' in (request.headers.get('Accept') or ''):
        return redirect('/', 303)
    return _refuse(401, 'You were signed out. Reload the page.')


def _refuse(status, message):
    from flask import Response, request
    from pgadmin.utils.ajax import make_json_response
    if request.method == 'GET' and 'text/html' in (request.headers.get('Accept') or ''):
        return Response(_page(message), status=status, mimetype='text/html')
    return make_json_response(success=0, status=status, errormsg=message)


def _page(message):
    portal = html.escape(common.PORTAL_URL + '/servers', quote=True)
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1"><title>Not available</title>'
        '<style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;'
        'background:#0e1013;color:#eceef1;font:15px/1.5 system-ui,sans-serif;padding:20px}'
        'main{max-width:520px;background:#15181d;border:1px solid #262b34;border-radius:14px;padding:28px;'
        'display:flex;flex-direction:column;gap:14px}h1{margin:0;font-size:24px}p{margin:0;color:#a7aeba}'
        'a{color:#f2b33d}</style></head><body><main><h1>Not available</h1><p>%s</p>'
        '<p><a href="%s">Back to my servers</a></p></main></body></html>' % (html.escape(message), portal)
    )


def _sync():
    """Runs after pgAdmin's own hooks: mirrors the servers opened in the portal."""
    from flask import request
    from flask_login import current_user
    from pgadmin.model import db

    endpoint = request.endpoint or ''
    if _skip(endpoint) or not current_user.is_authenticated:
        return None
    ctx = request.environ.get('dbportal.ctx')
    if ctx is None:
        return None
    with _user_lock(current_user.id):
        try:
            _apply(ctx)
        except Exception:  # noqa: BLE001 (the request goes on; connections are checked again anyway)
            db.session.rollback()
            log.exception('DB Portal: could not update the server list')
    return None


def _apply(ctx):
    from flask import session
    from flask_login import current_user
    from pgadmin.model import Server, ServerGroup, db

    uid = current_user.id
    groups = ServerGroup.query.filter_by(user_id=uid).order_by(ServerGroup.id).all()
    group = next((g for g in groups if g.name == GROUP_NAME), None)
    if group is None and groups:
        group = groups[0]
        group.name = GROUP_NAME
    if group is None:
        group = ServerGroup(user_id=uid, name=GROUP_NAME)
        db.session.add(group)
    db.session.flush()

    keep = {}
    for row in Server.query.filter_by(user_id=uid).all():
        key = _row_key(row)
        if key and key in ctx.open_rows and row.servergroup_id == group.id and key not in keep \
                and not row.is_adhoc:
            keep[key] = row
        else:
            _release(session.sid, row.id)
            db.session.delete(row)
    for other in groups:
        if other is not group:
            db.session.delete(other)

    rows = {}
    for key, descriptor in ctx.by_row.items():
        values = _row_values(descriptor, group.id)
        row = keep.get(key)
        if row is None:
            row = Server(user_id=uid, **values)
            db.session.add(row)
        else:
            changed = [name for name, value in values.items() if getattr(row, name) != value]
            for name in changed:
                setattr(row, name, values[name])
            if CONNECTION_FIELDS.intersection(changed):
                _release(session.sid, row.id)
        rows[key] = row
    if db.session.new or db.session.dirty or db.session.deleted:
        db.session.commit()

    _remember_servers(session.sid, ctx.user, {row.id: ctx.by_row[key]['key'] for key, row in rows.items()})
    # pgAdmin's database tools read connection settings from its in-memory server managers.
    for key, row in rows.items():
        manager = _manager(session.sid, row.id)
        if manager is not None:
            try:
                _prepare(manager, ctx.by_row[key], real=False)
            except PermissionError:
                pass


def _row_key(row):
    value = (row.discovery_id or '') if row is not None else ''
    key = value[len(ROW_PREFIX):]
    return key if value.startswith(ROW_PREFIX) and ROW_RE.match(key) else None


def _database(descriptor):
    return str(descriptor.get('database') or '') or 'postgres'


def _row_values(descriptor, group_id):
    if descriptor.get('method') == 'ssh':
        host, port = '127.0.0.1', tunnels.reserve(_tunnel_key(descriptor)) or 1
    else:
        host, port = str(descriptor.get('host') or ''), int(descriptor.get('port') or 5432)
    environment = str(descriptor.get('environment') or '')
    return {
        'servergroup_id': group_id,
        'name': str(descriptor.get('name') or 'Server')[:128],
        'host': host[:128],
        'port': port,
        'maintenance_db': _database(descriptor)[:64],
        'username': str(descriptor.get('user') or '')[:64],
        'password': None,
        'save_password': 1,
        'role': None,
        'comment': COMMENT,
        'discovery_id': ROW_PREFIX + descriptor['row'],
        'db_res': None,
        'passexec_cmd': None,
        'passexec_expiration': None,
        'passexec_name': None,
        'service': None,
        'use_ssh_tunnel': 0,
        'tunnel_host': None,
        'tunnel_port': 22,
        'tunnel_username': None,
        'tunnel_authentication': 0,
        'tunnel_identity_file': None,
        'tunnel_prompt_password': 0,
        'tunnel_password': None,
        'tunnel_keep_alive': 0,
        'shared': False,
        'shared_username': None,
        'kerberos_conn': False,
        'cloud_status': 0,
        'connection_params': _conn_params(descriptor),
        'is_adhoc': 0,
        'post_connection_sql': None,
        'bgcolor': None,
        'fgcolor': None,
        'tags': [{'text': environment, 'color': ENV_TAGS[environment]}] if environment in ENV_TAGS else None,
    }


# ---------------------------------------------------------------------------------------------
# Connection settings
# ---------------------------------------------------------------------------------------------

def _system_bundle():
    if not _system_ca:
        with open(common.SYSTEM_CA, encoding='utf-8') as handle:
            _system_ca.append(handle.read())
    return _system_ca[0]


def _storage_pem(pem):
    """pgAdmin only reads certificate files from the user's own storage folder: put a copy there."""
    from pgadmin.utils.paths import get_storage_directory
    storage = get_storage_directory()
    if not storage:
        raise PermissionError('pgAdmin has no storage folder for this user.')
    path = common.write_pem(os.path.join(storage, '.dbportal'), pem)
    return '/.dbportal/' + os.path.basename(path)


def _conn_params(descriptor):
    method = descriptor.get('method')
    params = {'connect_timeout': 10}
    if method == 'tls':
        pem = str(descriptor.get('ca_pem') or '')
        params.update(sslmode='verify-full', sslrootcert=_storage_pem(pem if pem.strip() else _system_bundle()))
    elif method == 'pinned' and descriptor.get('pin_strict'):
        params.update(sslmode='verify-ca', sslrootcert=_storage_pem(str(descriptor.get('pin_pem') or '')))
    elif method == 'pinned':
        params['sslmode'] = 'require'
    else:
        params['sslmode'] = 'prefer'
    return params


def _tunnel_key(descriptor):
    from flask_login import current_user
    ssh = descriptor.get('ssh') if isinstance(descriptor.get('ssh'), dict) else {}
    material = [current_user.username, descriptor.get('row'), ssh.get('host'), ssh.get('port'), ssh.get('user'),
                ssh.get('auth'), ssh.get('hostkey'), descriptor.get('host'), descriptor.get('port')]
    return hashlib.sha256(json.dumps(material, default=str).encode()).hexdigest()


def _prepare(manager, descriptor, real):
    """
    Points pgAdmin's server manager at the open session's settings. For a real connection the
    address policy, the certificate pin and the SSH tunnel are checked first.
    """
    method = descriptor.get('method')
    host = str(descriptor.get('host') or '')
    port = int(descriptor.get('port') or 5432)
    try:
        if method == 'ssh':
            ssh = descriptor.get('ssh') if isinstance(descriptor.get('ssh'), dict) else {}
            key = _tunnel_key(descriptor)
            if real:
                net.check_remote(str(ssh.get('host') or ''))
                port = tunnels.open_tunnel(key, ssh, str(ssh.get('hostkey') or ''), host, port)['port']
                _remember_tunnel(key, descriptor['key'])
            else:
                port = tunnels.reserve(key) or 1
            host = '127.0.0.1'
        elif method in ('internal', 'tls', 'pinned'):
            if real:
                if method == 'internal':
                    net.check_internal(host)
                else:
                    net.check_remote(host)
                if method == 'pinned' and not descriptor.get('pin_strict'):
                    seen = probe.cached_fingerprint(descriptor['key'], host, port)
                    if not common.same(descriptor.get('pin_sha256') or '', seen):
                        raise UserError("The certificate of %s:%d changed since you trusted it. Open the server's "
                                        'settings in DB Portal and run a test to review it.' % (host, port))
        else:
            raise UserError('This server has an unknown connection method.')
        params = _conn_params(descriptor)
    except UserError as error:
        raise PermissionError(str(error)) from None
    manager.host = host
    manager.port = port
    manager.user = str(descriptor.get('user') or '')
    manager.db = _database(descriptor)
    manager.connection_params = params
    manager.use_ssh_tunnel = 0
    manager.service = None
    manager.passexec = None
    manager.kerberos_conn = False


def _descriptor_for(server_id):
    """The open session (from this request's cookies) behind one of pgAdmin's server entries."""
    from flask import has_request_context, request
    from flask_login import current_user
    from pgadmin.model import Server

    if not has_request_context():
        return None
    ctx = request.environ.get('dbportal.ctx')
    if ctx is None or not current_user or not current_user.is_authenticated:
        return None
    if server_id not in ctx.sid_cache:
        row = Server.query.filter_by(id=server_id, user_id=current_user.id).first()
        key = _row_key(row)
        ctx.sid_cache[server_id] = ctx.by_row.get(key) if key else None
    return ctx.sid_cache[server_id]


def _patch():
    from pgadmin.utils.driver.psycopg3.connection import Connection
    from pgadmin.utils.driver.psycopg3.server_manager import ServerManager

    original_connect = Connection.connect
    original_string = ServerManager.create_connection_string

    def connect(self, **kwargs):
        _local.depth = getattr(_local, 'depth', 0) + 1
        try:
            return original_connect(self, **kwargs)
        finally:
            _local.depth -= 1

    def create_connection_string(self, database, user, password=None, for_utility=False):
        descriptor = _descriptor_for(self.sid)
        if descriptor is None:
            raise PermissionError(MSG_NOT_OPEN)
        if user and user != descriptor.get('user'):
            raise PermissionError(MSG_OTHER_USER % descriptor.get('user'))
        _prepare(self, descriptor, real=bool(for_utility) or getattr(_local, 'depth', 0) > 0)
        return original_string(self, database, str(descriptor.get('user') or ''),
                               str(descriptor.get('password') or '') or None, for_utility)

    def export_password_env(self, env, name='PGPASSWORD'):
        descriptor = _descriptor_for(self.sid)
        if descriptor is None:
            raise PermissionError(MSG_NOT_OPEN)
        _prepare(self, descriptor, real=True)
        if descriptor.get('password'):
            env[str(name)] = str(descriptor['password'])
        return None

    Connection.connect = connect
    ServerManager.create_connection_string = create_connection_string
    ServerManager.export_password_env = export_password_env


# ---------------------------------------------------------------------------------------------
# Which pgAdmin session uses which open portal session (for the cleanup thread)
# ---------------------------------------------------------------------------------------------

def _user_lock(uid):
    with _lock:
        return _user_locks.setdefault(uid, threading.Lock())


def _remember_session(sid, user):
    with _lock:
        entry = _sessions.get(sid)
        if entry is None or entry['user'] != user:
            entry = _sessions[sid] = {'user': user, 'seen': 0, 'servers': {}}
        entry['seen'] = time.time()


def _remember_servers(sid, user, servers):
    with _lock:
        _sessions[sid] = {'user': user, 'seen': time.time(), 'servers': dict(servers)}


def _remember_tunnel(key, ticket):
    with _lock:
        _tunnel_users.setdefault(key, set()).add(ticket)


def _forget_session(sid):
    with _lock:
        _sessions.pop(sid, None)


def _manager(sid, server_id):
    from config import PG_DEFAULT_DRIVER
    from pgadmin.utils.driver import get_driver
    managers = get_driver(PG_DEFAULT_DRIVER).managers.get(sid)
    return managers.get(str(server_id)) if isinstance(managers, dict) else None


def _release(sid, server_id):
    from config import PG_DEFAULT_DRIVER
    from pgadmin.utils.driver import get_driver
    managers = get_driver(PG_DEFAULT_DRIVER).managers.get(sid)
    manager = managers.pop(str(server_id), None) if isinstance(managers, dict) else None
    if manager is not None:
        try:
            manager.release()
        except Exception:  # noqa: BLE001
            log.exception('DB Portal: could not close a connection')


def _reap(app):
    now = time.time()
    with _lock:
        for sid in [sid for sid, entry in _sessions.items() if entry['seen'] < now - 86400]:
            _sessions.pop(sid, None)
        sessions = {sid: dict(entry['servers']) for sid, entry in _sessions.items()}
        tunnel_users = {key: set(users) for key, users in _tunnel_users.items()}
    tickets = set()
    for servers in sessions.values():
        tickets.update(servers.values())
    for users in tunnel_users.values():
        tickets.update(users)
    tickets = {ticket for ticket in tickets if KEY_RE.match(str(ticket))}
    if not tickets:
        return
    answer = common.post_json('/internal/pga-alive', {'tickets': sorted(tickets)}, timeout=10)
    if answer is None:
        return  # portal unreachable: try again next time
    alive = {ticket for ticket in answer.get('alive') or [] if isinstance(ticket, str)}
    dead = tickets - alive
    closing = []
    if dead:
        # A throwaway request context (on a path pgAdmin keeps no session for): closing a
        # connection updates the manager's state in "the" session.
        with app.test_request_context('/misc/ping'):
            for sid, servers in sessions.items():
                for server_id, ticket in servers.items():
                    manager = _manager(sid, server_id) if ticket in dead else None
                    if manager is not None:
                        try:
                            manager.release()
                        except Exception:  # noqa: BLE001
                            log.exception('DB Portal: could not close a connection')
        with _lock:
            for entry in _sessions.values():
                entry['servers'] = {s: t for s, t in entry['servers'].items() if t not in dead}
            for key in list(_tunnel_users):
                _tunnel_users[key] -= dead
                if not _tunnel_users[key]:
                    del _tunnel_users[key]
                    closing.append(key)
        for key in closing:
            tunnels.close(key)
    tunnels.touch([key for key, users in tunnel_users.items() if users & alive])


def _reaper(app):
    while True:
        time.sleep(60)
        try:
            _reap(app)
        except Exception:  # noqa: BLE001
            log.exception('DB Portal: cleanup failed')


def install(app):
    """Installs the layer on pgAdmin's Flask app and returns it."""
    app.before_request_funcs.setdefault(None, []).insert(0, _guard)
    app.before_request(_sync)
    _patch()
    app.wsgi_app = Gate(app.wsgi_app)
    threading.Thread(target=_reaper, args=(app,), daemon=True, name='dbportal-cleanup').start()
    return app
