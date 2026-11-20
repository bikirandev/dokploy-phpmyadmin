"""
SSH tunnel service for pgAdmin's container, started by the entrypoint (python -m dbportal.tunneld).

Protocol: one JSON request per connection on a unix socket, one JSON line back.
Tunnels close after 30 minutes without use and after 12 hours at most. A tunnel keeps its local
port while this service knows it, so pgAdmin's server entry can point at the port before the
tunnel opens (and again after an idle tunnel is reopened).
"""
import ipaddress
import json
import os
import re
import signal
import socket
import socketserver
import subprocess
import threading
import time

SOCKET = '/run/dbportal/tunneld.sock'
RUN = '/run/dbportal'
DIR = '/run/dbportal/tunnels'
IDLE_SECONDS = 1800
MAX_AGE_SECONDS = 43200
PATH_ENV = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

_KEY = re.compile(r'^([a-f0-9]{64}|test-[a-f0-9]{12})$')
_HOST = re.compile(r'^[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,251}[A-Za-z0-9_])?$')
_USER = re.compile(r'^[A-Za-z0-9._-]{1,64}$')

_tunnels = {}    # key -> {'proc', 'port', 'started', 'used'}
_ports = {}      # key -> [local port, last used]
_lock = threading.Lock()
_key_locks = {}


def log(message):
    print('[tunneld] %s' % message, flush=True)


def valid_key(key):
    return isinstance(key, str) and bool(_KEY.match(key))


def valid_host(host):
    if not isinstance(host, str) or not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_HOST.match(host))


def valid_port(port):
    return isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535


def _key_lock(key):
    with _lock:
        return _key_locks.setdefault(key, threading.Lock())


def _alive(proc):
    return proc.poll() is None


def _port_open(port):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=0.3):
            return True
    except OSError:
        return False


def _port_free(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind(('127.0.0.1', port))
            return True
        except OSError:
            return False


def _reserve(key):
    with _lock:
        entry = _ports.get(key)
        if entry is None:
            taken = {port for port, _ in _ports.values()}
            port = 0
            for _ in range(50):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.bind(('127.0.0.1', 0))
                    port = sock.getsockname()[1]
                if port not in taken:
                    break
            entry = _ports[key] = [port, time.time()]
        entry[1] = time.time()
        return entry[0]


def _files(key):
    return ['%s/%s.%s' % (DIR, key, ext) for ext in ('known_hosts', 'key', 'log')]


def _cleanup_files(key):
    for path in _files(key):
        try:
            os.unlink(path)
        except OSError:
            pass


def _terminate(proc):
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except OSError:
        pass
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass


def _stop(key, forget_port=False):
    with _lock:
        tunnel = _tunnels.pop(key, None)
        if forget_port:
            _ports.pop(key, None)
    if tunnel:
        _terminate(tunnel['proc'])
    _cleanup_files(key)


def _run(cmd, stdin):
    try:
        result = subprocess.run(cmd, input=stdin.encode(), capture_output=True, timeout=20, cwd=RUN,
                                env={'PATH': PATH_ENV, 'HOME': RUN}, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ''
    return result.stdout.decode('utf-8', 'replace')


def fingerprint(line):
    """'SHA256:... (ED25519)' for a known_hosts line."""
    out = _run(['ssh-keygen', '-l', '-E', 'sha256', '-f', '-'], line + '\n').strip()
    parts = out.split()
    kind = parts[-1].strip('()') if parts else ''
    return (parts[1] if len(parts) > 1 else out) + (' (%s)' % kind if kind else '')


def ssh_error(text, host):
    if 'Host key verification failed' in text or 'REMOTE HOST IDENTIFICATION HAS CHANGED' in text:
        return "The host key of %s doesn't match the one you trusted." % host
    if 'Permission denied' in text:
        return 'The SSH server rejected the user, key or password.'
    if 'Connection refused' in text:
        return 'The SSH server %s refused the connection. Check the port.' % host
    if 'timed out' in text or 'No route' in text or 'unreachable' in text:
        return "Can't reach the SSH server %s. Check the address and its firewall." % host
    if 'Could not resolve' in text:
        return "Can't find the SSH server %s." % host
    if 'invalid format' in text or 'load pubkey' in text or 'Load key' in text:
        return 'The private key could not be read. Paste the whole key, including the BEGIN and END lines.'
    if 'administratively prohibited' in text or 'forwarding' in text:
        return 'The SSH server does not allow port forwarding for this user (AllowTcpForwarding).'
    return 'Could not open the SSH tunnel.'


def open_tunnel(r):
    key = r.get('key')
    host = r.get('host')
    port = r.get('port', 22)
    user = r.get('user')
    auth = r.get('auth', 'key')
    secret = r.get('secret') or ''
    hostkey = str(r.get('hostkey') or '').strip()
    learn = bool(r.get('learn')) and hostkey == ''
    db_host = r.get('db_host')
    db_port = r.get('db_port', 5432)
    if not valid_key(key) or not valid_host(host) or not valid_port(port) or not valid_host(db_host) \
            or not valid_port(db_port) or not isinstance(user, str) or not _USER.match(user) \
            or auth not in ('key', 'password') or not isinstance(secret, str) or secret == '' \
            or (hostkey == '' and not learn) or '\n' in hostkey:
        return {'ok': False, 'error': 'The SSH settings are incomplete.'}

    with _key_lock(key):
        with _lock:
            tunnel = _tunnels.get(key)
        if tunnel:
            if _alive(tunnel['proc']) and _port_open(tunnel['port']):
                tunnel['used'] = time.time()
                _reserve(key)
                return {'ok': True, 'port': tunnel['port']}
            _stop(key)

        local = _reserve(key)
        if not _port_free(local):
            # Something else took the port while the tunnel was closed: use another one.
            with _lock:
                _ports.pop(key, None)
            local = _reserve(key)

        known_hosts, key_file, log_file = _files(key)
        _cleanup_files(key)
        # First login (learn): record whatever key the server presents, for the user to confirm.
        # Afterwards: only the trusted key is accepted.
        with open(known_hosts, 'w', encoding='utf-8') as handle:
            handle.write('' if learn else hostkey + '\n')
        os.chmod(known_hosts, 0o600)

        cmd = [
            'ssh', '-N', '-T', '-F', '/dev/null',
            '-o', 'StrictHostKeyChecking=' + ('accept-new' if learn else 'yes'),
            '-o', 'UserKnownHostsFile=' + known_hosts,
            '-o', 'GlobalKnownHostsFile=/dev/null',
            '-o', 'UpdateHostKeys=no',
            '-o', 'ExitOnForwardFailure=yes',
            '-o', 'ServerAliveInterval=15',
            '-o', 'ServerAliveCountMax=3',
            '-o', 'ConnectTimeout=10',
            '-o', 'LogLevel=ERROR',
            '-o', 'ForwardAgent=no',
            '-o', 'ForwardX11=no',
            '-o', 'PermitLocalCommand=no',
            '-o', 'ClearAllForwardings=no',
            '-p', str(port),
            '-l', user,
            '-L', '127.0.0.1:%d:%s:%d' % (local, db_host, db_port),
        ]
        env = {'HOME': RUN, 'PATH': PATH_ENV}
        if auth == 'key':
            fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                handle.write(secret.rstrip() + '\n')
            cmd += ['-i', key_file, '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
                    '-o', 'PreferredAuthentications=publickey', '-o', 'PasswordAuthentication=no']
        else:
            cmd = ['sshpass', '-e'] + cmd + ['-o', 'PreferredAuthentications=password,keyboard-interactive',
                                             '-o', 'PubkeyAuthentication=no', '-o', 'NumberOfPasswordPrompts=1']
            env['SSHPASS'] = secret
        cmd.append(host)

        try:
            with open(log_file, 'ab') as log_handle:
                proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=log_handle, stderr=log_handle,
                                        cwd=RUN, env=env, start_new_session=True, close_fds=True)
        except OSError:
            _cleanup_files(key)
            return {'ok': False, 'error': 'Could not start SSH.'}

        deadline = time.time() + 15
        up = False
        while time.time() < deadline:
            if not _alive(proc):
                break
            if _port_open(local):
                up = True
                break
            time.sleep(0.15)
        try:
            os.unlink(key_file)  # ssh has read it by now (or failed)
        except OSError:
            pass

        if not up:
            try:
                with open(log_file, encoding='utf-8', errors='replace') as handle:
                    text = handle.read(20000)
            except OSError:
                text = ''
            _terminate(proc)
            _cleanup_files(key)
            return {'ok': False, 'error': ssh_error(text, host)}

        now = time.time()
        with _lock:
            _tunnels[key] = {'proc': proc, 'port': local, 'started': now, 'used': now}

        learned = ''
        if learn:
            try:
                with open(known_hosts, encoding='utf-8') as handle:
                    for line in handle:
                        if line.strip() and not line.strip().startswith('#'):
                            learned = line.strip()
                            break
            except OSError:
                learned = ''
            if not learned:
                _stop(key, forget_port=True)
                return {'ok': False, 'error': "Couldn't read the SSH host key of %s." % host}

        return {'ok': True, 'port': local, 'hostkey': learned, 'fingerprint': fingerprint(learned) if learned else ''}


def scan(host, port):
    if not valid_host(host) or not valid_port(port):
        return {'ok': False, 'error': 'Enter a valid SSH host and port.'}
    out = _run(['ssh-keyscan', '-T', '6', '-p', str(port), '-t', 'ed25519,ecdsa,rsa', host], '')
    lines = {}
    for line in out.splitlines():
        parts = line.strip().split()
        if len(parts) >= 3 and not parts[0].startswith('#'):
            lines[parts[1]] = ' '.join(parts[:3])
    line = lines.get('ssh-ed25519') or lines.get('ecdsa-sha2-nistp256') or lines.get('ssh-rsa') \
        or next(iter(lines.values()), '')
    if not line:
        return {'ok': False, 'error': "Can't reach the SSH server %s:%d, or it didn't send a host key." % (host, port)}
    return {'ok': True, 'line': line, 'fingerprint': fingerprint(line)}


def dispatch(r):
    action = r.get('action')
    if action == 'open':
        return open_tunnel(r)
    if action == 'reserve':
        key = r.get('key')
        return {'ok': True, 'port': _reserve(key)} if valid_key(key) else {'ok': False}
    if action == 'touch':
        now = time.time()
        with _lock:
            for key in r.get('keys') or []:
                if key in _tunnels:
                    _tunnels[key]['used'] = now
                if key in _ports:
                    _ports[key][1] = now
        return {'ok': True}
    if action == 'close':
        key = r.get('key')
        if not valid_key(key):
            return {'ok': False}
        with _key_lock(key):
            _stop(key, forget_port=True)
        return {'ok': True}
    if action == 'scan':
        return scan(r.get('host'), r.get('port', 22))
    return {'ok': False, 'error': 'Unknown request.'}


def reap():
    while True:
        time.sleep(5)
        now = time.time()
        with _lock:
            tunnels = list(_tunnels.items())
            stale_ports = [key for key, (_, used) in _ports.items()
                           if key not in _tunnels and used + MAX_AGE_SECONDS < now]
            for key in stale_ports:
                _ports.pop(key, None)
        for key, tunnel in tunnels:
            if not _alive(tunnel['proc']) or tunnel['used'] + IDLE_SECONDS < now \
                    or tunnel['started'] + MAX_AGE_SECONDS < now:
                lock = _key_lock(key)
                if lock.acquire(blocking=False):
                    try:
                        _stop(key)
                    finally:
                        lock.release()


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(5)
        try:
            line = self.rfile.readline(65536)
            request = json.loads(line) if line else None
        except (OSError, ValueError):
            request = None
        try:
            response = dispatch(request if isinstance(request, dict) else {})
        except Exception as error:  # noqa: BLE001 (one bad request must not stop the service)
            log('error: %s' % error)
            response = {'ok': False, 'error': 'The SSH tunnel service hit an error.'}
        try:
            self.wfile.write(json.dumps(response).encode() + b'\n')
        except OSError:
            pass


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True


def main():
    os.makedirs(DIR, mode=0o700, exist_ok=True)
    try:
        os.unlink(SOCKET)
    except OSError:
        pass
    server = Server(SOCKET, Handler)
    os.chmod(SOCKET, 0o600)
    threading.Thread(target=reap, daemon=True).start()

    def stop(*_):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    log('ready')
    try:
        server.serve_forever()
    finally:
        for key in list(_tunnels):
            _stop(key)


if __name__ == '__main__':
    main()
