"""
Client for the SSH tunnel service (dbportal.tunneld), which runs as its own process.
"""
import json
import re
import socket

from .common import UserError

SOCKET = '/run/dbportal/tunneld.sock'


def _call(message, timeout):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(3)
        sock.connect(SOCKET)
    except OSError:
        sock.close()
        raise UserError('The SSH tunnel service is not running. Try again in a moment.') from None
    data = b''
    try:
        sock.settimeout(timeout)
        sock.sendall(json.dumps(message).encode() + b'\n')
        while not data.endswith(b'\n') and len(data) < 1_000_000:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
    except OSError:
        data = b''
    finally:
        sock.close()
    try:
        result = json.loads(data)
    except ValueError:
        result = None
    if not isinstance(result, dict):
        raise UserError('The SSH tunnel service did not answer in time.')
    return result


def open_tunnel(key, ssh, hostkey, db_host, db_port, learn=False):
    """
    Opens (or reuses) a tunnel and returns {'port', 'hostkey', 'fingerprint'}. With learn and no
    host key, the SSH server's key is recorded on this first login and returned for the user to
    trust; later connections require that exact key.
    """
    result = _call({
        'action': 'open', 'key': key,
        'host': str(ssh.get('host') or ''), 'port': int(ssh.get('port') or 22),
        'user': str(ssh.get('user') or ''), 'auth': str(ssh.get('auth') or 'key'),
        'secret': str(ssh.get('secret') or ''), 'hostkey': hostkey, 'learn': bool(learn),
        'db_host': db_host, 'db_port': int(db_port),
    }, 30)
    if not result.get('ok'):
        raise UserError(str(result.get('error') or 'Could not open the SSH tunnel.'))
    return {
        'port': int(result['port']),
        'hostkey': str(result.get('hostkey') or ''),
        'fingerprint': str(result.get('fingerprint') or ''),
    }


def reserve(key):
    """The local port this tunnel uses (kept while it is open or closed only for being idle)."""
    try:
        result = _call({'action': 'reserve', 'key': key}, 5)
    except UserError:
        return 0
    return int(result.get('port') or 0) if result.get('ok') else 0


def touch(keys):
    """Marks tunnels as still in use."""
    if keys:
        try:
            _call({'action': 'touch', 'keys': sorted(keys)}, 5)
        except UserError:
            pass


def close(key):
    try:
        _call({'action': 'close', 'key': key}, 10)
    except UserError:
        pass  # the tunnel service closes idle tunnels on its own


def scan(host, port):
    result = _call({'action': 'scan', 'host': host, 'port': int(port)}, 20)
    if not result.get('ok'):
        raise UserError(str(result.get('error') or "Couldn't read the SSH host key."))
    return {'line': str(result['line']), 'fingerprint': str(result['fingerprint'])}


def same_key(a, b):
    """Compares two known_hosts lines by key type and key, ignoring the host part."""
    pa = re.split(r'\s+', (a or '').strip())
    pb = re.split(r'\s+', (b or '').strip())
    return len(pa) >= 3 and len(pb) >= 3 and pa[1] == pb[1] and pa[2] == pb[2]
