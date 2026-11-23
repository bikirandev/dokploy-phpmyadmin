"""
Shared helpers. This container holds no long-term secrets: connection details arrive per request,
encrypted with a key that only the user's own browser cookie carries.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import urllib.error
import urllib.request

from nacl import bindings as sodium
from nacl.exceptions import CryptoError


class UserError(Exception):
    """A problem the user can fix; the message is safe to show."""


class AuthFailed(Exception):
    """The database rejected the user name or password."""


def env(key, default=''):
    value = os.environ.get(key, '').strip()
    return value if value else default


def env_list(key):
    return [part.strip() for part in env(key).split(',') if part.strip()]


PORTAL_INTERNAL = env('PORTAL_INTERNAL_URL', 'http://portal:8080').rstrip('/')
PORTAL_URL = env('PORTAL_PUBLIC_URL').rstrip('/')
PGA_URL = env('PGA_PUBLIC_URL').rstrip('/')
COOKIE_PREFIX = '__Host-dbp_g'
MAX_SLOTS = 10
RUN_DIR = '/run/dbportal'
# "Not encrypted" (allowed by an admin): no TLS, and the password only through SCRAM, so it never
# crosses the network. Used by the tester and by every connection pgAdmin opens.
PLAIN_PARAMS = {'sslmode': 'disable', 'require_auth': 'scram-sha-256'}
SYSTEM_CA = '/etc/ssl/certs/ca-certificates.crt'

_B64 = re.compile(r'^[A-Za-z0-9_-]+$')


def token():
    return env('PGA_TOKEN')


def b64d(data):
    """Decodes unpadded base64url; returns b'' for anything malformed."""
    if not isinstance(data, str) or not _B64.match(data):
        return b''
    try:
        return base64.urlsafe_b64decode(data + '=' * (-len(data) % 4))
    except (ValueError, TypeError):
        return b''


def same(a, b):
    """Constant-time comparison of two strings."""
    return hmac.compare_digest(str(a).encode(), str(b).encode())


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


def post_json(path, payload, timeout=5.0):
    """POSTs to the portal's internal API. Returns the decoded object, or None on any failure."""
    request = urllib.request.Request(
        PORTAL_INTERNAL + path,
        data=json.dumps(payload, separators=(',', ':')).encode(),
        headers={'Content-Type': 'application/json', 'X-Internal-Token': token()},
        method='POST',
    )
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            if response.status != 200:
                return None
            data = json.loads(response.read(4_000_000))
    except (urllib.error.URLError, OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def open_ticket(ticket, key, ciphertext, nonce):
    """
    Decrypts one open session's connection details. The ticket id comes from the cookie and binds
    the ciphertext to it; the key comes from the cookie only. Returns the descriptor dict or None.
    """
    if len(key) != sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES \
            or len(nonce) != sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES or not ciphertext:
        return None
    id_hash = hashlib.sha256(ticket).hexdigest()
    try:
        plain = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext, ('dbportal/ticket/' + id_hash).encode(), nonce, key)
        descriptor = json.loads(plain)
    except (CryptoError, ValueError, TypeError):
        return None
    if not isinstance(descriptor, dict):
        return None
    descriptor['key'] = id_hash
    return descriptor


def write_pem(directory, pem):
    """Writes a PEM certificate once (named by its hash) and returns its path."""
    os.makedirs(directory, mode=0o700, exist_ok=True)
    path = os.path.join(directory, hashlib.sha256(pem.encode()).hexdigest()[:40] + '.pem')
    if not os.path.isfile(path):
        tmp = '%s.%d.tmp' % (path, os.getpid())
        with open(tmp, 'w', encoding='utf-8') as handle:
            handle.write(pem)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    return path
