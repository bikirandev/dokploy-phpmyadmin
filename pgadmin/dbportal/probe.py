"""
Reads a PostgreSQL server's TLS certificate (TLS starts inside the PostgreSQL protocol).
"""
import hashlib
import ipaddress
import socket
import ssl
import struct
import threading
import time

from cryptography import x509

from .common import UserError

_SSL_REQUEST = struct.pack('!II', 8, 80877103)
_cache = {}
_cache_lock = threading.Lock()


def fingerprint(der):
    digest = hashlib.sha256(der).hexdigest().upper()
    return ':'.join(digest[i:i + 2] for i in range(0, len(digest), 2))


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def self_signed(der):
    """
    A self-signed certificate can be pinned strictly: PostgreSQL's client library trusts exactly
    that certificate (sslmode=verify-ca). Others are checked by fingerprint before connecting.
    """
    try:
        cert = x509.load_der_x509_certificate(der)
        if cert.issuer != cert.subject:
            return False
        cert.verify_directly_issued_by(cert)
        return True
    except Exception:  # noqa: BLE001 (any parsing or signature problem means "not self-signed")
        return False


def certificate(host, port, timeout=8):
    """Returns {'pem', 'sha256', 'strict', 'tls'} for the server's certificate."""
    target = '%s:%d' % (host, port)
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        raise UserError("Can't reach %s. Check the address, the port and the firewall." % target) from None
    try:
        sock.settimeout(timeout)
        sock.sendall(_SSL_REQUEST)
        answer = sock.recv(1)
        if answer == b'N':
            raise UserError("%s doesn't offer TLS. Turn on TLS (ssl = on) on the database server, "
                            'or use an SSH tunnel.' % target)
        if answer == b'E':
            raise UserError('%s refused the connection. It may block this portal\'s IP address.' % target)
        if answer != b'S':
            raise UserError("%s doesn't answer like PostgreSQL." % target)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            tls = context.wrap_socket(sock, server_hostname=None if _is_ip(host) else host)
        except (ssl.SSLError, OSError):
            raise UserError('The TLS handshake with %s failed.' % target) from None
        try:
            der = tls.getpeercert(binary_form=True)
            version = tls.version() or ''
        finally:
            tls.close()
        if not der:
            raise UserError('%s did not present a certificate.' % target)
        return {
            'pem': ssl.DER_cert_to_PEM_cert(der),
            'sha256': fingerprint(der),
            'strict': self_signed(der),
            'tls': version,
        }
    except socket.timeout:
        raise UserError("%s didn't answer in time." % target) from None
    except OSError:
        raise UserError("Can't reach %s. Check the address, the port and the firewall." % target) from None
    finally:
        sock.close()


def cached_fingerprint(key, host, port):
    """Fingerprint check before connecting, cached for a few minutes per open session."""
    now = time.time()
    with _cache_lock:
        hit = _cache.get(key)
        if hit and hit[0] > now - 300 and hit[1] == (host, port):
            return hit[2]
    sha = certificate(host, port)['sha256']
    with _cache_lock:
        _cache[key] = (now, (host, port), sha)
        for stale in [k for k, v in _cache.items() if v[0] < now - 3600]:
            _cache.pop(stale, None)
    return sha
