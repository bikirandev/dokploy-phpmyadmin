"""
Address policy. The network guard (pga-guard) enforces the same rules at the packet level.
"""
import ipaddress
import re
import socket
from urllib.parse import urlparse

from .common import PORTAL_INTERNAL, UserError, env_list

_HOST = re.compile(r'^[A-Za-z0-9_.-]{1,253}$')
PRIVATE = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7']


def _ip(value):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def resolve(host):
    """All addresses a host name resolves to (or the address itself)."""
    if _ip(host) is not None:
        return [host]
    if not _HOST.match(host or ''):
        return []
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (OSError, UnicodeError):
        return []
    ips = []
    for info in infos:
        ip = info[4][0].split('%', 1)[0]
        if ip not in ips:
            ips.append(ip)
    return ips


def is_public(ip):
    addr = _ip(ip)
    if addr is None:
        return False
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


def in_cidrs(ip, cidrs):
    addr = _ip(ip)
    if addr is None:
        return False
    for cidr in cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if addr.version == network.version and addr in network:
            return True
    return False


def check_remote(host):
    """
    Remote databases and SSH servers must use public addresses (or an explicitly allowed range).
    This server's own public address counts as remote too.
    """
    ips = resolve(host)
    if not ips:
        raise UserError("Can't find %s. Check the host name." % host)
    for ip in ips:
        if in_cidrs(ip, env_list('EGRESS_BLOCK_CIDRS')):
            raise UserError("Connections to %s are blocked by this portal's settings." % host)
        if not is_public(ip) and not in_cidrs(ip, env_list('EGRESS_ALLOW_CIDRS')):
            raise UserError('%s points to a private address. Remote servers need a public address; '
                            'use an SSH tunnel for private databases.' % host)
    return ips


def check_internal(host):
    """Databases "on this server" must be on the private pma-databases network."""
    ips = resolve(host)
    if not ips:
        raise UserError("Can't find %s. In Dokploy, attach the database to the pma-databases network, "
                        'then try again.' % host)
    portal = resolve(urlparse(PORTAL_INTERNAL).hostname or 'portal')
    for ip in ips:
        if ip in portal or not in_cidrs(ip, PRIVATE):
            raise UserError('%s is not a database on the pma-databases network. '
                            'For other servers choose "Remote server".' % host)
    return ips
