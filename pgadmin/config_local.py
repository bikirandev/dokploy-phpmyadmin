"""
DB Portal configuration for pgAdmin, loaded after pgAdmin's own config.py.

pgAdmin is only reachable through the gateway, which first asks the portal whether the request
carries a live session. The DB Portal layer (dbportal/pgadmin_hooks.py) then signs the person in
as their own pgAdmin user, lists only the servers they opened in the portal, and hands pgAdmin the
connection settings and password for each connection. pgAdmin stores no database passwords.
"""
import logging

SERVER_MODE = True

# Files: settings and Storage Manager files on the volume; login sessions only in memory (tmpfs).
DATA_DIR = '/var/lib/pgadmin'
SQLITE_PATH = '/var/lib/pgadmin/pgadmin4.db'
STORAGE_DIR = '/var/lib/pgadmin/storage'
SESSION_DB_PATH = '/run/pgadmin/sessions'
AZURE_CREDENTIAL_CACHE_DIR = '/run/pgadmin/azure'
KERBEROS_CCACHE_DIR = '/run/pgadmin/krb5'
LOG_FILE = '/dev/null'
CONSOLE_LOG_LEVEL = logging.WARNING
FILE_LOG_LEVEL = logging.CRITICAL
CA_FILE = '/etc/ssl/certs/ca-certificates.crt'
HELP_PATH = '../../docs'

# Sign-in: the DB Portal layer sets REMOTE_USER only after the portal vouched for the request.
# A request header can never name the user.
AUTHENTICATION_SOURCES = ['webserver']
WEBSERVER_AUTO_CREATE_USER = True
WEBSERVER_REMOTE_USER = 'REMOTE_USER'
WEBSERVER_REMOTE_USER_FROM_HEADER = False
WEBSERVER_TRUSTED_PROXIES = []
MASTER_PASSWORD_REQUIRED = False
MFA_ENABLED = False
# The account pgAdmin's setup creates can't sign in (only webserver sign-in is enabled).
ALLOW_SPECIAL_EMAIL_DOMAINS = ['invalid']

# Passwords: never saved by pgAdmin. The DB Portal layer passes them per connection.
ALLOW_SAVE_PASSWORD = False
ALLOW_SAVE_TUNNEL_PASSWORD = False
# SSH tunnels are opened by DB Portal's own tunnel service (with the pinned host key).
SUPPORT_SSH_TUNNEL = False

# Cookies and sessions (pgAdmin has its own host name, so __Host- cookies work)
SESSION_COOKIE_NAME = '__Host-pga_session'
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_EXPIRATION_TIME = 1
ENHANCED_COOKIE_PROTECTION = True
# Like the portal: signed out after 30 minutes without activity.
USER_INACTIVITY_TIMEOUT = 1800
OVERRIDE_USER_INACTIVITY_TIMEOUT = True

# Behind the gateway, which sets X-Forwarded-For and X-Forwarded-Proto (and nothing else).
PROXY_X_FOR_COUNT = 1
PROXY_X_PROTO_COUNT = 1
PROXY_X_HOST_COUNT = 0
PROXY_X_PORT_COUNT = 0
PROXY_X_PREFIX_COUNT = 0
X_FRAME_OPTIONS = 'SAMEORIGIN'
STRICT_TRANSPORT_SECURITY_ENABLED = False  # the gateway sends HSTS

# Features that could reach beyond the user's own databases, or run programs, are off.
ENABLE_PSQL = False
LLM_ENABLED = False
ALLOWED_LLM_API_URLS = []
UPGRADE_CHECK_ENABLED = False
SHOW_GRAVATAR_IMAGE = False  # no requests from users' browsers to gravatar.com
AUTO_DISCOVER_SERVERS = False
ENABLE_BINARY_PATH_BROWSING = False
SHARED_STORAGE = []
SERVER_MODE_ALLOWED_SERVICES = []
SERVER_PASSEXEC_COMMANDS = {}

# Backup, restore and maintenance use the PostgreSQL tools in the image; users can't change these.
DEFAULT_BINARY_PATHS = {'pg': '/usr/local/pgsql-18', 'ppas': '/usr/local/pgsql-18'}
for _version in range(13, 19):
    DEFAULT_BINARY_PATHS['pg-%d' % _version] = '/usr/local/pgsql-%d' % _version
    DEFAULT_BINARY_PATHS['ppas-%d' % _version] = '/usr/local/pgsql-%d' % _version
FIXED_BINARY_PATHS = dict(DEFAULT_BINARY_PATHS)
del _version
