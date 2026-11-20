"""WSGI entry point: pgAdmin with DB Portal's layer installed (see dbportal/pgadmin_hooks.py)."""
import run_pgadmin  # noqa: E402  (creates pgAdmin's Flask app in server mode)

from dbportal import pgadmin_hooks

app = pgadmin_hooks.install(run_pgadmin.app)
