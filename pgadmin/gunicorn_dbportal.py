"""Gunicorn settings for pgAdmin in DB Portal (started by the entrypoint)."""
import gunicorn

gunicorn.SERVER_SOFTWARE = 'pgAdmin'

# pgAdmin keeps database connections in its own memory: it must run as a single process.
workers = 1
worker_class = 'gthread'
threads = 25
bind = '0.0.0.0:8080'
timeout = 300
graceful_timeout = 20
limit_request_line = 8190
limit_request_fields = 100
limit_request_field_size = 8190

# The visitor's address arrives in X-Real-IP from the gateway.
accesslog = '-'
access_log_format = '%({x-real-ip}i)s %(t)s "%(r)s" %(s)s %(b)s %(M)sms'
errorlog = '-'
loglevel = 'warning'
