"""
Internal API for the portal (port 8081, internal network only, protected by PGA_TOKEN).
  POST /test    full connection test
  POST /verify  quick login check before opening pgAdmin
Started by the entrypoint: python -m dbportal.internal_api
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import tester
from .common import same, token


class Handler(BaseHTTPRequestHandler):
    server_version = 'dbportal'
    sys_version = ''
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass

    def _send(self, status, data=None):
        body = b'' if data is None else json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_POST(self):  # noqa: N802 (BaseHTTPRequestHandler naming)
        expected = token()
        given = self.headers.get('X-Internal-Token', '')
        if not expected or not same(expected, given) or self.path not in ('/test', '/verify'):
            self._send(404)
            return
        try:
            length = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > 1_000_000:
            self._send(400, {'ok': False, 'error': 'Bad request.'})
            return
        try:
            body = json.loads(self.rfile.read(length))
        except ValueError:
            body = None
        descriptor = body.get('descriptor') if isinstance(body, dict) else None
        if not isinstance(descriptor, dict):
            self._send(400, {'ok': False, 'error': 'Bad request.'})
            return
        self._send(200, tester.run(descriptor, self.path == '/test'))

    def do_GET(self):  # noqa: N802
        self._send(404)


class Server(ThreadingHTTPServer):
    daemon_threads = True


def main():
    Server(('0.0.0.0', 8081), Handler).serve_forever()


if __name__ == '__main__':
    main()
