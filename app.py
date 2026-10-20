"""Vercel WSGI entrypoint. Durable state lives in Supabase Postgres."""
import io
import os
import sys
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

from flask import Flask, Response, request

sys.path.insert(0, str(Path(__file__).parent / 'agent-system'))
from server import Handler
from postgres_store import PostgresStore
from supabase_auth import SupabaseAuth

app = Flask(__name__, static_folder=None)
app.config['MAX_CONTENT_LENGTH'] = 65536


@lru_cache(maxsize=1)
def context():
    origin = os.environ['PUBLIC_ORIGIN'].rstrip('/')
    parsed = urlsplit(origin)
    if parsed.scheme != 'https' or parsed.path or not parsed.hostname:
        raise ValueError('PUBLIC_ORIGIN must be an HTTPS origin.')
    origins = {origin}
    for key in ('VERCEL_URL', 'VERCEL_BRANCH_URL', 'VERCEL_PROJECT_PRODUCTION_URL'):
        host = os.environ.get(key)
        if host:
            origins.add('https://' + host)
    return SimpleNamespace(
        store=PostgresStore(os.environ['DATABASE_URL']),
        auth=SupabaseAuth(os.environ['SUPABASE_URL'], os.environ['SUPABASE_PUBLISHABLE_KEY']),
        demo=False, cookie_name='__Host-zr_session', secure_cookies=True,
        public_origins=origins, server_port=443, failures={}, inquiry_requests=[])


class WebHandler(Handler):
    def __init__(self, server):
        self.server = server
        self.path = request.full_path.rstrip('?')
        self.command = request.method
        self.headers = request.headers
        # Vercel overwrites this header at its trusted edge.
        address = request.headers.get('x-forwarded-for') or request.remote_addr or 'unknown'
        self.client_address = (address.split(',')[0].strip(), 0)
        self.rfile = io.BytesIO(request.get_data())
        self.wfile = io.BytesIO()
        self.response_headers = []
        self.status = 200

    def send_response(self, code, message=None):
        self.status = code

    def send_header(self, key, value):
        self.response_headers.append((key, value))

    def end_headers(self):
        pass


@app.route('/', defaults={'path': ''}, methods=['GET', 'HEAD', 'POST'])
@app.route('/<path:path>', methods=['GET', 'HEAD', 'POST'])
def dispatch(path):
    handler = WebHandler(context())
    handler.handle_request(request.method == 'POST')
    return Response(handler.wfile.getvalue(), status=handler.status, headers=handler.response_headers)
