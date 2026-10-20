"""Exercise production HTTPS/origin/cookie behavior with an isolated local fixture."""
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'agent-system'), str(ROOT / 'agent-system/tests')]
import app
from store import Store
from test_supabase_auth import FakeSupabase

ORIGIN = 'https://zrenai.aiedu.academy'


class WebRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        store = Store(Path(self.temp.name) / 'test.sqlite3')
        auth = FakeSupabase()
        auth.install(store)
        auth.bootstrap(store, 'owner@example.test')
        auth.add('owner@example.test')
        self.server = SimpleNamespace(
            store=store, auth=auth, demo=False, cookie_name='__Host-zr_session',
            secure_cookies=True, public_origins={ORIGIN}, server_port=443,
            failures={}, inquiry_requests=[])
        self.mock = patch('app.context', return_value=self.server)
        self.mock.start()
        self.client = app.app.test_client()

    def tearDown(self):
        self.mock.stop()
        self.temp.cleanup()

    def post(self, path, data, **headers):
        return self.client.post(path, base_url=ORIGIN, json=data,
                                headers={'Origin': ORIGIN, **headers})

    def test_public_routes_and_private_files(self):
        for path in ['/', '/admin', '/recommend?ref=EXAMPLE', '/app.js', '/landing-art.png']:
            response = self.client.get(path, base_url=ORIGIN, headers={'Sec-Fetch-Site': 'cross-site'})
            self.assertEqual(response.status_code, 200, path)
        for path in ['/app.py', '/.env.cloud', '/agent-system/data/supabase.sqlite3', '/agent-system/sql/cloud-schema.sql']:
            self.assertEqual(self.client.get(path, base_url=ORIGIN).status_code, 404, path)
        session = self.client.get('/api/session', base_url=ORIGIN).json
        self.assertEqual(session['auth_provider'], 'supabase')
        self.assertTrue(session['cloud'])
        self.assertIsNone(session['user'])
        self.assertEqual(self.client.get('/api/dashboard', base_url=ORIGIN).status_code, 401)

    def test_exact_origin_and_csrf(self):
        self.assertEqual(self.client.get('/', base_url='https://evil.example').status_code, 403)
        self.assertEqual(self.post('/api/login', {}, Origin='https://evil.example').status_code, 403)
        self.assertEqual(self.client.post('/api/login', base_url=ORIGIN, json={}).status_code, 403)
        self.assertEqual(self.post('/api/setup', {}).status_code, 403)
        response = self.post('/api/login', {'username': 'owner@example.test', 'password': 'Remote-password-2026!'})
        self.assertEqual(response.status_code, 200, response.json)
        cookie = response.headers['Set-Cookie']
        for expected in ['__Host-zr_session=', 'Secure', 'HttpOnly', 'Path=/', 'SameSite=Strict']:
            self.assertIn(expected, cookie)
        self.assertNotIn('Domain=', cookie)
        self.assertEqual(self.client.get('/api/dashboard', base_url=ORIGIN).status_code, 200)
        session = self.client.get('/api/session', base_url=ORIGIN).json
        self.assertNotIn('access_token', str(session))
        self.assertEqual(self.post('/api/logout', {}).status_code, 403)
        self.assertEqual(self.post('/api/logout', {}, **{'X-CSRF-Token': session['user']['csrf']}).status_code, 200)
        self.assertEqual(self.client.get('/api/dashboard', base_url=ORIGIN).status_code, 401)

    def test_trusted_edge_address_and_body_limit(self):
        with app.app.test_request_context('/', base_url=ORIGIN, headers={'X-Forwarded-For': '203.0.113.17'}):
            self.assertEqual(app.WebHandler(self.server).client_address[0], '203.0.113.17')
        response = self.client.post('/api/login', base_url=ORIGIN, data=b'x' * 65537, headers={'Origin': ORIGIN})
        self.assertEqual(response.status_code, 413)


if __name__ == '__main__':
    unittest.main(verbosity=2)
