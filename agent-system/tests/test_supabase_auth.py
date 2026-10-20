import hashlib
import json
import sqlite3
import unittest
from unittest.mock import patch
from uuid import uuid4

import test_system
from store import Problem
from supabase_auth import SupabaseAuth


class FakeSupabase(SupabaseAuth):
    def __init__(self):
        super().__init__('https://crzeiwqcsthxwcajnnai.supabase.co', 'sb_publishable_test')
        self.identities = {}
        self.tokens = {}
        self.calls = []

    def add(self, email, password='Remote-password-2026!', confirmed=True):
        identity = {'id': str(uuid4()), 'email': email, 'email_confirmed_at': '2026-10-20T00:00:00Z' if confirmed else None,
                    'user_metadata': {'kind': 'admin'}, 'is_anonymous': False}
        self.identities[email] = (identity, password)
        return identity

    def request(self, method, path, payload=None, access_token=None):
        self.calls.append((method, path))
        if path == '/token?grant_type=password':
            entry = self.identities.get(payload['email'])
            if not entry or entry[1] != payload['password']:
                raise Problem('Supabase verification failed', 401)
            token = 'test-' + str(uuid4())
            self.tokens[token] = entry[0]
            return {'access_token': token, 'expires_in': 3600, 'refresh_token': 'MUST-NOT-BE-STORED'}
        if path == '/signup':
            return self.add(payload['email'], payload['password'], confirmed=False)
        if access_token not in self.tokens:
            raise Problem('Supabase verification failed', 401)
        if method == 'GET' and path == '/user':
            return self.tokens[access_token]
        if method == 'PUT' and path == '/user':
            identity = self.tokens[access_token]
            self.identities[identity['email']] = (identity, payload['password'])
            return identity
        if path.startswith('/logout'):
            if path.endswith('global'):
                identifier = self.tokens[access_token]['id']
                self.tokens = {k:v for k,v in self.tokens.items() if v['id'] != identifier}
            else:
                self.tokens.pop(access_token)
            return {}
        raise AssertionError((method, path))


class SupabaseHttpTests(unittest.TestCase):
    setUp = test_system.HttpTests.setUp
    tearDown = test_system.HttpTests.tearDown
    request = test_system.HttpTests.request

    def configure(self):
        self.auth = FakeSupabase()
        self.auth.install(self.store)
        self.auth.bootstrap(self.store, 'owner@example.test')
        self.auth.add('owner@example.test')
        self.server.auth = self.auth

    def login(self, email='owner@example.test', password='Remote-password-2026!'):
        status, body = self.request('/api/login', {'username': email, 'password': password})
        self.assertEqual(status, 200, body)
        self.csrf = self.request('/api/session')[1]['user']['csrf']

    def test_supabase_login_local_password_rejected_and_logout(self):
        self.configure()
        session = self.request('/api/session')[1]
        self.assertFalse(session['needs_setup'])
        self.assertEqual(session['auth_provider'], 'supabase')
        self.assertEqual(self.request('/api/setup', {'username':'attacker','password':'Long-password-here'})[0], 403)
        self.assertEqual(self.request('/api/login', {'username':'owner@example.test','password':'Local-password-2026!'})[0], 401)
        self.login()
        dashboard = self.request('/api/dashboard')
        self.assertEqual(dashboard[0], 200)
        self.assertNotIn('test-', json.dumps(self.request('/api/session')[1]))
        with self.store.connect() as db:
            sessions = [dict(row) for row in db.execute('SELECT * FROM supabase_sessions')]
            self.assertNotIn('MUST-NOT-BE-STORED', json.dumps(sessions))
        self.assertEqual(self.request('/api/logout', {})[0], 200)
        self.assertEqual(self.request('/api/dashboard')[0], 401)
        self.assertIn(('POST','/logout?scope=local'), self.auth.calls)

    def test_agent_metadata_cannot_grant_admin_and_new_accounts_use_email(self):
        self.configure()
        self.login()
        self.assertEqual(self.request('/api/agents', {'name':'A','username':'not-email'})[0], 400)
        status, a = self.request('/api/agents', {'name':'A','username':'agent@example.test'})
        self.assertEqual(status, 200)
        self.assertNotIn('temporary_password', a)
        self.assertEqual(a['auth_provider'], 'supabase')
        self.auth.add('agent@example.test')
        self.request('/api/logout', {})
        self.cookie = self.csrf = None
        self.login('agent@example.test')
        self.assertEqual(self.request('/api/session')[1]['user']['kind'], 'agent')
        self.assertEqual(self.request('/api/policy', {})[0], 403)
        self.assertEqual(self.request('/api/agents', {})[0], 403)
        self.assertEqual(len(self.request('/api/dashboard')[1]['agents']), 1)
        with self.store.tx() as db:
            db.execute("UPDATE users SET active=0 WHERE username='agent@example.test'")
        self.assertEqual(self.request('/api/dashboard')[0], 401)

    def test_registration_requires_allowlist_and_confirmed_identity(self):
        self.configure()
        self.assertEqual(self.request('/api/register', {'username':'outsider@example.test','password':'Remote-password-2026!'})[0], 403)
        self.assertNotIn(('POST','/signup'), self.auth.calls)
        self.assertEqual(self.request('/api/register', {'username':'owner@example.test','password':'Remote-password-2026!'})[0], 200)
        self.assertEqual(self.request('/api/login', {'username':'owner@example.test','password':'Remote-password-2026!'})[0], 401)
        self.auth.identities['owner@example.test'][0]['email_confirmed_at'] = '2026-10-20T00:00:00Z'
        self.login()

    def test_live_identity_check_failure_closed_and_immutable_binding(self):
        self.configure()
        self.login()
        self.auth.tokens.clear()
        self.assertEqual(self.request('/api/dashboard')[0], 401)
        self.cookie = self.csrf = None
        self.login()
        with patch.object(self.auth, 'verified_user', side_effect=Problem('offline',503)):
            self.assertEqual(self.request('/api/dashboard')[0], 503)
        with patch.object(self.auth, 'request', side_effect=Problem('offline',503)):
            self.assertEqual(self.request('/api/logout', {})[0], 200)
        self.assertEqual(self.request('/api/dashboard')[0], 401)
        self.cookie = self.csrf = None
        self.auth.add('owner@example.test')  # Deleted/recreated account, new UUID, same email.
        self.assertEqual(self.request('/api/login', {'username':'owner@example.test','password':'Remote-password-2026!'})[0], 403)

    def test_password_changes_in_supabase_and_revokes_local_sessions(self):
        self.configure()
        self.login()
        with self.store.connect() as db:
            old_hash = db.execute("SELECT password_hash FROM users WHERE username='owner@example.test'").fetchone()[0]
        self.assertEqual(self.request('/api/password', {'current_password':'Remote-password-2026!','new_password':'Changed-password-2026!'})[0], 200)
        self.assertEqual(self.request('/api/dashboard')[0], 401)
        self.cookie = self.csrf = None
        self.login(password='Changed-password-2026!')
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT password_hash FROM users WHERE username='owner@example.test'").fetchone()[0], old_hash)
        self.assertIn(('PUT','/user'), self.auth.calls)

    def test_legacy_sessions_do_not_work_in_supabase_mode(self):
        self.store.setup({'username':'owner@example.test','password':'Local-password-2026!'})
        self.request('/api/login', {'username':'owner@example.test','password':'Local-password-2026!'})
        self.configure()
        self.assertIsNone(self.request('/api/session')[1]['user'])
        self.assertEqual(self.request('/api/dashboard')[0], 401)

    def test_connection_context_closes_and_rolls_back(self):
        db = self.store.connect()
        with db:
            db.execute('SELECT 1')
        with self.assertRaises(sqlite3.ProgrammingError):
            db.execute('SELECT 1')
        with self.assertRaises(ValueError):
            with self.store.connect() as db:
                db.execute("UPDATE products SET name='not committed'")
                raise ValueError()
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM products WHERE name='not committed'").fetchone()[0], 0)


if __name__ == '__main__':
    unittest.main()
