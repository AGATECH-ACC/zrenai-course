import concurrent.futures
import hashlib
import hmac
import os
import secrets
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import test_system
from test_supabase_auth import FakeSupabase
from store import Problem
import payment_sso


class PaymentSSOTests(unittest.TestCase):
    setUp = test_system.HttpTests.setUp
    tearDown = test_system.HttpTests.tearDown
    request = test_system.HttpTests.request

    def configure(self):
        self.env = patch.dict(os.environ, {"PAYMENT_SSO_SECRET": "test-signing-secret-" * 3,
                                         "PAYMENT_ORIGIN": "https://payments.example.com"})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.auth = FakeSupabase()
        self.auth.install(self.store)
        self.auth.bootstrap(self.store, "owner@example.test")
        self.auth.add("owner@example.test")
        self.server.auth = self.auth
        payment_sso.install(self.store)
        token, _ = self.auth.login(self.store, {"username": "owner@example.test", "password": "Remote-password-2026!"})
        self.digest = hashlib.sha256(token.encode()).hexdigest()
        self.user = {"token_hash": self.digest}
        self.state, self.verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(32)

    def grant(self):
        url = payment_sso.issue(self.store, self.user, self.state, payment_sso.challenge(self.verifier))["redirect_url"]
        self.assertEqual(urlsplit(url).netloc, "payments.example.com")
        return {"code": parse_qs(urlsplit(url).query)["code"][0], "state": self.state, "verifier": self.verifier}

    def test_code_is_one_use_and_does_not_expose_provider_token(self):
        self.configure()
        grant = self.grant()
        result = payment_sso.exchange(self.store, self.auth, grant)
        self.assertEqual(result["sub"], self.auth.identities["owner@example.test"][0]["id"])
        self.assertNotIn("access_token", result)
        with self.assertRaises(Problem):
            payment_sso.exchange(self.store, self.auth, grant)

    def test_wrong_pkce_or_state_does_not_redeem_valid_code(self):
        self.configure()
        grant = self.grant()
        for wrong in [{"verifier": secrets.token_urlsafe(32)}, {"state": secrets.token_urlsafe(32)}]:
            with self.assertRaises(Problem):
                payment_sso.exchange(self.store, self.auth, {**grant, **wrong})
        self.assertEqual(payment_sso.exchange(self.store, self.auth, grant)["session_handle"], self.digest)

    def test_expired_code_or_revoked_source_session_rejected(self):
        self.configure()
        grant = self.grant()
        with self.store.tx() as db:
            db.execute("UPDATE payment_login_codes SET expires_at=?", (int(time.time()) - 1,))
        with self.assertRaises(Problem):
            payment_sso.exchange(self.store, self.auth, grant)
        grant = self.grant()
        with self.store.tx() as db:
            db.execute("DELETE FROM sessions WHERE token_hash=?", (self.digest,))
        with self.assertRaises(Problem):
            payment_sso.exchange(self.store, self.auth, grant)

    def test_disabled_account_or_changed_auth_uuid_rejected(self):
        self.configure()
        with self.store.tx() as db:
            db.execute("UPDATE users SET active=0")
        with self.assertRaises(Problem):
            payment_sso.identity(self.store, self.auth, self.digest)
        with self.store.tx() as db:
            db.execute("UPDATE users SET active=1")
            db.execute("UPDATE supabase_links SET auth_id='different-uuid'")
        with self.assertRaises(Problem):
            payment_sso.identity(self.store, self.auth, self.digest)

    def test_concurrent_redemption_only_succeeds_once(self):
        self.configure()
        grant = self.grant()
        def redeem(_):
            try:
                payment_sso.exchange(self.store, self.auth, grant)
                return True
            except Problem:
                return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sum(pool.map(redeem, range(2))), 1)

    def test_http_backchannel_requires_service_signature(self):
        self.configure()
        self.assertEqual(self.request("/api/payment-sso/session", {"session_handle": self.digest})[0], 401)
        self.assertEqual(self.request("/api/payment-sso/authorize", {"state":self.state,"challenge":payment_sso.challenge(self.verifier)})[0], 401)

    def test_http_signed_exchange_and_session_validation(self):
        self.configure()
        grant = self.grant()
        secret, _ = payment_sso.config()
        def send(path, data, timestamp=None):
            timestamp = timestamp or str(int(time.time()))
            signature = hmac.new(secret.encode(), payment_sso.signed_message(timestamp, path, data), hashlib.sha256).hexdigest()
            return self.request(path, data, **{"X-ZrenAI-Time": timestamp, "X-ZrenAI-Signature": signature})
        path = "/api/payment-sso/exchange"
        self.assertEqual(send(path, grant, str(int(time.time()) - 90))[0], 401)
        status, result = send(path, grant)
        self.assertEqual(status, 200, result)
        self.assertEqual(send(path, grant)[0], 401)
        self.assertEqual(send("/api/payment-sso/session", {"session_handle": result["session_handle"]})[0], 200)
        with self.store.tx() as db:
            db.execute("DELETE FROM sessions WHERE token_hash=?", (self.digest,))
        self.assertEqual(send("/api/payment-sso/session", {"session_handle": result["session_handle"]})[0], 401)

    def test_demo_mode_cannot_issue_codes(self):
        self.configure()
        self.server.auth = None
        self.assertEqual(self.request("/api/payment-sso/authorize", {})[0], 403)
