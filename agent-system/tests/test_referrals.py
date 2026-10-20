import sqlite3
import unittest
import test_system
from demo import seed_demo, ensure_demo_portal
from store import Problem


class ReferralTests(unittest.TestCase):
    setUp = test_system.HttpTests.setUp
    tearDown = test_system.HttpTests.tearDown
    request = test_system.HttpTests.request
    setup_login = test_system.HttpTests.setup_login

    def login_agent(self, agent):
        self.cookie = self.csrf = None
        self.assertEqual(self.request('/api/login', {'username': agent['username'], 'password': agent['temporary_password']})[0], 200)
        self.csrf = self.request('/api/session')[1]['user']['csrf']

    def test_referral_ownership_conversion_and_admin_only_accounting(self):
        self.setup_login()
        a = self.request('/api/agents', {'name': 'Alice', 'username': 'alice'})[1]
        b = self.request('/api/agents', {'name': 'Bob', 'username': 'bob'})[1]
        self.cookie = self.csrf = None
        status, landing = self.request('/api/referral?code=' + a['code'].lower())
        self.assertEqual(status, 200)
        self.assertEqual(set(landing['agent']), {'name', 'code'})
        self.assertNotIn('delivery_bp', landing['products'][0])
        self.assertEqual(self.request('/recommend')[0], 200)
        inquiry = {'code': a['code'], 'agent_id': b['id'], 'product_id': 'operator-5', 'customer_name': 'Visitor',
                   'contact': 'visitor@example.test', 'participants': 5, 'message': 'Please contact me',
                   'consent': True, 'request_key': 'visitor-request-1'}
        self.assertEqual(self.request('/api/inquiries', inquiry)[0], 201)
        self.assertEqual(self.request('/api/inquiries', inquiry)[0], 201)
        self.assertEqual(self.request('/api/inquiries', {**inquiry, 'code': b['code']})[0], 409)
        self.login_agent(a)
        dash = self.request('/api/dashboard')[1]
        self.assertEqual(len(dash['inquiries']), 1)
        lead = dash['inquiries'][0]
        self.assertEqual(lead['agent_id'], a['id'])
        self.assertEqual(len(dash['orders']), 0)
        self.assertEqual(len(dash['commissions']), 0)
        self.assertEqual(self.request('/api/inquiries/'+lead['id']+'/followup', {'status': 'contacted', 'followup': 'Discussed team course'})[0], 200)
        self.login_agent(b)
        self.assertEqual(self.request('/api/dashboard')[1]['inquiries'], [])
        self.assertEqual(self.request('/api/inquiries/'+lead['id']+'/followup', {'status': 'closed'})[0], 404)
        order = {'inquiry_id': lead['id'], 'request_key': 'convert-1', 'customer_account': 'visitor@example.test',
                 'agent_id': b['id'], 'product_id': 'operator-1', 'customer_name': 'Tampered', 'participants': 1, 'amount': '0.01'}
        self.assertEqual(self.request('/api/orders', order)[0], 404)
        self.login_agent(a)
        status, created = self.request('/api/orders', order)
        self.assertEqual(status, 200)
        self.assertEqual(self.request('/api/orders', order)[0], 200)
        self.assertEqual(self.request('/api/orders', {**order, 'request_key': 'convert-2'})[0], 409)
        dash = self.request('/api/dashboard')[1]
        self.assertEqual(len(dash['orders']), 1)
        actual = dash['orders'][0]
        self.assertEqual((actual['agent_id'], actual['product_id'], actual['customer_name'], actual['amount'], actual['participants']),
                         (a['id'], 'operator-5', 'Visitor', 698000, 5))
        self.assertEqual(dash['inquiries'][0]['order_id'], created['id'])
        self.assertEqual(dash['inquiries'][0]['status'], 'converted')
        self.assertEqual(dash['commissions'], [])
        for endpoint in ('/api/orders/'+created['id']+'/paid', '/api/orders/'+created['id']+'/refund', '/api/agents', '/api/policy', '/api/agents/'+a['id']+'/payout'):
            self.assertEqual(self.request(endpoint, {})[0], 403)
        self.login_agent(b)
        self.assertEqual(self.request('/api/dashboard')[1]['orders'], [])
        self.assertEqual(self.request('/api/orders/'+created['id']+'/cancel', {})[0], 404)
        self.assertNotIn(b'visitor@example.test', self.request('/api/export/orders')[1])

    def test_invalid_disabled_referrals_consent_and_custom_quotes(self):
        self.setup_login()
        a = self.request('/api/agents', {'name': 'Alice', 'username': 'alice'})[1]
        self.assertEqual(self.request('/api/referral?code=missing')[0], 404)
        lead = {'code': a['code'], 'product_id': 'architect-custom', 'customer_name': 'Company', 'contact': 'company@example.test', 'participants': 120, 'consent': True, 'request_key': 'custom-1'}
        self.assertEqual(self.request('/api/inquiries', {**lead, 'consent': False})[0], 400)
        self.assertEqual(self.request('/api/inquiries', {**lead, 'participants': 100})[0], 400)
        self.assertEqual(self.request('/api/inquiries', lead, Origin='https://evil.example')[0], 403)
        self.assertEqual(self.request('/api/inquiries', lead)[0], 201)
        lead_id = self.request('/api/dashboard')[1]['inquiries'][0]['id']
        self.login_agent(a)
        self.assertEqual(self.request('/api/orders', {'inquiry_id': lead_id, 'request_key': 'quote-1', 'customer_account': 'company@example.test', 'amount': '100000'})[0], 403)
        self.cookie = self.csrf = None
        self.request('/api/login', {'username': 'admin', 'password': 'HTTP-test-password-42'})
        self.csrf = self.request('/api/session')[1]['user']['csrf']
        self.assertEqual(self.request('/api/orders', {'inquiry_id': lead_id, 'request_key': 'quote-admin', 'customer_account': 'company@example.test', 'amount': '100000'})[0], 200)
        self.request('/api/agents/'+a['id']+'/status', {'active': False})
        self.assertEqual(self.request('/api/referral?code='+a['code'])[0], 404)
        self.assertEqual(self.request('/api/inquiries', {**lead, 'request_key': 'disabled'})[0], 404)

    def test_demo_portal_is_idempotent_and_refuses_real_database(self):
        with self.assertRaises(Problem):
            ensure_demo_portal(self.store.path)
        demo_path = self.store.path.parent / 'demo.sqlite3'
        seed_demo(demo_path)
        first = ensure_demo_portal(demo_path)
        second = ensure_demo_portal(demo_path)
        self.assertEqual(first['id'], second['id'])
        with sqlite3.connect(demo_path) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM agents').fetchone()[0], 5)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM inquiries').fetchone()[0], 2)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM orders').fetchone()[0], 25)
            self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
            self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(), [])
            db.execute('UPDATE agents SET active=0 WHERE id=?', (first['id'],))
        self.assertEqual(ensure_demo_portal(demo_path)['id'], first['id'])


if __name__ == '__main__':
    unittest.main()
